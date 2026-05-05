"""Tests for the scheduler — dependency resolution, capacity checks, dispatch."""

from unittest.mock import patch

import pytest

from core.mcp.models import (
    CommandResources,
    HostCapacity,
    SchedulerConfig,
    Task,
    TaskState,
)
from core.mcp.scheduler import Scheduler
from core.mcp.state import TaskStore


@pytest.fixture
def store(tmp_path):
    return TaskStore(db_path=tmp_path / "test.db")


@pytest.fixture
def scheduler(store):
    config = SchedulerConfig(
        poll_interval_sec=1,
        probe_ttl_sec=0,
        local_hostname="thefarm",
    )
    return Scheduler(store, config)


def _seed_capacity(store, cpu=30.0, ram_avail=16000.0, active=0, max_conc=4):
    cap = HostCapacity(
        host="thefarm",
        cpu_percent=cpu,
        ram_available_mb=ram_avail,
        active_tasks=active,
        max_concurrent=max_conc,
    )
    store.upsert_capacity(cap)


class TestDependencyResolution:
    def test_blocked_task_unblocks_when_dep_completes(self, store, scheduler):
        _seed_capacity(store)
        dep = Task(command="scan", target="/tmp/a")
        store.create_task(dep)

        child = Task(command="validate", target="/tmp/a", depends_on=[dep.id], state=TaskState.BLOCKED)
        store.create_task(child)

        # Dep not complete yet — child stays blocked
        stats = scheduler.run_cycle_once()
        child_now = store.get_task(child.id)
        assert child_now.state == TaskState.BLOCKED

        # Complete the dependency
        store.update_state(dep.id, TaskState.SCHEDULED)
        store.update_state(dep.id, TaskState.DISPATCHED)
        store.update_state(dep.id, TaskState.RUNNING)
        store.update_state(dep.id, TaskState.COMPLETED)

        # Now unblock should work
        stats = scheduler.run_cycle_once()
        child_now = store.get_task(child.id)
        assert child_now.state in (TaskState.SUBMITTED, TaskState.SCHEDULED)

    def test_task_with_unmet_deps_gets_blocked(self, store, scheduler):
        _seed_capacity(store)
        dep = Task(command="scan", target="/tmp/a")
        store.create_task(dep)

        child = Task(command="validate", target="/tmp/a", depends_on=[dep.id])
        store.create_task(child)

        stats = scheduler.run_cycle_once()
        child_now = store.get_task(child.id)
        assert child_now.state == TaskState.BLOCKED


class TestCapacityAwareScheduling:
    def test_schedules_when_capacity_available(self, store, scheduler):
        _seed_capacity(store, cpu=30.0, ram_avail=16000.0, active=0)
        task = Task(command="scan", target="/tmp/test")
        store.create_task(task)

        with patch("core.mcp.scheduler.probe_local") as mock_probe:
            mock_probe.return_value = HostCapacity(
                host="thefarm", cpu_percent=30.0, ram_available_mb=16000.0,
            )
            stats = scheduler.run_cycle_once()

        updated = store.get_task(task.id)
        assert updated.state in (TaskState.SCHEDULED, TaskState.DISPATCHED)

    def test_skips_when_cpu_saturated(self, store, scheduler):
        _seed_capacity(store, cpu=95.0, ram_avail=16000.0)
        task = Task(command="scan", target="/tmp/test")
        store.create_task(task)

        with patch("core.mcp.scheduler.probe_local") as mock_probe:
            mock_probe.return_value = HostCapacity(
                host="thefarm", cpu_percent=95.0, ram_available_mb=16000.0,
            )
            stats = scheduler.run_cycle_once()

        updated = store.get_task(task.id)
        assert updated.state == TaskState.SUBMITTED  # not scheduled

    def test_skips_when_max_concurrent_reached(self, store, scheduler):
        _seed_capacity(store, cpu=30.0, ram_avail=16000.0, active=4, max_conc=4)
        task = Task(command="scan", target="/tmp/test")
        store.create_task(task)

        with patch("core.mcp.scheduler.probe_local") as mock_probe:
            mock_probe.return_value = HostCapacity(
                host="thefarm", cpu_percent=30.0, ram_available_mb=16000.0,
                active_tasks=4, max_concurrent=4,
            )
            stats = scheduler.run_cycle_once()

        updated = store.get_task(task.id)
        assert updated.state == TaskState.SUBMITTED

    def test_priority_ordering(self, store, scheduler):
        _seed_capacity(store, cpu=30.0, ram_avail=16000.0, active=0, max_conc=1)
        low = Task(command="scan", target="/tmp/low", priority=8)
        high = Task(command="scan", target="/tmp/high", priority=1)
        store.create_task(low)
        store.create_task(high)

        with patch("core.mcp.scheduler.probe_local") as mock_probe:
            mock_probe.return_value = HostCapacity(
                host="thefarm", cpu_percent=30.0, ram_available_mb=16000.0,
                active_tasks=0, max_concurrent=1,
            )
            stats = scheduler.run_cycle_once()

        high_now = store.get_task(high.id)
        low_now = store.get_task(low.id)
        # High priority should be scheduled, low should still be submitted
        assert high_now.state in (TaskState.SCHEDULED, TaskState.DISPATCHED)
        assert low_now.state == TaskState.SUBMITTED


class TestSchedulerStatus:
    def test_status_returns_counts(self, store, scheduler):
        store.create_task(Task(command="scan", target="/tmp/a"))
        store.create_task(Task(command="scan", target="/tmp/b"))

        status = scheduler.status()
        assert status["tasks_by_state"]["submitted"] == 2
        assert status["running"] is False

    def test_pause_and_resume(self, scheduler):
        assert not scheduler.is_paused
        scheduler.pause()
        assert scheduler.is_paused
        scheduler.resume()
        assert not scheduler.is_paused
