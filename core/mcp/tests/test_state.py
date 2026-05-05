"""Tests for the SQLite-backed TaskStore."""

import tempfile
from pathlib import Path

import pytest

from core.mcp.models import Task, TaskState
from core.mcp.state import TaskStore


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "test.db"
    return TaskStore(db_path=db)


class TestTaskCRUD:
    def test_create_and_get(self, store):
        task = Task(command="scan", target="/tmp/test")
        store.create_task(task)

        retrieved = store.get_task(task.id)
        assert retrieved is not None
        assert retrieved.command == "scan"
        assert retrieved.target == "/tmp/test"
        assert retrieved.state == TaskState.SUBMITTED

    def test_get_nonexistent(self, store):
        assert store.get_task("nonexistent") is None

    def test_create_with_args(self, store):
        task = Task(
            command="fuzz",
            target="/tmp/binary",
            args={"duration": 3600, "policy_groups": "secrets"},
            priority=2,
        )
        store.create_task(task)

        retrieved = store.get_task(task.id)
        assert retrieved.args["duration"] == 3600
        assert retrieved.priority == 2

    def test_create_with_dependencies(self, store):
        dep = Task(command="scan", target="/tmp/test")
        store.create_task(dep)

        task = Task(command="validate", target="/tmp/test", depends_on=[dep.id])
        store.create_task(task)

        retrieved = store.get_task(task.id)
        assert retrieved.depends_on == [dep.id]


class TestStateTransitions:
    def test_valid_transition_submitted_to_scheduled(self, store):
        task = Task(command="scan", target="/tmp/test")
        store.create_task(task)

        updated = store.update_state(task.id, TaskState.SCHEDULED, extra={"host": "thefarm"})
        assert updated.state == TaskState.SCHEDULED
        assert updated.host == "thefarm"
        assert updated.scheduled_at is not None

    def test_valid_transition_scheduled_to_dispatched(self, store):
        task = Task(command="scan", target="/tmp/test")
        store.create_task(task)
        store.update_state(task.id, TaskState.SCHEDULED)
        updated = store.update_state(
            task.id, TaskState.DISPATCHED,
            extra={"screen_session": "raptor-scan-abc123"},
        )
        assert updated.state == TaskState.DISPATCHED
        assert updated.screen_session == "raptor-scan-abc123"

    def test_valid_transition_running_to_completed(self, store):
        task = Task(command="scan", target="/tmp/test")
        store.create_task(task)
        store.update_state(task.id, TaskState.SCHEDULED)
        store.update_state(task.id, TaskState.DISPATCHED)
        store.update_state(task.id, TaskState.RUNNING)
        updated = store.update_state(task.id, TaskState.COMPLETED)
        assert updated.state == TaskState.COMPLETED
        assert updated.completed_at is not None

    def test_invalid_transition_raises(self, store):
        task = Task(command="scan", target="/tmp/test")
        store.create_task(task)

        with pytest.raises(ValueError, match="Invalid transition"):
            store.update_state(task.id, TaskState.COMPLETED)

    def test_retry_failed_task(self, store):
        task = Task(command="fuzz", target="/tmp/binary")
        store.create_task(task)
        store.update_state(task.id, TaskState.SCHEDULED)
        store.update_state(task.id, TaskState.DISPATCHED)
        store.update_state(task.id, TaskState.RUNNING)
        store.update_state(task.id, TaskState.FAILED, extra={"error": "timeout"})

        retried = store.increment_retry(task.id)
        assert retried.state == TaskState.SUBMITTED
        assert retried.retry_count == 1
        assert retried.error is None

    def test_cancel_from_any_non_terminal(self, store):
        for initial_state_seq in [
            [],
            [TaskState.SCHEDULED],
            [TaskState.SCHEDULED, TaskState.DISPATCHED],
            [TaskState.SCHEDULED, TaskState.DISPATCHED, TaskState.RUNNING],
        ]:
            task = Task(command="scan", target="/tmp/test")
            store.create_task(task)
            for s in initial_state_seq:
                store.update_state(task.id, s)
            updated = store.update_state(task.id, TaskState.CANCELLED)
            assert updated.state == TaskState.CANCELLED


class TestListAndFilter:
    def test_list_by_state(self, store):
        for i in range(3):
            store.create_task(Task(command="scan", target=f"/tmp/test{i}"))

        task4 = Task(command="fuzz", target="/tmp/binary")
        store.create_task(task4)
        store.update_state(task4.id, TaskState.SCHEDULED)

        submitted = store.list_tasks(state=TaskState.SUBMITTED)
        assert len(submitted) == 3

        scheduled = store.list_tasks(state=TaskState.SCHEDULED)
        assert len(scheduled) == 1

    def test_list_by_project(self, store):
        store.create_task(Task(command="scan", target="/tmp/a", project="myapp"))
        store.create_task(Task(command="scan", target="/tmp/b", project="myapp"))
        store.create_task(Task(command="scan", target="/tmp/c", project="other"))

        results = store.list_tasks(project="myapp")
        assert len(results) == 2

    def test_schedulable_tasks_ordered_by_priority(self, store):
        store.create_task(Task(command="scan", target="/tmp/low", priority=8))
        store.create_task(Task(command="scan", target="/tmp/high", priority=1))
        store.create_task(Task(command="scan", target="/tmp/med", priority=5))

        schedulable = store.schedulable_tasks()
        priorities = [t.priority for t in schedulable]
        assert priorities == [1, 5, 8]

    def test_active_task_count(self, store):
        t1 = Task(command="scan", target="/tmp/a")
        store.create_task(t1)
        store.update_state(t1.id, TaskState.SCHEDULED, extra={"host": "thefarm"})
        store.update_state(t1.id, TaskState.DISPATCHED)

        t2 = Task(command="fuzz", target="/tmp/b")
        store.create_task(t2)
        store.update_state(t2.id, TaskState.SCHEDULED, extra={"host": "thefarm"})
        store.update_state(t2.id, TaskState.DISPATCHED)
        store.update_state(t2.id, TaskState.RUNNING)

        assert store.active_task_count("thefarm") == 2
        assert store.active_task_count("rengy") == 0


class TestHostCapacity:
    def test_upsert_and_get(self, store):
        from core.mcp.models import HostCapacity

        cap = HostCapacity(
            host="thefarm",
            cpu_percent=45.2,
            ram_used_pct=60.0,
            ram_available_mb=16000.0,
            gpu_util_pct=30.0,
            active_tasks=2,
            max_concurrent=4,
        )
        store.upsert_capacity(cap)

        retrieved = store.get_capacity("thefarm")
        assert retrieved is not None
        assert retrieved.cpu_percent == 45.2
        assert retrieved.active_tasks == 2

    def test_upsert_updates_existing(self, store):
        from core.mcp.models import HostCapacity

        cap1 = HostCapacity(host="thefarm", cpu_percent=30.0)
        store.upsert_capacity(cap1)

        cap2 = HostCapacity(host="thefarm", cpu_percent=80.0)
        store.upsert_capacity(cap2)

        retrieved = store.get_capacity("thefarm")
        assert retrieved.cpu_percent == 80.0

    def test_all_capacity(self, store):
        from core.mcp.models import HostCapacity

        store.upsert_capacity(HostCapacity(host="thefarm", cpu_percent=50.0))
        store.upsert_capacity(HostCapacity(host="rengy", cpu_percent=20.0))

        all_caps = store.all_capacity()
        assert len(all_caps) == 2
        hosts = {c.host for c in all_caps}
        assert hosts == {"thefarm", "rengy"}
