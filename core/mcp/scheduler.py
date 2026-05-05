"""Background scheduler — probe, schedule, dispatch, poll.

Runs as a daemon thread. Wakes every poll_interval_sec (default 30s):

1. Probe: refresh capacity on all known hosts (local + SSH)
2. Unblock: re-evaluate blocked tasks whose dependencies completed
3. Schedule: assign hosts to submitted tasks (capacity + capability aware)
4. Dispatch: launch into screen sessions (local) or SSH (remote)
5. Poll: check running tasks for completion

Multi-host aware: dispatches to thefarm (local), rengy (Windows via SSH),
or Mac (via SSH) based on task requirements and available capacity.

Claude headless: tasks with _claude_headless=True in args are dispatched
as `claude -p "prompt"` sessions instead of raptor.py commands.
"""

import logging
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.mcp.completion import CompletionResult, check_local_task
from core.mcp.models import (
    COMMAND_RESOURCE_MAP,
    CommandResources,
    HostCapacity,
    SchedulerConfig,
    Task,
    TaskState,
)
from core.mcp.probe import probe_host, probe_local
from core.mcp.state import TaskStore

log = logging.getLogger(__name__)

# Host capability requirements per command
_CAPABILITY_REQUIREMENTS = {
    "fuzz": {"fuzz"},
    "gpu-fuzz": {"fuzz"},
    "reverse": {"r2"},
    "crash-analysis": {"gdb"},
}

# Commands that MUST run on Windows
_WINDOWS_COMMANDS = set()

# File extensions that route to Windows
_WINDOWS_EXTENSIONS = frozenset({".exe", ".dll", ".sys", ".msi"})


class Scheduler:
    """Multi-host compute-aware task scheduler."""

    def __init__(self, store: TaskStore, config: SchedulerConfig = None):
        self._store = store
        self._config = config or SchedulerConfig()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._paused = threading.Event()
        self._paused.set()
        self._hosts: Dict[str, dict] = {}
        self._load_hosts()

    def _load_hosts(self) -> None:
        """Load host registry from hosts.json."""
        try:
            from core.remote.hosts import HostRegistry
            reg = HostRegistry()
            for host in reg.all_hosts():
                self._hosts[host.name] = {
                    "os": host.os.lower(),
                    "ssh_target": host.ssh_target,
                    "port": host.port,
                    "capabilities": set(c.lower() for c in host.capabilities),
                    "screen_support": host.screen_support,
                    "max_concurrent": 4 if host.os.lower() == "linux" else 2,
                }
            if self._hosts:
                log.info("loaded %d hosts: %s", len(self._hosts),
                         ", ".join(self._hosts.keys()))
        except Exception:
            log.warning("could not load hosts.json — local dispatch only")

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def is_paused(self) -> bool:
        return not self._paused.is_set()

    def start(self) -> None:
        if self.is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="raptor-scheduler",
            daemon=True,
        )
        self._thread.start()
        log.info("scheduler started (poll=%ds, hosts=%s)",
                 self._config.poll_interval_sec,
                 list(self._hosts.keys()) or ["local"])

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        log.info("scheduler stopped")

    def pause(self) -> None:
        self._paused.clear()
        log.info("scheduler paused")

    def resume(self) -> None:
        self._paused.set()
        log.info("scheduler resumed")

    def run_cycle_once(self) -> dict:
        return self._cycle()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            if self._paused.wait(timeout=1):
                try:
                    self._cycle()
                except Exception:
                    log.exception("scheduler cycle failed")
            self._stop_event.wait(timeout=self._config.poll_interval_sec)

    def _cycle(self) -> dict:
        stats = {"probed": 0, "unblocked": 0, "scheduled": 0, "dispatched": 0, "completed": 0}
        stats["probed"] = self._probe_all()
        stats["unblocked"] = self._unblock()
        stats["scheduled"] = self._schedule()
        stats["dispatched"] = self._dispatch()
        stats["completed"] = self._poll()
        return stats

    # --- Probe all hosts ---

    def _probe_all(self) -> int:
        probed = 0
        now = datetime.now(timezone.utc)

        # Local (thefarm)
        local_name = self._config.local_hostname
        existing = self._store.get_capacity(local_name)
        if not existing or (now - existing.last_probed).total_seconds() >= self._config.probe_ttl_sec:
            try:
                cap = probe_local(local_name)
                cap.active_tasks = self._store.active_task_count(local_name)
                cap.max_concurrent = self._hosts.get(local_name, {}).get("max_concurrent", 4)
                self._store.upsert_capacity(cap)
                probed += 1
            except Exception:
                log.debug("local probe failed", exc_info=True)

        # Remote hosts
        for name, info in self._hosts.items():
            if name == local_name:
                continue
            existing = self._store.get_capacity(name)
            if existing and (now - existing.last_probed).total_seconds() < self._config.probe_ttl_sec:
                continue
            try:
                cap = probe_host(
                    name, info["os"], info["ssh_target"], info["port"],
                    info["max_concurrent"],
                )
                cap.active_tasks = self._store.active_task_count(name)
                self._store.upsert_capacity(cap)
                probed += 1
            except Exception:
                log.debug("probe failed for %s", name, exc_info=True)
                self._store.upsert_capacity(HostCapacity(
                    host=name, is_reachable=False,
                    max_concurrent=info["max_concurrent"],
                ))

        return probed

    # --- Unblock ---

    def _unblock(self) -> int:
        blocked = self._store.blocked_tasks()
        unblocked = 0
        for task in blocked:
            if self._dependencies_met(task):
                self._store.update_state(task.id, TaskState.SUBMITTED)
                unblocked += 1
        return unblocked

    def _dependencies_met(self, task: Task) -> bool:
        for dep_id in task.depends_on:
            dep = self._store.get_task(dep_id)
            if dep is None or dep.state != TaskState.COMPLETED:
                return False
        return True

    # --- Schedule (multi-host) ---

    def _schedule(self) -> int:
        schedulable = self._store.schedulable_tasks()
        scheduled = 0

        for task in schedulable:
            if not self._dependencies_met(task):
                self._store.update_state(task.id, TaskState.BLOCKED)
                continue

            host = self._pick_host(task)
            if host is None:
                continue

            self._store.update_state(
                task.id, TaskState.SCHEDULED,
                extra={"host": host},
            )

            # Update in-memory capacity count
            cap = self._store.get_capacity(host)
            if cap:
                cap.active_tasks += 1
                self._store.upsert_capacity(cap)

            scheduled += 1

        return scheduled

    def _pick_host(self, task: Task) -> Optional[str]:
        """Pick the best host for a task based on requirements and capacity."""
        target_ext = Path(task.target).suffix.lower()
        resources = COMMAND_RESOURCE_MAP.get(task.command, CommandResources())
        required_caps = _CAPABILITY_REQUIREMENTS.get(task.command, set())

        # Windows targets go to Windows hosts
        needs_windows = target_ext in _WINDOWS_EXTENSIONS or task.command in _WINDOWS_COMMANDS

        candidates = []

        # Local host (thefarm) is always a candidate for non-Windows tasks
        if not needs_windows:
            local_name = self._config.local_hostname
            local_cap = self._store.get_capacity(local_name)
            local_info = self._hosts.get(local_name, {})
            local_caps = local_info.get("capabilities", set())

            if local_cap and self._has_capacity(local_cap, resources):
                if not required_caps or required_caps.issubset(local_caps):
                    candidates.append((local_name, local_cap, 0))  # priority 0 = prefer local

        # Remote hosts
        for name, info in self._hosts.items():
            if name == self._config.local_hostname:
                continue

            host_os = info["os"]
            host_caps = info["capabilities"]

            if needs_windows and host_os != "windows":
                continue
            if not needs_windows and host_os == "windows":
                continue

            if required_caps and not required_caps.issubset(host_caps):
                continue

            cap = self._store.get_capacity(name)
            if cap and self._has_capacity(cap, resources):
                priority = 1  # remote = slightly lower priority
                candidates.append((name, cap, priority))

        if not candidates:
            return None

        # Sort: prefer local (priority 0), then least loaded
        candidates.sort(key=lambda c: (c[2], c[1].active_tasks))
        return candidates[0][0]

    def _has_capacity(self, cap: HostCapacity, resources: CommandResources) -> bool:
        if not cap.is_reachable:
            return False
        if cap.active_tasks >= cap.max_concurrent:
            return False
        if cap.cpu_percent is not None and cap.cpu_percent > self._config.cpu_threshold_pct:
            return False
        if cap.ram_available_mb is not None and cap.ram_available_mb < self._config.ram_min_available_mb:
            return False
        if resources.needs_gpu and cap.gpu_util_pct is not None and cap.gpu_util_pct > 90:
            return False
        return True

    # --- Dispatch (local + remote) ---

    def _dispatch(self) -> int:
        scheduled = self._store.list_tasks(state=TaskState.SCHEDULED)
        dispatched = 0
        for task in scheduled:
            try:
                if self._dispatch_task(task):
                    dispatched += 1
            except Exception:
                log.exception("dispatch failed for task %s", task.id)
                self._store.update_state(
                    task.id, TaskState.FAILED,
                    extra={"error": "dispatch exception"},
                )
        return dispatched

    def _dispatch_task(self, task: Task) -> bool:
        host = task.host or self._config.local_hostname
        is_local = (host == self._config.local_hostname)
        is_claude = task.args.get("_claude_headless", False)

        session = f"raptor-{task.command}-{task.id}"
        log_file = f"/tmp/{session}.log"

        raptor_dir = os.environ.get("RAPTOR_DIR")
        if not raptor_dir:
            self._store.update_state(task.id, TaskState.FAILED,
                                     extra={"error": "RAPTOR_DIR not set"})
            return False

        if is_claude:
            cmd = self._build_claude_command(task, raptor_dir)
        else:
            cmd = self._build_tool_command(task, raptor_dir)

        if is_local:
            return self._dispatch_local(task, session, log_file, cmd)
        else:
            return self._dispatch_remote(task, host, session, log_file, cmd)

    def _dispatch_local(self, task: Task, session: str, log_file: str,
                        cmd: str) -> bool:
        screen_cmd = (
            f"screen -dmS {session} -L -Logfile {log_file} "
            f"bash -c '{cmd}; echo EXIT_CODE=$? >> {log_file}'"
        )
        result = subprocess.run(
            ["bash", "-c", screen_cmd],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            self._store.update_state(
                task.id, TaskState.FAILED,
                extra={"error": f"screen launch failed: {result.stderr[:500]}"},
            )
            return False

        self._store.update_state(
            task.id, TaskState.DISPATCHED,
            extra={"screen_session": session},
        )
        log.info("dispatched %s → local screen %s", task.id, session)
        return True

    def _dispatch_remote(self, task: Task, host: str, session: str,
                         log_file: str, cmd: str) -> bool:
        """Dispatch to a remote host via SSH."""
        host_info = self._hosts.get(host)
        if not host_info:
            self._store.update_state(task.id, TaskState.FAILED,
                                     extra={"error": f"unknown host: {host}"})
            return False

        try:
            from core.remote.hosts import HostRegistry
            reg = HostRegistry()
            remote_host = reg.get(host)
            if remote_host is None:
                self._store.update_state(task.id, TaskState.FAILED,
                                         extra={"error": f"host {host} not in registry"})
                return False

            from core.remote.execute import remote_screen, remote_exec
            if remote_host.screen_support:
                success = remote_screen(remote_host, f"{task.command}-{task.id}", cmd)
            else:
                # Windows: direct background execution
                from core.remote.execute import _wrap_windows_background
                bg_cmd = _wrap_windows_background(cmd, session)
                rc, _, stderr = remote_exec(remote_host, bg_cmd)
                success = rc == 0

            if not success:
                self._store.update_state(task.id, TaskState.FAILED,
                                         extra={"error": f"remote dispatch to {host} failed"})
                return False

            self._store.update_state(
                task.id, TaskState.DISPATCHED,
                extra={"screen_session": session},
            )
            log.info("dispatched %s → %s (remote) screen %s", task.id, host, session)
            return True

        except Exception as exc:
            self._store.update_state(task.id, TaskState.FAILED,
                                     extra={"error": f"remote dispatch error: {exc}"})
            return False

    def _build_tool_command(self, task: Task, raptor_dir: str) -> str:
        """Build shell command for tool-based phases."""
        target_flag = {
            "scan": "--repo", "codeql": "--repo", "agentic": "--repo",
            "fuzz": "--binary", "web": "--url",
        }.get(task.command, "--repo")

        parts = [f"cd {raptor_dir}", "&&", "python3", "raptor.py", task.command]
        parts.extend([target_flag, task.target])

        if task.output_dir:
            parts.extend(["--out", task.output_dir])

        for key, val in task.args.items():
            if key.startswith("_"):
                continue  # skip internal metadata
            flag = f"--{key.replace('_', '-')}"
            if isinstance(val, bool):
                if val:
                    parts.append(flag)
            else:
                parts.extend([flag, str(val)])

        return " ".join(parts)

    def _build_claude_command(self, task: Task, raptor_dir: str) -> str:
        """Build command for Claude Code headless reasoning sessions."""
        from core.mcp.campaign import build_claude_prompt
        prompt = build_claude_prompt(task, self._store)

        escaped_prompt = prompt.replace("'", "'\\''")
        return (
            f"cd {raptor_dir} && "
            f"claude -p '{escaped_prompt}' "
            f"--allowedTools 'Bash(read_only=true),Read,Grep,Glob,WebFetch'"
        )

    # --- Poll (local + remote) ---

    def _poll(self) -> int:
        active = self._store.active_tasks()
        completed = 0

        for task in active:
            if not task.screen_session:
                continue

            is_local = (task.host == self._config.local_hostname)
            if is_local:
                info = check_local_task(task.screen_session, task.output_dir)
            else:
                info = self._poll_remote_task(task)

            if info.result == CompletionResult.STILL_RUNNING:
                if task.state == TaskState.DISPATCHED:
                    self._store.update_state(task.id, TaskState.RUNNING)
                continue

            if info.result == CompletionResult.COMPLETED:
                self._store.update_state(task.id, TaskState.COMPLETED)
                if info.exit_code is not None:
                    self._store.update_result_summary(
                        task.id, {"exit_code": info.exit_code},
                    )
                completed += 1
                log.info("task %s completed (exit=%s, host=%s)",
                         task.id, info.exit_code, task.host)

            elif info.result == CompletionResult.FAILED:
                error = info.error or f"exit code {info.exit_code}"
                if task.retry_count < task.max_retries:
                    self._store.increment_retry(task.id)
                    log.info("task %s failed, retrying (%d/%d): %s",
                             task.id, task.retry_count + 1, task.max_retries, error)
                else:
                    self._store.update_state(
                        task.id, TaskState.FAILED,
                        extra={"error": error},
                    )
                    log.warning("task %s failed permanently: %s", task.id, error)
                completed += 1

        return completed

    def _poll_remote_task(self, task: Task):
        """Check a remote task's status by querying its screen session."""
        from core.mcp.completion import TaskCompletionInfo, CompletionResult
        try:
            from core.remote.hosts import HostRegistry
            from core.remote.execute import remote_screen_list, remote_screen_log

            reg = HostRegistry()
            host = reg.get(task.host)
            if host is None:
                return TaskCompletionInfo(result=CompletionResult.UNKNOWN)

            sessions = remote_screen_list(host)
            session_alive = any(task.screen_session in s for s in sessions)

            if session_alive:
                return TaskCompletionInfo(result=CompletionResult.STILL_RUNNING)

            # Session gone — check log for exit code
            log_text = remote_screen_log(host, f"{task.command}-{task.id}")
            for line in reversed(log_text.splitlines()):
                if line.strip().startswith("EXIT_CODE="):
                    try:
                        code = int(line.strip().split("=", 1)[1])
                        return TaskCompletionInfo(
                            result=CompletionResult.COMPLETED if code == 0 else CompletionResult.FAILED,
                            exit_code=code,
                            log_tail=log_text[-2000:],
                        )
                    except (ValueError, IndexError):
                        pass

            return TaskCompletionInfo(
                result=CompletionResult.FAILED,
                error="remote screen session ended without exit code",
            )
        except Exception:
            log.debug("remote poll failed for %s on %s", task.id, task.host, exc_info=True)
            return TaskCompletionInfo(result=CompletionResult.STILL_RUNNING)

    def status(self) -> dict:
        counts = {}
        for state in TaskState:
            tasks = self._store.list_tasks(state=state, limit=10000)
            counts[state.value] = len(tasks)

        host_caps = self._store.all_capacity()
        hosts = []
        for cap in host_caps:
            hosts.append({
                "host": cap.host,
                "cpu": cap.cpu_percent,
                "ram_avail_mb": cap.ram_available_mb,
                "gpu": cap.gpu_util_pct,
                "active": cap.active_tasks,
                "reachable": cap.is_reachable,
            })

        return {
            "running": self.is_running,
            "paused": self.is_paused,
            "poll_interval_sec": self._config.poll_interval_sec,
            "tasks_by_state": counts,
            "hosts": hosts,
        }
