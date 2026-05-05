"""MCP tool handlers — the interface Claude Code calls.

Tools: submit, campaign, status, cancel, logs, capacity, scheduler_status.
Each function takes typed arguments and returns a JSON-serializable dict.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.mcp.campaign import campaign_status, create_campaign
from core.mcp.completion import get_task_logs
from core.mcp.models import (
    KNOWN_COMMANDS,
    Task,
    TaskState,
)
from core.mcp.probe import probe_local
from core.mcp.scheduler import Scheduler
from core.mcp.state import TaskStore

log = logging.getLogger(__name__)


def _task_to_dict(task: Task) -> Dict[str, Any]:
    d = task.model_dump()
    d["state"] = task.state.value
    for field in ("submitted_at", "scheduled_at", "started_at", "completed_at"):
        val = d.get(field)
        d[field] = val.isoformat() if val else None
    d["duration_seconds"] = task.duration_seconds
    return d


def raptor_submit(store: TaskStore, scheduler: Scheduler,
                  command: str, target: str,
                  project: str = None,
                  args: Dict[str, Any] = None,
                  priority: int = 5,
                  depends_on: List[str] = None,
                  campaign_id: str = None) -> Dict[str, Any]:
    """Submit a task to the orchestrator queue."""
    if command not in KNOWN_COMMANDS:
        return {"error": f"Unknown command: {command}. Known: {sorted(KNOWN_COMMANDS)}"}

    if not target:
        return {"error": "target is required"}

    if priority < 1 or priority > 10:
        return {"error": "priority must be 1-10"}

    if depends_on:
        for dep_id in depends_on:
            dep = store.get_task(dep_id)
            if dep is None:
                return {"error": f"dependency {dep_id} not found"}

    initial_state = TaskState.SUBMITTED
    if depends_on:
        all_met = all(
            store.get_task(d) is not None and store.get_task(d).state == TaskState.COMPLETED
            for d in depends_on
        )
        if not all_met:
            initial_state = TaskState.BLOCKED

    task = Task(
        command=command,
        target=target,
        project=project,
        args=args or {},
        priority=priority,
        depends_on=depends_on or [],
        campaign_id=campaign_id,
        state=initial_state,
    )

    store.create_task(task)
    log.info("submitted task %s: %s %s (priority=%d, state=%s)",
             task.id, command, target, priority, initial_state.value)

    return {
        "task_id": task.id,
        "command": command,
        "target": target,
        "state": initial_state.value,
        "priority": priority,
    }


def raptor_status(store: TaskStore,
                  task_id: str = None,
                  campaign_id: str = None,
                  project: str = None,
                  state: str = None,
                  host: str = None,
                  limit: int = 50) -> Dict[str, Any]:
    """Query task status."""
    if task_id:
        task = store.get_task(task_id)
        if task is None:
            return {"error": f"task {task_id} not found"}
        return {"tasks": [_task_to_dict(task)]}

    state_enum = TaskState(state) if state else None
    tasks = store.list_tasks(
        state=state_enum,
        host=host,
        project=project,
        campaign_id=campaign_id,
        limit=limit,
    )

    return {
        "count": len(tasks),
        "tasks": [_task_to_dict(t) for t in tasks],
    }


def raptor_cancel(store: TaskStore,
                  task_id: str) -> Dict[str, Any]:
    """Cancel a task. Kills its screen session if running."""
    task = store.get_task(task_id)
    if task is None:
        return {"error": f"task {task_id} not found"}

    if task.is_terminal:
        return {"error": f"task {task_id} already in terminal state: {task.state.value}"}

    if task.screen_session and task.state in (TaskState.DISPATCHED, TaskState.RUNNING):
        _kill_screen_session(task.screen_session)

    previous_state = task.state.value
    store.update_state(task_id, TaskState.CANCELLED)

    log.info("cancelled task %s (was %s)", task_id, previous_state)
    return {
        "task_id": task_id,
        "previous_state": previous_state,
        "new_state": "cancelled",
    }


def raptor_logs(store: TaskStore,
                task_id: str,
                tail_lines: int = 100) -> Dict[str, Any]:
    """Fetch recent log output from a task's screen session."""
    task = store.get_task(task_id)
    if task is None:
        return {"error": f"task {task_id} not found"}

    if not task.screen_session:
        return {"error": f"task {task_id} has no screen session (state: {task.state.value})"}

    log_text = get_task_logs(task.screen_session, tail_lines)
    return {
        "task_id": task_id,
        "screen_session": task.screen_session,
        "host": task.host,
        "log_tail": log_text,
    }


def raptor_capacity(store: TaskStore,
                    host: str = None,
                    refresh: bool = False) -> Dict[str, Any]:
    """Show host resource capacity."""
    if refresh or not store.all_capacity():
        cap = probe_local()
        active_count = store.active_task_count(cap.host)
        cap.active_tasks = active_count
        store.upsert_capacity(cap)

    if host:
        cap = store.get_capacity(host)
        if cap is None:
            return {"error": f"no capacity data for host: {host}"}
        return {"hosts": [cap.model_dump()]}

    all_caps = store.all_capacity()
    return {
        "hosts": [c.model_dump() for c in all_caps],
    }


def raptor_campaign(store: TaskStore,
                    target: str,
                    project: str = None,
                    priority: int = 3,
                    phases: List[str] = None) -> Dict[str, Any]:
    """Launch an autonomous campaign — full pipeline from scan to report."""
    if not target:
        return {"error": "target is required"}
    return create_campaign(store, target, project, priority, phases)


def raptor_campaign_status(store: TaskStore,
                           campaign_id: str) -> Dict[str, Any]:
    """Get detailed campaign progress."""
    return campaign_status(store, campaign_id)


def raptor_scheduler_status(scheduler: Scheduler) -> Dict[str, Any]:
    """Show scheduler status, task counts, and host capacity."""
    return scheduler.status()


def _kill_screen_session(session: str) -> None:
    """Kill a screen session. Best-effort, no error on failure."""
    import subprocess
    try:
        subprocess.run(
            ["screen", "-X", "-S", session, "quit"],
            capture_output=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        pass
