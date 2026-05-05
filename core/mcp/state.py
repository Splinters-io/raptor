"""SQLite-backed task store with WAL mode and PID locking.

State lives at ~/.raptor/orchestrator.db on the orchestrator host.
Single writer (PID lock), multiple readers (WAL mode).
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from core.mcp.models import (
    HostCapacity,
    Task,
    TaskState,
    TERMINAL_STATES,
)

_DEFAULT_DB = Path.home() / ".raptor" / "orchestrator.db"
_LOCK_FILE = Path.home() / ".raptor" / "orchestrator.pid"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id              TEXT PRIMARY KEY,
    project         TEXT,
    campaign_id     TEXT,
    command         TEXT NOT NULL,
    target          TEXT NOT NULL,
    args            TEXT DEFAULT '{}',
    phase           INTEGER,
    priority        INTEGER DEFAULT 5,
    state           TEXT NOT NULL DEFAULT 'submitted',
    host            TEXT,
    screen_session  TEXT,
    output_dir      TEXT,
    submitted_at    TEXT NOT NULL,
    scheduled_at    TEXT,
    started_at      TEXT,
    completed_at    TEXT,
    error           TEXT,
    result_summary  TEXT DEFAULT '{}',
    retry_count     INTEGER DEFAULT 0,
    max_retries     INTEGER DEFAULT 2,
    depends_on      TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS host_capacity (
    host            TEXT PRIMARY KEY,
    last_probed     TEXT NOT NULL,
    cpu_percent     REAL,
    ram_used_pct    REAL,
    ram_available_mb REAL,
    gpu_util_pct    REAL,
    gpu_mem_used_mb REAL,
    active_tasks    INTEGER DEFAULT 0,
    max_concurrent  INTEGER DEFAULT 4,
    is_reachable    INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
CREATE INDEX IF NOT EXISTS idx_tasks_host ON tasks(host);
CREATE INDEX IF NOT EXISTS idx_tasks_campaign ON tasks(campaign_id);
CREATE INDEX IF NOT EXISTS idx_tasks_priority ON tasks(priority, submitted_at);
"""


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class TaskStore:
    """SQLite-backed persistent task store."""

    def __init__(self, db_path: Path = None):
        self._path = db_path or _DEFAULT_DB
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self._path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _row_to_task(self, row: sqlite3.Row) -> Task:
        d = dict(row)
        d["args"] = json.loads(d["args"]) if d["args"] else {}
        d["result_summary"] = json.loads(d["result_summary"]) if d["result_summary"] else {}
        d["depends_on"] = json.loads(d["depends_on"]) if d["depends_on"] else []
        d["is_reachable"] = bool(d.get("is_reachable", True))
        for field in ("submitted_at", "scheduled_at", "started_at", "completed_at"):
            val = d.get(field)
            if val:
                d[field] = datetime.fromisoformat(val)
            else:
                d[field] = None
        return Task(**d)

    def _task_to_row(self, task: Task) -> Dict:
        d = task.model_dump()
        d["args"] = json.dumps(d["args"])
        d["result_summary"] = json.dumps(d["result_summary"])
        d["depends_on"] = json.dumps(d["depends_on"])
        d["state"] = d["state"].value if isinstance(d["state"], TaskState) else d["state"]
        for field in ("submitted_at", "scheduled_at", "started_at", "completed_at"):
            val = d.get(field)
            d[field] = val.isoformat() if val else None
        return d

    def create_task(self, task: Task) -> Task:
        row = self._task_to_row(task)
        cols = ", ".join(row.keys())
        placeholders = ", ".join(f":{k}" for k in row.keys())
        with self._conn() as conn:
            conn.execute(f"INSERT INTO tasks ({cols}) VALUES ({placeholders})", row)
        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
            row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_task(row)

    def update_state(self, task_id: str, new_state: TaskState,
                     extra: Dict = None) -> Optional[Task]:
        task = self.get_task(task_id)
        if task is None:
            return None

        if not task.can_transition_to(new_state):
            raise ValueError(
                f"Invalid transition: {task.state.value} → {new_state.value} "
                f"for task {task_id}"
            )

        now = datetime.now(timezone.utc).isoformat()
        updates = {"state": new_state.value}

        if new_state == TaskState.SCHEDULED:
            updates["scheduled_at"] = now
        elif new_state in (TaskState.DISPATCHED, TaskState.RUNNING):
            updates["started_at"] = now
        elif new_state in TERMINAL_STATES:
            updates["completed_at"] = now

        if extra:
            for k, v in extra.items():
                if k in ("host", "screen_session", "output_dir", "error"):
                    updates[k] = v

        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [task_id]

        with self._conn() as conn:
            conn.execute(f"UPDATE tasks SET {set_clause} WHERE id = ?", values)

        return self.get_task(task_id)

    def increment_retry(self, task_id: str) -> Optional[Task]:
        with self._conn() as conn:
            conn.execute(
                "UPDATE tasks SET retry_count = retry_count + 1, "
                "state = 'submitted', error = NULL WHERE id = ?",
                (task_id,),
            )
        return self.get_task(task_id)

    def list_tasks(self, state: TaskState = None, host: str = None,
                   project: str = None, campaign_id: str = None,
                   limit: int = 100) -> List[Task]:
        conditions = []
        params = []

        if state is not None:
            conditions.append("state = ?")
            params.append(state.value)
        if host is not None:
            conditions.append("host = ?")
            params.append(host)
        if project is not None:
            conditions.append("project = ?")
            params.append(project)
        if campaign_id is not None:
            conditions.append("campaign_id = ?")
            params.append(campaign_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)

        with self._conn() as conn:
            cur = conn.execute(
                f"SELECT * FROM tasks {where} ORDER BY priority ASC, submitted_at ASC LIMIT ?",
                params,
            )
            return [self._row_to_task(row) for row in cur.fetchall()]

    def schedulable_tasks(self) -> List[Task]:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT * FROM tasks WHERE state = 'submitted' "
                "ORDER BY priority ASC, submitted_at ASC",
            )
            return [self._row_to_task(row) for row in cur.fetchall()]

    def blocked_tasks(self) -> List[Task]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM tasks WHERE state = 'blocked'")
            return [self._row_to_task(row) for row in cur.fetchall()]

    def active_tasks(self, host: str = None) -> List[Task]:
        if host:
            query = "SELECT * FROM tasks WHERE state IN ('dispatched', 'running') AND host = ?"
            params = (host,)
        else:
            query = "SELECT * FROM tasks WHERE state IN ('dispatched', 'running')"
            params = ()
        with self._conn() as conn:
            cur = conn.execute(query, params)
            return [self._row_to_task(row) for row in cur.fetchall()]

    def active_task_count(self, host: str) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE state IN ('dispatched', 'running') AND host = ?",
                (host,),
            )
            return cur.fetchone()[0]

    def update_result_summary(self, task_id: str, summary: Dict) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE tasks SET result_summary = ? WHERE id = ?",
                (json.dumps(summary), task_id),
            )

    # --- Host capacity ---

    def upsert_capacity(self, cap: HostCapacity) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO host_capacity "
                "(host, last_probed, cpu_percent, ram_used_pct, ram_available_mb, "
                "gpu_util_pct, gpu_mem_used_mb, active_tasks, max_concurrent, is_reachable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cap.host, cap.last_probed.isoformat(), cap.cpu_percent,
                    cap.ram_used_pct, cap.ram_available_mb, cap.gpu_util_pct,
                    cap.gpu_mem_used_mb, cap.active_tasks, cap.max_concurrent,
                    int(cap.is_reachable),
                ),
            )

    def get_capacity(self, host: str) -> Optional[HostCapacity]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM host_capacity WHERE host = ?", (host,))
            row = cur.fetchone()
        if row is None:
            return None
        d = dict(row)
        d["last_probed"] = datetime.fromisoformat(d["last_probed"])
        d["is_reachable"] = bool(d["is_reachable"])
        return HostCapacity(**d)

    def all_capacity(self) -> List[HostCapacity]:
        with self._conn() as conn:
            cur = conn.execute("SELECT * FROM host_capacity")
            results = []
            for row in cur.fetchall():
                d = dict(row)
                d["last_probed"] = datetime.fromisoformat(d["last_probed"])
                d["is_reachable"] = bool(d["is_reachable"])
                results.append(HostCapacity(**d))
            return results

    # --- PID lock ---

    @staticmethod
    def acquire_lock() -> bool:
        _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        if _LOCK_FILE.exists():
            try:
                existing_pid = int(_LOCK_FILE.read_text().strip())
                if _pid_alive(existing_pid):
                    return False
            except (ValueError, OSError):
                pass
        _LOCK_FILE.write_text(str(os.getpid()))
        return True

    @staticmethod
    def release_lock() -> None:
        try:
            if _LOCK_FILE.exists():
                pid = int(_LOCK_FILE.read_text().strip())
                if pid == os.getpid():
                    _LOCK_FILE.unlink(missing_ok=True)
        except (ValueError, OSError):
            pass
