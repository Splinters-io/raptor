"""Task completion detection — screen session polling + exit code parsing.

Checks whether a dispatched/running task has finished by inspecting:
1. Screen session existence (gone = task ended)
2. Exit code marker in the screen log (EXIT_CODE=N)
3. .raptor-run.json status field in the output directory
"""

import json
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class CompletionResult(str, Enum):
    STILL_RUNNING = "still_running"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TaskCompletionInfo:
    result: CompletionResult
    exit_code: Optional[int] = None
    log_tail: str = ""
    error: Optional[str] = None


def check_local_task(screen_session: str,
                     output_dir: Optional[str] = None) -> TaskCompletionInfo:
    """Check completion of a locally-dispatched screen session.

    Called by the scheduler every poll cycle for dispatched/running tasks
    on thefarm (the local host).
    """
    session_alive = _screen_session_exists(screen_session)

    if session_alive:
        tail = _read_screen_log(screen_session)
        exit_code = _parse_exit_code(tail)
        if exit_code is not None:
            return TaskCompletionInfo(
                result=CompletionResult.COMPLETED if exit_code == 0 else CompletionResult.FAILED,
                exit_code=exit_code,
                log_tail=tail[-2000:] if len(tail) > 2000 else tail,
            )
        return TaskCompletionInfo(
            result=CompletionResult.STILL_RUNNING,
            log_tail=tail[-2000:] if len(tail) > 2000 else tail,
        )

    # Session gone — check the log for exit code
    tail = _read_screen_log(screen_session)
    exit_code = _parse_exit_code(tail)

    if exit_code is not None:
        return TaskCompletionInfo(
            result=CompletionResult.COMPLETED if exit_code == 0 else CompletionResult.FAILED,
            exit_code=exit_code,
            log_tail=tail[-2000:] if len(tail) > 2000 else tail,
        )

    # Check .raptor-run.json if we have an output dir
    if output_dir:
        run_status = _check_run_metadata(output_dir)
        if run_status:
            return run_status

    # Screen gone, no exit code, no metadata — assume failed
    return TaskCompletionInfo(
        result=CompletionResult.FAILED,
        error="screen session terminated without exit code",
        log_tail=tail[-2000:] if len(tail) > 2000 else tail,
    )


def get_task_logs(screen_session: str, tail_lines: int = 100) -> str:
    """Fetch recent log output from a screen session."""
    full_log = _read_screen_log(screen_session)
    if not full_log:
        return "(no log available)"
    lines = full_log.splitlines()
    return "\n".join(lines[-tail_lines:])


def _screen_session_exists(session: str) -> bool:
    try:
        result = subprocess.run(
            ["screen", "-ls"],
            capture_output=True, text=True, timeout=5,
        )
        return session in result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return False


def _read_screen_log(session: str) -> str:
    log_path = Path(f"/tmp/{session}.log")
    try:
        if log_path.exists():
            return log_path.read_text(errors="replace")
    except OSError:
        pass
    return ""


def _parse_exit_code(log_text: str) -> Optional[int]:
    for line in reversed(log_text.splitlines()):
        stripped = line.strip()
        if stripped.startswith("EXIT_CODE="):
            try:
                return int(stripped.split("=", 1)[1])
            except (ValueError, IndexError):
                pass
    return None


def _check_run_metadata(output_dir: str) -> Optional[TaskCompletionInfo]:
    meta_path = Path(output_dir) / ".raptor-run.json"
    try:
        if not meta_path.exists():
            return None
        data = json.loads(meta_path.read_text())
        status = data.get("status", "")
        if status == "completed":
            return TaskCompletionInfo(result=CompletionResult.COMPLETED)
        if status == "failed":
            return TaskCompletionInfo(
                result=CompletionResult.FAILED,
                error=data.get("extra", {}).get("error", ""),
            )
    except (json.JSONDecodeError, OSError):
        pass
    return None
