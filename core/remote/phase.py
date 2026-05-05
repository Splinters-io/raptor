"""Phase tracking for long-running headless campaigns.

Writes a `.phase` file in the run directory that records:
- What phase the campaign is in
- What completed so far
- What was found (high-level counts)
- What the next action should be (for the human or next session)

The phase file is the single source of truth for campaign state.
Read it to know where things stand without parsing logs.

Usage in campaign scripts:
    from core.remote.phase import PhaseTracker

    tracker = PhaseTracker(run_dir)
    tracker.start("triage", "Triaging 15 Ubiquiti binaries")

    for binary in binaries:
        triage(binary)
        tracker.progress(f"Triaged {binary.name}: {fn_count} functions")

    tracker.complete("triage", findings={"binaries_triaged": 15, "total_functions": 42000})
    tracker.start("decompile", "Decompiling critical targets")
    ...

Reading from another session:
    tracker = PhaseTracker(run_dir)
    status = tracker.read()
    print(status["phase"])        # "decompile"
    print(status["next_action"])  # "Review triage results, then /validate critical findings"
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

PHASE_FILE = ".phase"


class PhaseTracker:
    """Track campaign phases in a .phase file."""

    def __init__(self, run_dir: Path):
        self._dir = Path(run_dir)
        self._file = self._dir / PHASE_FILE
        self._dir.mkdir(parents=True, exist_ok=True)

    def start(self, phase: str, description: str,
              next_action: str = "") -> None:
        """Mark a phase as started."""
        state = self._load()
        state["phase"] = phase
        state["status"] = "running"
        state["description"] = description
        state["started_at"] = _now()
        state["next_action"] = next_action
        state.setdefault("history", [])
        state["history"].append({
            "phase": phase,
            "event": "started",
            "time": _now(),
            "description": description,
        })
        self._save(state)

    def progress(self, message: str, data: Dict[str, Any] = None) -> None:
        """Record progress within the current phase."""
        state = self._load()
        state["last_progress"] = message
        state["last_progress_time"] = _now()
        if data:
            state.setdefault("phase_data", {}).update(data)
        state.setdefault("history", []).append({
            "phase": state.get("phase", "?"),
            "event": "progress",
            "time": _now(),
            "message": message,
        })
        self._save(state)

    def complete(self, phase: str, findings: Dict[str, Any] = None,
                 next_action: str = "") -> None:
        """Mark a phase as completed with summary findings."""
        state = self._load()
        state["status"] = "phase_complete"
        state["completed_at"] = _now()

        if findings:
            state.setdefault("findings", {}).update(findings)

        if next_action:
            state["next_action"] = next_action

        # Calculate duration
        started = state.get("started_at", "")
        if started:
            try:
                start_ts = time.mktime(time.strptime(started, "%Y-%m-%d %H:%M:%S UTC"))
                end_ts = time.mktime(time.strptime(_now(), "%Y-%m-%d %H:%M:%S UTC"))
                state["phase_duration_minutes"] = round((end_ts - start_ts) / 60, 1)
            except (ValueError, OverflowError):
                pass

        state.setdefault("history", []).append({
            "phase": phase,
            "event": "completed",
            "time": _now(),
            "findings": findings,
            "next_action": next_action,
        })
        self._save(state)

    def fail(self, phase: str, error: str) -> None:
        """Mark a phase as failed."""
        state = self._load()
        state["status"] = "failed"
        state["error"] = error
        state["failed_at"] = _now()
        state["next_action"] = f"Investigate failure in {phase}: {error}"
        state.setdefault("history", []).append({
            "phase": phase,
            "event": "failed",
            "time": _now(),
            "error": error,
        })
        self._save(state)

    def campaign_complete(self, summary: Dict[str, Any] = None) -> None:
        """Mark the entire campaign as done."""
        state = self._load()
        state["status"] = "campaign_complete"
        state["campaign_completed_at"] = _now()
        if summary:
            state["campaign_summary"] = summary
        state.setdefault("history", []).append({
            "phase": "campaign",
            "event": "complete",
            "time": _now(),
            "summary": summary,
        })
        self._save(state)

    def read(self) -> Dict[str, Any]:
        """Read current phase state. Safe to call from any session."""
        return self._load()

    def is_complete(self) -> bool:
        state = self._load()
        return state.get("status") in ("campaign_complete", "failed")

    def _load(self) -> Dict[str, Any]:
        if self._file.exists():
            try:
                return json.loads(self._file.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self, state: Dict[str, Any]) -> None:
        self._file.write_text(json.dumps(state, indent=2, default=str))


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())


def check_campaigns(projects_dir: Path) -> List[Dict]:
    """Check all active campaigns across all projects.

    Returns a list of campaign statuses for any project that has
    a running or recently completed campaign.
    """
    results = []

    if not projects_dir.exists():
        return results

    for project_json in projects_dir.glob("*.json"):
        try:
            data = json.loads(project_json.read_text())
            output_dir = Path(data.get("output_dir", ""))
            if not output_dir.exists():
                continue

            # Find run directories with .phase files
            for run_dir in sorted(output_dir.iterdir(), reverse=True):
                phase_file = run_dir / PHASE_FILE
                if phase_file.exists():
                    state = json.loads(phase_file.read_text())
                    results.append({
                        "project": data.get("name", project_json.stem),
                        "run": run_dir.name,
                        "phase": state.get("phase", "?"),
                        "status": state.get("status", "?"),
                        "next_action": state.get("next_action", ""),
                        "last_progress": state.get("last_progress", ""),
                        "findings": state.get("findings", {}),
                    })
        except (json.JSONDecodeError, OSError):
            continue

    return results
