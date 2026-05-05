"""Autonomous campaign engine — full pipeline from target to deliverables.

Submit a target, get the full pipeline:
  EXTRACT → TRIAGE → DECOMPILE → SCAN → UNDERSTAND → VALIDATE → EXPLOIT → REPORT

Phases 1-5 dispatch as tool commands (raptor.py, r2, semgrep, etc.).
Phases 6-8 dispatch as Claude Code headless sessions that reason about
findings, develop exploits, and write reports.

The campaign engine creates all tasks with dependency chains, so the
scheduler daemon processes them in order as each phase completes.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from core.mcp.models import (
    COMMAND_RESOURCE_MAP,
    Task,
    TaskState,
)
from core.mcp.state import TaskStore

log = logging.getLogger(__name__)

# Maps pipeline phases to the commands/modes that execute them.
# "tool" phases run raptor.py or shell commands.
# "claude" phases run headless Claude Code sessions with reasoning prompts.
PHASE_SPEC = [
    {
        "phase": 1,
        "name": "scan",
        "command": "scan",
        "mode": "tool",
        "description": "Static analysis with Semgrep + CodeQL",
    },
    {
        "phase": 2,
        "name": "understand",
        "command": "understand",
        "mode": "tool",
        "args": {"map": True},
        "description": "Map entry points, trust boundaries, sinks",
    },
    {
        "phase": 3,
        "name": "validate",
        "command": "validate",
        "mode": "claude",
        "description": "Prove findings are real, reachable, exploitable",
    },
    {
        "phase": 4,
        "name": "exploit",
        "command": "exploit",
        "mode": "claude",
        "description": "Build working PoCs for confirmed findings",
    },
    {
        "phase": 5,
        "name": "report",
        "command": "report",
        "mode": "claude",
        "description": "Generate vulnerability advisories and technical writeups",
    },
]

# For binary targets, prepend RE phases
BINARY_PHASES = [
    {
        "phase": 0,
        "name": "triage",
        "command": "reverse",
        "mode": "tool",
        "args": {"mode": "triage"},
        "description": "r2 triage: arch, mitigations, strings, functions",
    },
]

BINARY_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".elf", ".so", ".dylib", ".bin",
    ".jar", ".war", ".class", ".apk", ".asar", ".msi",
})


def create_campaign(store: TaskStore,
                    target: str,
                    project: str = None,
                    priority: int = 3,
                    phases: List[str] = None,
                    host_preference: str = None) -> Dict[str, Any]:
    """Create a full autonomous campaign for a target.

    Returns campaign_id and the list of created tasks.
    """
    campaign_id = uuid4().hex[:10]
    target_path = Path(target)
    is_binary = target_path.suffix.lower() in BINARY_EXTENSIONS

    # Build phase list
    if phases:
        spec = [p for p in PHASE_SPEC if p["name"] in phases]
    else:
        spec = list(PHASE_SPEC)

    if is_binary:
        spec = BINARY_PHASES + spec

    # Determine host routing per phase
    tasks = []
    prev_task_id = None

    for phase_info in spec:
        depends = [prev_task_id] if prev_task_id else []

        task_args = dict(phase_info.get("args", {}))
        task_args["_campaign_phase"] = phase_info["name"]
        task_args["_campaign_mode"] = phase_info["mode"]

        if phase_info["mode"] == "claude":
            task_args["_claude_headless"] = True

        task = Task(
            command=phase_info["command"],
            target=target,
            project=project,
            campaign_id=campaign_id,
            phase=phase_info["phase"],
            priority=priority,
            args=task_args,
            depends_on=depends,
            state=TaskState.BLOCKED if depends else TaskState.SUBMITTED,
        )

        store.create_task(task)
        tasks.append({
            "task_id": task.id,
            "phase": phase_info["phase"],
            "name": phase_info["name"],
            "command": phase_info["command"],
            "mode": phase_info["mode"],
            "state": task.state.value,
            "depends_on": depends,
            "description": phase_info["description"],
        })

        prev_task_id = task.id
        log.info("campaign %s: created task %s (%s) phase=%d",
                 campaign_id, task.id, phase_info["name"], phase_info["phase"])

    return {
        "campaign_id": campaign_id,
        "target": target,
        "project": project,
        "is_binary": is_binary,
        "task_count": len(tasks),
        "tasks": tasks,
    }


def campaign_status(store: TaskStore, campaign_id: str) -> Dict[str, Any]:
    """Get detailed status for a campaign."""
    tasks = store.list_tasks(campaign_id=campaign_id, limit=100)
    if not tasks:
        return {"error": f"no tasks found for campaign {campaign_id}"}

    phases = []
    for task in sorted(tasks, key=lambda t: t.phase or 0):
        phases.append({
            "task_id": task.id,
            "phase": task.phase,
            "name": task.args.get("_campaign_phase", task.command),
            "state": task.state.value,
            "host": task.host,
            "duration_seconds": task.duration_seconds,
            "error": task.error,
        })

    completed = sum(1 for t in tasks if t.state == TaskState.COMPLETED)
    failed = sum(1 for t in tasks if t.state == TaskState.FAILED)
    running = sum(1 for t in tasks if t.state in (TaskState.DISPATCHED, TaskState.RUNNING))

    total = len(tasks)
    status = "running"
    if completed == total:
        status = "completed"
    elif failed > 0 and completed + failed == total:
        status = "failed"
    elif all(t.state == TaskState.CANCELLED for t in tasks):
        status = "cancelled"

    return {
        "campaign_id": campaign_id,
        "status": status,
        "target": tasks[0].target if tasks else "",
        "project": tasks[0].project if tasks else None,
        "progress": f"{completed}/{total}",
        "completed": completed,
        "failed": failed,
        "running": running,
        "phases": phases,
    }


def build_claude_prompt(task: Task, store: TaskStore) -> str:
    """Build the headless Claude Code prompt for a reasoning phase.

    Loads context from prior phases in the same campaign: findings,
    context maps, brain documents. Constructs a self-contained prompt
    that tells Claude what to do.
    """
    phase_name = task.args.get("_campaign_phase", task.command)
    campaign_id = task.campaign_id

    # Gather output dirs from completed prior phases
    prior_outputs = []
    if campaign_id:
        prior_tasks = store.list_tasks(campaign_id=campaign_id, limit=100)
        for pt in prior_tasks:
            if pt.state == TaskState.COMPLETED and pt.output_dir:
                prior_outputs.append(pt.output_dir)

    output_context = ""
    if prior_outputs:
        output_context = "Prior phase outputs:\n" + "\n".join(f"  - {o}" for o in prior_outputs)

    prompts = {
        "validate": f"""You are running an autonomous exploitability validation.

Target: {task.target}
Project: {task.project or 'standalone'}
{output_context}

Run /validate {task.target} to prove findings from the scan phase are real,
reachable, and exploitable. Follow the full validation pipeline (stages 0→1).
For each finding, determine: is it reachable from attacker-controlled input?
Can it be triggered? What are the constraints?

Write the validation report to the output directory. Mark each finding as
exploitable, confirmed, unlikely, or disproven with evidence.

Do not stop until every finding has been evaluated.""",

        "exploit": f"""You are running autonomous exploit development.

Target: {task.target}
Project: {task.project or 'standalone'}
{output_context}

Run /exploit for each finding marked as exploitable in the validation report.
Build working PoCs that demonstrate the vulnerability:
- RCE/EoP: must show command execution (reverse shell or user add)
- Info leak: must dump actual sensitive data
- DoS: must demonstrate the crash

Every PoC must be self-contained and runnable. No simulated results.
If a PoC doesn't work, document what's blocking and move on.

Write all exploits to the output directory.""",

        "report": f"""You are generating the final campaign deliverables.

Target: {task.target}
Project: {task.project or 'standalone'}
{output_context}

Generate the following documents from the campaign findings:

1. **Vulnerability Advisory** (advisory.md):
   - Executive summary (2-3 sentences)
   - Each vulnerability: title, severity, CVSS, affected component,
     description, proof of exploitation, remediation
   - Timeline and disclosure recommendation

2. **Technical Writeup** (writeup.md):
   - Target overview and attack surface
   - Methodology (tools used, approach)
   - Detailed analysis per vulnerability class
   - Exploitation walkthrough with code/traces
   - Root cause analysis

3. **Executive Summary** (executive-summary.md):
   - 1-page overview for non-technical stakeholders
   - Risk rating, business impact, recommended actions

Read all prior phase outputs and the project brain to gather evidence.
Every claim must be backed by a specific finding, trace, or PoC output.""",
    }

    return prompts.get(phase_name, f"Run /{phase_name} {task.target}")
