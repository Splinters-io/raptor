"""Campaign pipeline — enforces phase ordering with hard gates.

Prevents LLM analysis from running before tool-based scanning is
complete. This exists because flat LLM prompts over raw code were
run twice as a shortcut, both times producing garbage findings.

The pipeline order is fixed:
    1. EXTRACT  — unpack firmware, extract binaries, container layers
    2. TRIAGE   — r2 triage every binary (arch, mitigations, strings, functions)
    3. DECOMPILE — batch decompile all functions (r2, JADX, CFR, ilspycmd)
    4. SCAN     — Semgrep, CodeQL, YARA on source/decompiled/bytecode
    5. UNDERSTAND — /understand --map: entry points, trust boundaries, sinks
    6. VALIDATE — /validate: prove findings are real, reachable, exploitable
    7. EXPLOIT  — /exploit: build working PoCs for confirmed findings
    8. REPORT   — synthesize into brain documents

LLM is used at phases 6 and 7 — to reason about TOOL FINDINGS.
LLM is NEVER used at phases 2-5 as a substitute for tools.
"""

from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Dict, List, Optional

from core.logging import get_logger

logger = get_logger()


class Phase(IntEnum):
    EXTRACT = 1
    TRIAGE = 2
    DECOMPILE = 3
    SCAN = 4
    UNDERSTAND = 5
    VALIDATE = 6
    EXPLOIT = 7
    REPORT = 8


PHASE_NAMES = {
    Phase.EXTRACT: "extract",
    Phase.TRIAGE: "triage",
    Phase.DECOMPILE: "decompile",
    Phase.SCAN: "scan",
    Phase.UNDERSTAND: "understand",
    Phase.VALIDATE: "validate",
    Phase.EXPLOIT: "exploit",
    Phase.REPORT: "report",
}

# Phases where LLM analysis is allowed
LLM_ALLOWED_PHASES = {Phase.VALIDATE, Phase.EXPLOIT, Phase.REPORT}

# Phases that MUST complete before the next starts
HARD_GATES = {
    Phase.TRIAGE: {"requires": Phase.EXTRACT},
    Phase.DECOMPILE: {"requires": Phase.TRIAGE},
    Phase.SCAN: {"requires": Phase.DECOMPILE},
    Phase.UNDERSTAND: {"requires": Phase.SCAN},
    Phase.VALIDATE: {"requires": Phase.SCAN, "needs_tool_findings": True},
    Phase.EXPLOIT: {"requires": Phase.VALIDATE, "needs_validated_findings": True},
}


@dataclass
class PhaseStatus:
    phase: Phase
    completed: bool = False
    tool_findings_count: int = 0
    validated_findings_count: int = 0


class PipelineGate:
    """Enforces phase ordering in campaigns.

    Call check_gate() before starting any phase. It will refuse
    to proceed if prerequisites aren't met.
    """

    def __init__(self, run_dir: Path):
        self._dir = Path(run_dir)
        self._status: Dict[Phase, PhaseStatus] = {
            p: PhaseStatus(phase=p) for p in Phase
        }

    def mark_complete(self, phase: Phase, findings_count: int = 0) -> None:
        """Mark a phase as completed."""
        self._status[phase].completed = True
        if phase == Phase.SCAN:
            self._status[phase].tool_findings_count = findings_count
        elif phase == Phase.VALIDATE:
            self._status[phase].validated_findings_count = findings_count
        logger.info(f"Pipeline: {PHASE_NAMES[phase]} complete"
                     + (f" ({findings_count} findings)" if findings_count else ""))

    def check_gate(self, target_phase: Phase) -> tuple:
        """Check if a phase can proceed.

        Returns:
            (allowed: bool, reason: str)
        """
        gate = HARD_GATES.get(target_phase)
        if not gate:
            return True, ""

        # Check prerequisite phase completed
        requires = gate.get("requires")
        if requires and not self._status[requires].completed:
            return False, (
                f"Cannot start {PHASE_NAMES[target_phase]}: "
                f"{PHASE_NAMES[requires]} has not completed yet"
            )

        # Check tool findings exist before validation
        if gate.get("needs_tool_findings"):
            scan_status = self._status[Phase.SCAN]
            if not scan_status.completed:
                return False, (
                    f"Cannot start {PHASE_NAMES[target_phase]}: "
                    f"scan phase has not completed — run Semgrep/CodeQL/YARA first"
                )
            if scan_status.tool_findings_count == 0:
                logger.warning(
                    f"Starting {PHASE_NAMES[target_phase]} with 0 tool findings — "
                    f"consider running additional scans first"
                )

        # Check validated findings exist before exploitation
        if gate.get("needs_validated_findings"):
            val_status = self._status[Phase.VALIDATE]
            if not val_status.completed:
                return False, (
                    f"Cannot start {PHASE_NAMES[target_phase]}: "
                    f"validate phase has not completed"
                )
            if val_status.validated_findings_count == 0:
                return False, (
                    f"Cannot start {PHASE_NAMES[target_phase]}: "
                    f"no validated findings to exploit"
                )

        return True, ""

    def check_llm_allowed(self, current_phase: Phase) -> tuple:
        """Check if LLM analysis is allowed at the current phase.

        Returns:
            (allowed: bool, reason: str)
        """
        if current_phase in LLM_ALLOWED_PHASES:
            return True, ""

        return False, (
            f"LLM analysis is not allowed during {PHASE_NAMES[current_phase]}. "
            f"Use tools (Semgrep, CodeQL, YARA, r2) at this phase. "
            f"LLM reasoning is allowed at: validate, exploit, report."
        )

    def get_next_phase(self) -> Optional[Phase]:
        """Return the next phase that should run."""
        for phase in Phase:
            if not self._status[phase].completed:
                return phase
        return None

    def summary(self) -> str:
        """Human-readable pipeline status."""
        lines = ["Pipeline Status:"]
        for phase in Phase:
            status = self._status[phase]
            marker = "[done]" if status.completed else "[    ]"
            extra = ""
            if status.tool_findings_count:
                extra = f" ({status.tool_findings_count} findings)"
            if status.validated_findings_count:
                extra = f" ({status.validated_findings_count} validated)"
            lines.append(f"  {marker} {phase.value}. {PHASE_NAMES[phase]}{extra}")
        return "\n".join(lines)
