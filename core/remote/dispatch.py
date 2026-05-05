"""Task dispatch — decide interactive vs headless, local vs remote.

Classifies tasks by their characteristics and routes them to the
right execution environment. Not a preference — a detection based
on what the task actually needs.

Interactive (current session):
  - Needs human judgment (is this real? chase this lead?)
  - Exploratory (following xrefs, building per-target tools)
  - Short-running (<10 min)
  - Needs conversation context

Headless (thefarm, screen session):
  - Long-running (>30 min): fuzzing, batch scanning, bulk decompile
  - Compute-heavy: GPU-fuzz, parallel AFL++, LLM batch analysis
  - No judgment needed: fixed config, structured output
  - Can use local LLMs on the GPU
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from core.logging import get_logger

logger = get_logger()


class ExecutionMode(Enum):
    INTERACTIVE = "interactive"
    HEADLESS = "headless"


class ExecutionTarget(Enum):
    LOCAL = "local"
    THEFARM = "thefarm"
    RENGY = "rengy"


@dataclass(frozen=True)
class TaskRouting:
    """Where and how a task should run."""
    mode: ExecutionMode
    target: ExecutionTarget
    reason: str
    screen_name: Optional[str] = None
    estimated_duration: Optional[int] = None
    needs_gpu: bool = False
    needs_local_llm: bool = False

    @property
    def is_headless(self) -> bool:
        return self.mode == ExecutionMode.HEADLESS

    @property
    def is_remote(self) -> bool:
        return self.target != ExecutionTarget.LOCAL


# Task classification rules. Ordered by specificity — first match wins.
_RULES = [
    # Fuzzing is always headless on thefarm
    {
        "commands": ["fuzz", "gpu-fuzz"],
        "mode": ExecutionMode.HEADLESS,
        "target": ExecutionTarget.THEFARM,
        "reason": "fuzzing is long-running compute — screen session on thefarm",
        "needs_gpu": True,
        "needs_local_llm": True,
    },
    # Batch scanning of large repos
    {
        "commands": ["agentic"],
        "min_duration": 1800,
        "mode": ExecutionMode.HEADLESS,
        "target": ExecutionTarget.THEFARM,
        "reason": "agentic pipeline >30min — headless on thefarm with local LLMs",
        "needs_local_llm": True,
    },
    # Full binary RE (decompile everything)
    {
        "commands": ["reverse"],
        "args_contain": ["--mode full"],
        "mode": ExecutionMode.HEADLESS,
        "target": ExecutionTarget.THEFARM,
        "reason": "full binary decompilation is compute-heavy — headless on thefarm",
    },
    # File type rules BEFORE command catch-alls — target platform matters
    # Windows PE/.NET analysis goes to rengy
    {
        "file_types": [".exe", ".dll", ".sys", ".msi"],
        "mode": ExecutionMode.INTERACTIVE,
        "target": ExecutionTarget.RENGY,
        "reason": "Windows binary — rengy has DynamoRIO, x64dbg, Sysinternals",
    },
    # Java — decompile with JADX/CFR then scan
    {
        "file_types": [".jar", ".war", ".class"],
        "mode": ExecutionMode.HEADLESS,
        "target": ExecutionTarget.THEFARM,
        "reason": "Java bytecode — JADX/CFR decompile then Semgrep scan on recovered source",
    },
    # Electron apps — extract and scan locally
    {
        "file_types": [".asar"],
        "mode": ExecutionMode.INTERACTIVE,
        "target": ExecutionTarget.LOCAL,
        "reason": "Electron app — extract and scan locally",
    },
    # Binary triage is quick and interactive (catch-all for /reverse)
    {
        "commands": ["reverse"],
        "mode": ExecutionMode.INTERACTIVE,
        "target": ExecutionTarget.LOCAL,
        "reason": "triage/trace is exploratory — interactive locally",
    },
    # Source code scanning is quick
    {
        "commands": ["scan", "codeql", "understand"],
        "mode": ExecutionMode.INTERACTIVE,
        "target": ExecutionTarget.LOCAL,
        "reason": "source scanning is interactive — results inform next steps",
    },
    # Validation needs human judgment
    {
        "commands": ["validate"],
        "mode": ExecutionMode.INTERACTIVE,
        "target": ExecutionTarget.LOCAL,
        "reason": "validation requires judgment calls — interactive",
    },
    # Exploit development is deeply interactive
    {
        "commands": ["exploit"],
        "mode": ExecutionMode.INTERACTIVE,
        "target": ExecutionTarget.LOCAL,
        "reason": "exploit dev needs iterative reasoning — interactive",
    },
    # Crash analysis can go either way
    {
        "commands": ["crash-analysis"],
        "mode": ExecutionMode.HEADLESS,
        "target": ExecutionTarget.THEFARM,
        "reason": "crash analysis runs rr/gdb — headless on thefarm",
    },
]


def classify_task(command: str, target_path: str = "",
                  args: str = "", duration_hint: int = None) -> TaskRouting:
    """Classify a task and return routing decision.

    Args:
        command: The RAPTOR command (scan, fuzz, reverse, etc.)
        target_path: Path to the target file/directory.
        args: Raw argument string for pattern matching.
        duration_hint: Estimated duration in seconds (if known).

    Returns:
        TaskRouting with mode, target, and reason.
    """
    import platform
    from pathlib import Path

    target_ext = Path(target_path).suffix.lower() if target_path else ""
    current_os = platform.system().lower()

    for rule in _RULES:
        # Match command
        if "commands" in rule and command not in rule["commands"]:
            continue

        # Match file type
        if "file_types" in rule:
            if target_ext not in rule["file_types"]:
                continue

        # Match args pattern
        if "args_contain" in rule:
            if not any(pat in args for pat in rule["args_contain"]):
                continue

        # Match minimum duration
        if "min_duration" in rule:
            if duration_hint is not None and duration_hint < rule["min_duration"]:
                continue

        # Rule matched
        mode = rule["mode"]
        target = rule["target"]

        # Override: if we're already on the target machine, stay local
        if target == ExecutionTarget.THEFARM and current_os == "linux":
            target = ExecutionTarget.LOCAL

        if target == ExecutionTarget.RENGY and current_os == "windows":
            target = ExecutionTarget.LOCAL

        screen_name = f"{command}-{Path(target_path).stem}" if mode == ExecutionMode.HEADLESS else None

        routing = TaskRouting(
            mode=mode,
            target=target,
            reason=rule["reason"],
            screen_name=screen_name,
            estimated_duration=duration_hint,
            needs_gpu=rule.get("needs_gpu", False),
            needs_local_llm=rule.get("needs_local_llm", False),
        )

        logger.info(f"[dispatch] {command} → {mode.value} on {target.value}: {rule['reason']}")
        return routing

    # Default: interactive locally
    return TaskRouting(
        mode=ExecutionMode.INTERACTIVE,
        target=ExecutionTarget.LOCAL,
        reason="default — interactive locally",
    )


def suggest_routing(command: str, target_path: str = "",
                    args: str = "") -> str:
    """Return a human-readable routing suggestion.

    Called by commands before starting work to tell the user
    what will happen and where.
    """
    routing = classify_task(command, target_path, args)

    if routing.is_headless and routing.is_remote:
        return (
            f"This is a {routing.mode.value} task → dispatching to {routing.target.value} "
            f"in screen session `{routing.screen_name}`. "
            f"Reason: {routing.reason}"
        )
    elif routing.is_remote:
        return (
            f"Target needs {routing.target.value} — routing there. "
            f"Reason: {routing.reason}"
        )
    else:
        return f"Running {routing.mode.value}ly. {routing.reason}"
