"""Pydantic models for the MCP task orchestrator."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class TaskState(str, Enum):
    SUBMITTED = "submitted"
    BLOCKED = "blocked"
    SCHEDULED = "scheduled"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATES = frozenset({
    TaskState.COMPLETED,
    TaskState.FAILED,
    TaskState.CANCELLED,
})

VALID_TRANSITIONS = {
    TaskState.SUBMITTED: {TaskState.BLOCKED, TaskState.SCHEDULED, TaskState.CANCELLED},
    TaskState.BLOCKED: {TaskState.SCHEDULED, TaskState.CANCELLED},
    TaskState.SCHEDULED: {TaskState.DISPATCHED, TaskState.CANCELLED},
    TaskState.DISPATCHED: {TaskState.RUNNING, TaskState.FAILED, TaskState.CANCELLED},
    TaskState.RUNNING: {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED},
    TaskState.FAILED: {TaskState.SUBMITTED},  # retry
}

KNOWN_COMMANDS = frozenset({
    "scan", "codeql", "fuzz", "gpu-fuzz", "agentic", "reverse",
    "validate", "understand", "crash-analysis", "web", "exploit",
})


class CommandResources(BaseModel):
    weight: str = "medium"
    ram_mb: int = 2048
    needs_gpu: bool = False
    estimated_minutes: int = 15
    max_concurrent: int = 3


COMMAND_RESOURCE_MAP: Dict[str, CommandResources] = {
    "scan": CommandResources(weight="light", ram_mb=2048, estimated_minutes=10, max_concurrent=4),
    "codeql": CommandResources(weight="heavy", ram_mb=8192, estimated_minutes=40, max_concurrent=2),
    "fuzz": CommandResources(weight="heavy", ram_mb=4096, needs_gpu=True, estimated_minutes=120, max_concurrent=2),
    "gpu-fuzz": CommandResources(weight="heavy", ram_mb=4096, needs_gpu=True, estimated_minutes=120, max_concurrent=1),
    "agentic": CommandResources(weight="heavy", ram_mb=4096, estimated_minutes=30, max_concurrent=2),
    "reverse": CommandResources(weight="medium", ram_mb=2048, estimated_minutes=20, max_concurrent=3),
    "validate": CommandResources(weight="light", ram_mb=1024, estimated_minutes=15, max_concurrent=4),
    "understand": CommandResources(weight="light", ram_mb=1024, estimated_minutes=10, max_concurrent=4),
    "crash-analysis": CommandResources(weight="heavy", ram_mb=4096, estimated_minutes=30, max_concurrent=2),
    "web": CommandResources(weight="medium", ram_mb=2048, estimated_minutes=15, max_concurrent=3),
    "exploit": CommandResources(weight="medium", ram_mb=2048, estimated_minutes=20, max_concurrent=2),
}


class Task(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    project: Optional[str] = None
    campaign_id: Optional[str] = None
    command: str
    target: str
    args: Dict[str, Any] = Field(default_factory=dict)
    phase: Optional[int] = None
    priority: int = 5
    state: TaskState = TaskState.SUBMITTED
    host: Optional[str] = None
    screen_session: Optional[str] = None
    output_dir: Optional[str] = None
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    result_summary: Dict[str, Any] = Field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 2
    depends_on: List[str] = Field(default_factory=list)

    def can_transition_to(self, new_state: TaskState) -> bool:
        allowed = VALID_TRANSITIONS.get(self.state, set())
        return new_state in allowed

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        if self.started_at:
            return (datetime.now(timezone.utc) - self.started_at).total_seconds()
        return None


class HostCapacity(BaseModel):
    host: str
    last_probed: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cpu_percent: Optional[float] = None
    ram_used_pct: Optional[float] = None
    ram_available_mb: Optional[float] = None
    gpu_util_pct: Optional[float] = None
    gpu_mem_used_mb: Optional[float] = None
    active_tasks: int = 0
    max_concurrent: int = 4
    is_reachable: bool = True


class SchedulerConfig(BaseModel):
    poll_interval_sec: int = 30
    probe_ttl_sec: int = 60
    cpu_threshold_pct: float = 80.0
    ram_min_available_mb: float = 1024.0
    max_retries: int = 2
    local_hostname: str = "thefarm"
