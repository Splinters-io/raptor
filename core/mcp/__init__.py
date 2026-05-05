"""MCP task orchestrator — persistent compute-aware scheduling.

Runs on thefarm as a persistent MCP server. Claude Code connects via SSH.
Tasks dispatch locally into screen sessions (no SSH-to-self for the common
case). Reaches other hosts (rengy, local Mac) via SSH from thefarm.

Phase 1 (MVP): submit/status/cancel, thefarm-local dispatch, SQLite state.
"""

from core.mcp.models import Task, TaskState, HostCapacity
from core.mcp.state import TaskStore

__all__ = ["Task", "TaskState", "HostCapacity", "TaskStore"]
