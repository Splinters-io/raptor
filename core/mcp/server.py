"""MCP server entry point — stdio transport over SSH.

Spawned per Claude Code connection. Does NOT run the scheduler — that's
the daemon (core.mcp.daemon) running in a screen session. This process
reads/writes the shared SQLite database and exposes MCP tools.

Claude Code connects via SSH in .mcp.json:
    {
      "mcpServers": {
        "raptor-orchestrator": {
          "command": "ssh",
          "args": ["carroll@192.168.1.100",
                   "cd ~/raptor && RAPTOR_DIR=~/raptor python3 -m core.mcp.server"]
        }
      }
    }

Requires: pip install mcp>=1.0.0
"""

import asyncio
import json
import logging
import signal
import sys
from typing import Any

log = logging.getLogger("raptor.mcp")


def _check_mcp_available() -> bool:
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


async def _run_server() -> None:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server

    from core.mcp.models import SchedulerConfig
    from core.mcp.scheduler import Scheduler
    from core.mcp.state import TaskStore
    from core.mcp import tools as t

    store = TaskStore()
    config = SchedulerConfig()
    scheduler = Scheduler(store, config)

    server = Server("raptor-orchestrator")

    @server.list_tools()
    async def list_tools() -> list:
        return [
            {
                "name": "raptor_submit",
                "description": (
                    "Submit a security analysis task to the orchestrator queue. "
                    "Tasks are scheduled based on compute capacity and run in "
                    "persistent screen sessions."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "RAPTOR command: scan, codeql, fuzz, gpu-fuzz, agentic, reverse, validate, understand, crash-analysis, web, exploit",
                        },
                        "target": {
                            "type": "string",
                            "description": "Path to target (file, directory, or URL)",
                        },
                        "project": {
                            "type": "string",
                            "description": "Project name (optional)",
                        },
                        "args": {
                            "type": "object",
                            "description": "Extra arguments as key-value pairs (e.g. {\"duration\": 3600})",
                        },
                        "priority": {
                            "type": "integer",
                            "description": "Priority 1-10 (1=highest, default 5)",
                            "default": 5,
                        },
                        "depends_on": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Task IDs this task depends on",
                        },
                        "campaign_id": {
                            "type": "string",
                            "description": "Group tasks into a campaign",
                        },
                    },
                    "required": ["command", "target"],
                },
            },
            {
                "name": "raptor_status",
                "description": "Query task status. Filter by task_id, project, campaign, state, or host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_id": {"type": "string"},
                        "campaign_id": {"type": "string"},
                        "project": {"type": "string"},
                        "state": {
                            "type": "string",
                            "enum": ["submitted", "blocked", "scheduled", "dispatched", "running", "completed", "failed", "cancelled"],
                        },
                        "host": {"type": "string"},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
            {
                "name": "raptor_cancel",
                "description": "Cancel a task. Kills its screen session if running.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_id": {"type": "string", "description": "Task ID to cancel"},
                    },
                    "required": ["task_id"],
                },
            },
            {
                "name": "raptor_logs",
                "description": "Fetch recent log output from a task's screen session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "task_id": {"type": "string"},
                        "tail_lines": {"type": "integer", "default": 100},
                    },
                    "required": ["task_id"],
                },
            },
            {
                "name": "raptor_capacity",
                "description": "Show host CPU/RAM/GPU capacity and active task counts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "refresh": {"type": "boolean", "default": False},
                    },
                },
            },
            {
                "name": "raptor_campaign",
                "description": (
                    "Launch a full autonomous campaign: scan → understand → validate → "
                    "exploit → report. Creates chained tasks with dependencies. "
                    "The daemon processes them automatically, including Claude Code "
                    "headless sessions for reasoning phases."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Path to target (file, directory, or URL)",
                        },
                        "project": {
                            "type": "string",
                            "description": "Project name (optional)",
                        },
                        "priority": {
                            "type": "integer",
                            "description": "Priority 1-10 (1=highest, default 3)",
                            "default": 3,
                        },
                        "phases": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Subset of phases to run (default: all). Options: scan, understand, validate, exploit, report",
                        },
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "raptor_campaign_status",
                "description": "Get detailed campaign progress: phase completion, running tasks, failures.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "campaign_id": {"type": "string", "description": "Campaign ID"},
                    },
                    "required": ["campaign_id"],
                },
            },
            {
                "name": "raptor_scheduler_status",
                "description": "Show scheduler status: running/paused, task counts, host capacity.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list:
        handlers = {
            "raptor_submit": lambda a: t.raptor_submit(store, scheduler, **a),
            "raptor_campaign": lambda a: t.raptor_campaign(store, **a),
            "raptor_campaign_status": lambda a: t.raptor_campaign_status(store, **a),
            "raptor_status": lambda a: t.raptor_status(store, **a),
            "raptor_cancel": lambda a: t.raptor_cancel(store, **a),
            "raptor_logs": lambda a: t.raptor_logs(store, **a),
            "raptor_capacity": lambda a: t.raptor_capacity(store, **a),
            "raptor_scheduler_status": lambda a: t.raptor_scheduler_status(scheduler),
        }

        handler = handlers.get(name)
        if handler is None:
            result = {"error": f"unknown tool: {name}"}
        else:
            try:
                result = handler(arguments or {})
            except Exception as exc:
                log.exception("tool %s failed", name)
                result = {"error": str(exc)}

        return [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]

    async with stdio_server() as streams:
        log.info("raptor-orchestrator MCP server connected (stdio)")
        await server.run(
            streams[0], streams[1],
            server.create_initialization_options(),
        )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    if not _check_mcp_available():
        print(
            "error: mcp package not installed. Run: pip install 'mcp>=1.0.0'",
            file=sys.stderr,
        )
        sys.exit(1)

    asyncio.run(_run_server())


if __name__ == "__main__":
    main()
