"""Scheduler daemon — runs in a screen session on thefarm.

Manages the background scheduling loop independently of any MCP connection.
Shares the SQLite database with the MCP server (which is spawned per SSH
connection from Claude Code).

Usage:
    python3 -m core.mcp.daemon

The daemon:
- Acquires the PID lock (~/.raptor/orchestrator.pid)
- Runs the probe → schedule → dispatch → poll cycle every 30s
- Stays alive in a screen session
- MCP server instances connect to the same SQLite and read/write tasks
"""

import logging
import os
import signal
import sys
import time

log = logging.getLogger("raptor.mcp.daemon")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    from core.mcp.models import SchedulerConfig
    from core.mcp.scheduler import Scheduler
    from core.mcp.state import TaskStore

    if not TaskStore.acquire_lock():
        log.error("another orchestrator daemon is running — exiting")
        sys.exit(1)

    log.info("orchestrator daemon starting (PID %d)", os.getpid())

    store = TaskStore()
    config = SchedulerConfig()
    scheduler = Scheduler(store, config)

    running = True

    def _shutdown(signum, frame):
        nonlocal running
        log.info("received signal %d, shutting down", signum)
        running = False

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    scheduler.start()
    log.info("scheduler running (poll=%ds)", config.poll_interval_sec)

    try:
        while running:
            time.sleep(1)
    finally:
        scheduler.stop()
        TaskStore.release_lock()
        log.info("daemon stopped")


if __name__ == "__main__":
    main()
