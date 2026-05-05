"""Entry point for python3 -m core.mcp.

    python3 -m core.mcp server    # MCP stdio server (per SSH connection)
    python3 -m core.mcp daemon    # Scheduler daemon (screen session)
    python3 -m core.mcp           # Default: server mode
"""

import sys


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "server"

    if mode == "daemon":
        from core.mcp.daemon import main as daemon_main
        daemon_main()
    elif mode == "server":
        from core.mcp.server import main as server_main
        server_main()
    else:
        print(f"unknown mode: {mode}", file=sys.stderr)
        print("usage: python3 -m core.mcp [server|daemon]", file=sys.stderr)
        sys.exit(1)


main()
