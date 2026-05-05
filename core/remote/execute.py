"""Remote command execution — SSH with screen sessions and logging.

Runs commands on remote hosts defined in hosts.json. Uses screen
for persistent sessions on Linux/Mac, PowerShell background jobs
on Windows. All output is logged to the run directory.

NEVER passes credentials on the command line. Authentication is
handled by SSH config, key auth, or agent forwarding.
"""

import base64
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from core.config import RaptorConfig
from core.logging import get_logger
from core.remote.hosts import RemoteHost

logger = get_logger()


def remote_exec(host: RemoteHost, command: str,
                timeout: int = None,
                log_dir: Path = None) -> Tuple[int, str, str]:
    """Execute a command on a remote host via SSH.

    For Windows hosts, wraps the command in base64-encoded PowerShell
    to avoid escaping issues.

    Args:
        host: Remote host to execute on.
        command: Shell command to run.
        timeout: Timeout in seconds (default: RaptorConfig.DEFAULT_TIMEOUT).
        log_dir: Directory to save command log (optional).

    Returns:
        (return_code, stdout, stderr)
    """
    timeout = timeout or RaptorConfig.DEFAULT_TIMEOUT

    if host.os.lower() == "windows":
        remote_cmd = _wrap_windows_command(command)
    else:
        remote_cmd = command

    full_cmd = host.ssh_cmd_prefix + [remote_cmd]

    logger.info(f"remote_exec: {host.name} ({host.ssh_target})")

    result = subprocess.run(
        full_cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=RaptorConfig.get_safe_env(),
    )

    if log_dir:
        _write_log(log_dir, host.name, command, result)

    return result.returncode, result.stdout, result.stderr


def remote_screen(host: RemoteHost, session_name: str, command: str,
                  log_dir: Path = None) -> bool:
    """Start a persistent screen session on a remote host.

    Only works on hosts with screen_support=True (Linux/Mac).
    For Windows, falls back to a direct background execution.

    Args:
        host: Remote host.
        session_name: Screen session name (prefixed with 'raptor-').
        command: Command to run inside the screen session.
        log_dir: Directory to save the screen log.

    Returns:
        True if the session was started successfully.
    """
    session = f"raptor-{session_name}"

    if not host.screen_support:
        logger.info(f"No screen on {host.name} ({host.os}), running directly")
        if host.os.lower() == "windows":
            bg_cmd = _wrap_windows_background(command, session)
        else:
            bg_cmd = f"nohup {command} > /tmp/{session}.log 2>&1 &"
        rc, _, stderr = remote_exec(host, bg_cmd, log_dir=log_dir)
        return rc == 0

    log_file = f"/tmp/{session}.log"
    screen_cmd = (
        f"screen -dmS {session} -L -Logfile {log_file} "
        f"bash -c '{command}; echo EXIT_CODE=$? >> {log_file}'"
    )

    rc, _, stderr = remote_exec(host, screen_cmd, log_dir=log_dir)
    if rc != 0:
        logger.warning(f"Failed to start screen session on {host.name}: {stderr}")
        return False

    logger.info(f"Screen session '{session}' started on {host.name}")
    return True


def remote_screen_list(host: RemoteHost) -> List[str]:
    """List active screen sessions on a remote host."""
    if not host.screen_support:
        return []

    rc, stdout, _ = remote_exec(host, "screen -ls 2>/dev/null || true")
    sessions = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("raptor-") or ".raptor-" in stripped:
            sessions.append(stripped.split("\t")[0].strip() if "\t" in stripped else stripped)
    return sessions


def remote_screen_log(host: RemoteHost, session_name: str) -> str:
    """Fetch the log from a screen session."""
    session = f"raptor-{session_name}"
    rc, stdout, _ = remote_exec(host, f"cat /tmp/{session}.log 2>/dev/null || echo '(no log)'")
    return stdout


def remote_file_exists(host: RemoteHost, path: str) -> bool:
    """Check if a file exists on a remote host."""
    if host.os.lower() == "windows":
        cmd = _wrap_windows_command(f"Test-Path '{path}'")
    else:
        cmd = f"test -f {path} && echo yes || echo no"
    rc, stdout, _ = remote_exec(host, cmd)
    return "yes" in stdout.lower() or "true" in stdout.lower()


def remote_copy_to(host: RemoteHost, local_path: Path, remote_path: str,
                   timeout: int = 600) -> bool:
    """Copy a file to a remote host via scp."""
    cmd = ["scp", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
    if host.port != 22:
        cmd.extend(["-P", str(host.port)])
    cmd.extend([str(local_path), f"{host.ssh_target}:{remote_path}"])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                            env=RaptorConfig.get_safe_env())
    return result.returncode == 0


def remote_copy_from(host: RemoteHost, remote_path: str, local_path: Path,
                     timeout: int = 600) -> bool:
    """Copy a file from a remote host via scp."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["scp", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
    if host.port != 22:
        cmd.extend(["-P", str(host.port)])
    cmd.extend([f"{host.ssh_target}:{remote_path}", str(local_path)])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                            env=RaptorConfig.get_safe_env())
    return result.returncode == 0


def _wrap_windows_command(command: str) -> str:
    """Wrap a command for Windows SSH using PowerShell -EncodedCommand.

    Avoids all escaping issues by base64-encoding the command.
    """
    encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    return f"powershell -EncodedCommand {encoded}"


def _wrap_windows_background(command: str, job_name: str) -> str:
    """Wrap a command to run as a PowerShell background job on Windows."""
    script = (
        f"$job = Start-Job -Name '{job_name}' -ScriptBlock {{ {command} }}; "
        f"$job.Id"
    )
    return _wrap_windows_command(script)


def _write_log(log_dir: Path, host_name: str, command: str,
               result: subprocess.CompletedProcess) -> None:
    """Write a command execution log."""
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    log_file = log_dir / f"remote-{host_name}-{timestamp}.log"

    lines = [
        f"Host: {host_name}",
        f"Time: {timestamp}",
        f"Command: {command}",
        f"Exit code: {result.returncode}",
        "",
        "--- stdout ---",
        result.stdout,
        "",
        "--- stderr ---",
        result.stderr,
    ]
    log_file.write_text("\n".join(lines))
