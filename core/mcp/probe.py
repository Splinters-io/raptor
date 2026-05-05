"""Host resource probing — local for thefarm, SSH for remotes.

thefarm (orchestrator): reads /proc, free, nvidia-smi directly.
rengy (Windows): SSH + PowerShell Get-Counter.
Mac: SSH + vm_stat / sysctl.
"""

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.mcp.models import HostCapacity


def probe_host(hostname: str, host_os: str = "linux",
               ssh_target: str = None, ssh_port: int = 22,
               max_concurrent: int = 4) -> HostCapacity:
    """Probe any host. Local if no ssh_target, remote via SSH otherwise."""
    if ssh_target is None:
        return probe_local(hostname, max_concurrent)
    return probe_remote(hostname, host_os, ssh_target, ssh_port, max_concurrent)


def probe_local(hostname: str = "thefarm",
                max_concurrent: int = 4) -> HostCapacity:
    cpu = _probe_cpu()
    ram_used, ram_avail = _probe_ram()
    gpu_util, gpu_mem = _probe_gpu()

    return HostCapacity(
        host=hostname,
        last_probed=datetime.now(timezone.utc),
        cpu_percent=cpu,
        ram_used_pct=ram_used,
        ram_available_mb=ram_avail,
        gpu_util_pct=gpu_util,
        gpu_mem_used_mb=gpu_mem,
        max_concurrent=max_concurrent,
        is_reachable=True,
    )


def probe_remote(hostname: str, host_os: str, ssh_target: str,
                 ssh_port: int = 22, max_concurrent: int = 2) -> HostCapacity:
    """Probe a remote host via SSH."""
    try:
        if host_os == "windows":
            return _probe_windows(hostname, ssh_target, ssh_port, max_concurrent)
        elif host_os == "darwin":
            return _probe_mac(hostname, ssh_target, ssh_port, max_concurrent)
        else:
            return _probe_linux_remote(hostname, ssh_target, ssh_port, max_concurrent)
    except Exception:
        return HostCapacity(
            host=hostname,
            last_probed=datetime.now(timezone.utc),
            is_reachable=False,
            max_concurrent=max_concurrent,
        )


def _ssh_exec(ssh_target: str, command: str, port: int = 22, timeout: int = 10) -> str:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
           "-o", "StrictHostKeyChecking=accept-new"]
    if port != 22:
        cmd.extend(["-p", str(port)])
    cmd.extend([ssh_target, command])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        return ""
    return result.stdout


def _probe_linux_remote(hostname: str, ssh_target: str, ssh_port: int,
                        max_concurrent: int) -> HostCapacity:
    output = _ssh_exec(
        ssh_target,
        "cat /proc/loadavg; echo '---'; free -m; echo '---'; "
        "nvidia-smi --query-gpu=utilization.gpu,memory.used "
        "--format=csv,noheader,nounits 2>/dev/null || echo 'no-gpu'; "
        "echo '---'; nproc",
        ssh_port,
    )
    parts = output.split("---")
    cpu, ram_used, ram_avail, gpu_util, gpu_mem = None, None, None, None, None

    if len(parts) >= 4:
        # CPU
        try:
            nproc = int(parts[3].strip())
            load_1m = float(parts[0].strip().split()[0])
            cpu = round((load_1m / nproc) * 100, 1)
        except (ValueError, IndexError):
            pass

        # RAM
        for line in parts[1].strip().splitlines():
            if line.startswith("Mem:"):
                try:
                    p = line.split()
                    total = float(p[1])
                    available = float(p[6])
                    ram_used = round(((total - available) / total) * 100, 1)
                    ram_avail = available
                except (ValueError, IndexError):
                    pass

        # GPU
        gpu_line = parts[2].strip()
        if gpu_line and "no-gpu" not in gpu_line:
            try:
                gp = [x.strip() for x in gpu_line.split("\n")[0].split(",")]
                gpu_util = float(gp[0])
                gpu_mem = float(gp[1])
            except (ValueError, IndexError):
                pass

    return HostCapacity(
        host=hostname,
        last_probed=datetime.now(timezone.utc),
        cpu_percent=cpu,
        ram_used_pct=ram_used,
        ram_available_mb=ram_avail,
        gpu_util_pct=gpu_util,
        gpu_mem_used_mb=gpu_mem,
        max_concurrent=max_concurrent,
        is_reachable=True,
    )


def _probe_windows(hostname: str, ssh_target: str, ssh_port: int,
                   max_concurrent: int) -> HostCapacity:
    import base64
    ps_script = (
        "$cpu = (Get-Counter '\\Processor(_Total)\\% Processor Time').CounterSamples[0].CookedValue; "
        "$os = Get-CimInstance Win32_OperatingSystem; "
        "$ramTotal = $os.TotalVisibleMemorySize / 1024; "
        "$ramFree = $os.FreePhysicalMemory / 1024; "
        "Write-Output \"CPU:$([math]::Round($cpu,1))\"; "
        "Write-Output \"RAM_TOTAL:$([math]::Round($ramTotal,0))\"; "
        "Write-Output \"RAM_FREE:$([math]::Round($ramFree,0))\""
    )
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    output = _ssh_exec(ssh_target, f"powershell -EncodedCommand {encoded}", ssh_port)

    cpu, ram_used, ram_avail = None, None, None
    for line in output.splitlines():
        if line.startswith("CPU:"):
            try:
                cpu = float(line.split(":")[1])
            except ValueError:
                pass
        elif line.startswith("RAM_TOTAL:"):
            try:
                total = float(line.split(":")[1])
            except ValueError:
                total = 0
        elif line.startswith("RAM_FREE:"):
            try:
                ram_avail = float(line.split(":")[1])
                if total > 0:
                    ram_used = round(((total - ram_avail) / total) * 100, 1)
            except (ValueError, NameError):
                pass

    return HostCapacity(
        host=hostname,
        last_probed=datetime.now(timezone.utc),
        cpu_percent=cpu,
        ram_used_pct=ram_used,
        ram_available_mb=ram_avail,
        max_concurrent=max_concurrent,
        is_reachable=True,
    )


def _probe_mac(hostname: str, ssh_target: str, ssh_port: int,
               max_concurrent: int) -> HostCapacity:
    output = _ssh_exec(
        ssh_target,
        "sysctl -n vm.loadavg hw.ncpu hw.memsize; "
        "vm_stat | head -5",
        ssh_port,
    )
    cpu, ram_used, ram_avail = None, None, None

    lines = output.strip().splitlines()
    try:
        # loadavg line: { 1.23 1.45 1.67 }
        load_str = lines[0].strip().strip("{}").split()[0]
        load_1m = float(load_str)
        nproc = int(lines[1].strip())
        cpu = round((load_1m / nproc) * 100, 1)
    except (ValueError, IndexError):
        pass

    try:
        total_bytes = int(lines[2].strip())
        total_mb = total_bytes / (1024 * 1024)
        # vm_stat parsing is approximate
        for line in lines[3:]:
            if "Pages free" in line:
                free_pages = int(line.split(":")[1].strip().rstrip("."))
                free_mb = (free_pages * 4096) / (1024 * 1024)
                ram_avail = round(free_mb, 0)
                ram_used = round(((total_mb - free_mb) / total_mb) * 100, 1)
    except (ValueError, IndexError):
        pass

    return HostCapacity(
        host=hostname,
        last_probed=datetime.now(timezone.utc),
        cpu_percent=cpu,
        ram_used_pct=ram_used,
        ram_available_mb=ram_avail,
        max_concurrent=max_concurrent,
        is_reachable=True,
    )


# --- Local probing helpers (thefarm) ---

def _probe_cpu() -> Optional[float]:
    try:
        loadavg = Path("/proc/loadavg").read_text().split()
        load_1m = float(loadavg[0])
        nproc = _cpu_count()
        return round((load_1m / nproc) * 100, 1) if nproc > 0 else None
    except (OSError, ValueError, IndexError):
        return None


def _probe_ram() -> tuple:
    try:
        result = subprocess.run(
            ["free", "-m"], capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None, None
        for line in result.stdout.splitlines():
            if line.startswith("Mem:"):
                parts = line.split()
                total = float(parts[1])
                available = float(parts[6])
                used_pct = round(((total - available) / total) * 100, 1) if total > 0 else None
                return used_pct, available
    except (subprocess.TimeoutExpired, OSError, ValueError, IndexError):
        pass
    return None, None


def _probe_gpu() -> tuple:
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=utilization.gpu,memory.used",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None, None
        line = result.stdout.strip().split("\n")[0]
        parts = [p.strip() for p in line.split(",")]
        return float(parts[0]), float(parts[1])
    except (subprocess.TimeoutExpired, OSError, ValueError, IndexError, FileNotFoundError):
        return None, None


def _cpu_count() -> int:
    try:
        return len(Path("/proc/stat").read_text().strip().split("\n")) - 1
    except OSError:
        import os
        return os.cpu_count() or 1
