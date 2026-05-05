"""Probe system tracing capabilities at runtime.

Detects what's available: eBPF, bpftrace, strace, ltrace, Frida.
Results are cached for the session lifetime.
"""

import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.logging import get_logger

logger = get_logger()

_cached: Optional["TracingCapabilities"] = None


@dataclass(frozen=True)
class TracingCapabilities:
    """What tracing backends are available on this system."""
    os: str
    ebpf_available: bool = False
    ebpf_version: str = ""
    bpftrace_path: str = ""
    bcc_available: bool = False
    strace_path: str = ""
    ltrace_path: str = ""
    frida_available: bool = False
    kernel_version: str = ""
    btf_available: bool = False

    @property
    def preferred_syscall_tracer(self) -> str:
        if self.ebpf_available:
            return "ebpf"
        if self.strace_path:
            return "strace"
        if self.frida_available:
            return "frida"
        return "none"

    @property
    def preferred_coverage_tracer(self) -> str:
        if self.ebpf_available:
            return "ebpf"
        if self.frida_available:
            return "frida"
        return "none"

    @property
    def preferred_malloc_tracer(self) -> str:
        if self.ebpf_available:
            return "ebpf"
        if self.frida_available:
            return "frida"
        if self.ltrace_path:
            return "ltrace"
        return "none"


def probe_capabilities() -> TracingCapabilities:
    """Detect available tracing backends. Cached after first call."""
    global _cached
    if _cached is not None:
        return _cached

    os_name = platform.system().lower()

    caps = TracingCapabilities(
        os=os_name,
        strace_path=shutil.which("strace") or "",
        ltrace_path=shutil.which("ltrace") or "",
        frida_available=bool(shutil.which("frida")),
        bpftrace_path=shutil.which("bpftrace") or "",
    )

    if os_name == "linux":
        caps = _probe_linux_ebpf(caps)

    _cached = caps

    if caps.ebpf_available:
        logger.info(f"Tracing: eBPF available (kernel {caps.kernel_version}, BTF: {caps.btf_available})")
    else:
        logger.info(f"Tracing: eBPF not available, using {caps.preferred_syscall_tracer}")

    return caps


def _probe_linux_ebpf(caps: TracingCapabilities) -> TracingCapabilities:
    """Check Linux eBPF availability."""
    kernel_version = ""
    btf = False
    ebpf = False
    bcc = False

    try:
        kernel_version = platform.release()
    except Exception:
        pass

    # Check for BTF support (required for CO-RE / portable eBPF)
    btf = Path("/sys/kernel/btf/vmlinux").exists()

    # Check if bpf() syscall works
    if caps.bpftrace_path:
        try:
            result = subprocess.run(
                [caps.bpftrace_path, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                ebpf = True
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Check for BCC (Python bindings)
    try:
        import importlib
        bcc = importlib.util.find_spec("bcc") is not None
    except Exception:
        pass

    # If neither bpftrace nor BCC, check raw capability
    if not ebpf and not bcc:
        # Try loading a trivial BPF program
        ebpf = _check_bpf_syscall()

    return TracingCapabilities(
        os=caps.os,
        ebpf_available=ebpf or bcc,
        ebpf_version=kernel_version,
        bpftrace_path=caps.bpftrace_path,
        bcc_available=bcc,
        strace_path=caps.strace_path,
        ltrace_path=caps.ltrace_path,
        frida_available=caps.frida_available,
        kernel_version=kernel_version,
        btf_available=btf,
    )


def _check_bpf_syscall() -> bool:
    """Check if bpf() syscall is available to current user."""
    try:
        result = subprocess.run(
            ["cat", "/proc/sys/kernel/unprivileged_bpf_disabled"],
            capture_output=True, text=True, timeout=2,
        )
        val = result.stdout.strip()
        # 0 = unprivileged allowed, 1 = root only, 2 = disabled
        # If root only, check if we're root
        if val == "0":
            return True
        if val == "1":
            import os
            return os.getuid() == 0
    except Exception:
        pass
    return False
