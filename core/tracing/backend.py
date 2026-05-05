"""Tracing backend selection and unified API.

Auto-selects the best available backend for each tracing task.
eBPF is always preferred on Linux when available.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.config import RaptorConfig
from core.logging import get_logger

from .probe import probe_capabilities, TracingCapabilities

logger = get_logger()


class Tracer:
    """Unified tracing API — dispatches to the best available backend."""

    def __init__(self, caps: TracingCapabilities = None):
        self._caps = caps or probe_capabilities()

    @property
    def capabilities(self) -> TracingCapabilities:
        return self._caps

    def trace_syscalls(self, target: str, duration: int = 10,
                       filter_calls: List[str] = None,
                       output_file: Path = None) -> Tuple[int, str]:
        """Trace syscalls made by a target binary.

        Args:
            target: Binary path or PID.
            duration: Max trace duration in seconds.
            filter_calls: Only trace these syscalls (e.g., ["read", "write", "open"]).
            output_file: Write trace output here.

        Returns:
            (return_code, trace_output)
        """
        backend = self._caps.preferred_syscall_tracer

        if backend == "ebpf":
            return self._ebpf_syscall_trace(target, duration, filter_calls, output_file)
        elif backend == "strace":
            return self._strace_trace(target, duration, filter_calls, output_file)
        elif backend == "frida":
            return self._frida_syscall_trace(target, duration, filter_calls, output_file)

        logger.warning("No syscall tracer available")
        return 1, ""

    def trace_coverage(self, binary: str, input_data: bytes = None,
                       input_file: Path = None) -> Optional[Dict]:
        """Collect edge coverage from a single execution.

        Returns dict with edge_count, edges (list of addresses), and
        the backend used.
        """
        backend = self._caps.preferred_coverage_tracer

        if backend == "ebpf":
            return self._ebpf_coverage(binary, input_data, input_file)
        elif backend == "frida":
            return self._frida_coverage(binary, input_data, input_file)

        logger.warning("No coverage tracer available")
        return None

    def trace_mallocs(self, target: str, duration: int = 10,
                      output_file: Path = None) -> Tuple[int, str]:
        """Trace heap allocations (malloc/free/realloc).

        Returns (return_code, trace_output) with allocation sizes,
        addresses, and free/realloc patterns.
        """
        backend = self._caps.preferred_malloc_tracer

        if backend == "ebpf":
            return self._ebpf_malloc_trace(target, duration, output_file)
        elif backend == "frida":
            return self._frida_malloc_trace(target, duration, output_file)
        elif backend == "ltrace":
            return self._ltrace_malloc_trace(target, duration, output_file)

        logger.warning("No malloc tracer available")
        return 1, ""

    def trace_crashes(self, pid: int, callback=None) -> Optional[int]:
        """Monitor a process for crashes via eBPF signal tracepoint.

        Only available on Linux with eBPF. Returns immediately on
        other platforms (use AFL's crash detection instead).

        Args:
            pid: Process to monitor.
            callback: Called with (signal, registers) on crash.

        Returns:
            The crash signal number, or None if monitoring isn't available.
        """
        if not self._caps.ebpf_available:
            return None

        return self._ebpf_crash_monitor(pid, callback)

    # --- eBPF backends ---

    def _ebpf_syscall_trace(self, target, duration, filter_calls, output_file):
        bpftrace = self._caps.bpftrace_path
        if not bpftrace:
            logger.warning("bpftrace not found — falling back to strace")
            return self._strace_trace(target, duration, filter_calls, output_file)

        # Build bpftrace one-liner for syscall tracing
        filter_clause = ""
        if filter_calls:
            probes = ",".join(f"tracepoint:syscalls:sys_enter_{s}" for s in filter_calls)
        else:
            probes = "tracepoint:syscalls:sys_enter_*"

        script = f'{probes} /pid == $1/ {{ printf("%s(%d)\\n", probe, tid); }}'

        try:
            pid = target if str(target).isdigit() else None
            cmd = [bpftrace, "-e", script]

            if pid:
                cmd.extend(["-p", str(pid)])
            else:
                # Launch the target and trace it
                cmd = [bpftrace, "-e", script, "-c", str(target)]

            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=duration + 5,
                env=RaptorConfig.get_safe_env(),
            )

            output = result.stdout
            if output_file:
                output_file.write_text(output)

            return result.returncode, output

        except subprocess.TimeoutExpired:
            return 0, "(trace timed out — this is normal)"
        except Exception as e:
            logger.warning(f"eBPF syscall trace failed: {e}")
            return self._strace_trace(target, duration, filter_calls, output_file)

    def _ebpf_coverage(self, binary, input_data, input_file):
        """eBPF uprobe-based coverage — trace function entries."""
        bpftrace = self._caps.bpftrace_path
        if not bpftrace:
            return self._frida_coverage(binary, input_data, input_file)

        # Use uprobes to trace all function entries in the binary
        script = f'uprobe:{binary}:* {{ @coverage[probe] = count(); }}'

        stdin_data = input_data
        cmd = [bpftrace, "-e", script, "-c", str(binary)]

        try:
            result = subprocess.run(
                cmd, input=stdin_data, capture_output=True,
                text=(stdin_data is None), timeout=30,
                env=RaptorConfig.get_safe_env(),
            )

            edges = []
            for line in result.stdout.splitlines():
                if "@coverage" in line and ":" in line:
                    edges.append(line.strip())

            return {
                "backend": "ebpf",
                "edge_count": len(edges),
                "edges": edges,
            }
        except Exception as e:
            logger.warning(f"eBPF coverage failed: {e}")
            return None

    def _ebpf_malloc_trace(self, target, duration, output_file):
        bpftrace = self._caps.bpftrace_path
        if not bpftrace:
            return self._ltrace_malloc_trace(target, duration, output_file)

        script = """
uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc { @size[tid] = arg0; }
uretprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc { printf("malloc(%d) = %p\\n", @size[tid], retval); }
uprobe:/lib/x86_64-linux-gnu/libc.so.6:free { printf("free(%p)\\n", arg0); }
uprobe:/lib/x86_64-linux-gnu/libc.so.6:realloc { printf("realloc(%p, %d)\\n", arg0, arg1); }
"""

        try:
            cmd = [bpftrace, "-e", script, "-c", str(target)]
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=duration + 5,
                env=RaptorConfig.get_safe_env(),
            )

            if output_file:
                output_file.write_text(result.stdout)
            return result.returncode, result.stdout

        except subprocess.TimeoutExpired:
            return 0, "(trace timed out)"
        except Exception as e:
            logger.warning(f"eBPF malloc trace failed: {e}")
            return self._ltrace_malloc_trace(target, duration, output_file)

    def _ebpf_crash_monitor(self, pid, callback):
        bpftrace = self._caps.bpftrace_path
        if not bpftrace:
            return None

        script = f"""
tracepoint:signal:signal_deliver /pid == {pid} && (args->sig == 11 || args->sig == 6 || args->sig == 7 || args->sig == 4)/ {{
    printf("CRASH sig=%d pid=%d comm=%s\\n", args->sig, pid, comm);
    exit();
}}
"""
        try:
            result = subprocess.run(
                [bpftrace, "-e", script],
                capture_output=True, text=True, timeout=300,
                env=RaptorConfig.get_safe_env(),
            )

            for line in result.stdout.splitlines():
                if line.startswith("CRASH"):
                    parts = line.split()
                    for p in parts:
                        if p.startswith("sig="):
                            return int(p.split("=")[1])
        except Exception:
            pass

        return None

    # --- strace/ltrace backends ---

    def _strace_trace(self, target, duration, filter_calls, output_file):
        strace = self._caps.strace_path
        if not strace:
            return 1, "strace not available"

        cmd = [strace, "-f", "-tt"]
        if filter_calls:
            cmd.extend(["-e", "trace=" + ",".join(filter_calls)])

        if str(target).isdigit():
            cmd.extend(["-p", str(target)])
        else:
            cmd.append(str(target))

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=duration + 5,
                env=RaptorConfig.get_safe_env(),
            )
            output = result.stderr  # strace writes to stderr
            if output_file:
                output_file.write_text(output)
            return result.returncode, output
        except subprocess.TimeoutExpired:
            return 0, "(trace timed out)"

    def _ltrace_malloc_trace(self, target, duration, output_file):
        ltrace = self._caps.ltrace_path
        if not ltrace:
            return 1, "ltrace not available"

        cmd = [ltrace, "-e", "malloc+free+realloc", str(target)]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=duration + 5,
                env=RaptorConfig.get_safe_env(),
            )
            output = result.stderr
            if output_file:
                output_file.write_text(output)
            return result.returncode, output
        except subprocess.TimeoutExpired:
            return 0, "(trace timed out)"

    # --- Frida backends ---

    def _frida_syscall_trace(self, target, duration, filter_calls, output_file):
        if not self._caps.frida_available:
            return 1, "frida not available"
        # Frida syscall tracing would use Interceptor on libc wrappers
        # For now, fall back to strace if available
        if self._caps.strace_path:
            return self._strace_trace(target, duration, filter_calls, output_file)
        return 1, "no syscall tracer available"

    def _frida_coverage(self, binary, input_data, input_file):
        if not self._caps.frida_available:
            return None
        # Frida Stalker-based coverage — would use frida-trace
        # Placeholder for full implementation
        return None

    def _frida_malloc_trace(self, target, duration, output_file):
        if not self._caps.frida_available:
            return 1, "frida not available"
        # Would use Interceptor.attach on malloc/free
        return 1, "frida malloc tracing not yet implemented"


def get_tracer(caps: TracingCapabilities = None) -> Tracer:
    """Get a Tracer instance with auto-detected capabilities."""
    return Tracer(caps)
