"""Runtime tracing — eBPF preferred, falls back to strace/ltrace/Frida.

Provides a unified API for syscall tracing, library call tracing,
coverage collection, and crash detection. Detects platform capabilities
at runtime and selects the best available backend.

Linux with eBPF: near-zero overhead, in-kernel filtering, no ptrace.
Linux without eBPF: strace/ltrace (ptrace-based, ~2x slowdown).
macOS/Windows: Frida or platform-specific tools.

Usage:
    from core.tracing import get_tracer

    tracer = get_tracer()           # auto-selects best backend
    tracer.trace_syscalls(pid)      # syscall trace
    tracer.trace_coverage(binary)   # edge coverage for fuzzing
    tracer.trace_mallocs(pid)       # heap allocation tracking
"""

from .probe import probe_capabilities, TracingCapabilities
from .backend import get_tracer

__all__ = ["get_tracer", "probe_capabilities", "TracingCapabilities"]
