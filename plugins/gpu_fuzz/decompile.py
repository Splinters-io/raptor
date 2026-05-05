"""Decompile input-handling functions from the target binary using r2.

Extracts the parser code that processes the fuzzing input, giving
the LLM mutator context about what structures, boundaries, and
validation checks the target expects.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()


def decompile_input_handlers(binary: Path, input_mode: str = "stdin") -> Dict[str, str]:
    """Decompile functions that handle fuzzing input.

    Uses r2 to list all functions, filters by name patterns relevant
    to the input mode, then decompiles each match.

    Returns:
        Dict mapping function name to pseudocode.
    """
    r2_bin = shutil.which("r2")
    if not r2_bin:
        logger.warning("r2 not found — LLM mutator will run without parser context")
        return {}

    # Step 1: Get function list as JSON
    result = subprocess.run(
        [r2_bin, "-q", "-e", "bin.cache=true", "-c", "aaa;aflj", str(binary)],
        capture_output=True, text=True,
        timeout=RaptorConfig.DEFAULT_TIMEOUT,
        env=RaptorConfig.get_safe_env(),
    )

    if result.returncode != 0:
        logger.warning(f"r2 analysis failed: {result.stderr[:200]}")
        return {}

    try:
        functions = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        logger.warning("Failed to parse r2 function list")
        return {}

    # Step 2: Filter functions by name patterns
    patterns = _get_sink_imports(input_mode)
    targets = []
    for fn in functions:
        name = fn.get("name", "")
        name_lower = name.lower()
        if any(p in name_lower for p in patterns):
            targets.append((name, fn["offset"]))

    if not targets:
        # Fallback: decompile main and the 10 largest non-library functions
        user_fns = [
            f for f in functions
            if not f.get("name", "").startswith(("sym.imp.", "fcn.", "loc."))
            and f.get("size", 0) > 20
        ]
        user_fns.sort(key=lambda f: f.get("size", 0), reverse=True)
        targets = [(f["name"], f["offset"]) for f in user_fns[:10]]

    logger.info(f"Decompiling {len(targets)} functions from {binary.name}")

    # Step 3: Decompile each target function
    # Build a single r2 session for all functions (faster than one per function)
    cmds = ["aaa"]
    for name, offset in targets:
        cmds.append(f"echo FUNC_START:{name}")
        cmds.append(f"s {offset}")
        cmds.append("pdf")
        cmds.append(f"echo FUNC_END:{name}")

    result = subprocess.run(
        [r2_bin, "-q", "-e", "bin.cache=true", "-c", ";".join(cmds), str(binary)],
        capture_output=True, text=True,
        timeout=RaptorConfig.DEFAULT_TIMEOUT,
        env=RaptorConfig.get_safe_env(),
    )

    output = _strip_ansi(result.stdout)
    results = {}
    current_name = None
    current_lines = []

    for line in output.splitlines():
        if line.startswith("FUNC_START:"):
            current_name = line.split(":", 1)[1]
            current_lines = []
        elif line.startswith("FUNC_END:"):
            if current_name and current_lines:
                code = "\n".join(
                    l for l in current_lines
                    if "No debug register" not in l and l.strip()
                )
                if len(code) > 30:
                    results[current_name] = code
            current_name = None
            current_lines = []
        elif current_name is not None:
            current_lines.append(line)

    return results


def decompile_functions_by_name(binary: Path, names: List[str]) -> Dict[str, str]:
    """Decompile specific functions by name."""
    r2 = shutil.which("r2")
    if not r2:
        return {}

    commands = ["aaa"]
    for name in names:
        commands.append(f"s sym.{name} 2>/dev/null || s sym.imp.{name} 2>/dev/null")
        commands.append(f"echo FUNC_START:{name}")
        commands.append("pdg 2>/dev/null || pdc 2>/dev/null || pdf")
        commands.append(f"echo FUNC_END:{name}")

    result = subprocess.run(
        [r2, "-q", "-e", "bin.cache=true", "-c", ";".join(commands), str(binary)],
        capture_output=True, text=True,
        timeout=RaptorConfig.DEFAULT_TIMEOUT,
        env=RaptorConfig.get_safe_env(),
    )

    return _parse_decompilation(result.stdout)


def get_binary_info(binary: Path) -> Optional[Dict]:
    """Quick triage — arch, format, mitigations."""
    r2 = shutil.which("r2")
    if not r2:
        return None

    result = subprocess.run(
        [r2, "-q", "-e", "bin.cache=true", "-c", "iIj", str(binary)],
        capture_output=True, text=True, timeout=30,
        env=RaptorConfig.get_safe_env(),
    )

    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return None


def _get_sink_imports(input_mode: str) -> List[str]:
    """Input-handling functions to look for based on input mode."""
    common = ["main", "parse", "process", "handle", "decode", "read_"]
    if input_mode == "stdin":
        return common + ["fread", "fgets", "scanf", "getline", "read"]
    elif input_mode == "file":
        return common + ["fopen", "fread", "mmap", "open", "read"]
    else:
        return common + ["recv", "recvfrom", "recvmsg", "read", "accept"]


def extract_format_hints(binary: Path) -> Dict:
    """Extract format-critical data from the binary without decompilation.

    Pulls strings, constants used in comparisons, struct-like data
    references, and error messages — the pieces the LLM needs to
    recover the input format reliably.

    This is faster and more reliable than parsing disassembly for
    magic bytes and field layouts.
    """
    r2_bin = shutil.which("r2")
    if not r2_bin:
        return {}

    # Single r2 session: strings from ALL sections + imports + hex search
    cmds = [
        "aaa",
        "echo SECTION:strings",
        "izzj",                    # strings from ALL sections (catches .text inlined constants)
        "echo SECTION:imports",
        "iij",                     # imports (JSON)
    ]

    result = subprocess.run(
        [r2_bin, "-q", "-e", "bin.cache=true", "-c", ";".join(cmds), str(binary)],
        capture_output=True, text=True,
        timeout=60,
        env=RaptorConfig.get_safe_env(),
    )

    output = _strip_ansi(result.stdout)
    hints = {
        "strings": [],
        "error_messages": [],
        "magic_candidates": [],
        "imports": [],
        "format_strings": [],
        "field_names": [],
    }

    # Parse strings section
    for section_data in _split_sections(output):
        name, data = section_data
        if name == "strings":
            try:
                strings = json.loads(data)
                for s in strings:
                    val = s.get("string", "")
                    if not val or len(val) < 2:
                        continue

                    # Filter out compiler/ASAN/AFL noise
                    noise_patterns = ["*.LC", "__asan", "__ubsan", "__afl",
                                       "__sanitizer", "__stack_chk", "_ZN",
                                       "==", "ABORTING", "ERROR:", "WARNING:",
                                       ".c:", ".h:", "runtime", "GLIBC",
                                       "TAG_", "kError", "Buffer"]
                    if any(p in val for p in noise_patterns):
                        continue

                    # x86 prologue byte sequences look like short strings
                    # (e.g., AUATUSH, AWAVAUI) — filter by checking if
                    # it's mostly uppercase with no vowels
                    if (len(val) >= 5 and val.isupper()
                            and not any(c in val for c in "AEIOUY")):
                        continue

                    val_lower = val.lower()

                    # Classify: error messages (reveal validation logic)
                    if any(k in val_lower for k in ["bad ", "invalid ", "too ",
                                                      "error", "fail", "unknown",
                                                      "corrupt", "malform"]):
                        hints["error_messages"].append(val)
                    # Classify: short alphanumeric = magic byte candidate
                    # Exclude common function/variable names
                    elif (2 <= len(val) <= 6 and val.isascii()
                          and val.isalnum()
                          and val not in ("main", "free", "atoi", "fork",
                                          "bool", "swap", "uptr", "argv",
                                          "argc", "clear", "empty", "close",
                                          "begin", "Print", "trace")):
                        hints["magic_candidates"].append({
                            "string": val,
                            "hex": val.encode().hex(),
                            "offset": s.get("vaddr", 0),
                        })
                    elif "%" in val:
                        hints["format_strings"].append(val)
                    # Field/variable names from debug symbols — very valuable
                    elif (val_lower in ("width", "height", "size", "length",
                                        "offset", "count", "type", "flags",
                                        "magic", "header", "payload", "data",
                                        "palette", "pixels", "bpp", "depth",
                                        "extra", "version", "checksum",
                                        "expected", "capacity")):
                        hints["field_names"].append(val)
                    elif len(val) > 2:
                        hints["strings"].append(val)
            except (json.JSONDecodeError, TypeError):
                pass

        elif name == "imports":
            try:
                imports = json.loads(data)
                for imp in imports:
                    hints["imports"].append(imp.get("name", ""))
            except (json.JSONDecodeError, TypeError):
                pass

    # Keep only interesting strings (deduplicated, capped)
    hints["strings"] = list(dict.fromkeys(hints["strings"]))[:30]
    hints["error_messages"] = list(dict.fromkeys(hints["error_messages"]))[:20]
    hints["imports"] = [i for i in hints["imports"] if i][:30]

    return hints


def _split_sections(output: str) -> List:
    """Split r2 output by SECTION: markers."""
    sections = []
    current_name = None
    current_lines = []

    for line in output.splitlines():
        if line.startswith("SECTION:"):
            if current_name:
                sections.append((current_name, "\n".join(current_lines)))
            current_name = line.split(":", 1)[1]
            current_lines = []
        elif current_name:
            current_lines.append(line)

    if current_name:
        sections.append((current_name, "\n".join(current_lines)))
    return sections


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from r2 output."""
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', text)
