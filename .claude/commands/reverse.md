---
description: Binary reverse engineering with r2 and Frida
---

# /reverse - Binary Reverse Engineering

Systematic reverse engineering using the right tool for the target format. Auto-detects file type and routes accordingly.

## Usage

```
/reverse <target_path> [--mode triage|full|trace|instrument] [--out <dir>]
```

**Auto-detection by file type:**
- **ELF / Mach-O / raw binaries** → r2 (radare2) for disassembly and decompilation
- **JAR / WAR** → JADX + CFR decompile to Java source, then Semgrep scan
- **PE / DLL / SYS** → route to rengy (Windows RE toolkit)
- **.NET assemblies** → ilspycmd decompile to C# source
- **ASAR** → extract and scan JS source
- **.node** → r2 (native shared library)

**Modes:**
- `triage` (default) — Quick characterization: arch, mitigations, imports, strings, sections
- `full` — Complete decompilation of all functions + triage + targeted analysis
- `trace <function>` — Deep analysis of a specific function with xrefs and call graph
- `instrument <function>` — Frida hook generation for a specific function (requires live target)

## Execution

1. Load the skill: read `.claude/skills/binary-re/SKILL.md`
2. Load the persona: read `tiers/personas/reverse_engineer.md`
3. Start run lifecycle:
   ```bash
   OUTPUT_DIR=$(libexec/raptor-run-lifecycle start reverse --target "$TARGET_PATH" | tail -1 | cut -d= -f2)
   ```
4. Verify r2 is available: `r2 -v`
5. Execute the requested mode using r2 (see skill for commands)
6. For `instrument` mode, verify frida is available: `frida --version`
7. Write outputs to `$OUTPUT_DIR/`:
   - `triage.json` — binary characterization
   - `decompiled.json` — function pseudocode (full mode)
   - `functions.json` — function inventory
   - `strings_categorized.json` — categorized strings
   - `findings.json` — identified vulnerabilities and behaviors
   - `hooks/` — generated Frida scripts (instrument mode)
8. Complete lifecycle:
   ```bash
   libexec/raptor-run-lifecycle complete "$OUTPUT_DIR"
   ```

## Evidence requirement

Every finding MUST cite a specific address, function name, or instrumentation trace. No fabricated results. No "this likely does X" without decompiled code or trace output to prove it.

## Examples

```
/reverse /path/to/binary                    # Quick triage
/reverse /path/to/binary --mode full        # Full decompilation + analysis
/reverse /path/to/binary --trace main       # Deep-dive on main()
/reverse /path/to/binary --instrument recv  # Generate Frida hooks for recv
```

## Dependencies

**Core (required):**
- r2 (radare2) — `brew install radare2` or build from source
- r2ghidra plugin — `r2pm -ci r2ghidra` (Ghidra decompiler inside r2)
- r2dec plugin — `r2pm -ci r2dec` (alternative decompiler)
- r2pipe — `pip install r2pipe` (scripted batch analysis)

**Dynamic instrumentation:**
- frida-tools — `pip install frida-tools` (runtime hooking, memory inspection)
- strace — `apt install strace` (syscall tracing, Linux)
- ltrace — `apt install ltrace` (library call tracing, Linux)

**Extraction and unpacking:**
- binwalk — `pip install binwalk` (firmware extraction, entropy analysis)
- msiextract — `apt install msitools` (MSI installer extraction)
- 7z — `apt install p7zip-full` (nested archive extraction)

**.NET decompilation:**
- ilspycmd — `dotnet tool install -g ilspycmd` (C# source recovery)

**Detection rules:**
- yara — `apt install yara` / `brew install yara` (pattern matching, rule scanning)
