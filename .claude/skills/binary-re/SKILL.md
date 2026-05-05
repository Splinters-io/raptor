# Binary Reverse Engineering — SKILL

Systematic binary reverse engineering using radare2 (r2) for static analysis and Frida for dynamic instrumentation. This is a malware analyst's workflow, not a strings-and-pray approach.

## Philosophy

**Pull binaries down to the bone.** Every binary gets full decompilation — every function, every code path. Strings are leads to follow, not findings to report. An import table is a question ("what does it call and why?"), not an answer. If you haven't decompiled the function, you don't understand the binary.

**Evidence-based only.** Every claim cites decompiled code, a memory address, or an instrumentation trace. No fabrication, no simulation, no "this likely does X" without proof. We're doing science — form hypotheses, prove or disprove them, document the evidence.

**r2 over Ghidra.** Claude handles r2's CLI natively — scriptable, JSON output everywhere, no GUI dependency. Use r2pipe for programmatic analysis when batch processing is needed.

**Frida for runtime truth.** Static analysis lies; dynamic analysis confirms. Hook functions, trace arguments, intercept crypto, dump memory — Frida fills the gap between "the code could do X" and "the code does X."

## Anti-Shortcuts — What NOT To Do

These are the hallmarks of lazy analysis. Never do any of them:

1. **Don't stop at strings.** `strings binary | grep password` is not analysis. It's a starting point. Every interesting string must be followed to its cross-references, and the referencing code must be decompiled and understood.
2. **Don't stop at imports.** "It imports `EVP_EncryptInit_ex`" tells you nothing about how it's used, what key material is passed, or whether the IV is reused. Decompile the caller.
3. **Don't stop at triage.** Triage tells you what to look at. Decompilation tells you what it does. Frida tells you what it actually does at runtime. All three are required.
4. **Don't summarize without reading.** Never describe what a function "probably does" based on its name. Decompile it. Read the pseudocode. Name says `validate_token`? Maybe it does, maybe it returns true unconditionally. Read the code.
5. **Don't fabricate decompilation output.** If r2 can't decompile a function, say so. Show the disassembly instead. Never invent pseudocode.
6. **Don't report a vuln without the instruction sequence.** "There's a buffer overflow in parse_input" is not a finding. The finding is the specific instruction sequence that writes past the buffer boundary, with addresses, register values, and the decompiled code showing the unchecked size.
7. **Don't skip binaries.** Every binary in the target gets at minimum a triage pass. "Helper DLLs" and "support utilities" contain vulns too — often more, because they get less attention.
8. **Don't claim crypto is broken without showing the constants.** "Uses weak encryption" is meaningless. Show the S-box, the round constant, the key derivation, the IV generation — at specific addresses.

## Tool Requirements

### Core (required)

| Tool | Binary | Install | Purpose |
|------|--------|---------|---------|
| radare2 | `r2` | `brew install radare2` / build from source | Static analysis, disassembly, decompilation |
| r2ghidra | (r2 plugin) | `r2pm -ci r2ghidra` | Ghidra decompiler inside r2 (`pdg` command) |
| r2dec | (r2 plugin) | `r2pm -ci r2dec` | Alternative decompiler (`pdc` command) |
| r2pipe | (Python) | `pip install r2pipe` | Scripted/batch r2 analysis from Python |

### Dynamic instrumentation

| Tool | Binary | Install | Purpose |
|------|--------|---------|---------|
| Frida | `frida` | `pip install frida-tools` | Runtime hooking, function interception, memory inspection |
| frida-trace | `frida-trace` | Included with frida-tools | Quick function tracing by pattern |
| strace | `strace` | `apt install strace` | Syscall tracing (Linux) |
| ltrace | `ltrace` | `apt install ltrace` | Library call tracing (Linux) |

### Extraction and unpacking

| Tool | Binary | Install | Purpose |
|------|--------|---------|---------|
| binwalk | `binwalk` | `pip install binwalk` / `apt install binwalk` | Firmware extraction, embedded file detection, entropy analysis |
| msiextract | `msiextract` | `apt install msitools` | MSI installer extraction (Windows targets on Linux) |
| 7z | `7z` | `apt install p7zip-full` | Archive extraction (CAB, ZIP, 7z, nested installers) |

### Java bytecode

| Tool | Binary | Install | Purpose |
|------|--------|---------|---------|
| JADX | `jadx` | Download from GitHub releases to `~/tools/jadx/` | Primary Java/Android decompiler — recovers source with package structure |
| CFR | `cfr.jar` | Download from GitHub releases to `~/tools/cfr.jar` | Cross-reference decompiler — catches different edge cases than JADX |

Java JARs/WARs MUST be decompiled before any analysis. Semgrep and CodeQL cannot scan bytecode — they need `.java` source files.

```bash
# JADX (primary — better structure recovery, handles obfuscation)
jadx --output-dir decompiled/<name> --threads-count 8 --deobf --show-bad-code target.jar

# CFR (cross-reference — sometimes recovers code JADX misses)
java -jar ~/tools/cfr.jar target.jar --outputdir decompiled-cfr/<name>

# Then scan the recovered source
semgrep scan --config p/java --config p/security-audit --config p/owasp-top-ten decompiled/
```

**Separate vendor code from OSS deps:** Check each JAR for vendor-specific packages before decompiling everything:
```bash
jar tf target.jar | grep -iE "com/ubnt|com/vendor|com/product"
```
Only decompile and deeply analyse vendor JARs. OSS deps get a version check for known CVEs, not full RE.

### .NET and managed code

| Tool | Binary | Install | Purpose |
|------|--------|---------|---------|
| ilspycmd | `ilspycmd` | `dotnet tool install -g ilspycmd` | .NET assembly decompilation to C# source |

For .NET binaries, use ilspycmd instead of r2:
```bash
ilspycmd -p -o decompiled/<assembly_name>/ <assembly>.dll
```

### Detection rules and signatures

| Tool | Binary | Install | Purpose |
|------|--------|---------|---------|
| YARA | `yara` | `apt install yara` / `brew install yara` | Pattern matching, rule scanning, compiled rule extraction |
| yarac | `yarac` | Included with yara | YARA rule compilation/decompilation |

### Verify toolchain

```bash
r2 -v && r2 -c 'e asm.arch' -- && echo "r2 OK"
frida --version 2>/dev/null && echo "frida OK"
binwalk --help >/dev/null 2>&1 && echo "binwalk OK"
yara --version 2>/dev/null && echo "yara OK"
ilspycmd --version 2>/dev/null && echo "ilspycmd OK"
strace -V 2>/dev/null && echo "strace OK"
```

## r2 Conventions

Always use JSON output (`j` suffix) for machine-parseable results:
- `iIj` — binary info (arch, bits, class, os)
- `iij` — imports
- `iEj` — exports
- `izj` — strings (data section)
- `izzj` — strings (all sections, slower but catches more)
- `aflj` — function list (after analysis)
- `axtj @addr` — cross-references to address
- `axfj @addr` — cross-references from address
- `pdfj @func` — disassembly of function (JSON)
- `pdcj @func` — decompiled pseudocode (r2dec, JSON)
- `pdgj @func` — Ghidra decompilation (r2ghidra, JSON)

Analysis depth:
- `aaa` — full analysis (default, good enough for most binaries)
- `aaaa` — experimental analysis (slower, more aggressive, sometimes better)
- `aac` — analyze function calls
- `aap` — analyze function preludes (finds more functions)

## Phase 0: Triage

Before diving deep, characterize the binary. This takes <30 seconds and tells you what you're dealing with.

```bash
# One-shot triage (no interactive session needed)
r2 -q -e bin.cache=true -c '
iIj;
iij;
iEj;
izj;
iSj;
iVj
' target_binary
```

**Mandatory triage outputs:**
1. Architecture, format, compiler, linkage (static/dynamic)
2. Security mitigations: RELRO, NX, stack canaries, PIE, ASLR, Fortify
3. Import summary — what libraries and syscalls does it use?
4. Export summary — what does it expose?
5. String triage — not just dump, but categorize: URLs, file paths, registry keys, error messages, crypto constants, debug strings, format strings
6. Section analysis — unusual sections, packed indicators, high entropy

**What to look for in strings (not just grep):**
- Network indicators: URLs, IPs, domains, ports, protocol identifiers
- File system: paths, extensions, temp directories
- Crypto: algorithm names, key sizes, IV patterns, certificate strings
- IPC: pipe names, shared memory names, mutex names, COM CLSIDs
- Debug: function names in error messages, assert strings, log format strings
- Registry: Windows registry paths (HKLM, HKCU patterns)
- Embedded data: base64, hex blobs, PEM headers, magic bytes

## Phase 1: Full Decompilation

**Goal: Pseudocode for every function.** Not just the interesting ones — completeness reveals patterns.

### Batch decompilation with r2pipe

```python
#!/usr/bin/env python3
"""Batch decompile all functions in a binary using r2pipe."""
import r2pipe
import json
import sys

r2 = r2pipe.open(sys.argv[1], flags=['-2'])
r2.cmd('aaa')

functions = r2.cmdj('aflj') or []
results = {}
for fn in functions:
    name = fn.get('name', f"fcn_{fn['offset']:#x}")
    try:
        # Try r2ghidra first, fall back to r2dec, fall back to disasm
        decomp = r2.cmd(f'pdg @{fn["offset"]}')
        if not decomp.strip():
            decomp = r2.cmd(f'pdc @{fn["offset"]}')
        if not decomp.strip():
            decomp = r2.cmd(f'pdf @{fn["offset"]}')
        results[name] = {
            'offset': fn['offset'],
            'size': fn.get('size', 0),
            'pseudocode': decomp
        }
    except Exception as e:
        results[name] = {'offset': fn['offset'], 'error': str(e)}

with open(sys.argv[2] if len(sys.argv) > 2 else 'decompiled.json', 'w') as f:
    json.dump(results, f, indent=2)
r2.quit()
```

### Per-function interactive analysis

When investigating specific functions:
```
r2 -A binary
[0x00401000]> s sym.interesting_function
[0x00401234]> pdg          # Ghidra decompile
[0x00401234]> VV           # visual graph mode
[0x00401234]> agCd         # call graph (dot format)
[0x00401234]> axt          # who calls this?
[0x00401234]> axf          # what does this call?
```

### Output structure

For each binary analyzed, produce in the output directory:
- `triage.json` — Phase 0 triage results
- `decompiled.json` — all function pseudocode (or `decompiled/` directory with per-function files for large binaries)
- `functions.json` — function list with addresses, sizes, call counts
- `strings_categorized.json` — strings organized by category (network, crypto, IPC, debug, etc.)
- `xrefs.json` — interesting cross-reference chains
- `findings.json` — identified vulnerabilities, interesting behaviors, anomalies

## Phase 2: Targeted Analysis

After batch decompilation, focus on high-value targets:

### Attack surface mapping
1. **Entry points** — main, exported functions, signal handlers, thread entry points
2. **Input handlers** — anything that reads from network, file, stdin, IPC
3. **Parsers** — format-specific parsing (PE, ELF, XML, JSON, protocol buffers)
4. **Crypto functions** — identify by constants (S-boxes, round constants), imports, or structure
5. **Privilege boundaries** — setuid checks, capability queries, token manipulation

### What to trace
- Data flow from input to sink (buffer operations, format strings, command execution)
- Authentication/authorization logic (how are credentials verified?)
- Error handling paths (what happens on failure? information leaks?)
- State machines (protocol handling, command dispatch)
- Anti-analysis (debugger detection, timing checks, integrity verification)

## Phase 3: Dynamic Instrumentation with Frida

**When to use Frida:** After static analysis has identified targets. Frida confirms hypotheses.

### Common patterns

```javascript
// Hook a function and log arguments
Interceptor.attach(Module.findExportByName(null, "target_func"), {
    onEnter(args) {
        console.log(`target_func(${args[0]}, ${args[1].readUtf8String()})`);
        this.arg0 = args[0];
    },
    onLeave(retval) {
        console.log(`  -> returned ${retval}`);
    }
});

// Trace all calls to a class of functions
const funcs = ["recv", "read", "recvfrom", "recvmsg"];
funcs.forEach(name => {
    const addr = Module.findExportByName(null, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter(args) { console.log(`${name}(fd=${args[0]}, buf=${args[1]}, len=${args[2]})`); },
            onLeave(retval) {
                if (retval.toInt32() > 0) {
                    console.log(`  data: ${this.context.x1.readByteArray(retval.toInt32())}`);
                }
            }
        });
    }
});

// Dump memory at a specific point
Interceptor.attach(ptr("0x401234"), {
    onEnter() {
        console.log(hexdump(this.context.rdi, { length: 256 }));
    }
});
```

### Frida trace for quick exploration
```bash
# Trace all calls to crypto functions
frida-trace -i "EVP_*" -i "AES_*" -i "SHA*" ./target

# Trace file operations
frida-trace -i "open*" -i "read" -i "write" -i "close" ./target

# Trace network
frida-trace -i "connect" -i "send*" -i "recv*" -i "bind" ./target

# Trace with a specific script
frida -l hook_script.js -f ./target
```

## Evidence Standards

1. **Every claim cites an address or function name** — "the key is XOR'd at `0x4012ab` in `decrypt_config`"
2. **Crypto claims show constants** — don't say "uses AES" without showing the S-box or round constant at a specific address
3. **Vulnerability claims include the instruction sequence** — show the buffer overflow, not just "there's a buffer overflow"
4. **Dynamic findings include the trace output** — hook output, memory dumps, argument values
5. **Negative results are documented** — "checked for anti-debug at typical locations, none found" is useful

## Phase 4: Extraction and Unpacking

For packed, encrypted, or installer-wrapped targets, extract everything before analysis.

### Installer extraction
```bash
# MSI files (Windows installers analyzed on Linux)
msiextract installer.msi -C extracted/

# CAB / nested archives
7z x installer.cab -oextracted/

# Self-extracting executables — binwalk finds embedded archives
binwalk -e target.exe --directory=extracted/
```

### Packed binary detection
```bash
# Entropy analysis — high entropy sections suggest packing/encryption
r2 -q -c 'iSj' binary | python3 -c "
import json, sys
for s in json.load(sys.stdin):
    entropy = s.get('entropy', 0)
    name = s.get('name', '?')
    if entropy > 6.5:
        print(f'HIGH ENTROPY: {name} = {entropy:.2f} (likely packed/encrypted)')
"

# binwalk entropy visualization
binwalk -E binary
```

### Encrypted asset detection
Look for:
- Magic byte headers at data section starts
- XOR patterns (repeating byte sequences in .rdata)
- Hardcoded keys near decrypt function calls (search r2 xrefs from known crypto imports)
- Entropy anomalies in specific sections

When encrypted assets are found, build a `decrypt.py` tool:
```python
#!/usr/bin/env python3
"""Decrypt assets using extracted key material."""
# Key extraction methodology:
# 1. Find the decrypt function via xrefs from encrypted data
# 2. Extract the key from .rdata or function constants
# 3. Identify algorithm (XOR, AES, custom)
# 4. Reimplement in Python
```

## Phase 5: Rule and Signature Extraction

For targets that contain detection rules (EDR/AV products, IDS/IPS, WAFs).

### YARA rules
```bash
# Scan for embedded YARA rules
r2 -q -c '/ yara' binary          # search for "yara" string
r2 -q -c '/ rule ' binary         # search for rule definitions
yara -r extracted_rules/ target    # test extracted rules against samples
```

### Lua/scripted detection engines
Search for embedded interpreters and scripts:
```bash
# Find Lua VM indicators
r2 -q -c '/ luaL_newstate; / lua_pcall; / .lua' binary

# Find JavaScript engine indicators
r2 -q -c '/ v8::; / JS_NewRuntime; / duktape' binary
```

Extract scripts from encrypted containers — follow the loader function, find the decryption key, dump plaintext scripts to `rules/`.

### Signature databases
- Parse vendor-specific formats into JSON/YARA
- Document the format (header structure, record layout, encoding)
- Build a `parser.py` tool for the vendor format

### Output: `rules/` directory
```
rules/
├── yara/           # YARA rules (compiled → decompiled to source)
├── lua/            # Lua behavioral scripts
├── signatures/     # Vendor signature databases (parsed)
├── behavioral/     # Behavioral IOA/IOC definitions
├── exclusions/     # Hardcoded exclusions, allowlists, exemptions
└── README.md       # Rule inventory with counts and coverage
```

## Phase 6: ML Model Extraction

For targets with embedded ML models or classification engines.

### Find embedded models
```bash
# TFLite headers
r2 -q -c '/x 180000005446 4c33' binary

# Large floating-point arrays in .rdata (decision tree weights)
r2 -q -c 'iSj' binary  # check .rdata size — large sections suggest models

# XGBoost/LightGBM/Bonsai serialized trees
r2 -q -c '/ booster; / tree_param; / bonsai' binary
```

### Extract and reimplement
1. Locate the model in the binary (section, offset, size)
2. Extract raw weights/structure to JSON
3. Decompile the feature extraction function (what attributes are scored)
4. Map scoring thresholds (clean/suspicious/malicious boundaries)
5. Build standalone scanner in `models/scanner/`:
   - Load extracted weights
   - Extract features from test files
   - Produce scores
   - Validate against known samples

### Output: `models/` directory
```
models/
├── weights/        # Raw model weights, decision trees, TFLite files
├── features/       # Feature extraction logic (decompiled)
├── configs/        # Model configs, thresholds, scoring parameters
├── scanner/        # Standalone Python reimplementation
└── README.md       # Model inventory (type, size, accuracy)
```

## Phase 7: Per-Target Tool Development

During analysis, build tools specific to the target. Don't wait to be asked — if you see an update URL, a signature database, or an encrypted asset, build the tool proactively.

| Tool type | When to build | Example |
|-----------|---------------|---------|
| `decrypt.py` | Assets are encrypted | XOR/AES decryptor using extracted key material |
| `download.py` | Signatures available online | Pull latest detection content from update server |
| `scanner.py` | ML pipeline can be reimplemented | Standalone scoring engine with extracted weights |
| `parser.py` | Custom signature/config format | Convert proprietary format to JSON/YARA |
| `protocol.py` | Network protocol reversed | Client for cloud API, command channel, telemetry |

### Tool standards
- Self-contained Python, minimal dependencies
- Documented: header comment with what it does, how the key/format was found, r2 addresses
- Tested: verify against known inputs before delivering

## Structured Output Directory

For comprehensive binary analysis (EDR, malware, complex targets), use this layout:

```
<output_dir>/
├── triage.json                  # Phase 0 characterization
├── decompiled.json              # Phase 1 pseudocode (or decompiled/ directory)
├── functions.json               # Function inventory
├── strings_categorized.json     # Strings by category
├── xrefs.json                   # Cross-reference chains
├── findings.json                # Vulnerabilities and behaviors
├── hooks/                       # Generated Frida scripts
├── extracted/                   # Unpacked installer contents
│   ├── binaries/                # EXEs, DLLs, SOs, drivers
│   └── configs/                 # Configuration files
├── rules/                       # Detection rules (if applicable)
├── models/                      # ML models (if applicable)
└── tools/                       # Per-target utilities built during analysis
```

## Integration with RAPTOR

- `/reverse` uses this skill for the RE methodology
- Findings feed into `/validate` for exploitability assessment
- Exploit feasibility analysis (`packages/exploit_feasibility/`) runs after vulns are found
- Output directory follows RAPTOR run lifecycle conventions
- YARA rules extracted during RE can feed back into `/scan` for pattern matching
- strace/ltrace output complements Frida traces for syscall-level analysis

## Gates

- **GATE 0 — Triage:** Every binary must have a complete triage (arch, mitigations, imports, exports, categorized strings, section entropy). No binary is skipped — "helper" and "support" binaries get triaged too.
- **GATE 1 — Decompilation:** Every function in the binary must have pseudocode (r2ghidra `pdg`, r2dec `pdc`, or raw disassembly `pdf` as fallback). Partial decompilation is not "done." If a function fails decompilation, log it and show the disassembly.
- **GATE 2 — Cross-references:** Every interesting string, import, and constant must have its xrefs traced. "The binary contains the string X" is not a finding. "The string X is referenced by function Y at address Z, which does W" is a finding.
- **GATE 3 — Data flow:** For every identified input handler, trace the data from entry to processing to output. Document buffer sizes, validation checks (or lack of), and where the data is consumed.
- **GATE 4 — Dynamic confirmation:** Static findings that claim exploitability must have Frida instrumentation confirming the code path is reachable and the arguments are attacker-controlled. A static hypothesis without dynamic confirmation is labeled "hypothesis," not "finding."
- **GATE 5 — Evidence:** All claims in findings.json must cite a specific address, disassembly sequence, or Frida trace output. No exceptions. No "this function probably does X."
- **GATE 6 — Encrypted assets:** Must be decrypted before rule/model extraction. Document the key, algorithm, and r2 addresses where they were found.
- **GATE 7 — Tools:** Per-target tools must be tested against known inputs before delivery.

### Depth checklist — before marking a binary "analyzed"

- [ ] Full triage (arch, mitigations, imports, exports, strings, sections, entropy)
- [ ] Every function decompiled (pseudocode, not just names)
- [ ] All crypto identified by constants, not by string names
- [ ] All input handlers traced from entry to sink
- [ ] All interesting xref chains documented
- [ ] Frida hooks run on reachable code paths
- [ ] Findings have instruction-level evidence
- [ ] Negative results documented ("checked X, not present")
