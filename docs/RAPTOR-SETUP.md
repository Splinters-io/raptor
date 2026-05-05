# RAPTOR Setup — Architecture, Infrastructure, and Reasoning

This document captures the full setup of RAPTOR as configured for this lab — the decisions made, why they were made, and how everything connects. It's written so someone picking this up cold can understand not just what's here, but why.

---

## Philosophy

Three principles govern everything:

**Evidence over hope.** Every finding is a hypothesis until proven with code, traces, or memory dumps. No fabricated results, no simulated output, no "this likely does X" without decompiled code at a specific address. Hypotheses are stated as hypotheses, then proven or disproven. We're doing science.

**Depth over speed.** A 30-minute scan that finds nothing is worse than an 8-hour campaign that finds one real vulnerability with a working PoC. The infrastructure exists to do thorough work — let it work. Never truncate analysis to save time. Never skip "low priority" binaries. Never report partial results as findings.

**Pull binaries down to the bone.** `strings` is a starting point, not an analysis. Every binary gets full decompilation. Every function gets pseudocode. Every interesting string gets its cross-references traced to the code that uses it. Every claim about what code "does" is backed by the disassembly at a specific address.

---

## Lab Infrastructure

### Why Three Machines

Each machine exists for a reason. The split isn't arbitrary — it's driven by what each OS and hardware configuration is best at.

#### thefarm (Linux) — Primary Compute

| Resource | Spec |
|----------|------|
| CPU | AMD Ryzen Threadripper 9960X — 24 cores, 48 threads, 5.49 GHz |
| RAM | 122 GB |
| GPU | NVIDIA RTX PRO 6000 Blackwell — 96 GB VRAM |
| Boot disk | 1.8 TB (599 GB free) |
| Cold storage | 916 GB |
| Kernel | 6.17.0 (full eBPF/BTF support) |

**Why this machine matters:** 96 GB VRAM runs abliterated 35B LLMs at full context for local analysis — zero marginal cost per query. 48 threads parallelise AFL++ fuzzing campaigns. eBPF provides zero-overhead runtime tracing. This is where headless campaigns run: overnight fuzzing, batch decompilation, LLM-guided mutation loops.

**What runs here:**
- RAPTOR headless campaigns in screen sessions
- AFL++ fuzzing (parallel instances across 48 threads)
- GPU-fuzz plugin (LLM-guided mutation via Ollama on the GPU)
- r2 batch decompilation of large binaries
- eBPF syscall/coverage/malloc tracing
- Ollama with 14 local models for analysis dispatch
- Vault (13K vulnerability technique library) for RAG retrieval

**Access:** `ssh carroll@thefarm` (key auth)

#### rengy (Windows) — Windows RE

| Resource | Spec |
|----------|------|
| CPU | Intel Core Ultra 9 285HX — 24 cores |
| RAM | 64 GB |
| Storage | 1.86 TB (1.5 TB free) |
| OS | Windows 11 Pro |

**Why this machine matters:** Windows binaries need Windows tools. DynamoRIO for coverage tracing, x64dbg for debugging, Sysinternals for runtime monitoring, ilspycmd for .NET decompilation. You can't do serious PE/DLL analysis on Linux.

**What runs here:**
- DynamoRIO coverage tracing on Windows targets
- x64dbg interactive debugging
- PE-bear structure analysis, Detect It Easy packer identification
- Sysinternals (ProcMon, ProcExp) for runtime behaviour
- ilspycmd .NET decompilation
- Frida Windows hooking
- Python RE stack (pefile, capstone, unicorn, keystone, yara)

**Access:** `ssh agent@rengy` (key auth). Windows SSH has escaping issues — all commands are wrapped in `powershell -EncodedCommand` (base64) to avoid them. No screen sessions on Windows — use PowerShell background jobs.

#### Local Mac — Orchestration

The Mac running Claude Code is the interactive control plane. Source code scanning, exploratory RE, exploit development, and conversation all happen here. It has r2, Frida, Semgrep, CodeQL, and AFL++ for local work, but heavy compute goes to thefarm.

### Why These Specific Tools

#### r2 over Ghidra

Radare2 is the primary binary analysis tool. Not Ghidra. The reasoning: Claude handles r2's CLI natively — it's scriptable, produces JSON output on every command (append `j`), and has no GUI dependency. No Java heap issues, no headless Ghidra project management, no X11 forwarding. r2ghidra plugin gives Ghidra-quality decompilation inside r2 (`pdg` command) when available; `pdf` (disassembly) works everywhere as fallback.

Carroll's reasoning: "I'm not autistic enough to use R2 full time, Claude is." r2's CLI-first design is a perfect fit for LLM-driven analysis.

**Installed on:** thefarm, local Mac. r2ghidra plugin on thefarm.

#### Frida for Dynamic Analysis

Static analysis produces hypotheses. Frida confirms them. Hook functions, observe arguments at runtime, intercept crypto operations, dump memory. Frida is the bridge between "the code could do X" and "the code does X at runtime with these specific values."

Frida complements eBPF — eBPF observes passively at kernel level (syscalls, coverage, allocations), Frida intercepts and modifies at userspace level (function arguments, return values, memory). Both are needed.

**Installed on:** thefarm, rengy, local Mac.

#### eBPF for Linux Tracing (Preferred over strace)

eBPF replaces strace, ltrace, and manual coverage tracking with zero-overhead kernel-level instrumentation. On thefarm's kernel 6.17 with BTF support, bpftrace scripts can:
- Trace syscalls without ptrace overhead (replaces strace)
- Track malloc/free via uprobes without ASAN's 2x memory cost
- Provide edge coverage on uninstrumented binaries (replaces AFL++ QEMU mode)
- Detect crashes instantly via signal tracepoints

The tracing module (`core/tracing/`) auto-detects capabilities at runtime. On Linux with eBPF, it uses bpftrace. On macOS or Linux without eBPF, it falls back to strace/Frida. The API is the same — `get_tracer().trace_syscalls()` dispatches to whatever's available.

**eBPF is Linux-only.** macOS has DTrace, Windows has ETW. The tracing module handles this transparently.

#### DynamoRIO for Windows Coverage

eBPF can't help on Windows. DynamoRIO provides instruction-level tracing and coverage on Windows binaries without recompilation — the Windows equivalent of eBPF uprobes for coverage purposes.

**Installed on:** rengy only.

### Storage

#### FuzzyDump NAS — sin.local

21 TB SMB share at `//sin.local/volume1/FuzzyDump`. Mounted at `/mnt/fuzzydump` on thefarm. Stores:
- Fuzzing corpora and crash artifacts (auto-dumped by gpu-fuzz plugin)
- Existing campaigns: chiapos (1572 crashes), libuv (2067 crashes), Wickr Pro protobuf/opus/vpx/aac
- Target binaries and installers

**Credentials:** In `/root/.smb-fuzzydump` on thefarm (mode 600). Not in code, not in config files, not in git.

#### Cold Storage

916 GB drive at `/media/carroll/COLD` on thefarm. Contains `FuzzDump/` directory — secondary storage for large artifacts.

---

## Model Architecture

RAPTOR has two separate LLM layers with a hard boundary between them.

### Orchestration Layer — Claude Code

Claude Code is always the orchestrator. The CLAUDE.md, skills, commands, and conversation all run through Claude. The model powering Claude Code is selected via Claude Code's own settings (`/model` or `--model`). This layer handles:
- Interactive analysis and decision-making
- Skill execution (the `/reverse`, `/scan`, `/validate` commands)
- Conversation context and judgment calls
- Code reading, writing, and tool use

### Analysis Dispatch Layer — Local LLMs via Ollama

The analysis dispatch layer handles bulk work that doesn't need the orchestrator's context window or reasoning depth. Configured in `~/.config/raptor/models.json`:

| Model | Role | Size | Why |
|-------|------|------|-----|
| Qwen 3.6 abliterated 35B | `analysis` | 24 GB VRAM | Primary reasoning — abliterated means it won't refuse to analyse exploit code, malware behaviour, or offensive techniques. MoE architecture = faster than dense 35B. |
| Qwen 2.5 Coder 32B | `code` | 20 GB VRAM | Code-heavy tasks — decompilation review, pseudocode analysis, patch writing, structured JSON output. Most reliable for format recovery in gpu-fuzz. |
| Gemma 4 abliterated 31B | `consensus` | 20 GB VRAM | Second opinion — different model family catches different things. Used for multi-model consensus validation. |
| Qwen 3 8B | `triage` | 5 GB VRAM | Fast bulk triage — string classification, initial severity assessment. Cheap enough to run on every finding. |

**Why abliterated models:** Stock models refuse to analyse exploit code, discuss ROP chains, or reason about malware behaviour. This is a security research lab. The models need to work with offensive content without hedging or refusing. huihui_ai's abliterated variants remove these guardrails while preserving the base model's reasoning quality.

**Why local over cloud for bulk work:** 96 GB VRAM means two models run simultaneously at zero marginal cost. A 10,000-finding triage that would cost hundreds of dollars via cloud API costs nothing on local hardware. Cloud models (Anthropic Claude) are reserved for tasks requiring deep reasoning — exploit development, complex validation, architectural analysis.

**Qwen 3.6 thinking model caveat:** Qwen 3.6's thinking mode consumes output tokens internally, producing empty responses via the Ollama API unless thinking is explicitly disabled. The gpu-fuzz mutator uses Qwen 2.5 Coder instead for structured JSON generation. This is a known limitation, not a bug.

### Where Local LLMs Work and Where They Don't

Local models are tools, not oracles. They excel at structured, bounded tasks where the input format is well-defined and the output can be verified mechanically. They produce garbage when asked to do unbounded reasoning or act as a substitute for proper tooling.

**Local LLMs are good at:**
- **Structured JSON generation** — format recovery for gpu-fuzz (given decompiled parser code, produce a format spec). Qwen 2.5 Coder is the most reliable here.
- **String and finding classification** — "is this string a path, a URL, a crypto constant, or noise?" Qwen 3 8B handles this at high volume.
- **Severity triage** — given a SARIF finding with context, classify as critical/high/medium/low. Fast enough to run on every finding.
- **Multi-model consensus** — run the same question through Qwen and Gemma; if they disagree, flag for human review. Different model families catch different failure modes.
- **Vault-enriched mutation** — given a vulnerability class and real-world technique writeups, generate targeted fuzz inputs. The vault provides grounding that prevents hallucination.

**Local LLMs produce garbage at:**
- **Flat vulnerability scanning** — sending raw disassembly or decompiled code to an LLM and asking "find vulnerabilities" produces confident-sounding nonsense with no evidence. This was tried twice during the UniFi campaign and caught both times — once treating Go import paths as API routes, once generating fabricated findings from a credential server. Tools (Semgrep, CodeQL, YARA) find vulnerabilities. The LLM reasons about what the tools found.
- **Architectural reasoning** — local 35B models don't maintain coherent reasoning across complex multi-step exploitation chains. They lose track of constraints, forget mitigations mentioned 2000 tokens earlier, and hallucinate gadget addresses. Cloud Claude handles this.
- **Thinking-mode structured output** — Qwen 3.6 in thinking mode eats output tokens for internal reasoning, returning empty responses via the Ollama API. Always disable thinking for structured generation tasks.
- **Ungrounded analysis** — any task where the LLM has to reason without tool-provided evidence. No amount of prompt engineering fixes this — the model doesn't have ground truth, so it invents it.

**The hard rule:** Tools first, LLM after. Enforced by `PipelineGate.check_llm_allowed()` in `core/remote/pipeline.py`. LLM reasoning is allowed at phases 6 (validate), 7 (exploit), and 8 (report) — to reason about tool findings. LLM is never used at phases 1–5 as a substitute for tools.

---

## Java Target Detection and Tooling

When RAPTOR encounters Java targets (`.jar`, `.war`, `.class` files, or directories containing them), a mandatory decompilation step runs before any static analysis. Semgrep and CodeQL cannot scan Java bytecode directly — scanning JARs without decompiling produces zero findings.

### Detection

The task dispatch module (`core/remote/dispatch.py`) detects Java targets by file extension and routes them to thefarm for headless decompilation:

```python
# From dispatch rules — file_types trigger before command catch-alls
{
    "file_types": [".jar", ".war", ".class"],
    "mode": ExecutionMode.HEADLESS,
    "target": ExecutionTarget.THEFARM,
    "reason": "Java bytecode — JADX/CFR decompile then Semgrep scan on recovered source",
}
```

### Decompilation Pipeline

Two decompilers, not one. Each catches different edge cases:

| Tool | Location | Strengths |
|------|----------|-----------|
| JADX | `~/tools/jadx/bin/jadx` on thefarm | Better structure recovery, handles obfuscated code, produces cleaner class hierarchies |
| CFR | `~/tools/cfr.jar` on thefarm | Better at edge-case bytecode patterns, catches things JADX misses, good cross-reference |

**Workflow:**
1. **Separate vendor from OSS** — check for vendor-specific packages (e.g., `com.ubnt`/`com.ubiquiti` for UniFi targets) vs standard library and third-party deps. Focus analysis on vendor-authored code.
2. **Decompile with JADX** (primary) — produces recovered `.java` source tree.
3. **Cross-reference with CFR** — run CFR on the same JARs, diff output against JADX for classes where decompilation differs. Different decompilers disagree on obfuscated or complex bytecode — the diff reveals which recovery is more faithful.
4. **Scan recovered source** — run Semgrep with `p/java` rules on the decompiled `.java` files. Run CodeQL if a database can be built from the recovered source.

### Why This Matters

Skipping decompilation is a silent failure — the scan completes successfully with zero findings, which looks like "clean code" when it's actually "code we never looked at." The pipeline gate at phase 3 (DECOMPILE) enforces this before phase 4 (SCAN) can proceed.

---

## Vault — Vulnerability Knowledge Base

Located at `/home/carroll/tools/vault/` on thefarm. An Obsidian vault containing:

- **13,082 technique files** — real-world vulnerability writeups from HackerOne disclosures, Project Zero, Exploit-DB, Packet Storm, LKML. Organised by category: Overflow (430), UAF (66), RCE (1019), Privesc (453), XSS (1979), SSRF (297), etc.
- **16 primitive MOCs** — methodology documents for each vulnerability class (overflow, uaf, leak, confusion, race, toctou, heap-spray, kernel, etc.) with exploitation methodology, chain reasoning, and links to technique examples.
- **4 methodologies** — Binary Analysis, Source Code Review, Web Application Testing, Recon Checklist.
- **Automated ingestion** — daily cron job fetches new techniques from RSS feeds (Project Zero, Exploit-DB, LKML, Packet Storm). Classifier sorts by vulnerability category. Refinement pipeline purges noise.

**Architecture:** No vector database, no embeddings. The LLM navigates the vault's structured markdown graph using file-reading tools, filtering on YAML frontmatter before committing to full reads. This gives better precision for domain-specific security content than general-purpose embeddings.

### How the Vault Integrates with RAPTOR

The vault is not a passive archive — it's wired into three active systems:

**1. GPU-Fuzz Mutation Enrichment.** When the gpu-fuzz plugin detects a potential vulnerability class in a target (e.g., unchecked memcpy → Overflow), it pulls real-world exploitation writeups from `techniques/Overflow/` and feeds them to the LLM mutator. The LLM generates mutations based on proven patterns, not random guessing. A format-aware seed that mimics a known CVE trigger is worth a thousand random bitflips.

**2. Brain Cross-References.** When findings are ingested into a project's brain (`ProjectBrain.ingest_findings()`, `ProjectBrain.ingest_sarif()`), each finding is automatically cross-referenced against the vault via `cross_reference_vault()`. The method maps finding terms to vault categories (e.g., "buffer overflow" → `Overflow`, "use-after-free" → `UAF`), then links the relevant primitive MOC and technique count into the brain entry. This means every finding in `02_VULNERABILITIES.md` carries a pointer to proven exploitation methodology and real-world examples of the same class.

**3. Variant Hunting.** During `/understand --hunt`, the vault provides grounding for pattern matching — "this code has the same structure as the technique described in vault/techniques/Overflow/CVE-2024-XXXXX.md." The vault turns pattern recognition from "this looks suspicious" into "this matches a known exploitation primitive with 430 documented instances."

### When the Vault Helps vs When It Doesn't

The vault is most valuable for binary targets where vulnerability classes are well-established (overflow, UAF, race, type confusion). 13K technique files with YAML frontmatter give precise retrieval for exploit development and chain reasoning.

It's less useful for application-layer web bugs (logic flaws, business logic bypasses, auth issues) where each target's logic is unique. The XSS and SSRF categories are large but the patterns are more generic — the vault's value there is methodology, not specific technique matching.

---

## Plugin: GPU-Fuzz

`plugins/gpu_fuzz/` — LLM-guided mutation for AFL++ fuzzing campaigns.

### Why This Exists

AFL++'s random mutations (havoc, bitflip, splice) find shallow bugs. They don't understand the input format — a random bitflip on a magic byte wastes every execution that follows. LLM-guided mutation reads the target's decompiled parser code, understands the format, and generates inputs that are structurally valid but target specific code paths and edge cases.

### How It Works

**Two-phase approach:**

1. **Format Recovery** — the LLM reads the binary's disassembly + extracted strings/error messages and produces a structured format specification (magic bytes, header fields, field types, validation checks, dangerous operations). This happens once before fuzzing starts.

2. **Seed Generation + Mutation Loop** — using the recovered format, the LLM generates:
   - Initial format-aware seeds (replaces AFL's default `AAAA` seeds)
   - Coverage-guided mutations at intervals during fuzzing
   - Vault-enriched mutations when a vulnerability class is detected

**The mutation loop runs alongside AFL++, not instead of it.** AFL++ continues its own havoc/bitflip mutations. The LLM injects its seeds into AFL++'s queue directory — AFL++ treats them like any other seed, runs them, measures coverage, keeps the interesting ones. Dumb fuzzing and smart fuzzing feed each other.

### Tested Results

On a test binary with 4 planted bugs (integer overflow, unchecked memcpy, null deref, palette overflow):
- Format recovery correctly identified the `RIMG` magic bytes, header layout, and dangerous operations
- 10/10 LLM-generated seeds had correct magic bytes (vs 0/10 with random seeds)
- 3 crashes found in 3 minutes (all starting with valid `RIMG` headers)
- Vault enrichment pulled Overflow and UAF patterns from the 13K technique library

### Configuration

The plugin reads `~/.config/raptor/models.json` for the Ollama model (prefers `code` role, falls back to `analysis`). Crash artifacts are auto-dumped to the NAS path configured under `fuzz_corpus_path`.

---

## Task Dispatch and Multi-Host Orchestration

RAPTOR distributes work across three machines based on what each task needs. The split is detection-based — not a preference, a classification of whether the task needs human judgment, heavy compute, or a specific OS.

### Interactive vs Headless

The fundamental distinction:

**Interactive** tasks need a human in the loop. Exploratory RE where you're following leads, exploit development where you're iterating on constraints, validation where you're making judgment calls about whether a finding is real. These stay in the current Claude Code session.

**Headless** tasks are pure compute. Overnight fuzzing, batch decompilation of 200 functions, corpus generation, crash analysis replay. No human judgment needed — structured input, structured output. These dispatch to thefarm in screen sessions and write results to the project brain when done.

### Routing Rules

`core/remote/dispatch.py` classifies tasks by command, file type, and estimated duration:

| Task | Mode | Target | Reasoning |
|------|------|--------|-----------|
| `/fuzz`, `/gpu-fuzz` | Headless | thefarm | Long-running, needs GPU for LLM mutation, 48 threads for parallel AFL++ |
| `/agentic` (large, >30min) | Headless | thefarm | Full pipeline, bulk analysis via local LLMs |
| `/reverse --mode full` | Headless | thefarm | Batch decompilation of every function is compute-heavy |
| `/reverse` (triage/trace) | Interactive | local | Exploratory — following leads, building tools |
| `/crash-analysis` | Headless | thefarm | rr/gdb replay, deterministic but long-running |
| `/scan`, `/codeql`, `/understand` | Interactive | local | Results inform immediate next steps |
| `/validate`, `/exploit` | Interactive | local | Needs judgment calls, iterative reasoning |
| `.jar`/`.war`/`.class` | Headless | thefarm | JADX/CFR decompile then scan on recovered source |
| `.exe`/`.dll`/`.sys`/`.msi` | Interactive | rengy | Needs DynamoRIO, x64dbg, Sysinternals |
| `.asar` (Electron) | Interactive | local | Extract and scan locally |

The dispatch module auto-detects platform — if you're already on thefarm, headless tasks stay local. Windows targets auto-route to rengy.

### Parallel Computing and Resource Management

Parallelism isn't optional. If CPU is below 40% during headless work, something is wrong.

**Thread allocation on thefarm:**
- **44 of 48 threads** are available for RAPTOR work
- **4 reserved** for system, Ollama serving, SSH, and monitoring
- Pinning all 48 at 100% makes the machine unresponsive — the reservation exists because it was needed

**Parallelism patterns:**
- **r2 batch decompilation:** `ProcessPoolExecutor(max_workers=20)` — 20 workers at 1 core each. Pre-analyse the binary once (`aaa`), then workers do raw disassembly at known offsets. Small batch sizes (20 functions per chunk) for fast turnaround and even distribution. The `aaa` bottleneck is avoided by not re-running it per chunk.
- **AFL++ fuzzing:** Multiple parallel instances across available threads. Each instance gets its own core. GPU runs LLM-guided mutation in parallel with CPU fuzzing.
- **Semgrep/CodeQL scanning:** Independent per-target, parallelised when scanning multiple binaries or source trees.
- **GPU + CPU concurrency:** The GPU runs Ollama inference (format recovery, mutation generation, triage) while the CPU handles decompilation, scanning, and fuzzing simultaneously. They don't compete for the same resources.

**Resource gates in the MCP orchestrator:**
- CPU < 80% before scheduling new tasks
- RAM available > 1 GB
- Active tasks < max_concurrent per command type
- GPU utilisation checked for fuzz/gpu-fuzz tasks

### MCP Task Orchestrator

For campaigns involving multiple tasks with dependencies, the MCP orchestrator (`core/mcp/`) provides persistent, compute-aware scheduling. It runs on thefarm as two processes sharing a SQLite database:

**Daemon** (`python3 -m core.mcp daemon`) — runs in a screen session, manages the 30-second scheduling loop: probe local resources → unblock tasks whose deps completed → schedule tasks to available capacity → dispatch into screen sessions → poll running tasks for completion.

**Server** (`python3 -m core.mcp server`) — spawned per Claude Code SSH connection, exposes MCP tools. Claude Code on the Mac connects via SSH transport and submits/queries tasks.

| MCP Tool | Purpose |
|----------|---------|
| `raptor_submit` | Submit a task (command, target, project, priority, depends_on) |
| `raptor_status` | Query tasks by id/project/campaign/state/host |
| `raptor_cancel` | Kill screen session, update state |
| `raptor_logs` | Tail screen session logs for a running task |
| `raptor_capacity` | Show host CPU/RAM/GPU/active tasks |
| `raptor_scheduler_status` | Scheduler running/paused, task counts by state |

**Task lifecycle:** submitted → blocked (if deps) → scheduled → dispatched → running → completed/failed/cancelled. Failed tasks auto-retry up to 2 times.

**Command resource profiles** define weight, RAM, GPU needs, estimated duration, and max concurrency per command type. A `gpu-fuzz` task (heavy, GPU-required, 120min estimated, max 1 concurrent) won't compete with a `scan` task (light, no GPU, 10min, max 4 concurrent) for the same resources.

### Remote Execution

`core/remote/` — SSH execution, screen sessions, file transfer.

**Host Registry:** `~/.config/raptor/hosts.json` defines available machines with OS, capabilities, and access details. No credentials in the file — authentication uses SSH keys.

**Screen Sessions:** Headless tasks on Linux/Mac run in named screen sessions (`raptor-<task>`). Output logs to `/tmp/raptor-<session>.log`. Screen provides persistence across SSH disconnects, reattachment for monitoring, and log capture for post-analysis.

**Windows:** No screen support. Commands are wrapped in `powershell -EncodedCommand <base64>` (UTF-16LE) to avoid SSH escaping issues. Background work uses PowerShell `Start-Job`.

### When to Use Which Mode

The decision tree is simple:

1. **Am I going to stare at the output and make decisions?** → Interactive, local (or rengy for Windows targets).
2. **Can this run for hours without me?** → Headless, thefarm, screen session.
3. **Does this need the GPU for LLM inference?** → thefarm (the only machine with 96 GB VRAM).
4. **Is the target a Windows binary?** → rengy (the only machine with the Windows RE toolkit).
5. **Do I have multiple independent tasks?** → MCP orchestrator with dependency graph.

---

## Phase Tracking

`core/remote/phase.py` — feedback loop for long-running campaigns.

### The Problem

You kick off a headless campaign. It runs for hours. When do you come back? What completed? What was found? What's the next step?

### The Solution

The `.phase` file in each run directory records:
- Current phase and status (`triage` → `decompile` → `analysis`)
- Progress within the phase (last action, timestamps)
- Findings so far (binary counts, function counts, crash counts)
- Next action (what to do when this phase completes)
- Full history of phase transitions

Check from anywhere:
```bash
libexec/raptor-campaign-status          # checks local + thefarm
ssh thefarm 'cat ~/raptor/out/projects/unifi-os/reverse-*/.phase'
```

### Integration with Project Brain and Orchestrator

When a campaign phase completes, results are ingested into the project's `brain/` directory — structured markdown documents that accumulate across sessions. A new Claude session reads `brain/INDEX.md` to understand the state of analysis without asking "where were we."

For MCP-orchestrated campaigns, the orchestrator tracks phase as a field on each task. Tasks can declare dependencies (`depends_on`) so phase 4 (scan) blocks until phase 3 (decompile) completes. The scheduler handles the ordering — submit all phases upfront and let the dependency graph enforce sequencing while allowing independent tasks within the same phase to run in parallel.

---

## Project Brain

`core/project/brain.py` — structured markdown knowledge base per project.

### Structure

```
brain/
├── INDEX.md                 # Auto-generated summary — load this at session start
├── 00_OVERVIEW.md           # Target characterisation, components, build info
├── 01_ATTACK_SURFACE.md     # Entry points, trust boundaries, sinks
├── 02_VULNERABILITIES.md    # Confirmed and suspected findings with evidence
├── 03_HYPOTHESES.md         # Tested and untested hypotheses with status
├── 04_EXPLOITS.md           # Working PoCs, failed attempts, blocking constraints
├── 05_RULES_AND_MODELS.md   # Extracted detection rules, ML models, signatures
├── 06_TRADECRAFT.md         # Evasion techniques, detection gaps, bypass methods
├── 07_TOOLS.md              # Per-target tools built during analysis
└── 08_OBSERVATIONS.md       # Interesting behaviours, anomalies, open questions
```

### Why Numbered Documents

The numbering follows Justin Elze's EDR reverse engineering methodology — a systematic, complete approach where every product gets the same treatment. The numbers enforce reading order and prevent skipping sections. Documents grow as analysis progresses across sessions.

### Auto-Ingestion

When a run completes (via the run lifecycle `complete_run()`), findings, context maps, and triage data are automatically appended to the relevant brain document. INDEX.md is rebuilt with key findings, open hypotheses, and exploit status. This means headless campaigns on thefarm automatically populate the brain — the next interactive session picks up where the campaign left off.

Three ingestion methods feed different document types:
- `ingest_findings()` / `ingest_sarif()` → `02_VULNERABILITIES.md` — SARIF from Semgrep/CodeQL and structured findings from validation runs. Each finding gets vault cross-references appended automatically.
- `ingest_context_map()` → `01_ATTACK_SURFACE.md` — entry points, sinks, and trust boundaries from `/understand --map`.
- `ingest_triage()` → `00_OVERVIEW.md` — binary metadata (arch, bits, OS, compiler) from `/reverse` triage.

### When the Brain Is Useful and When It Isn't

**The brain solves session continuity.** Claude Code sessions are ephemeral — context window clears, conversation compresses, previous analysis vanishes. The brain persists structured knowledge in plain markdown that any future session (or any human) can read cold. After a headless campaign on thefarm decompiles 200 functions and runs Semgrep across recovered source, the brain contains the findings, attack surface map, and open hypotheses. The next interactive session reads `brain/INDEX.md` and knows exactly where to pick up.

**The brain is most valuable for multi-session campaigns** — firmware teardowns, large binary RE projects, anything that takes more than one sitting. A single `/scan` run against a small repo doesn't need the brain. A 3-day UniFi OS campaign with extract → triage → decompile → scan → validate → exploit across multiple binaries needs every document populated.

**The brain is less valuable for one-shot analysis** — a quick `/scan` of a web app, a single binary triage, a targeted `/validate` on one finding. The overhead of creating a project, populating brain documents, and rebuilding the index isn't worth it for work that fits in a single session. Just use the timestamped output directory in `out/`.

**The brain + vault together** are the knowledge loop: the vault provides proven techniques and methodology (what has worked before), and the brain accumulates what's been learned about this specific target (what's true here). Vault cross-references in brain entries connect the two — a finding in `02_VULNERABILITIES.md` links to the exploitation primitive in `vault/primitives/` and the real-world examples in `vault/techniques/`.

---

## Binary RE Methodology

`.claude/skills/binary-re/SKILL.md` — the gate-enforced RE workflow.

### Anti-Shortcuts

These are explicitly banned:
1. Don't stop at strings
2. Don't stop at imports
3. Don't stop at triage
4. Don't summarise without reading the decompiled code
5. Don't fabricate decompilation output
6. Don't report a vuln without the instruction sequence
7. Don't skip binaries
8. Don't claim crypto is broken without showing the constants

### Gates

8 gates enforce depth:
- **GATE 0:** Every binary triaged (arch, mitigations, imports, strings, entropy)
- **GATE 1:** Every function decompiled (pseudocode, not just names)
- **GATE 2:** Every string/import cross-referenced to the code that uses it
- **GATE 3:** Every input handler traced from entry to sink
- **GATE 4:** Static findings confirmed with Frida instrumentation
- **GATE 5:** All claims cite specific addresses with disassembly evidence
- **GATE 6:** Encrypted assets decrypted before rule/model extraction
- **GATE 7:** Per-target tools tested against known inputs

### PoC Standards

Every vulnerability is a concern until it has a fully functional PoC. RCE and EoP PoCs must demonstrate:
1. Command execution (not just a crash)
2. Local user creation if running as admin/root
3. Netcat reverse or bind shell

### Patch Analysis

Known CVEs are intelligence, not targets. A patch tells you what the vendor thinks the problem is. The question is whether they're right:
- **Patch completeness** — does the fix cover the root cause or just the trigger?
- **Patch bypass** — can the fix be circumvented?
- **Variant hunting** — the CVE reveals a class; use `/understand --hunt` to find siblings
- **Regression** — did the fix introduce new bugs?

---

## Working Style

**No status reports** until there are working PoCs or concrete evidence-backed results. Status updates without results are noise.

**No "final" anything.** Never claim something is a "final check." Demonstrate that all recourse is exhausted — show what was tried, what failed, why nothing else is available.

**No fabrication.** If r2 can't decompile a function, show the disassembly. If an exploit doesn't work, say what's blocking it. Never invent pseudocode or simulate results.

**Quality over speed.** Let headless jobs run as long as they need. Don't push incomplete summaries. When results come back, analyse them properly before presenting anything.

---

## Electron App RE

Full toolkit across all three machines for Electron app teardown:

| Step | Tool | Where |
|------|------|-------|
| Extract ASAR | `asar extract` | Any (Node.js on all three) |
| Deobfuscate JS | `prettier` | Any |
| Source maps | `source-map-explorer` | Any |
| Scan JS source | RAPTOR `/scan` (Semgrep) | Local or thefarm |
| Native .node modules | r2 | thefarm or local |
| Runtime hooking | Frida | Any |
| Windows Electron apps | DynamoRIO + x64dbg | rengy |

---

## Security — Credentials and Secrets

**No credentials in code, config files, or git.** Ever.

- SSH authentication: key-based (`ssh-copy-id`)
- SMB credentials: `/root/.smb-fuzzydump` on thefarm (mode 600)
- API keys: `~/.config/raptor/models.json` (mode 600, auto-tightened by startup)
- Ollama host: environment variable, not hardcoded
- Remote Ollama server location: never disclosed in code, comments, or logs

---

## Tool Inventory

12 tools in `TOOL_DEPS` with startup dependency checking:

| Tool | Severity | Affects | Installed |
|------|----------|---------|-----------|
| afl++ | required | /fuzz | thefarm, local |
| bpftrace | degrades | /reverse, /fuzz | thefarm only (Linux) |
| binwalk | degrades | /reverse | thefarm, local |
| codeql | scanner group | /codeql, /agentic | thefarm, local |
| frida | degrades | /reverse | all three |
| gdb | required | /crash-analysis, /fuzz | thefarm, local |
| ilspycmd | degrades | /reverse (.NET) | rengy only |
| jadx | required | Java targets | thefarm (`~/tools/jadx/bin/jadx`) |
| cfr | required | Java targets | thefarm (`~/tools/cfr.jar`) |
| r2 | required | /reverse | thefarm, local |
| rr | degrades | /crash-analysis | thefarm only |
| semgrep | scanner group | /scan, /agentic | thefarm, local |
| strace | degrades | /reverse | thefarm only (Linux) |
| yara | degrades | /reverse, /scan | all three |

The startup banner shows tool availability on session start. Missing tools with `degrades` severity limit functionality but don't block the command. Missing `required` tools prevent the command from running.

---

## What This Setup Enables

The end-to-end flow for a target like UniFi OS Server:

1. **Download and extract** — pull firmware, extract embedded archives (ZIP, tar, container layers)
2. **Inventory** — separate vendor-authored binaries from OSS dependencies
3. **Create project** — `/project create unifi-os --target /path` sets up output directory and brain
4. **Dispatch** — task classifier routes binary RE to thefarm (headless, screen session)
5. **Campaign** — batch triage + decompile all binaries, prioritised by attack surface
6. **Phase tracking** — `.phase` file records progress, findings, next actions
7. **Brain ingestion** — results flow into numbered analysis documents automatically
8. **Interactive follow-up** — read brain INDEX.md, chase leads, build tools, develop exploits
9. **Validation** — `/validate` proves findings are real, reachable, exploitable
10. **PoC development** — working exploit with command execution, user creation, netcat
11. **Patch analysis** — verify vendor fixes, hunt variants the patch missed
12. **NAS archival** — crashes, corpora, and results dumped to FuzzyDump for long-term storage

Every step is evidence-based. Every finding cites an address. Every hypothesis is proven or disproven. The brain accumulates knowledge across sessions so no work is lost and no question needs to be asked twice.
