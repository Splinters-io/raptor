---
description: LLM-guided fuzzing with GPU-accelerated mutation
---

# /gpu-fuzz - LLM-Guided Fuzzing

Uses local LLMs (via Ollama on the GPU) to generate semantically intelligent mutations for AFL++ fuzzing campaigns. Random bitflips find shallow bugs. LLM-guided mutations find deep ones.

## Usage

```
/gpu-fuzz <binary> [--duration <secs>] [--corpus <dir>] [--input-mode stdin|file] [--jobs <n>] [--interval <secs>]
```

## How It Works

1. **Decompile** the target's input-handling functions using r2
2. **Generate format-aware seeds** — LLM reads the parser code, produces structurally valid inputs (not `AAAA`)
3. **Start AFL++** with the intelligent seed corpus
4. **Mutation loop** — every N seconds:
   - Read AFL++ coverage stats and queue samples
   - Identify stalled regions and coverage gaps
   - LLM generates targeted mutations based on parser code + coverage feedback
   - Inject mutations into AFL++ queue
5. **Vault enrichment** — when a potential vuln class is detected (e.g., unchecked memcpy), pull real-world exploitation patterns from the vault and generate class-specific mutations
6. **Dump to NAS** — crashes and interesting corpus items go to FuzzyDump

## Execution

```python
from plugins.gpu_fuzz.harness import GuidedFuzzHarness

harness = GuidedFuzzHarness(
    binary="/path/to/target",
    output_dir="/path/to/output",
    input_mode="stdin",
)
results = harness.run(duration=3600, mutation_interval=300)
```

Or via RAPTOR run lifecycle:
```bash
OUTPUT_DIR=$(libexec/raptor-run-lifecycle start gpu-fuzz --target "$BINARY" | tail -1 | cut -d= -f2)
```

Then instantiate `GuidedFuzzHarness` with the target binary and output directory. Run the campaign. On completion:
```bash
libexec/raptor-run-lifecycle complete "$OUTPUT_DIR"
```

## Requirements

- **AFL++** — `afl-fuzz` on PATH
- **r2** — for target decompilation
- **Ollama** — running locally with a model loaded (prefers abliterated Qwen 3.6 35B)
- **GPU** — not strictly required but the local LLM runs on GPU for speed

## Model Selection

Reads `~/.config/raptor/models.json` for the Ollama model. Falls back to `huihui_ai/Qwen3.6-abliterated:35b`. The abliterated model is important — stock models may refuse to generate exploit-oriented test inputs.

## NAS Integration

Crashes and interesting queue items are automatically dumped to the path configured in `models.json` under `fuzz_corpus_path` (default: `/mnt/fuzzydump`).

## Examples

```
/gpu-fuzz /path/to/parser                          # 1 hour, default settings
/gpu-fuzz /path/to/parser --duration 28800          # 8 hour overnight run
/gpu-fuzz /path/to/parser --interval 120 --jobs 4   # Aggressive: mutate every 2min, 4 AFL workers
```
