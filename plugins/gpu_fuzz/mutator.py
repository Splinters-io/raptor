"""LLM-guided mutator — generates semantically intelligent fuzzing inputs.

Two-phase approach that mirrors how a reverse engineer works:
1. FORMAT RECOVERY: Read the disassembly, extract the input format spec
   (magic bytes, header layout, field types, validation checks)
2. SEED GENERATION: Use the recovered format to generate structurally
   valid inputs that target specific code paths and edge cases

The LLM also receives:
- Coverage stats (where fuzzing has stalled)
- Queue samples (what inputs found new coverage)
- Vault techniques (real-world exploitation patterns for the vuln class)
"""

import base64
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()

FORMAT_RECOVERY_PROMPT = """You are a binary reverse engineer analyzing a parser's input format.

## Disassembly

{disasm}

## Task

Study the disassembly and extract the input format specification. Look for:
- Magic bytes: `cmp` instructions against constant values early in the function
- Header fields: sequential memory reads at fixed offsets (e.g., `movzx` at rsp+4, rsp+6)
- Field sizes: byte/word/dword reads tell you the field width
- Validation checks: comparisons against zero, range checks, flag bit tests
- Data length: how the parser calculates expected payload size from header fields
- Branch conditions: what values cause different code paths

Output a JSON object with this structure:
{{
  "magic": "hex string of magic bytes or null",
  "magic_offset": 0,
  "header_size": N,
  "fields": [
    {{"name": "descriptive_name", "offset": N, "size": N, "type": "uint16_le|uint8|...", "notes": "validation or usage"}}
  ],
  "payload_offset": N,
  "payload_size_calc": "how payload size is computed from header fields",
  "branch_conditions": [
    {{"field": "name", "condition": "description", "effect": "what code path this triggers"}}
  ],
  "dangerous_operations": ["memcpy at 0xNNNN with unchecked size", ...]
}}

Output ONLY the JSON object. No markdown. No explanation."""

SEED_GENERATION_PROMPT = """You are a fuzzing seed generator. Generate {num_seeds} test inputs
based on this recovered input format specification.

## Input Format

{format_spec}

## Instructions

Generate inputs as raw hex bytes. Each input MUST conform to the header
structure (correct magic bytes, valid field offsets) but should target
edge cases in the payload and field values.

Generate these categories:
1. MINIMAL: Smallest valid input (header only, minimum field values)
2. TYPICAL: Normal-sized valid input with all fields populated
3. MAX_VALUES: All numeric fields set to maximum (0xFF, 0xFFFF, etc.)
4. ZERO_VALUES: All numeric fields set to zero (tests division-by-zero, null checks)
5. OVERFLOW_TRIGGER: Fields calculated to cause integer overflow in size computations
6. FLAG_PATHS: Each distinct flag/branch condition exercised
7. TRUNCATED: Valid header but truncated payload (tests length validation)
8. OVERSIZED: Valid header but payload larger than declared size
9. BOUNDARY: Off-by-one values for each size field (size-1, size, size+1)
10. DANGEROUS_OP: Inputs designed to reach each dangerous operation listed in the format

For each input, output a JSON object:
{{"rationale": "what this tests", "data_hex": "complete input as hex"}}

Output ONLY a JSON array. No markdown fences. No explanation."""

MUTATION_PROMPT = """You are a fuzzing mutation engine targeting specific uncovered code paths.

## Input Format

{format_spec}

## Current Coverage State

{coverage_summary}

## Inputs That Found New Coverage (study these — they work)

{sample_inputs}

## Coverage Gaps

{coverage_gaps}

## Instructions

Generate {num_mutations} new inputs. Each MUST have correct magic bytes and header
structure. Target branches and conditions not yet exercised.

Strategy:
- Mutate fields that appear in branch conditions
- Combine flag values that haven't been seen together
- Vary payload content while keeping header valid
- Target the dangerous operations with crafted sizes

For each input:
{{"rationale": "which specific branch/condition this targets", "data_hex": "complete input as hex"}}

Output ONLY a JSON array."""


class LLMMutator:
    """Generates fuzzing mutations using a local LLM via Ollama."""

    def __init__(
        self,
        ollama_host: str = None,
        model: str = None,
        vault_path: str = None,
    ):
        self._host = ollama_host or os.getenv(
            "OLLAMA_HOST", "http://localhost:11434"
        )
        self._model = model or self._resolve_model()
        self._vault_path = vault_path
        self._format_spec: Optional[Dict] = None

    def recover_format(self, parser_code: Dict[str, str],
                       binary_path: Path = None) -> Optional[Dict]:
        """Phase 1: Extract input format specification.

        Two-step approach:
        1. Extract format hints (strings, magic candidates, error messages,
           imports) directly from the binary — fast, reliable, no LLM needed
        2. Give the LLM the hints + focused disassembly and ask it to
           synthesize the format spec

        The hints tell the LLM "the binary contains the string RIMG and
        the error message 'bad magic'" — far more reliable than expecting
        the LLM to find a `cmp` against 0x474d4952 buried in ASAN-padded
        disassembly.
        """
        # Step 1: Extract format hints from the binary
        hints_section = ""
        if binary_path:
            from .decompile import extract_format_hints
            hints = extract_format_hints(binary_path)
            if hints:
                parts = []
                if hints.get("magic_candidates"):
                    parts.append("Magic byte candidates (short strings in .rodata):")
                    for mc in hints["magic_candidates"]:
                        parts.append(f"  \"{mc['string']}\" = 0x{mc['hex']}")

                if hints.get("error_messages"):
                    parts.append("\nError messages (these reveal validation logic):")
                    for em in hints["error_messages"]:
                        parts.append(f"  \"{em}\"")

                if hints.get("field_names"):
                    parts.append(f"\nField/variable names from debug symbols (these are actual struct field names):")
                    parts.append(f"  {', '.join(hints['field_names'])}")

                if hints.get("imports"):
                    dangerous = [i for i in hints["imports"]
                                 if any(k in i for k in ["memcpy", "malloc", "free",
                                        "strcpy", "sprintf", "fread", "read",
                                        "memcmp", "strcmp"])]
                    if dangerous:
                        parts.append(f"\nDangerous imports: {', '.join(dangerous)}")

                hints_section = "\n".join(parts)

        # Step 2: Build focused disassembly
        disasm = self._prepare_disasm_for_format_recovery(parser_code)

        # Step 3: Ask LLM to synthesize the format spec
        prompt_parts = [FORMAT_RECOVERY_PROMPT.format(disasm=disasm)]
        if hints_section:
            prompt_parts.insert(1, f"\n## Binary Hints (extracted directly — these are ground truth)\n\n{hints_section}\n")

        prompt = "\n".join(prompt_parts)
        response = self._call_ollama(prompt)
        if not response:
            return None

        spec = self._parse_json_object(response)
        if spec and (spec.get("fields") or spec.get("magic")):
            self._format_spec = spec
            logger.info(
                f"Format recovered: magic={spec.get('magic', '?')}, "
                f"{len(spec.get('fields', []))} fields, "
                f"header_size={spec.get('header_size', '?')}"
            )
            return spec

        logger.warning("Format recovery failed — LLM could not extract format spec")
        return None

    def generate_format_seeds(
        self,
        parser_code: Dict[str, str],
        binary_info: Optional[Dict] = None,
        num_seeds: int = 10,
    ) -> List[Dict]:
        """Phase 2: Generate format-aware seeds using the recovered spec.

        If format hasn't been recovered yet, runs recovery first.
        """
        if not self._format_spec:
            self.recover_format(parser_code)

        if not self._format_spec:
            logger.warning("No format spec available — generating exploratory seeds")
            return self._generate_exploratory_seeds()

        prompt = SEED_GENERATION_PROMPT.format(
            format_spec=json.dumps(self._format_spec, indent=2),
            num_seeds=num_seeds,
        )

        response = self._call_ollama(prompt)
        if not response:
            return []

        return self._parse_mutations(response)

    def generate_mutations(
        self,
        parser_code: Dict[str, str],
        coverage: Dict,
        queue_samples: List[Tuple[str, bytes]],
        coverage_gaps: List[str],
        num_mutations: int = 20,
    ) -> List[Dict]:
        """Generate coverage-guided mutations using format knowledge."""
        if not self._format_spec:
            self.recover_format(parser_code)

        format_text = json.dumps(self._format_spec, indent=2) if self._format_spec else "(format unknown)"

        cvg_text = "\n".join(f"- {k}: {v}" for k, v in coverage.items())

        sample_text = self._format_queue_samples(queue_samples)

        gaps_text = "\n".join(f"- {g}" for g in coverage_gaps) if coverage_gaps else "(no specific gaps identified)"

        prompt = MUTATION_PROMPT.format(
            format_spec=format_text,
            coverage_summary=cvg_text,
            sample_inputs=sample_text,
            coverage_gaps=gaps_text,
            num_mutations=num_mutations,
        )

        response = self._call_ollama(prompt)
        if not response:
            return []

        return self._parse_mutations(response)

    def enrich_from_vault(
        self,
        vuln_class: str,
        parser_code: Dict[str, str],
    ) -> List[Dict]:
        """Pull real-world exploitation patterns from the vault for targeted mutation."""
        if not self._vault_path:
            return []

        vault = Path(self._vault_path)
        techniques_dir = vault / "techniques" / vuln_class
        if not techniques_dir.exists():
            return []

        technique_context = []
        for md_file in sorted(techniques_dir.glob("*.md"))[:3]:
            text = md_file.read_text()
            for section in ["Key Insight", "Technique Details"]:
                start = text.find(f"## {section}")
                if start != -1:
                    end = text.find("\n## ", start + 1)
                    snippet = text[start:end] if end != -1 else text[start:start + 500]
                    technique_context.append(snippet)

        if not technique_context:
            return []

        format_text = json.dumps(self._format_spec, indent=2) if self._format_spec else "(format unknown)"

        prompt = f"""Generate targeted fuzzing inputs based on real-world {vuln_class} patterns.

## Target Input Format

{format_text}

## Real-World {vuln_class} Patterns

{"---".join(technique_context)}

## Instructions

Apply these proven exploitation patterns to generate 10 inputs that
trigger {vuln_class} in the target parser. Each input MUST have the
correct header structure from the format spec above.

For each: {{"rationale": "which pattern and how", "data_hex": "hex bytes"}}
Output ONLY a JSON array."""

        response = self._call_ollama(prompt)
        if not response:
            return []

        return self._parse_mutations(response)

    # --- Internal helpers ---

    def _prepare_disasm_for_format_recovery(self, parser_code: Dict[str, str]) -> str:
        """Prepare focused disassembly for format recovery.

        Prioritize the main function and large processing functions.
        Trim to the first ~100 lines of each (the header parsing is
        always at the top). Cap total at 6K chars.
        """
        parts = []

        # Sort: main first, then by size (largest = most logic)
        ordered = sorted(
            parser_code.items(),
            key=lambda kv: (0 if "main" in kv[0].lower() else 1, -len(kv[1]))
        )

        for name, code in ordered:
            lines = code.splitlines()
            if len(lines) <= 4:
                continue
            # Take first 100 lines — header parsing is at the top
            snippet = "\n".join(lines[:100])
            parts.append(f"// Function: {name}\n{snippet}")

        result = "\n\n".join(parts)
        if len(result) > 6000:
            result = result[:6000] + "\n// ... (truncated)"
        return result

    def _generate_exploratory_seeds(self) -> List[Dict]:
        """Fallback seeds when format recovery fails.

        Generates a diverse set of inputs to help AFL discover the
        format through coverage feedback.
        """
        seeds = []
        patterns = [
            (b"\x00" * 32, "all nulls"),
            (b"\xff" * 32, "all 0xFF"),
            (b"\x41" * 32, "all ASCII A"),
            (bytes(range(256))[:32], "sequential bytes 0x00-0x1F"),
            (b"\x89PNG\r\n\x1a\n" + b"\x00" * 24, "PNG-like header"),
            (b"\xff\xd8\xff\xe0" + b"\x00" * 28, "JPEG-like header"),
            (b"PK\x03\x04" + b"\x00" * 28, "ZIP-like header"),
            (b"\x7fELF" + b"\x00" * 28, "ELF-like header"),
            (b"\x01\x00\x01\x00\x01\x00\x01\x00" * 4, "repeating pattern"),
            (b"\x00\x01\x00\x02\x00\x04\x00\x08" * 4, "power-of-two pattern"),
        ]
        for data, rationale in patterns:
            seeds.append({
                "rationale": rationale,
                "data": data,
                "source": "exploratory",
            })
        return seeds

    def _format_queue_samples(self, samples: List[Tuple[str, bytes]]) -> str:
        if not samples:
            return "(no queue samples yet)"

        lines = []
        for name, data in samples[:8]:
            hex_str = data[:48].hex()
            lines.append(f"- {hex_str}  ({len(data)} bytes, {name})")
        return "\n".join(lines)

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """Call the local Ollama model."""
        import requests

        try:
            resp = requests.post(
                f"{self._host}/api/generate",
                json={
                    "model": self._model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.7,
                        "num_predict": 4096,
                    },
                },
                timeout=300,
            )
            resp.raise_for_status()
            return resp.json().get("response", "")
        except Exception as e:
            logger.warning(f"Ollama call failed: {e}")
            return None

    def _parse_json_object(self, response: str) -> Optional[Dict]:
        """Parse a JSON object from LLM response."""
        start = response.find("{")
        end = response.rfind("}")
        if start == -1 or end == -1:
            return None
        try:
            return json.loads(response[start:end + 1])
        except json.JSONDecodeError:
            return None

    def _parse_mutations(self, response: str) -> List[Dict]:
        """Parse LLM response into mutation dicts with raw bytes."""
        start = response.find("[")
        end = response.rfind("]")
        if start == -1 or end == -1:
            logger.warning("No JSON array found in LLM response")
            return []

        try:
            items = json.loads(response[start:end + 1])
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM mutations: {e}")
            return []

        mutations = []
        for item in items:
            if not isinstance(item, dict):
                continue

            data = None
            if "data_hex" in item and item["data_hex"]:
                try:
                    data = bytes.fromhex(
                        item["data_hex"].replace(" ", "").replace("\n", "")
                    )
                except ValueError:
                    pass
            if data is None and "data_b64" in item:
                try:
                    data = base64.b64decode(item["data_b64"])
                except Exception:
                    pass

            if data and len(data) > 0:
                mutations.append({
                    "rationale": item.get("rationale", ""),
                    "data": data,
                    "source": "llm-mutator",
                })

        logger.info(f"LLM generated {len(mutations)} valid mutations")
        return mutations

    def _resolve_model(self) -> str:
        """Pick the best available model for mutation."""
        config_path = Path.home() / ".config" / "raptor" / "models.json"
        if config_path.exists():
            try:
                data = json.loads(config_path.read_text())
                models = data.get("models", data) if isinstance(data, dict) else data
                for m in models:
                    if m.get("provider") == "ollama" and m.get("role") == "code":
                        return m["model"]
                for m in models:
                    if m.get("provider") == "ollama" and m.get("role") == "analysis":
                        return m["model"]
            except (json.JSONDecodeError, KeyError):
                pass

        return "gemma4:e4b"
