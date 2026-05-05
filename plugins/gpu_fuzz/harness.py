"""LLM-guided fuzzing harness — orchestrates the mutation loop.

The loop:
1. Decompile input handlers from the target binary
2. Generate format-aware seed corpus using the LLM
3. Start AFL++ fuzzing
4. At intervals, check coverage and generate targeted mutations
5. Inject LLM mutations into AFL++ queue
6. Repeat until time limit or coverage plateau
7. Collect crashes → FuzzyDump NAS

Large corpora are dumped to the NAS mount automatically.
"""

import json
import shutil
import time
from pathlib import Path
from typing import Dict, Optional

from core.config import RaptorConfig
from core.logging import get_logger

from .coverage import (
    get_coverage_summary,
    find_stale_regions,
    load_queue_samples,
)
from .decompile import decompile_input_handlers, get_binary_info
from .mutator import LLMMutator

logger = get_logger()

DEFAULT_MUTATION_INTERVAL = 300  # Generate new mutations every 5 minutes
DEFAULT_NUM_MUTATIONS = 20
MAX_MUTATION_ROUNDS = 50


class GuidedFuzzHarness:
    """Orchestrates LLM-guided AFL++ fuzzing."""

    def __init__(
        self,
        binary: Path,
        output_dir: Path,
        corpus_dir: Optional[Path] = None,
        input_mode: str = "stdin",
        ollama_host: str = None,
        model: str = None,
        vault_path: str = None,
        nas_dump_path: str = None,
    ):
        self.binary = Path(binary).resolve()
        self.output_dir = Path(output_dir)
        self.corpus_dir = Path(corpus_dir) if corpus_dir else self.output_dir / "corpus"
        self.input_mode = input_mode
        self.nas_dump_path = self._resolve_nas_path(nas_dump_path)

        self._mutator = LLMMutator(
            ollama_host=ollama_host,
            model=model,
            vault_path=vault_path or self._resolve_vault_path(),
        )
        self._parser_code: Dict[str, str] = {}
        self._binary_info: Optional[Dict] = None
        self._mutation_round = 0

    def run(
        self,
        duration: int = 3600,
        parallel_jobs: int = 1,
        mutation_interval: int = DEFAULT_MUTATION_INTERVAL,
        num_mutations: int = DEFAULT_NUM_MUTATIONS,
        skip_llm_seeds: bool = False,
    ) -> Dict:
        """Run the full LLM-guided fuzzing campaign.

        Args:
            duration: Total fuzzing duration in seconds.
            parallel_jobs: Number of AFL++ instances.
            mutation_interval: Seconds between LLM mutation rounds.
            num_mutations: Mutations per round.
            skip_llm_seeds: Skip initial LLM seed generation.

        Returns:
            Campaign results dict.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        # Phase 1: Understand the target
        logger.info(f"[gpu-fuzz] Analyzing target: {self.binary}")
        self._binary_info = get_binary_info(self.binary)
        self._parser_code = decompile_input_handlers(self.binary, self.input_mode)

        if self._parser_code:
            logger.info(f"[gpu-fuzz] Decompiled {len(self._parser_code)} input-handling functions")
            decomp_file = self.output_dir / "parser_decompilation.json"
            _safe_write_json(decomp_file, self._parser_code)
        else:
            logger.info("[gpu-fuzz] No parser decompilation — LLM will use exploratory mutations")

        # Phase 1b: Recover input format specification from disassembly
        # This is the critical step — understanding the format BEFORE
        # generating seeds. Takes time but produces accurate results.
        if self._parser_code:
            logger.info("[gpu-fuzz] Recovering input format from disassembly (this takes a moment)...")
            format_spec = self._mutator.recover_format(self._parser_code, self.binary)
            if format_spec:
                _safe_write_json(self.output_dir / "format_spec.json", format_spec)
                logger.info(
                    f"[gpu-fuzz] Format recovered: magic={format_spec.get('magic', 'none')}, "
                    f"{len(format_spec.get('fields', []))} fields, "
                    f"{len(format_spec.get('dangerous_operations', []))} dangerous ops"
                )

        # Phase 2: Generate format-aware seeds using the recovered spec
        if not skip_llm_seeds:
            logger.info("[gpu-fuzz] Generating format-aware seed corpus")
            seeds = self._mutator.generate_format_seeds(
                self._parser_code, self._binary_info
            )
            self._inject_mutations(seeds, "llm-seeds")
            logger.info(f"[gpu-fuzz] Generated {len(seeds)} format-aware seeds")

        # Ensure corpus is never empty — AFL refuses to start without seeds
        if not any(self.corpus_dir.iterdir()):
            logger.info("[gpu-fuzz] No seeds generated — creating minimal fallback seeds")
            fallback_seeds = [
                b"A" * 16,
                b"\x00" * 16,
                b"\xff" * 16,
                b"test input data\n",
            ]
            for i, seed in enumerate(fallback_seeds):
                (self.corpus_dir / f"fallback_{i}").write_bytes(seed)

        # Phase 3: Start AFL++
        from packages.fuzzing import AFLRunner

        runner = AFLRunner(
            binary_path=self.binary,
            corpus_dir=self.corpus_dir,
            output_dir=self.output_dir / "afl",
            input_mode=self.input_mode,
        )

        afl_output = self.output_dir / "afl"

        # Start AFL in the background — we'll manage the mutation loop
        import subprocess
        import os

        is_instrumented = runner.check_binary_instrumentation()
        cmd = runner._build_afl_command(
            instance_name="main",
            is_main=True,
            timeout_ms=1000,
            use_qemu=not is_instrumented,
        )

        afl_env = os.environ.copy()
        afl_env["AFL_SKIP_CPUFREQ"] = "1"
        afl_env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        # Tell AFL to import new testcases from the mutations directory
        mutations_dir = self.output_dir / "llm-mutations"
        mutations_dir.mkdir(exist_ok=True)

        logger.info(f"[gpu-fuzz] Starting AFL++ ({duration}s, {parallel_jobs} jobs)")
        afl_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=afl_env,
        )

        # Phase 4: Mutation loop
        start_time = time.time()
        last_mutation_time = start_time
        results = {
            "binary": str(self.binary),
            "duration": duration,
            "mutation_rounds": 0,
            "total_llm_mutations": 0,
            "crashes": 0,
        }

        try:
            while time.time() - start_time < duration:
                time.sleep(10)

                # Check if AFL is still running
                if afl_proc.poll() is not None:
                    logger.warning("[gpu-fuzz] AFL exited early")
                    stderr = afl_proc.stderr.read() if afl_proc.stderr else ""
                    if stderr:
                        logger.warning(f"[gpu-fuzz] AFL stderr: {stderr[:500]}")
                    break

                elapsed = time.time() - start_time
                since_mutation = time.time() - last_mutation_time

                # Time for a new mutation round?
                if since_mutation >= mutation_interval and self._mutation_round < MAX_MUTATION_ROUNDS:
                    self._mutation_round += 1
                    coverage = get_coverage_summary(afl_output)
                    gaps = find_stale_regions(afl_output)
                    samples = load_queue_samples(afl_output)

                    logger.info(
                        f"[gpu-fuzz] Mutation round {self._mutation_round} — "
                        f"coverage: {coverage.get('bitmap_cvg', '?')}, "
                        f"paths: {coverage.get('paths_total', '?')}, "
                        f"crashes: {coverage.get('crashes', 0)}"
                    )

                    mutations = self._mutator.generate_mutations(
                        self._parser_code, coverage, samples, gaps, num_mutations
                    )

                    if mutations:
                        self._inject_mutations(mutations, f"round-{self._mutation_round}")
                        results["total_llm_mutations"] += len(mutations)

                    # If coverage is stalled and we have vault access,
                    # try vuln-class-specific mutations
                    if gaps and self._parser_code:
                        for vuln_class in self._detect_vuln_classes():
                            vault_mutations = self._mutator.enrich_from_vault(
                                vuln_class, self._parser_code
                            )
                            if vault_mutations:
                                self._inject_mutations(
                                    vault_mutations,
                                    f"vault-{vuln_class}-r{self._mutation_round}"
                                )
                                results["total_llm_mutations"] += len(vault_mutations)

                    last_mutation_time = time.time()

        finally:
            # Stop AFL
            afl_proc.terminate()
            try:
                afl_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                afl_proc.kill()

        # Collect results
        final_coverage = get_coverage_summary(afl_output)
        results["mutation_rounds"] = self._mutation_round
        results["crashes"] = final_coverage.get("crashes", 0)
        results["final_coverage"] = final_coverage

        # Dump to NAS if configured
        if self.nas_dump_path:
            self._dump_to_nas(results)

        # Save results
        _safe_write_json(self.output_dir / "gpu-fuzz-results.json", results)

        logger.info(
            f"[gpu-fuzz] Campaign complete — "
            f"{results['crashes']} crashes, "
            f"{results['mutation_rounds']} LLM rounds, "
            f"{results['total_llm_mutations']} mutations generated"
        )

        return results

    def _inject_mutations(self, mutations: list, label: str) -> int:
        """Write mutations into the AFL++ queue directory."""
        queue_dir = self.output_dir / "afl" / "main" / "queue"
        # If AFL hasn't created the queue yet, put them in corpus
        target_dir = queue_dir if queue_dir.exists() else self.corpus_dir

        count = 0
        for i, m in enumerate(mutations):
            data = m.get("data", b"")
            if not data:
                continue
            name = f"llm:{label}:{i:04d}"
            (target_dir / name).write_bytes(data)
            count += 1

        if count:
            logger.info(f"[gpu-fuzz] Injected {count} mutations ({label})")
        return count

    def _detect_vuln_classes(self) -> list:
        """Detect potential vuln classes from parser decompilation.

        Looks for dangerous patterns in the decompiled code to decide
        which vault categories to pull from.
        """
        classes = []
        all_code = " ".join(self._parser_code.values()).lower()

        patterns = {
            "Overflow": ["memcpy", "strcpy", "sprintf", "strcat", "gets", "memmove"],
            "UAF": ["free", "delete", "realloc"],
            "Injection": ["system", "exec", "popen", "eval"],
            "Deserialization": ["unserialize", "pickle", "unmarshal", "fromjson"],
            "TOCTOU": ["access", "stat", "open"],
        }

        for vuln_class, keywords in patterns.items():
            if any(kw in all_code for kw in keywords):
                classes.append(vuln_class)

        return classes

    def _dump_to_nas(self, results: Dict) -> None:
        """Copy crashes and corpus to NAS for archival."""
        if not self.nas_dump_path:
            return

        nas_dir = Path(self.nas_dump_path) / self.binary.stem
        try:
            nas_dir.mkdir(parents=True, exist_ok=True)

            # Copy crashes
            crashes_src = self.output_dir / "afl" / "main" / "crashes"
            if crashes_src.exists():
                crashes_dst = nas_dir / "crashes"
                if crashes_dst.exists():
                    shutil.rmtree(crashes_dst)
                shutil.copytree(crashes_src, crashes_dst)

            # Copy interesting queue items (not the whole corpus)
            queue_src = self.output_dir / "afl" / "main" / "queue"
            if queue_src.exists():
                queue_dst = nas_dir / "queue"
                queue_dst.mkdir(exist_ok=True)
                for f in sorted(queue_src.iterdir())[:100]:
                    if f.is_file():
                        shutil.copy2(f, queue_dst / f.name)

            # Save results
            _safe_write_json(nas_dir / "results.json", results)

            logger.info(f"[gpu-fuzz] Dumped results to NAS: {nas_dir}")
        except OSError as e:
            logger.warning(f"[gpu-fuzz] NAS dump failed: {e}")

    @staticmethod
    def _resolve_vault_path() -> Optional[str]:
        config_path = Path.home() / ".config" / "raptor" / "models.json"
        if config_path.exists():
            try:
                data = json.loads(config_path.read_text())
                if isinstance(data, dict):
                    return data.get("vault_path")
            except (json.JSONDecodeError, KeyError):
                pass
        return None

    @staticmethod
    def _resolve_nas_path(explicit: str = None) -> Optional[str]:
        if explicit:
            return explicit
        config_path = Path.home() / ".config" / "raptor" / "models.json"
        if config_path.exists():
            try:
                data = json.loads(config_path.read_text())
                if isinstance(data, dict):
                    return data.get("fuzz_corpus_path")
            except (json.JSONDecodeError, KeyError):
                pass
        return None


def _safe_write_json(path: Path, data) -> None:
    """Write JSON without raising on serialization failures."""
    try:
        path.write_text(json.dumps(data, indent=2, default=str))
    except (OSError, TypeError) as e:
        logger.warning(f"Failed to write {path}: {e}")
