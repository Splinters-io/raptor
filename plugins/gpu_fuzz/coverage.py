"""Coverage analysis — identify uncovered branches for targeted mutation.

Reads AFL++ coverage bitmaps and fuzzer_stats to find branches that
haven't been hit, then maps them back to decompiled code so the LLM
knows which code paths to target with its mutations.
"""

import json
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.logging import get_logger

logger = get_logger()

MAP_SIZE = 65536  # AFL++ default bitmap size


def read_bitmap(bitmap_path: Path) -> Optional[bytes]:
    """Read an AFL++ coverage bitmap."""
    if not bitmap_path.exists():
        return None
    data = bitmap_path.read_bytes()
    if len(data) != MAP_SIZE:
        logger.warning(f"Unexpected bitmap size: {len(data)} (expected {MAP_SIZE})")
    return data


def bitmap_coverage(bitmap: bytes) -> Tuple[int, int, float]:
    """Calculate coverage from a bitmap.

    Returns:
        (edges_hit, total_edges, coverage_pct)
    """
    hit = sum(1 for b in bitmap if b != 0)
    return hit, MAP_SIZE, (hit / MAP_SIZE) * 100


def diff_bitmaps(before: bytes, after: bytes) -> List[int]:
    """Find edges newly covered between two bitmaps.

    Returns list of edge indices that are hit in `after` but not `before`.
    """
    new_edges = []
    for i in range(min(len(before), len(after))):
        if before[i] == 0 and after[i] != 0:
            new_edges.append(i)
    return new_edges


def read_fuzzer_stats(output_dir: Path) -> Dict[str, str]:
    """Read AFL++ fuzzer_stats file."""
    stats_file = output_dir / "main" / "fuzzer_stats"
    if not stats_file.exists():
        return {}

    stats = {}
    for line in stats_file.read_text().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            stats[key.strip()] = value.strip()
    return stats


def get_coverage_summary(output_dir: Path) -> Dict:
    """Get a summary of fuzzing coverage for the LLM."""
    stats = read_fuzzer_stats(output_dir)

    queue_dir = output_dir / "main" / "queue"
    queue_count = len(list(queue_dir.iterdir())) if queue_dir.exists() else 0

    crashes_dir = output_dir / "main" / "crashes"
    crash_count = 0
    if crashes_dir.exists():
        crash_count = len([f for f in crashes_dir.iterdir() if f.name.startswith("id:")])

    hangs_dir = output_dir / "main" / "hangs"
    hang_count = 0
    if hangs_dir.exists():
        hang_count = len([f for f in hangs_dir.iterdir() if f.name.startswith("id:")])

    return {
        "execs_total": stats.get("execs_done", "0"),
        "execs_per_sec": stats.get("execs_per_sec", "0"),
        "paths_total": stats.get("paths_total", str(queue_count)),
        "paths_found": stats.get("paths_found", "0"),
        "bitmap_cvg": stats.get("bitmap_cvg", "0%"),
        "stability": stats.get("stability", "0%"),
        "crashes": crash_count,
        "hangs": hang_count,
        "queue_size": queue_count,
        "pending_favs": stats.get("pending_favs", "0"),
        "pending_total": stats.get("pending_total", "0"),
    }


def find_stale_regions(output_dir: Path, threshold_execs: int = 100000) -> List[str]:
    """Identify regions where coverage has plateaued.

    Returns human-readable descriptions of coverage gaps for the LLM.
    """
    stats = read_fuzzer_stats(output_dir)
    gaps = []

    execs = int(stats.get("execs_done", "0"))
    pending = int(stats.get("pending_total", "0"))
    bitmap_cvg = stats.get("bitmap_cvg", "0%").rstrip("%")

    try:
        cvg = float(bitmap_cvg)
    except ValueError:
        cvg = 0.0

    if execs > threshold_execs and pending == 0:
        gaps.append(
            f"Fuzzer has exhausted pending inputs after {execs} executions "
            f"with {cvg:.1f}% bitmap coverage — new mutation strategies needed"
        )

    if execs > threshold_execs and cvg < 5.0:
        gaps.append(
            f"Very low coverage ({cvg:.1f}%) after {execs} executions — "
            f"input format may be highly structured, needs format-aware seeds"
        )

    return gaps


def load_queue_samples(output_dir: Path, max_samples: int = 10,
                       max_size: int = 4096) -> List[Tuple[str, bytes]]:
    """Load sample inputs from AFL++ queue for LLM context.

    Returns list of (filename, content) tuples, preferring small
    interesting inputs over large ones.
    """
    queue_dir = output_dir / "main" / "queue"
    if not queue_dir.exists():
        return []

    entries = sorted(queue_dir.iterdir(), key=lambda f: f.stat().st_size)
    samples = []

    for entry in entries:
        if not entry.is_file() or entry.name.startswith("."):
            continue
        if entry.stat().st_size > max_size:
            continue
        try:
            data = entry.read_bytes()
            samples.append((entry.name, data))
        except OSError:
            continue
        if len(samples) >= max_samples:
            break

    return samples
