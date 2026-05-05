"""Project brain — structured markdown knowledge base.

Accumulates analysis knowledge across sessions into numbered markdown
documents inside a project's `brain/` directory. Each document covers
a domain (architecture, vulnerabilities, tradecraft, etc.) and grows
as runs complete. An INDEX.md provides session-start context.

Usage:
    from core.project.brain import ProjectBrain

    brain = ProjectBrain(project)
    brain.init()                          # create brain/ with skeleton docs
    brain.append("vulnerabilities", ...)  # add findings
    brain.rebuild_index()                 # regenerate INDEX.md
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from core.json import load_json
from core.logging import get_logger

logger = get_logger()

# Numbered document definitions: (filename, title, description)
BRAIN_DOCS = [
    ("00_OVERVIEW.md", "Overview", "Target characterization, components, build info"),
    ("01_ATTACK_SURFACE.md", "Attack Surface", "Entry points, trust boundaries, sinks, input handlers"),
    ("02_VULNERABILITIES.md", "Vulnerabilities", "Confirmed and suspected findings with evidence"),
    ("03_HYPOTHESES.md", "Hypotheses", "Tested and untested hypotheses with status"),
    ("04_EXPLOITS.md", "Exploits", "Working PoCs, failed attempts, blocking constraints"),
    ("05_RULES_AND_MODELS.md", "Rules and Models", "Extracted detection rules, ML models, signatures"),
    ("06_TRADECRAFT.md", "Tradecraft", "Evasion techniques, detection gaps, bypass methods"),
    ("07_TOOLS.md", "Tools", "Per-target tools built during analysis (decryptors, parsers, scanners)"),
    ("08_OBSERVATIONS.md", "Observations", "Interesting behaviors, anomalies, open questions"),
]


class ProjectBrain:
    """Manages a project's markdown knowledge base."""

    def __init__(self, project):
        self.project = project
        self.brain_dir = project.output_path / "brain"

    @property
    def index_path(self) -> Path:
        return self.brain_dir / "INDEX.md"

    def init(self) -> Path:
        """Create the brain directory with skeleton documents.

        Idempotent — skips files that already exist.
        Returns the brain directory path.
        """
        self.brain_dir.mkdir(parents=True, exist_ok=True)

        for filename, title, description in BRAIN_DOCS:
            doc_path = self.brain_dir / filename
            if not doc_path.exists():
                doc_path.write_text(
                    f"# {title}\n\n"
                    f"<!-- {description} -->\n\n"
                    f"*No entries yet.*\n"
                )

        self.rebuild_index()
        logger.info(f"Brain initialized: {self.brain_dir}")
        return self.brain_dir

    def append(self, doc_key: str, content: str, source: str = "") -> None:
        """Append a timestamped entry to a brain document.

        Args:
            doc_key: Document identifier — either the full filename
                     (e.g., "02_VULNERABILITIES.md") or a keyword
                     (e.g., "vulnerabilities", "attack_surface").
            content: Markdown content to append.
            source: Optional source label (e.g., run directory name,
                    command that produced the finding).
        """
        doc_path = self._resolve_doc(doc_key)
        if doc_path is None:
            logger.warning(f"Brain document not found for key: {doc_key}")
            return

        # Remove the "No entries yet" placeholder on first real entry
        existing = doc_path.read_text()
        if "*No entries yet.*" in existing:
            existing = existing.replace("*No entries yet.*\n", "")

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        header = f"\n---\n\n### {timestamp}"
        if source:
            header += f" — {source}"
        header += "\n\n"

        doc_path.write_text(existing.rstrip() + header + content.strip() + "\n")

    def read(self, doc_key: str) -> Optional[str]:
        """Read a brain document's contents."""
        doc_path = self._resolve_doc(doc_key)
        if doc_path and doc_path.exists():
            return doc_path.read_text()
        return None

    def rebuild_index(self) -> None:
        """Regenerate INDEX.md from current brain document state."""
        lines = [
            f"# {self.project.name} — Analysis Brain\n",
            f"**Target:** `{self.project.target}`\n",
            f"**Created:** {self.project.created}\n",
            f"**Last updated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n",
            "",
        ]

        # Summarize each document
        lines.append("## Documents\n")
        for filename, title, description in BRAIN_DOCS:
            doc_path = self.brain_dir / filename
            if doc_path.exists():
                text = doc_path.read_text()
                entry_count = text.count("\n---\n")
                has_content = "*No entries yet.*" not in text
                status = f"{entry_count} entries" if has_content else "empty"
            else:
                status = "missing"
            lines.append(f"- [{title}]({filename}) — {description} ({status})")

        # Pull key findings from vulnerabilities doc
        vuln_path = self.brain_dir / "02_VULNERABILITIES.md"
        if vuln_path.exists():
            vuln_text = vuln_path.read_text()
            if "*No entries yet.*" not in vuln_text:
                lines.append("\n## Key Findings\n")
                # Extract section headers (### lines that aren't timestamps)
                for line in vuln_text.splitlines():
                    if line.startswith("#### "):
                        lines.append(f"- {line[5:]}")

        # Pull open hypotheses
        hyp_path = self.brain_dir / "03_HYPOTHESES.md"
        if hyp_path.exists():
            hyp_text = hyp_path.read_text()
            if "*No entries yet.*" not in hyp_text:
                lines.append("\n## Open Hypotheses\n")
                for line in hyp_text.splitlines():
                    if "UNTESTED" in line or "IN PROGRESS" in line:
                        lines.append(f"- {line.strip()}")

        # Pull working exploits
        exploit_path = self.brain_dir / "04_EXPLOITS.md"
        if exploit_path.exists():
            exploit_text = exploit_path.read_text()
            if "*No entries yet.*" not in exploit_text:
                lines.append("\n## Exploit Status\n")
                for line in exploit_text.splitlines():
                    if "WORKING" in line or "BLOCKED" in line or "FAILED" in line:
                        lines.append(f"- {line.strip()}")

        lines.append("")
        self.index_path.write_text("\n".join(lines))

    def ingest_findings(self, run_dir: Path) -> int:
        """Import findings from a completed run into the brain.

        Reads findings.json from the run directory and appends each
        finding to the vulnerabilities document. Returns count added.
        """
        findings_file = run_dir / "findings.json"
        if not findings_file.exists():
            return 0

        data = load_json(findings_file)
        if not data:
            return 0

        findings = data if isinstance(data, list) else data.get("findings", [])
        if not findings:
            return 0

        entries = []
        for f in findings:
            title = f.get("title", f.get("vuln_type", "Unknown"))
            severity = f.get("severity", "unknown")
            file_path = f.get("file", "")
            line = f.get("line", "")
            status = f.get("status", f.get("validation_status", "unvalidated"))
            description = f.get("description", f.get("message", ""))

            entry = f"#### {title} [{severity}] — {status}\n"
            if file_path:
                entry += f"- **Location:** `{file_path}"
                if line:
                    entry += f":{line}"
                entry += "`\n"
            if description:
                entry += f"- {description}\n"

            # Cross-reference with vault
            vault_refs = self.cross_reference_vault(title + " " + description)
            if vault_refs:
                entry += vault_refs + "\n"

            entries.append(entry)

        if entries:
            self.append(
                "vulnerabilities",
                "\n".join(entries),
                source=run_dir.name,
            )

        return len(entries)

    def ingest_context_map(self, run_dir: Path) -> bool:
        """Import context-map.json (from /understand --map) into attack surface doc."""
        ctx_file = run_dir / "context-map.json"
        if not ctx_file.exists():
            return False

        data = load_json(ctx_file)
        if not data:
            return False

        lines = []

        entry_points = data.get("entry_points", [])
        if entry_points:
            lines.append(f"**Entry points:** {len(entry_points)}")
            for ep in entry_points[:20]:
                name = ep.get("name", ep.get("function", "?"))
                ep_type = ep.get("type", "")
                lines.append(f"- `{name}` ({ep_type})")

        sinks = data.get("sinks", [])
        if sinks:
            lines.append(f"\n**Sinks:** {len(sinks)}")
            for s in sinks[:20]:
                name = s.get("name", s.get("function", "?"))
                sink_type = s.get("type", s.get("category", ""))
                lines.append(f"- `{name}` ({sink_type})")

        boundaries = data.get("trust_boundaries", [])
        if boundaries:
            lines.append(f"\n**Trust boundaries:** {len(boundaries)}")
            for b in boundaries[:10]:
                name = b.get("name", b.get("boundary", "?"))
                lines.append(f"- {name}")

        if lines:
            self.append("attack_surface", "\n".join(lines), source=run_dir.name)
            return True
        return False

    def ingest_triage(self, run_dir: Path) -> bool:
        """Import triage.json (from /reverse) into overview doc."""
        triage_file = run_dir / "triage.json"
        if not triage_file.exists():
            return False

        data = load_json(triage_file)
        if not data:
            return False

        lines = []
        if isinstance(data, dict):
            for key in ("arch", "bits", "os", "bintype", "compiler", "class"):
                if key in data:
                    lines.append(f"- **{key}:** {data[key]}")

        if lines:
            self.append("overview", "\n".join(lines), source=run_dir.name)
            return True
        return False

    def _resolve_doc(self, key: str) -> Optional[Path]:
        """Resolve a document key to a file path.

        Accepts full filename ("02_VULNERABILITIES.md") or keyword
        ("vulnerabilities", "attack_surface", "exploits", etc.).
        """
        key_lower = key.lower().replace(" ", "_")

        # Direct filename match
        direct = self.brain_dir / key
        if direct.suffix == ".md" and direct.exists():
            return direct

        # Keyword match against document filenames
        for filename, title, _ in BRAIN_DOCS:
            name_part = filename.split("_", 1)[1].rsplit(".", 1)[0].lower()
            title_lower = title.lower().replace(" ", "_")
            if key_lower in (name_part, title_lower):
                return self.brain_dir / filename
            if key_lower in name_part or name_part in key_lower:
                return self.brain_dir / filename

        return None

    def cross_reference_vault(self, vuln_class: str, finding_title: str = "") -> str:
        """Search the vault for techniques related to a vulnerability class.

        Returns markdown cross-reference text to append to a brain entry.
        Links to vault primitives, techniques, and methodology docs.
        """
        vault_path = self._find_vault()
        if not vault_path:
            return ""

        # Map common finding terms to vault categories
        class_map = {
            "overflow": "Overflow",
            "buffer overflow": "Overflow",
            "heap overflow": "Overflow",
            "stack overflow": "Overflow",
            "integer overflow": "Overflow",
            "use-after-free": "UAF",
            "uaf": "UAF",
            "double free": "UAF",
            "dangling": "UAF",
            "out-of-bounds": "OOB",
            "oob": "OOB",
            "race condition": "Race",
            "race": "Race",
            "toctou": "TOCTOU",
            "time-of-check": "TOCTOU",
            "injection": "Injection",
            "command injection": "Injection",
            "sql injection": "Injection",
            "deserialization": "Deserialization",
            "rce": "RCE",
            "remote code execution": "RCE",
            "privilege escalation": "Privesc",
            "privesc": "Privesc",
            "ssrf": "SSRF",
            "xss": "XSS",
            "cross-site": "XSS",
            "leak": "Leak",
            "info leak": "Leak",
            "information disclosure": "Leak",
            "type confusion": "Confusion",
            "authentication": "Authentication",
            "auth bypass": "Authentication",
            "access control": "Access-Control",
        }

        # Resolve vault category
        category = None
        search = vuln_class.lower()
        for pattern, cat in class_map.items():
            if pattern in search:
                category = cat
                break

        if not category:
            return ""

        refs = []

        # Link to primitive MOC if it exists
        primitive_path = vault_path / "primitives" / f"{category.lower()}.md"
        if primitive_path.exists():
            refs.append(f"**Vault primitive:** `vault/primitives/{category.lower()}.md` — methodology, chain partners, proving skills")

        # Count and link techniques
        techniques_dir = vault_path / "techniques" / category
        if techniques_dir.exists():
            technique_files = list(techniques_dir.glob("*.md"))
            if technique_files:
                refs.append(f"**Vault techniques:** {len(technique_files)} entries in `vault/techniques/{category}/`")
                # Show first 3 technique titles (from YAML frontmatter or first heading)
                for tf in technique_files[:3]:
                    try:
                        text = tf.read_text(errors="replace")
                        title = None
                        for tline in text.splitlines():
                            if tline.startswith("title:"):
                                title = tline.split(":", 1)[1].strip().strip('"').strip("'")
                                break
                            if tline.startswith("# ") and not title:
                                title = tline[2:].strip()
                                break
                        if not title:
                            title = tf.stem.replace("-", " ").replace("_", " ")
                        if title:
                            refs.append(f"  - {title[:80]}")
                    except OSError:
                        pass

        # Link to methodology
        methodology_path = vault_path / "methodologies" / "Binary Analysis.md"
        if methodology_path.exists():
            refs.append(f"**Methodology:** `vault/methodologies/Binary Analysis.md`")

        if refs:
            return "\n**Vault cross-references:**\n" + "\n".join(refs)
        return ""

    def ingest_sarif(self, sarif_path: Path, source: str = "") -> int:
        """Import SARIF findings into the brain with vault cross-references.

        Reads a SARIF file (from Semgrep, CodeQL, etc.), appends each
        finding to the vulnerabilities document, and links related
        vault techniques.
        """
        data = load_json(sarif_path)
        if not data:
            return 0

        results = []
        for run in data.get("runs", []):
            results.extend(run.get("results", []))

        if not results:
            return 0

        entries = []
        for r in results:
            rule = r.get("ruleId", "unknown")
            level = r.get("level", "warning")
            msg = r.get("message", {}).get("text", "")
            loc = r.get("locations", [{}])[0].get("physicalLocation", {})
            fpath = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", "")

            short_path = "/".join(fpath.split("/")[-3:]) if fpath else ""

            entry = f"#### {rule} [{level}]\n"
            if short_path:
                entry += f"- **Location:** `{short_path}"
                if line:
                    entry += f":{line}"
                entry += "`\n"
            if msg:
                entry += f"- {msg[:200]}\n"

            # Cross-reference with vault
            vault_refs = self.cross_reference_vault(rule + " " + msg)
            if vault_refs:
                entry += vault_refs + "\n"

            entries.append(entry)

        if entries:
            self.append("vulnerabilities", "\n".join(entries), source=source)

        return len(entries)

    def _find_vault(self) -> Optional[Path]:
        """Locate the vault directory."""
        # Check models.json config
        config_path = Path.home() / ".config" / "raptor" / "models.json"
        if config_path.exists():
            try:
                import json
                data = json.loads(config_path.read_text())
                if isinstance(data, dict) and data.get("vault_path"):
                    vault = Path(data["vault_path"])
                    if vault.exists():
                        return vault
            except Exception:
                pass

        # Common locations
        for candidate in [
            Path.home() / "tools" / "vault",
            Path.home() / "vault",
        ]:
            if candidate.exists() and (candidate / "primitives").exists():
                return candidate

        return None

    def exists(self) -> bool:
        """Check if the brain directory has been initialized."""
        return self.index_path.exists()
