"""YARA-X scanner wrapper.

yara-x (the Rust successor to YARA from VirusTotal) is chosen over yara-python
because it ships pure-Python wheels with no system libyara dependency - this
matters for the Docker image size and for keeping CI simple across platforms.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

import yara_x

logger = logging.getLogger(__name__)

# Rules live under backend/rules/yara/ - resolved relative to this file so the
# scanner works whether invoked from uvicorn, pytest, or the typer CLI
RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "yara"


class YaraScanner:
    """Compile YARA-X rules once at init, reuse across scans.

    Rule compilation is the expensive step (parsing, AST, codegen). Scanning
    itself is fast. Instantiate once per process via get_scanner().
    """

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir or RULES_DIR
        self._rules = self._compile()

    def _compile(self) -> yara_x.Rules:
        compiler = yara_x.Compiler()
        loaded = 0
        for rule_file in sorted(self._rules_dir.glob("*.yar")):
            try:
                compiler.add_source(rule_file.read_text())
                loaded += 1
            except yara_x.CompileError as exc:
                # A broken rule file should NOT take down the whole scanner -
                # log and continue so remaining rules stay operational
                logger.warning(
                    "YARA rule %s failed to compile: %s",
                    rule_file.name,
                    exc,
                )
        logger.info(
            "Compiled %d YARA rule file(s) from %s",
            loaded,
            self._rules_dir,
        )
        return compiler.build()

    def scan(self, data: bytes) -> list[dict]:
        """Scan bytes against all compiled rules.

        Returns list of match dicts: {rule, namespace, tags, metadata}.
        Empty list if no rules match or data is empty.
        """
        if not data:
            return []

        results = self._rules.scan(data)
        return [
            {
                "rule": match.identifier,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "metadata": dict(match.metadata),
            }
            for match in results.matching_rules
        ]


@lru_cache(maxsize=1)
def get_scanner() -> YaraScanner:
    """Return a process-wide cached YaraScanner.

    Avoids recompiling rules on every request - rule compilation can take
    100ms+ for a large ruleset, which would dominate scan latency.
    """
    return YaraScanner()
