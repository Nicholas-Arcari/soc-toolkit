"""Sigma rule loader + batch evaluator.

Loading compiles every rule once, up front, so per-event evaluation avoids
YAML parsing overhead. This is the pattern used by production Sigma backends
(pysigma, sigmac), and it's essential if the engine is ever evaluated against
a log stream rather than a single event at a time.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from core.sigma.rule import SigmaMatch, SigmaRule, UnsupportedSigmaFeatureError

logger = logging.getLogger(__name__)

# Rule store lives alongside YARA rules under backend/rules/ so both rulesets
# ship together and are discoverable in one place
RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "sigma"


class SigmaEngine:
    """Compile a directory of Sigma YAML rules and evaluate events against them."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir or RULES_DIR
        self.rules: list[SigmaRule] = self._load()

    def _load(self) -> list[SigmaRule]:
        rules: list[SigmaRule] = []
        if not self._rules_dir.exists():
            logger.warning("Sigma rules dir missing: %s", self._rules_dir)
            return rules

        # Sigma files conventionally use .yml; also accept .yaml for portability
        for rule_file in sorted([*self._rules_dir.glob("*.yml"), *self._rules_dir.glob("*.yaml")]):
            try:
                # safe_load never executes arbitrary Python tags - untrusted rule
                # files from GitHub / community repos must NOT use yaml.load()
                data = yaml.safe_load(rule_file.read_text())
                if not isinstance(data, dict):
                    logger.warning("Skipping %s: not a YAML mapping", rule_file.name)
                    continue
                rules.append(SigmaRule.from_dict(data))
            except UnsupportedSigmaFeatureError as exc:
                # One rule using an unsupported feature shouldn't disable the
                # whole engine - log and keep loading the rest
                logger.warning("Skipping Sigma rule %s: %s", rule_file.name, exc)
            except yaml.YAMLError as exc:
                logger.warning("YAML parse error in %s: %s", rule_file.name, exc)

        logger.info("Loaded %d Sigma rule(s) from %s", len(rules), self._rules_dir)
        return rules

    def evaluate(self, event: dict[str, Any]) -> list[SigmaMatch]:
        """Evaluate one event against every loaded rule, return all matches."""
        matches: list[SigmaMatch] = []
        for rule in self.rules:
            try:
                if rule.matches(event):
                    matches.append(
                        SigmaMatch(
                            rule_id=rule.id,
                            title=rule.title,
                            level=rule.level,
                            tags=rule.tags,
                            description=rule.description,
                            event=event,
                        )
                    )
            except UnsupportedSigmaFeatureError as exc:
                # A rule that raises during evaluation is logged once per event
                # but doesn't abort the whole run - other rules still contribute
                logger.warning("Sigma rule %s failed to evaluate: %s", rule.id, exc)
        return matches

    def evaluate_batch(self, events: list[dict[str, Any]]) -> list[SigmaMatch]:
        """Evaluate a list of events; results come back in event order."""
        all_matches: list[SigmaMatch] = []
        for event in events:
            all_matches.extend(self.evaluate(event))
        return all_matches


@lru_cache(maxsize=1)
def get_engine() -> SigmaEngine:
    """Process-wide Sigma engine - avoids re-parsing rules per request."""
    return SigmaEngine()
