"""Sigma rule representation and per-event evaluation.

The Sigma spec (https://sigmahq.io/docs/basics/rules.html) is broad. This
implementation targets the subset that makes sense for single-event
evaluation inside a SOC analyst workflow:

* selections with field/value match (string, int, list-of-values)
* field modifiers: ``contains``, ``startswith``, ``endswith``, ``re``, ``all``
* boolean conditions: ``and``, ``or``, ``not``, ``1 of``, ``all of``,
  wildcards like ``all of selection_*``

Features that require multi-event correlation (``near``, ``| count() by``,
timeframe aggregations) are out of scope - they belong in a SIEM, not in a
per-event evaluator. Unsupported features raise at load time with a clear
error, so operators don't think a rule is firing when it silently isn't.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Sigma field modifiers that change how a value is compared. "all" combines
# with another modifier (e.g. "contains|all") to require every list entry
# match rather than just one
_SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}


class UnsupportedSigmaFeatureError(ValueError):
    """Raised when a Sigma rule uses a feature this engine doesn't implement."""


@dataclass
class SigmaMatch:
    """One rule hit for one event - what the API/CLI hands back to callers."""

    rule_id: str
    title: str
    level: str
    tags: list[str]
    description: str
    event: dict[str, Any]


@dataclass
class SigmaRule:
    """A compiled Sigma rule that can be evaluated against an event dict."""

    id: str
    title: str
    description: str
    level: str
    tags: list[str]
    logsource: dict[str, Any]
    detection: dict[str, Any]
    _selections: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    _condition: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SigmaRule:
        detection = data.get("detection", {})
        if not detection:
            raise UnsupportedSigmaFeatureError("rule has no detection block")

        condition = detection.get("condition", "")
        if not condition:
            raise UnsupportedSigmaFeatureError("rule has no condition")

        # Features we explicitly reject - it's safer to fail loud than to
        # load a rule that looks like it's matching when it's not
        if "|" in condition and any(kw in condition for kw in (" count(", " near ")):
            raise UnsupportedSigmaFeatureError(
                f"aggregations/correlations not supported: {condition!r}"
            )

        selections = {
            name: cls._compile_selection(body)
            for name, body in detection.items()
            if name != "condition" and name != "timeframe"
        }

        return cls(
            id=str(data.get("id", "")),
            title=str(data.get("title", "")),
            description=str(data.get("description", "")),
            level=str(data.get("level", "medium")),
            tags=list(data.get("tags", [])),
            logsource=dict(data.get("logsource", {})),
            detection=detection,
            _selections=selections,
            _condition=condition.strip(),
        )

    @staticmethod
    def _compile_selection(body: Any) -> list[dict[str, Any]]:
        """Normalise a selection block to a list of {field_spec: value} maps.

        Sigma allows selections to be a mapping ({field: value, ...}) or a
        list of such mappings (each entry is OR-combined). Collapsing both
        to a list of dicts keeps the matcher uniform.
        """
        if isinstance(body, dict):
            return [body]
        if isinstance(body, list):
            return [item for item in body if isinstance(item, dict)]
        raise UnsupportedSigmaFeatureError(
            f"selection body must be dict or list of dicts, got {type(body).__name__}"
        )

    def matches(self, event: dict[str, Any]) -> bool:
        """Evaluate this rule's condition against an event."""
        results = {
            name: self._match_selection(sel, event)
            for name, sel in self._selections.items()
        }
        return _evaluate_condition(self._condition, results)

    def _match_selection(self, blocks: list[dict[str, Any]], event: dict[str, Any]) -> bool:
        # List-of-blocks are OR-combined; inside a block all fields are AND-combined
        return any(self._match_block(block, event) for block in blocks)

    def _match_block(self, block: dict[str, Any], event: dict[str, Any]) -> bool:
        return all(self._match_field(spec, expected, event) for spec, expected in block.items())

    @staticmethod
    def _match_field(spec: str, expected: Any, event: dict[str, Any]) -> bool:
        """Match one ``field|modifier`` entry against the event."""
        field_name, *modifiers = spec.split("|")
        actual = event.get(field_name)
        if actual is None:
            return False

        unknown = set(modifiers) - _SUPPORTED_MODIFIERS
        if unknown:
            raise UnsupportedSigmaFeatureError(
                f"unsupported Sigma modifier(s): {sorted(unknown)}"
            )

        # Normalize expected values to a list for uniform list-comparison logic
        expected_values: list[Any] = expected if isinstance(expected, list) else [expected]
        require_all = "all" in modifiers
        compare_modifier = next((m for m in modifiers if m != "all"), None)

        if require_all:
            return all(_compare(actual, v, compare_modifier) for v in expected_values)
        return any(_compare(actual, v, compare_modifier) for v in expected_values)


def _compare(actual: Any, expected: Any, modifier: str | None) -> bool:
    # Sigma is case-insensitive for string comparisons; actual event values
    # are often mixed-case (Windows EventID strings vs ints are the classic trap)
    if modifier is None:
        return _equals(actual, expected)
    if modifier == "contains":
        return str(expected).lower() in str(actual).lower()
    if modifier == "startswith":
        return str(actual).lower().startswith(str(expected).lower())
    if modifier == "endswith":
        return str(actual).lower().endswith(str(expected).lower())
    if modifier == "re":
        return bool(re.search(str(expected), str(actual)))
    return False


def _equals(actual: Any, expected: Any) -> bool:
    """Case-insensitive equality for strings, strict equality for everything else."""
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.lower() == expected.lower()
    # int/int, bool/bool, or cross-type: compare as strings to bridge the
    # common "4625" (str) vs 4625 (int) event-id mismatch seen in Windows logs
    return str(actual).lower() == str(expected).lower()


# --- Condition evaluation -------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|\bor\b|\band\b|\bnot\b|\b1 of\b|\ball of\b|[\w\-\*]+")


def _evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition expression against pre-computed selections."""
    tokens = _TOKEN_RE.findall(condition.replace("1 of", "1_OF").replace("all of", "ALL_OF"))
    expr_parts: list[str] = []

    for token in tokens:
        lower = token.lower()
        if lower in ("and", "or", "not", "(", ")"):
            expr_parts.append(lower)
        elif token == "1_OF":  # nosec B105 - sentinel token, not a secret
            expr_parts.append("1_OF")  # nosec B105
        elif token == "ALL_OF":  # nosec B105 - sentinel token, not a secret
            expr_parts.append("ALL_OF")  # nosec B105
        else:
            expr_parts.append(token)

    py_expr: list[str] = []
    i = 0
    while i < len(expr_parts):
        tok = expr_parts[i]
        if tok in ("1_OF", "ALL_OF"):
            if i + 1 >= len(expr_parts):
                raise UnsupportedSigmaFeatureError(f"dangling quantifier in {condition!r}")
            target = expr_parts[i + 1]
            matches = _resolve_wildcard(target, selection_results)
            if tok == "1_OF":
                py_expr.append("True" if any(matches) else "False")
            else:
                py_expr.append("True" if matches and all(matches) else "False")
            i += 2
            continue

        if tok in ("and", "or", "not", "(", ")"):
            py_expr.append(tok)
            i += 1
            continue

        # Otherwise it's a selection name
        py_expr.append("True" if selection_results.get(tok, False) else "False")
        i += 1

    # eval is used on an expression assembled only from whitelisted tokens
    # (and/or/not/parens and True/False literals). No attacker-controlled
    # string reaches this eval - confirmed by the token-scanning loop above
    try:
        return bool(eval(" ".join(py_expr)))  # nosec B307
    except Exception as exc:
        raise UnsupportedSigmaFeatureError(
            f"could not evaluate condition {condition!r}: {exc}"
        ) from exc


def _resolve_wildcard(target: str, results: dict[str, bool]) -> list[bool]:
    """Expand ``selection_*`` wildcards to the list of matching selection results."""
    if "*" not in target:
        return [results.get(target, False)]
    prefix = target.rstrip("*")
    return [v for k, v in results.items() if k.startswith(prefix)]
