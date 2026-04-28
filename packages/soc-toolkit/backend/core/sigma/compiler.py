"""Compile Sigma rules to SIEM query languages.

The engine in :mod:`core.sigma.engine` evaluates rules against a stream
of event dicts in-process. That's useful during triage, but analysts
living inside Splunk / Elastic / Sentinel want the rule *as a query*
they can paste into their dashboard. This module does that lift.

Scope intentionally matches the evaluator: whatever our own engine can
run, we can compile. Unsupported Sigma features raise the same error
type as the parser, so callers see one coherent failure mode instead of
"loads fine, compiles weird".

Supported backends: ``splunk``, ``lucene`` (Elasticsearch/Kibana), and
``kql`` (Sentinel/Defender Kusto). Backends differ on:

* **quoting** - Lucene's quotes are optional for unreserved terms,
  Splunk tolerates both, KQL wants double-quoted strings.
* **wildcards** - SPL and Lucene use ``*``. KQL has no raw glob; we
  translate to ``contains`` / ``startswith`` / ``endswith`` operators.
* **regex** - each backend has its own syntax (``regex`` in SPL,
  ``/pattern/`` in Lucene, ``matches regex`` in KQL).
"""
from __future__ import annotations

import re
from typing import Any

from core.sigma.rule import SigmaRule, UnsupportedSigmaFeatureError

SUPPORTED_BACKENDS = ("splunk", "lucene", "kql")


def compile_rule(rule: SigmaRule, backend: str) -> str:
    """Return the SIEM-query equivalent of ``rule`` for ``backend``.

    Parameters
    ----------
    rule
        A :class:`SigmaRule` already parsed by our engine.
    backend
        One of :data:`SUPPORTED_BACKENDS`.
    """
    if backend not in SUPPORTED_BACKENDS:
        raise UnsupportedSigmaFeatureError(
            f"unsupported backend {backend!r}; expected one of {list(SUPPORTED_BACKENDS)}"
        )

    selection_exprs = {
        name: _compile_selection(blocks, backend)
        for name, blocks in rule._selections.items()
    }
    return _compile_condition(rule._condition, selection_exprs, backend)


# --- Selection compilation -----------------------------------------------


def _compile_selection(blocks: list[dict[str, Any]], backend: str) -> str:
    """Selection = list of dicts, OR-combined; dict entries AND-combined."""
    or_parts = [_compile_block(b, backend) for b in blocks]
    or_parts = [p for p in or_parts if p]
    if not or_parts:
        # Empty selection -> never matches. Use a tautology-negation that
        # is valid in every target language.
        return _FALSE_LITERAL[backend]
    if len(or_parts) == 1:
        return or_parts[0]
    return "(" + f" {_OR[backend]} ".join(or_parts) + ")"


def _compile_block(block: dict[str, Any], backend: str) -> str:
    parts = [_compile_field(spec, expected, backend) for spec, expected in block.items()]
    parts = [p for p in parts if p]
    if len(parts) == 1:
        return parts[0]
    return "(" + f" {_AND[backend]} ".join(parts) + ")"


def _compile_field(spec: str, expected: Any, backend: str) -> str:
    """Translate one ``field|modifier`` entry into the backend's syntax."""
    field_name, *modifiers = spec.split("|")
    unknown = set(modifiers) - {"contains", "startswith", "endswith", "re", "all"}
    if unknown:
        raise UnsupportedSigmaFeatureError(
            f"unsupported Sigma modifier(s): {sorted(unknown)}"
        )
    require_all = "all" in modifiers
    compare = next((m for m in modifiers if m != "all"), None)

    values = expected if isinstance(expected, list) else [expected]
    terms = [_compile_term(field_name, v, compare, backend) for v in values]
    joiner = _AND[backend] if require_all else _OR[backend]
    if len(terms) == 1:
        return terms[0]
    return "(" + f" {joiner} ".join(terms) + ")"


def _compile_term(field: str, value: Any, modifier: str | None, backend: str) -> str:
    """One atomic ``field operator value`` expression."""
    if backend == "splunk":
        return _splunk_term(field, value, modifier)
    if backend == "lucene":
        return _lucene_term(field, value, modifier)
    if backend == "kql":
        return _kql_term(field, value, modifier)
    raise UnsupportedSigmaFeatureError(f"unknown backend {backend!r}")  # defensive


# --- Splunk --------------------------------------------------------------


def _splunk_quote(value: str) -> str:
    # Splunk double-quotes with backslash-escaped inner quotes.
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _splunk_term(field: str, value: Any, modifier: str | None) -> str:
    if modifier == "re":
        # ``| where match(field, "pattern")`` is the idiomatic regex form;
        # inline as a search expression using ``regex`` operator.
        return f"{field}={_splunk_quote(str(value))} OR {field} regex {_splunk_quote(str(value))}"  # noqa: E501
    str_value = str(value)
    if modifier == "contains":
        return f"{field}={_splunk_quote('*' + str_value + '*')}"
    if modifier == "startswith":
        return f"{field}={_splunk_quote(str_value + '*')}"
    if modifier == "endswith":
        return f"{field}={_splunk_quote('*' + str_value)}"
    return f"{field}={_splunk_quote(str_value)}"


# --- Elasticsearch Lucene ------------------------------------------------


_LUCENE_SPECIAL = re.compile(r'([+\-!(){}\[\]^"~:\\/])')


def _lucene_escape(value: str) -> str:
    return _LUCENE_SPECIAL.sub(r"\\\1", value)


def _lucene_term(field: str, value: Any, modifier: str | None) -> str:
    str_value = str(value)
    if modifier == "re":
        # Lucene regex is ``/pattern/``; no escaping of the pattern itself.
        return f"{field}:/{str_value}/"
    if modifier == "contains":
        return f"{field}:*{_lucene_escape(str_value)}*"
    if modifier == "startswith":
        return f"{field}:{_lucene_escape(str_value)}*"
    if modifier == "endswith":
        return f"{field}:*{_lucene_escape(str_value)}"
    # Wrap in quotes whenever the value carries whitespace or Lucene specials.
    if re.search(r"\s", str_value) or _LUCENE_SPECIAL.search(str_value):
        quoted = str_value.replace("\\", "\\\\").replace('"', '\\"')
        return f'{field}:"{quoted}"'
    return f"{field}:{str_value}"


# --- KQL (Kusto / Sentinel) ----------------------------------------------


def _kql_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _kql_term(field: str, value: Any, modifier: str | None) -> str:
    str_value = str(value)
    if modifier == "re":
        return f"{field} matches regex {_kql_quote(str_value)}"
    if modifier == "contains":
        return f"{field} contains {_kql_quote(str_value)}"
    if modifier == "startswith":
        return f"{field} startswith {_kql_quote(str_value)}"
    if modifier == "endswith":
        return f"{field} endswith {_kql_quote(str_value)}"
    return f"{field} == {_kql_quote(str_value)}"


# --- Condition compilation -----------------------------------------------


_AND = {"splunk": "AND", "lucene": "AND", "kql": "and"}
_OR = {"splunk": "OR", "lucene": "OR", "kql": "or"}
_NOT = {"splunk": "NOT", "lucene": "NOT", "kql": "not"}
_FALSE_LITERAL = {
    # "0=1" reads as "false" in every SIEM that supports raw equality.
    "splunk": "0=1",
    "lucene": "(NOT *)",
    "kql": "false",
}
# Mirrors the tokenizer in :mod:`core.sigma.rule` - identifiers may end
# in ``*`` for selection-name wildcards (``selection_*``), which means
# a closing ``\b`` boundary would cut the glob off.
_CONDITION_TOKEN = re.compile(r"\(|\)|[\w\-\*]+")


def _compile_condition(
    condition: str, selections: dict[str, str], backend: str
) -> str:
    """Walk the Sigma condition grammar and emit the backend expression.

    Uses the same token vocabulary as :func:`core.sigma.rule._evaluate_condition`
    - ``and``/``or``/``not``, parentheses, selection names (with
    ``selection_*`` wildcard support), and ``1 of`` / ``all of``
    quantifiers. The two functions share enough shape that a future
    refactor could factor the parser out.
    """
    normalized = condition.replace("1 of", "1_OF").replace("all of", "ALL_OF")
    tokens = _CONDITION_TOKEN.findall(normalized)

    out: list[str] = []
    i = 0
    and_ = _AND[backend]
    or_ = _OR[backend]
    not_ = _NOT[backend]

    while i < len(tokens):
        tok = tokens[i]
        lower = tok.lower()
        if lower in ("and", "or", "not"):
            out.append({"and": and_, "or": or_, "not": not_}[lower])
            i += 1
            continue
        if tok in ("(", ")"):
            out.append(tok)
            i += 1
            continue
        if tok in ("1_OF", "ALL_OF"):
            if i + 1 >= len(tokens):
                raise UnsupportedSigmaFeatureError(
                    f"dangling quantifier in condition {condition!r}"
                )
            target = tokens[i + 1]
            matches = _resolve_wildcard(target, selections)
            if not matches:
                out.append(_FALSE_LITERAL[backend])
            elif tok == "1_OF":
                out.append("(" + f" {or_} ".join(matches) + ")")
            else:  # ALL_OF
                out.append("(" + f" {and_} ".join(matches) + ")")
            i += 2
            continue

        # Otherwise it's a selection name (possibly with a wildcard).
        matches = _resolve_wildcard(tok, selections)
        if not matches:
            out.append(_FALSE_LITERAL[backend])
        elif len(matches) == 1:
            out.append(matches[0])
        else:
            # Bare selection wildcard -> treat like "1 of", matching the
            # evaluator's loose default for wildcarded selection names.
            out.append("(" + f" {or_} ".join(matches) + ")")
        i += 1

    return " ".join(out).strip()


def _resolve_wildcard(target: str, selections: dict[str, str]) -> list[str]:
    if "*" not in target:
        return [selections[target]] if target in selections else []
    prefix = target.rstrip("*")
    return [expr for name, expr in selections.items() if name.startswith(prefix)]
