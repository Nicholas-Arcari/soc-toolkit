"""Sigma-to-SIEM compiler tests.

Covers the three supported backends (splunk, lucene, kql) across the
operator matrix the engine already understands: equality, contains /
startswith / endswith, regex, list-OR, ``all`` modifier, and the
condition grammar (and / or / not, ``1 of``, ``all of``, wildcards).
Plus the route-level happy/error paths.
"""
from __future__ import annotations

import pytest

from core.sigma.compiler import SUPPORTED_BACKENDS, compile_rule
from core.sigma.rule import SigmaRule, UnsupportedSigmaFeatureError


def _rule(detection: dict) -> SigmaRule:
    return SigmaRule.from_dict({
        "id": "unit-test",
        "title": "Unit test rule",
        "description": "",
        "level": "medium",
        "tags": [],
        "logsource": {},
        "detection": detection,
    })


# --- Splunk --------------------------------------------------------------


def test_splunk_equality_single_field() -> None:
    rule = _rule({
        "sel": {"event_type": "auth_failure"},
        "condition": "sel",
    })
    assert compile_rule(rule, "splunk") == 'event_type="auth_failure"'


def test_splunk_multiple_fields_and() -> None:
    rule = _rule({
        "sel": {"event_type": "auth_failure", "reason": "invalid_user"},
        "condition": "sel",
    })
    query = compile_rule(rule, "splunk")
    # Dict iteration is insertion-order in 3.7+, so the order is stable.
    assert query == '(event_type="auth_failure" AND reason="invalid_user")'


def test_splunk_contains() -> None:
    rule = _rule({
        "sel": {"request_uri|contains": "union select"},
        "condition": "sel",
    })
    assert compile_rule(rule, "splunk") == 'request_uri="*union select*"'


def test_splunk_startswith_endswith() -> None:
    starts = _rule({"sel": {"path|startswith": "/admin"}, "condition": "sel"})
    ends = _rule({"sel": {"path|endswith": ".php"}, "condition": "sel"})
    assert compile_rule(starts, "splunk") == 'path="/admin*"'
    assert compile_rule(ends, "splunk") == 'path="*.php"'


def test_splunk_list_is_or_combined() -> None:
    rule = _rule({
        "sel": {"reason": ["invalid_user", "bad_password"]},
        "condition": "sel",
    })
    assert compile_rule(rule, "splunk") == '(reason="invalid_user" OR reason="bad_password")'


def test_splunk_condition_or_between_selections() -> None:
    rule = _rule({
        "a": {"event_id": 4720},
        "b": {"event_id": 4732},
        "condition": "a or b",
    })
    assert compile_rule(rule, "splunk") == 'event_id="4720" OR event_id="4732"'


def test_splunk_condition_one_of_wildcard() -> None:
    rule = _rule({
        "sel_1": {"a": 1},
        "sel_2": {"b": 2},
        "condition": "1 of sel_*",
    })
    assert compile_rule(rule, "splunk") == '(a="1" OR b="2")'


def test_splunk_condition_all_of_wildcard() -> None:
    rule = _rule({
        "sel_1": {"a": 1},
        "sel_2": {"b": 2},
        "condition": "all of sel_*",
    })
    assert compile_rule(rule, "splunk") == '(a="1" AND b="2")'


def test_splunk_condition_not() -> None:
    rule = _rule({
        "sel": {"user": "admin"},
        "condition": "not sel",
    })
    assert compile_rule(rule, "splunk") == 'NOT user="admin"'


# --- Lucene --------------------------------------------------------------


def test_lucene_equality() -> None:
    rule = _rule({"sel": {"event_type": "auth_failure"}, "condition": "sel"})
    assert compile_rule(rule, "lucene") == "event_type:auth_failure"


def test_lucene_contains_escapes_specials() -> None:
    rule = _rule({
        "sel": {"request_uri|contains": "(select"},
        "condition": "sel",
    })
    # The "(" is Lucene-special and must be backslash-escaped.
    assert compile_rule(rule, "lucene") == r"request_uri:*\(select*"


def test_lucene_quotes_values_with_spaces() -> None:
    rule = _rule({
        "sel": {"message": "failed password"},
        "condition": "sel",
    })
    assert compile_rule(rule, "lucene") == 'message:"failed password"'


def test_lucene_regex_syntax() -> None:
    rule = _rule({
        "sel": {"user|re": r"admin\d+"},
        "condition": "sel",
    })
    assert compile_rule(rule, "lucene") == r"user:/admin\d+/"


# --- KQL -----------------------------------------------------------------


def test_kql_equality() -> None:
    rule = _rule({"sel": {"event_type": "auth_failure"}, "condition": "sel"})
    assert compile_rule(rule, "kql") == 'event_type == "auth_failure"'


def test_kql_contains_operator() -> None:
    rule = _rule({
        "sel": {"request_uri|contains": "union select"},
        "condition": "sel",
    })
    assert compile_rule(rule, "kql") == 'request_uri contains "union select"'


def test_kql_boolean_ops_are_lowercase() -> None:
    rule = _rule({
        "a": {"event_id": 4720},
        "b": {"event_id": 4732},
        "condition": "a and b",
    })
    assert compile_rule(rule, "kql") == 'event_id == "4720" and event_id == "4732"'


def test_kql_all_modifier_is_and() -> None:
    rule = _rule({
        "sel": {"tags|contains|all": ["critical", "prod"]},
        "condition": "sel",
    })
    assert compile_rule(rule, "kql") == (
        '(tags contains "critical" and tags contains "prod")'
    )


# --- End-to-end using the bundled rules ---------------------------------


@pytest.mark.parametrize("backend", SUPPORTED_BACKENDS)
def test_bundled_rules_all_compile(backend: str) -> None:
    """Every bundled Sigma rule compiles to a non-empty query for every backend."""
    from core.sigma.engine import SigmaEngine

    engine = SigmaEngine()
    assert engine.rules, "engine should load the bundled rules"
    for rule in engine.rules:
        query = compile_rule(rule, backend)
        assert query, f"empty query for {rule.id} on {backend}"


# --- Error paths ---------------------------------------------------------


def test_unsupported_backend_raises() -> None:
    rule = _rule({"sel": {"a": 1}, "condition": "sel"})
    with pytest.raises(UnsupportedSigmaFeatureError):
        compile_rule(rule, "graylog")


def test_compile_rejects_unknown_modifier() -> None:
    rule = _rule({
        "sel": {"a|base64": "x"},
        "condition": "sel",
    })
    with pytest.raises(UnsupportedSigmaFeatureError):
        compile_rule(rule, "splunk")


# --- Route integration ---------------------------------------------------


@pytest.mark.asyncio
async def test_route_lists_backends(async_client) -> None:
    resp = await async_client.get("/api/sigma/backends")
    assert resp.status_code == 200
    assert set(resp.json()["backends"]) == set(SUPPORTED_BACKENDS)


@pytest.mark.asyncio
async def test_route_compile_by_rule_id(async_client) -> None:
    # ssh_bruteforce is one of the bundled rules.
    resp = await async_client.post(
        "/api/sigma/compile",
        json={"rule_id": "7b2a4c3e-ssh-bruteforce-burst", "backend": "splunk"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["backend"] == "splunk"
    assert "event_type" in body["query"]


@pytest.mark.asyncio
async def test_route_compile_by_yaml(async_client) -> None:
    yaml_rule = """
title: Ad-hoc rule
id: inline-1
description: inline test
level: low
logsource:
  service: web
detection:
  sel:
    request_uri|contains: "passwd"
  condition: sel
"""
    resp = await async_client.post(
        "/api/sigma/compile",
        json={"rule_yaml": yaml_rule, "backend": "kql"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["backend"] == "kql"
    assert body["query"] == 'request_uri contains "passwd"'


@pytest.mark.asyncio
async def test_route_rejects_both_or_neither(async_client) -> None:
    both = await async_client.post(
        "/api/sigma/compile",
        json={"rule_id": "x", "rule_yaml": "...", "backend": "splunk"},
    )
    assert both.status_code == 400

    neither = await async_client.post(
        "/api/sigma/compile",
        json={"backend": "splunk"},
    )
    assert neither.status_code == 400


@pytest.mark.asyncio
async def test_route_rejects_unknown_backend(async_client) -> None:
    resp = await async_client.post(
        "/api/sigma/compile",
        json={"rule_id": "x", "backend": "nope"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_route_returns_404_for_unknown_rule_id(async_client) -> None:
    resp = await async_client.post(
        "/api/sigma/compile",
        json={"rule_id": "does-not-exist", "backend": "splunk"},
    )
    assert resp.status_code == 404
