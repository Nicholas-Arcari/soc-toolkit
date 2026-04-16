"""Sigma engine tests.

Two layers of coverage:
1. SigmaRule - unit tests on the matcher with hand-built rule dicts so every
   modifier / condition operator gets exercised in isolation.
2. SigmaEngine - integration tests that load the real YAML rules from
   backend/rules/sigma/ and fire matching/non-matching events through them.
"""

from pathlib import Path

import pytest

from core.sigma.engine import RULES_DIR, SigmaEngine
from core.sigma.rule import SigmaRule, UnsupportedSigmaFeatureError


# --- Rule matching unit tests --------------------------------------------


def _rule(detection: dict, **extra) -> SigmaRule:
    """Build a SigmaRule dict quickly for tests - keeps the YAML out of unit tests."""
    return SigmaRule.from_dict({
        "id": "test",
        "title": "Test rule",
        "description": "",
        "level": "medium",
        "tags": [],
        "logsource": {},
        "detection": detection,
        **extra,
    })


def test_simple_selection_matches():
    rule = _rule({
        "sel": {"event_type": "auth_failure", "reason": "invalid_user"},
        "condition": "sel",
    })
    assert rule.matches({"event_type": "auth_failure", "reason": "invalid_user"})
    assert not rule.matches({"event_type": "auth_failure", "reason": "bad_password"})


def test_selection_value_list_is_or_combined():
    """A list of values inside a field means OR, per Sigma spec."""
    rule = _rule({
        "sel": {"reason": ["invalid_user", "bad_password"]},
        "condition": "sel",
    })
    assert rule.matches({"reason": "invalid_user"})
    assert rule.matches({"reason": "bad_password"})
    assert not rule.matches({"reason": "timeout"})


def test_contains_modifier():
    rule = _rule({
        "sel": {"request_uri|contains": "union select"},
        "condition": "sel",
    })
    assert rule.matches({"request_uri": "/search?q=1' UNION SELECT pwd FROM users--"})
    assert not rule.matches({"request_uri": "/home"})


def test_startswith_modifier():
    rule = _rule({
        "sel": {"process_path|startswith": "C:\\Users\\Public\\"},
        "condition": "sel",
    })
    assert rule.matches({"process_path": "c:\\users\\public\\mal.exe"})
    assert not rule.matches({"process_path": "C:\\Windows\\System32\\svchost.exe"})


def test_regex_modifier():
    rule = _rule({
        "sel": {"request_uri|re": r"(cmd|exec|system)="},
        "condition": "sel",
    })
    assert rule.matches({"request_uri": "/shell.php?cmd=whoami"})
    assert not rule.matches({"request_uri": "/index.php?id=1"})


def test_all_modifier_requires_every_value():
    """contains|all: every value must appear somewhere in the field."""
    rule = _rule({
        "sel": {"command_line|contains|all": ["powershell", "-enc", "bypass"]},
        "condition": "sel",
    })
    assert rule.matches({
        "command_line": "powershell -nop -enc AAAA -exec bypass"
    })
    assert not rule.matches({
        "command_line": "powershell -nop -enc AAAA"  # missing 'bypass'
    })


def test_condition_and_not():
    rule = _rule({
        "sel": {"event_id": 4625},
        "filter": {"username": "svc_backup"},
        "condition": "sel and not filter",
    })
    assert rule.matches({"event_id": 4625, "username": "alice"})
    assert not rule.matches({"event_id": 4625, "username": "svc_backup"})


def test_condition_one_of_wildcard():
    rule = _rule({
        "sel_create": {"event_id": 4720},
        "sel_group_add": {"event_id": 4732},
        "condition": "1 of sel_*",
    })
    assert rule.matches({"event_id": 4720})
    assert rule.matches({"event_id": 4732})
    assert not rule.matches({"event_id": 4624})


def test_condition_all_of_wildcard():
    rule = _rule({
        "sel_a": {"a": 1},
        "sel_b": {"b": 2},
        "condition": "all of sel_*",
    })
    assert rule.matches({"a": 1, "b": 2})
    assert not rule.matches({"a": 1})


def test_missing_field_does_not_match():
    """Expected field absent from event = no match (fail closed, not fail open)."""
    rule = _rule({
        "sel": {"process_name": "powershell.exe"},
        "condition": "sel",
    })
    assert not rule.matches({})


def test_case_insensitive_string_equality():
    """Windows log fields are notoriously mixed-case; Sigma matches must be CI."""
    rule = _rule({"sel": {"process_name": "powershell.exe"}, "condition": "sel"})
    assert rule.matches({"process_name": "PowerShell.EXE"})


def test_int_vs_string_event_id_bridges():
    """EventID comes as int from some parsers, str from others - both must match."""
    rule = _rule({"sel": {"event_id": 4625}, "condition": "sel"})
    assert rule.matches({"event_id": "4625"})
    assert rule.matches({"event_id": 4625})


def test_rule_with_no_detection_rejected():
    with pytest.raises(UnsupportedSigmaFeatureError):
        SigmaRule.from_dict({"title": "bad", "detection": {}})


def test_unsupported_modifier_raises():
    rule = _rule({"sel": {"field|cidr": "10.0.0.0/8"}, "condition": "sel"})
    with pytest.raises(UnsupportedSigmaFeatureError):
        rule.matches({"field": "10.0.0.1"})


def test_aggregation_condition_rejected():
    """count()/near aggregations are multi-event - refuse them at load time."""
    with pytest.raises(UnsupportedSigmaFeatureError):
        SigmaRule.from_dict({
            "title": "agg",
            "detection": {
                "sel": {"event_id": 4625},
                "condition": "sel | count() by source_ip > 10",
            },
        })


# --- Engine integration tests --------------------------------------------


def test_engine_loads_bundled_rules():
    """The shipped rules under backend/rules/sigma/ must all load cleanly."""
    engine = SigmaEngine(rules_dir=RULES_DIR)
    assert len(engine.rules) >= 4
    titles = {r.title for r in engine.rules}
    assert any("SSH Brute Force" in t for t in titles)


def test_engine_detects_ssh_brute_force():
    engine = SigmaEngine(rules_dir=RULES_DIR)
    event = {
        "event_type": "auth_failure",
        "reason": "invalid_user",
        "source_ip": "203.0.113.50",
        "username": "root",
    }
    matches = engine.evaluate(event)
    assert any("SSH Brute Force" in m.title for m in matches)


def test_engine_detects_windows_admin_creation():
    engine = SigmaEngine(rules_dir=RULES_DIR)
    event = {"event_id": 4720, "username": "backdoor"}
    matches = engine.evaluate(event)
    assert any("Administrator Account" in m.title for m in matches)


def test_engine_detects_sqli():
    engine = SigmaEngine(rules_dir=RULES_DIR)
    event = {"request_uri": "/products?id=1 UNION SELECT password FROM users--"}
    matches = engine.evaluate(event)
    assert any("SQL Injection" in m.title for m in matches)


def test_engine_benign_event_has_no_matches():
    engine = SigmaEngine(rules_dir=RULES_DIR)
    event = {"event_type": "auth_success", "username": "alice"}
    assert engine.evaluate(event) == []


def test_engine_skips_missing_rule_dir(tmp_path: Path):
    engine = SigmaEngine(rules_dir=tmp_path / "does_not_exist")
    assert engine.rules == []
    assert engine.evaluate({"anything": 1}) == []


def test_engine_custom_rule_dir(tmp_path: Path):
    rule_path = tmp_path / "custom.yml"
    rule_path.write_text(
        "title: Custom\n"
        "id: custom-1\n"
        "description: ''\n"
        "logsource: {product: test}\n"
        "detection:\n"
        "    sel: {marker: canary}\n"
        "    condition: sel\n"
        "level: high\n"
        "tags: []\n"
    )

    engine = SigmaEngine(rules_dir=tmp_path)
    matches = engine.evaluate({"marker": "canary"})

    assert len(matches) == 1
    assert matches[0].title == "Custom"
    assert matches[0].level == "high"
