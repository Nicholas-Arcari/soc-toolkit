"""DNS mapping: parsing + finding emission.

We don't hit a real recursive resolver - every test stubs
`dns.asyncresolver.Resolver.resolve` so the cases exercised are
deterministic (SPF present/absent/permissive, DMARC policy variants,
NS cardinality).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import dns.resolver
import pytest
from sqlalchemy import select

from core.asm import dns_mapping as dns_mod
from db.models import Finding, Target


@dataclass
class _FakeAnswer:
    """Minimal stand-in for dnspython's Answer - iterable of rdata-ish objects."""

    values: list[str]

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(_FakeRdata(v) for v in self.values)


@dataclass
class _FakeRdata:
    value: str

    def __str__(self) -> str:
        # dnspython wraps TXT rdata in quotes; mimic that so the module's
        # `strip('"')` is exercised.
        if self.value.startswith(("v=spf1", "v=DMARC1", "v=dmarc1")):
            return f'"{self.value}"'
        return self.value


class _FakeResolver:
    """Dispatches `resolve(qname, rtype)` against a precomputed table.

    The table is `{(qname, rtype): ["rdata", ...]}`. Unknown queries
    raise `NoAnswer` so the module's "no record" path is hit - which is
    exactly what happens in production for missing SPF/DMARC.
    """

    def __init__(self, table: dict[tuple[str, str], list[str]]):
        self.table = table

    async def resolve(self, qname: str, rtype: str) -> _FakeAnswer:  # noqa: D401
        key = (qname.rstrip(".").lower(), rtype)
        if key not in self.table:
            raise dns.resolver.NoAnswer()
        return _FakeAnswer(self.table[key])


async def _make_target(session, *, scope: list[str]) -> Target:
    t = Target(
        name="acme",
        scope_domains=scope,
        authorized_to_scan=True,
        active=True,
    )
    session.add(t)
    await session.flush()
    return t


async def test_spf_missing_emits_medium_finding(db_session: Any) -> None:
    """A domain with no SPF TXT record should produce a 'medium' finding."""
    target = await _make_target(db_session, scope=["example.test"])
    # A-record present but no TXT at all → SPF absent.
    resolver = _FakeResolver({
        ("example.test", "A"): ["192.0.2.1"],
        ("example.test", "NS"): ["ns1.example.test.", "ns2.example.test."],
    })

    result = await dns_mod.map_dns(target, session=db_session, resolver=resolver)  # type: ignore[arg-type]

    assert result.findings_created == 2  # SPF missing + DMARC missing
    findings = (
        await db_session.execute(select(Finding).where(Finding.target_id == target.id))
    ).scalars().all()
    spf_finding = next(f for f in findings if "SPF" in f.description)
    assert spf_finding.severity == "medium"
    assert spf_finding.category == "email_auth"


async def test_spf_plus_all_emits_high_finding(db_session: Any) -> None:
    """`+all` is the dangerous terminal - flagged as high severity."""
    target = await _make_target(db_session, scope=["permissive.test"])
    resolver = _FakeResolver({
        ("permissive.test", "TXT"): ["v=spf1 +all"],
        ("_dmarc.permissive.test", "TXT"): ["v=DMARC1; p=reject"],
        ("permissive.test", "NS"): ["a.", "b."],
    })

    result = await dns_mod.map_dns(target, session=db_session, resolver=resolver)  # type: ignore[arg-type]

    assert result.findings_created == 1
    f = (
        await db_session.execute(select(Finding).where(Finding.target_id == target.id))
    ).scalars().first()
    assert f is not None
    assert f.severity == "high"
    assert "+all" in f.description


async def test_spf_hard_fail_emits_no_finding(db_session: Any) -> None:
    """A correctly-configured SPF + DMARC combo produces no findings."""
    target = await _make_target(db_session, scope=["strict.test"])
    resolver = _FakeResolver({
        ("strict.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        ("_dmarc.strict.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@b"],
        ("strict.test", "NS"): ["a.", "b."],
    })

    result = await dns_mod.map_dns(target, session=db_session, resolver=resolver)  # type: ignore[arg-type]

    assert result.findings_created == 0


async def test_dmarc_p_none_emits_low_finding(db_session: Any) -> None:
    """DMARC present but set to monitor-only should surface a low finding."""
    target = await _make_target(db_session, scope=["monitor.test"])
    resolver = _FakeResolver({
        ("monitor.test", "TXT"): ["v=spf1 -all"],
        ("_dmarc.monitor.test", "TXT"): ["v=DMARC1; p=none"],
        ("monitor.test", "NS"): ["a.", "b."],
    })

    result = await dns_mod.map_dns(target, session=db_session, resolver=resolver)  # type: ignore[arg-type]

    assert result.findings_created == 1
    f = (
        await db_session.execute(select(Finding).where(Finding.target_id == target.id))
    ).scalars().first()
    assert f is not None
    assert f.severity == "low"
    assert "p=none" in f.description


async def test_single_ns_record_emits_finding(db_session: Any) -> None:
    """RFC 2182 says ≥2 NS records; a single NS should be flagged."""
    target = await _make_target(db_session, scope=["lonely.test"])
    resolver = _FakeResolver({
        ("lonely.test", "TXT"): ["v=spf1 -all"],
        ("_dmarc.lonely.test", "TXT"): ["v=DMARC1; p=reject"],
        ("lonely.test", "NS"): ["only-ns.example."],
    })

    result = await dns_mod.map_dns(target, session=db_session, resolver=resolver)  # type: ignore[arg-type]

    ns_findings = [f for f in (
        await db_session.execute(select(Finding).where(Finding.target_id == target.id))
    ).scalars() if "nameserver" in f.description]
    assert len(ns_findings) == 1
    assert ns_findings[0].severity == "low"
    assert ns_findings[0].category == "dns"


async def test_summary_shape_is_json_safe(db_session: Any) -> None:
    """`summarize()` output must be serializable for Scan.summary storage."""
    target = await _make_target(db_session, scope=["a.test", "b.test"])
    resolver = _FakeResolver({
        ("a.test", "A"): ["1.1.1.1"],
        ("a.test", "MX"): ["10 mail.a.test."],
        ("a.test", "TXT"): ["v=spf1 -all"],
        ("_dmarc.a.test", "TXT"): ["v=DMARC1; p=reject"],
        ("a.test", "NS"): ["ns1.", "ns2."],
    })

    result = await dns_mod.map_dns(target, session=db_session, resolver=resolver)  # type: ignore[arg-type]
    summary = dns_mod.summarize(result)

    assert summary["domains_checked"] == 2
    assert isinstance(summary["domains"], list)
    # a.test: records present, b.test: missing everything
    a = next(d for d in summary["domains"] if d["domain"] == "a.test")
    assert a["spf"] == "v=spf1 -all"
    assert a["a"] == ["1.1.1.1"]
    b = next(d for d in summary["domains"] if d["domain"] == "b.test")
    assert b["spf"] is None
    assert b["a"] == []


async def test_resolver_exception_does_not_blow_up(db_session: Any) -> None:
    """Resolver exceptions are swallowed - the scan returns, no records."""
    target = await _make_target(db_session, scope=["flaky.test"])

    class _BadResolver:
        async def resolve(self, qname: str, rtype: str) -> Any:
            raise dns.resolver.NoNameservers()

    result = await dns_mod.map_dns(target, session=db_session, resolver=_BadResolver())  # type: ignore[arg-type]

    # SPF + DMARC both absent because every query errored → 2 findings.
    assert result.findings_created == 2


@pytest.mark.parametrize(
    "spf,should_emit",
    [
        ("v=spf1 all", True),            # bare "all" terminal
        ("v=spf1 +all", True),           # explicit permit
        ("v=spf1 -all", False),          # hard fail
        ("v=spf1 ~all", False),          # soft fail
        ("v=spf1 ?all", False),          # neutral
        ("v=spf1 include:_spf.google.com -all", False),  # includes + hard fail
    ],
)
async def test_spf_terminal_matrix(db_session: Any, spf: str, should_emit: bool) -> None:
    target = await _make_target(db_session, scope=["matrix.test"])
    resolver = _FakeResolver({
        ("matrix.test", "TXT"): [spf],
        ("_dmarc.matrix.test", "TXT"): ["v=DMARC1; p=reject"],
        ("matrix.test", "NS"): ["a.", "b."],
    })

    result = await dns_mod.map_dns(target, session=db_session, resolver=resolver)  # type: ignore[arg-type]

    spf_findings = [f for f in (
        await db_session.execute(select(Finding).where(Finding.target_id == target.id))
    ).scalars() if "SPF" in f.description]
    assert bool(spf_findings) == should_emit
