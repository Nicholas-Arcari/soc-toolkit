"""Target-scoped CSV writers.

Every function takes the already-fetched ORM rows (kept simple on the
route side) and returns bytes ready to stream. Keeping the writers
pure - no DB access inside - makes them trivial to unit-test and
safe to reuse from a future background-job exporter.
"""
from __future__ import annotations

import csv
import io
from collections.abc import Iterable

from db.models import Finding, Service, Subdomain


def _rows_to_csv(header: list[str], rows: Iterable[list[object]]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for row in rows:
        writer.writerow(row)
    # utf-8-sig so Excel on Windows shows accented characters correctly
    # without the user having to pick an import encoding.
    return buf.getvalue().encode("utf-8-sig")


def subdomains_csv(subdomains: Iterable[Subdomain]) -> bytes:
    return _rows_to_csv(
        ["fqdn", "source", "first_seen", "last_seen"],
        (
            [
                s.fqdn,
                s.source,
                s.first_seen.isoformat(),
                s.last_seen.isoformat(),
            ]
            for s in subdomains
        ),
    )


def services_csv(services: Iterable[Service]) -> bytes:
    return _rows_to_csv(
        ["ip", "port", "banner", "cves", "first_seen", "last_seen"],
        (
            [
                s.ip,
                s.port,
                s.banner,
                ";".join(s.cves or []),
                s.first_seen.isoformat(),
                s.last_seen.isoformat(),
            ]
            for s in services
        ),
    )


def findings_csv(findings: Iterable[Finding]) -> bytes:
    return _rows_to_csv(
        [
            "id",
            "severity",
            "category",
            "status",
            "description",
            "note",
            "created_at",
            "resolved_at",
        ],
        (
            [
                f.id,
                f.severity,
                f.category,
                f.status,
                f.description,
                f.note,
                f.created_at.isoformat(),
                f.resolved_at.isoformat() if f.resolved_at else "",
            ]
            for f in findings
        ),
    )
