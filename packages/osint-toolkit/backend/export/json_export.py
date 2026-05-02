"""Full-engagement JSON snapshot.

One call produces a deterministic package of everything the toolkit
knows about a target: scope, scan history, discovered assets, open
services, findings (with triage state). Intended for machine
consumption - archival, feeding into a downstream SIEM, or handing
off to another analyst in a different tool.
"""
from __future__ import annotations

import json
from typing import Any

from db.models import Finding, Scan, Service, Subdomain, Target


def engagement_report(
    target: Target,
    scans: list[Scan],
    subdomains: list[Subdomain],
    services: list[Service],
    findings: list[Finding],
) -> bytes:
    """Serialize the target + all persistent state into a single JSON blob."""
    payload: dict[str, Any] = {
        "target": {
            "id": target.id,
            "name": target.name,
            "owner_email": target.owner_email,
            "scope_domains": list(target.scope_domains or []),
            "authorized_to_scan": target.authorized_to_scan,
            "active": target.active,
            "created_at": target.created_at.isoformat(),
        },
        "scans": [
            {
                "id": s.id,
                "kind": s.kind,
                "status": s.status,
                "started_at": s.started_at.isoformat(),
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                "summary": s.summary or {},
                "error": s.error,
            }
            for s in scans
        ],
        "subdomains": [
            {
                "fqdn": s.fqdn,
                "source": s.source,
                "first_seen": s.first_seen.isoformat(),
                "last_seen": s.last_seen.isoformat(),
            }
            for s in subdomains
        ],
        "services": [
            {
                "subdomain_id": s.subdomain_id,
                "ip": s.ip,
                "port": s.port,
                "banner": s.banner,
                "cves": list(s.cves or []),
                "first_seen": s.first_seen.isoformat(),
                "last_seen": s.last_seen.isoformat(),
            }
            for s in services
        ],
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "category": f.category,
                "status": f.status,
                "description": f.description,
                "note": f.note,
                "created_at": f.created_at.isoformat(),
                "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2).encode("utf-8")
