"""Scan routes.

Currently exposes passive subdomain enumeration - more kinds (service
discovery, DNS mapping) will register through the same `kind` field on
the `Scan` model.
"""
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sec_common.integrations import CrtShClient, SecurityTrailsClient, ShodanClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from core.asm import dns_mapping as dns_mod
from core.asm import service_discovery as svc_mod
from core.asm.active_enum import (
    ActiveScannerUnavailableError,
    active_enumerate,
)
from core.asm.subdomain_enum import EnumClients, enumerate_subdomains, summarize
from core.notifications import notify_severe_findings
from db.models import Finding, Scan, Service, Subdomain, Target
from db.session import get_session
from export import csv_export, json_export

router = APIRouter()


class SubdomainEnumResponse(BaseModel):
    scan_id: int
    target_id: int
    status: str
    summary: dict[str, object]
    subdomains: list[str]


class SubdomainRow(BaseModel):
    fqdn: str
    source: str
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


def _build_enum_clients() -> EnumClients:
    """Settings → enum DI bundle. SecurityTrails degrades to no-op w/o key."""
    return EnumClients(
        crtsh=CrtShClient(),
        securitytrails=SecurityTrailsClient(api_key=settings.get_api_key("securitytrails")),
    )


@router.post(
    "/targets/{target_id}/subdomain-enum",
    response_model=SubdomainEnumResponse,
    status_code=status.HTTP_201_CREATED,
)
async def run_subdomain_enum(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> SubdomainEnumResponse:
    """Run a passive subdomain enum scan against an authorized target.

    A `Scan` row is created up-front (status=running) and flipped to
    completed/failed once the enumerator returns - so a long-running scan
    is visible in the UI while it's in flight, and failures leave a
    durable trail instead of disappearing.
    """
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    if not target.authorized_to_scan:
        # Defense-in-depth: the create-gate already enforces this, but
        # re-check in case the model was ever mutated elsewhere.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target is not authorized for scanning",
        )

    scan = Scan(target_id=target.id, kind="subdomain_enum", status="running")
    session.add(scan)
    await session.flush()

    try:
        result = await enumerate_subdomains(
            target, clients=_build_enum_clients(), session=session
        )
    except Exception as exc:
        # Commit the failure state **before** re-raising. Without the explicit
        # commit, the `get_session` dependency rolls the whole transaction
        # back on exception - including this "failed" update - and the scan
        # row disappears, defeating the point of creating it up-front.
        scan.status = "failed"
        scan.error = str(exc)[:1024]
        scan.finished_at = datetime.now(UTC)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"subdomain enumeration failed: {exc}",
        ) from exc

    scan.status = "completed"
    scan.finished_at = datetime.now(UTC)
    scan.summary = summarize(result)
    await session.flush()

    return SubdomainEnumResponse(
        scan_id=scan.id,
        target_id=target.id,
        status=scan.status,
        summary=scan.summary,
        subdomains=result.discovered,
    )


@router.get(
    "/targets/{target_id}/subdomains",
    response_model=list[SubdomainRow],
)
async def list_subdomains(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> list[SubdomainRow]:
    """List currently known subdomains for a target (last_seen desc)."""
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")

    stmt = (
        select(Subdomain)
        .where(Subdomain.target_id == target_id)
        .order_by(Subdomain.last_seen.desc())
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [SubdomainRow.model_validate(r) for r in rows]


class DNSMappingResponse(BaseModel):
    scan_id: int
    target_id: int
    status: str
    summary: dict[str, Any]


class ServiceRow(BaseModel):
    subdomain_id: int
    ip: str
    port: int
    banner: str
    cves: list[str]
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class FindingRow(BaseModel):
    id: int
    severity: str
    category: str
    description: str
    status: str
    note: str
    created_at: datetime
    resolved_at: datetime | None = None

    model_config = {"from_attributes": True}


# Accepted lifecycle transitions. `open` is the landing state; `resolved`
# and `false_positive` are terminal in practice but the API allows moves
# back to `open` for analysts who misclicked.
_VALID_FINDING_STATUSES = {"open", "acknowledged", "resolved", "false_positive"}


class FindingUpdate(BaseModel):
    status: str | None = None
    note: str | None = None


class ActiveScanRequest(BaseModel):
    """Active-scan body - ``confirmation`` must match target.name verbatim.

    Forces the analyst to re-state the scope they're about to probe.
    A tick-box UI by itself is muscle-memory; typing the name is
    friction that scales with how often you do it. The exact value
    check is case-insensitive.
    """

    confirmation: str


class ActiveScanResponse(BaseModel):
    scan_id: int
    target_id: int
    status: str
    summary: dict[str, Any]
    discovered: list[str]


async def _run_scan(
    session: AsyncSession,
    target_id: int,
    kind: str,
    body: Any,
) -> tuple[Scan, Target, Any]:
    """Shared scaffolding: create pending scan, resolve target, execute body.

    The body callable receives (target, session) and returns a result
    object. We take care of the status bookkeeping around it so every
    scan kind gets the same "row appears up-front / survives failure"
    behaviour.
    """
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    if not target.authorized_to_scan:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target is not authorized for scanning",
        )

    scan = Scan(target_id=target.id, kind=kind, status="running")
    session.add(scan)
    await session.flush()

    try:
        result = await body(target, session)
    except Exception as exc:
        scan.status = "failed"
        scan.error = str(exc)[:1024]
        scan.finished_at = datetime.now(UTC)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"{kind} failed: {exc}",
        ) from exc

    return scan, target, result


async def _dispatch_webhook(
    session: AsyncSession, target: Target, scan: Scan
) -> None:
    """Fire outbound webhook for severe findings created during this scan.

    Matches "during this scan" by ``created_at >= scan.started_at`` on
    findings tied to this target. Cheap, index-friendly, and tolerates
    scans that don't bother setting ``scan_id`` on every finding they
    emit. The webhook module itself handles empty URLs and transport
    errors quietly - this helper stays a plain fire-and-forget.
    """
    if not settings.webhook_url:
        return
    new_findings = (
        await session.execute(
            select(Finding)
            .where(Finding.target_id == target.id)
            .where(Finding.created_at >= scan.started_at)
        )
    ).scalars().all()
    await notify_severe_findings(
        target=target,
        findings=new_findings,
        webhook_url=settings.webhook_url,
    )


@router.post(
    "/targets/{target_id}/dns-mapping",
    response_model=DNSMappingResponse,
    status_code=status.HTTP_201_CREATED,
)
async def run_dns_mapping(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> DNSMappingResponse:
    """Resolve scope domains and flag email-auth misconfigurations.

    Persists findings for SPF/DMARC/NS issues; the raw record set is
    returned inside the scan summary so the UI can render a per-domain
    card without an extra query.
    """
    async def _body(target: Target, session: AsyncSession) -> dns_mod.DNSMappingResult:
        return await dns_mod.map_dns(target, session=session)

    scan, target, result = await _run_scan(session, target_id, "dns_mapping", _body)
    scan.status = "completed"
    scan.finished_at = datetime.now(UTC)
    scan.summary = dns_mod.summarize(result)
    await session.flush()

    await _dispatch_webhook(session, target, scan)

    return DNSMappingResponse(
        scan_id=scan.id,
        target_id=target_id,
        status=scan.status,
        summary=scan.summary,
    )


@router.post(
    "/targets/{target_id}/active-scan",
    response_model=ActiveScanResponse,
    status_code=status.HTTP_201_CREATED,
)
async def run_active_scan(
    target_id: int,
    body: ActiveScanRequest,
    session: AsyncSession = Depends(get_session),
) -> ActiveScanResponse:
    """Run an active subdomain scan (Amass/Subfinder subprocess).

    Gated on three axes - a misconfigured instance fails before a
    single DNS query is issued:

    1. ``settings.enable_active_scanning`` must be ``True`` - the
       operator has to flip the env var deliberately.
    2. ``target.authorized_to_scan`` must be ``True`` - the scope
       gate enforced on every scan.
    3. ``body.confirmation`` must equal ``target.name`` (case-insensitive)
       - per-request friction to stop accidental probes.

    A missing Amass/Subfinder binary returns 503 so the UI can surface
    a helpful install hint instead of a stack trace.
    """
    if not settings.enable_active_scanning:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "active scanning is disabled; set OSINT_ENABLE_ACTIVE_SCANNING=true "
                "to enable it on this instance"
            ),
        )

    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    if not target.authorized_to_scan:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target is not authorized for scanning",
        )
    if body.confirmation.strip().lower() != target.name.strip().lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="confirmation must match the target name",
        )

    scope = list(target.scope_domains or [])
    if not scope:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target has no scope_domains - refusing to run active scan",
        )

    scan = Scan(target_id=target.id, kind="active_enum", status="running")
    session.add(scan)
    await session.flush()

    discovered: set[str] = set()
    stderr_tail: list[str] = []
    tool_used = ""
    try:
        for root in scope:
            result = await active_enumerate(root)
            tool_used = result.tool
            discovered.update(result.discovered)
            if result.stderr:
                stderr_tail.append(result.stderr[-512:])
    except ActiveScannerUnavailableError as exc:
        scan.status = "failed"
        scan.error = str(exc)[:1024]
        scan.finished_at = datetime.now(UTC)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        scan.status = "failed"
        scan.error = str(exc)[:1024]
        scan.finished_at = datetime.now(UTC)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"active scan failed: {exc}",
        ) from exc

    now = datetime.now(UTC)
    existing_stmt = select(Subdomain).where(
        Subdomain.target_id == target.id,
        Subdomain.fqdn.in_(sorted(discovered)) if discovered else Subdomain.fqdn.is_(None),
    )
    existing = {
        s.fqdn: s for s in (await session.execute(existing_stmt)).scalars()
    }
    new_count = 0
    for fqdn in sorted(discovered):
        if fqdn in existing:
            existing[fqdn].last_seen = now
        else:
            session.add(
                Subdomain(
                    target_id=target.id,
                    fqdn=fqdn,
                    source=f"active:{tool_used}" if tool_used else "active",
                    first_seen=now,
                    last_seen=now,
                )
            )
            new_count += 1

    scan.status = "completed"
    scan.finished_at = now
    scan.summary = {
        "tool": tool_used,
        "discovered_total": len(discovered),
        "new": new_count,
        "stderr_tail": stderr_tail[-3:],
    }
    await session.flush()

    return ActiveScanResponse(
        scan_id=scan.id,
        target_id=target.id,
        status=scan.status,
        summary=scan.summary,
        discovered=sorted(discovered),
    )


def _build_discovery_clients() -> svc_mod.DiscoveryClients:
    return svc_mod.DiscoveryClients(
        shodan=ShodanClient(api_key=settings.get_api_key("shodan")),
    )


@router.post(
    "/targets/{target_id}/service-discovery",
    response_model=DNSMappingResponse,
    status_code=status.HTTP_201_CREATED,
)
async def run_service_discovery(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> DNSMappingResponse:
    """Query Shodan for open ports / banners / CVEs on every resolved IP.

    Depends on a prior subdomain enum - nothing to enrich if the target
    has no subdomains yet. Degrades cleanly without SHODAN_API_KEY.
    """
    async def _body(target: Target, session: AsyncSession) -> svc_mod.DiscoveryResult:
        return await svc_mod.discover_services(
            target, clients=_build_discovery_clients(), session=session
        )

    scan, target, result = await _run_scan(session, target_id, "service_discovery", _body)
    scan.status = "completed"
    scan.finished_at = datetime.now(UTC)
    scan.summary = svc_mod.summarize(result)
    await session.flush()

    await _dispatch_webhook(session, target, scan)

    return DNSMappingResponse(
        scan_id=scan.id,
        target_id=target_id,
        status=scan.status,
        summary=scan.summary,
    )


@router.get(
    "/targets/{target_id}/services",
    response_model=list[ServiceRow],
)
async def list_services(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> list[ServiceRow]:
    """Open services observed on this target's resolved IPs (last_seen desc)."""
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")

    stmt = (
        select(Service)
        .join(Subdomain, Service.subdomain_id == Subdomain.id)
        .where(Subdomain.target_id == target_id)
        .order_by(Service.last_seen.desc())
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [ServiceRow.model_validate(r) for r in rows]


@router.get(
    "/targets/{target_id}/findings",
    response_model=list[FindingRow],
)
async def list_findings(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> list[FindingRow]:
    """Analyst-visible issues raised against this target (newest first)."""
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")

    stmt = (
        select(Finding)
        .where(Finding.target_id == target_id)
        .order_by(Finding.created_at.desc())
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [FindingRow.model_validate(r) for r in rows]


@router.patch(
    "/targets/{target_id}/findings/{finding_id}",
    response_model=FindingRow,
)
async def update_finding(
    target_id: int,
    finding_id: int,
    patch: FindingUpdate,
    session: AsyncSession = Depends(get_session),
) -> FindingRow:
    """Update triage state (status + note) on a finding.

    Stamps ``resolved_at`` on transitions to ``resolved`` /
    ``false_positive`` so the UI can show when remediation landed.
    Moving back to ``open``/``acknowledged`` clears the stamp.
    """
    finding = await session.get(Finding, finding_id)
    if finding is None or finding.target_id != target_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    if patch.status is not None:
        if patch.status not in _VALID_FINDING_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid status; expected one of {sorted(_VALID_FINDING_STATUSES)}",
            )
        terminal = {"resolved", "false_positive"}
        previously_terminal = finding.status in terminal
        finding.status = patch.status
        if patch.status in terminal and not previously_terminal:
            finding.resolved_at = datetime.now(UTC)
        elif patch.status not in terminal:
            finding.resolved_at = None

    if patch.note is not None:
        finding.note = patch.note

    await session.commit()
    await session.refresh(finding)
    return FindingRow.model_validate(finding)


async def _require_target(session: AsyncSession, target_id: int) -> Target:
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    return target


def _csv_response(body: bytes, filename: str) -> Response:
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/targets/{target_id}/export/subdomains.csv")
async def export_subdomains_csv(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """CSV of discovered subdomains (ordered by last_seen desc)."""
    target = await _require_target(session, target_id)
    rows = (
        await session.execute(
            select(Subdomain)
            .where(Subdomain.target_id == target_id)
            .order_by(Subdomain.last_seen.desc())
        )
    ).scalars().all()
    return _csv_response(
        csv_export.subdomains_csv(rows),
        f"{target.name}-subdomains.csv",
    )


@router.get("/targets/{target_id}/export/services.csv")
async def export_services_csv(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """CSV of open services across every resolved IP."""
    target = await _require_target(session, target_id)
    rows = (
        await session.execute(
            select(Service)
            .join(Subdomain, Service.subdomain_id == Subdomain.id)
            .where(Subdomain.target_id == target_id)
            .order_by(Service.last_seen.desc())
        )
    ).scalars().all()
    return _csv_response(
        csv_export.services_csv(rows),
        f"{target.name}-services.csv",
    )


@router.get("/targets/{target_id}/export/findings.csv")
async def export_findings_csv(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """CSV of findings with triage state (status, note, resolved_at)."""
    target = await _require_target(session, target_id)
    rows = (
        await session.execute(
            select(Finding)
            .where(Finding.target_id == target_id)
            .order_by(Finding.created_at.desc())
        )
    ).scalars().all()
    return _csv_response(
        csv_export.findings_csv(rows),
        f"{target.name}-findings.csv",
    )


@router.get("/targets/{target_id}/export/report.json")
async def export_engagement_report(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Machine-readable snapshot of the full engagement.

    Bundles target metadata, scan history, assets, services, and triaged
    findings in a single JSON payload - suitable for archival, handoff,
    or piping into an external SIEM.
    """
    target = await _require_target(session, target_id)
    scans = (
        await session.execute(
            select(Scan).where(Scan.target_id == target_id).order_by(Scan.started_at.desc())
        )
    ).scalars().all()
    subdomains = (
        await session.execute(
            select(Subdomain).where(Subdomain.target_id == target_id)
        )
    ).scalars().all()
    services = (
        await session.execute(
            select(Service)
            .join(Subdomain, Service.subdomain_id == Subdomain.id)
            .where(Subdomain.target_id == target_id)
        )
    ).scalars().all()
    findings = (
        await session.execute(
            select(Finding).where(Finding.target_id == target_id)
        )
    ).scalars().all()

    body = json_export.engagement_report(
        target=target,
        scans=list(scans),
        subdomains=list(subdomains),
        services=list(services),
        findings=list(findings),
    )
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{target.name}-report.json"',
        },
    )
