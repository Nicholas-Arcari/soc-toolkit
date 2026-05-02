"""SQLAlchemy ORM models for OSINT toolkit persistent state.

Unlike soc-toolkit's disposable cache, these tables hold long-lived
target/scan/finding history - the toolkit treats each target as an
ongoing engagement, not a one-shot query.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


class Target(Base):
    """An authorized-to-scan perimeter.

    `scope_domains` is a JSON list of root domains in scope. Any
    subdomain discovered must end in one of these - prevents scope
    creep when passive sources return neighbor domains.
    """

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_email: Mapped[str] = mapped_column(String(255), default="")
    scope_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Must be True to create - forces the authorization gate server-side
    # even if the UI checkbox is bypassed.
    authorized_to_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scans: Mapped[list[Scan]] = relationship(back_populates="target", cascade="all, delete-orphan")
    subdomains: Mapped[list[Subdomain]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class Scan(Base):
    """One run against a target - passive enum, service discovery, etc.

    `kind` discriminates the scan type (``subdomain_enum``,
    ``service_discovery``, ...) so the UI can render the right
    progress/result view.
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    target: Mapped[Target] = relationship(back_populates="scans")


class Subdomain(Base):
    """Discovered subdomain with first/last-seen tracking.

    Unique per ``(target_id, fqdn)`` so re-scans update the last-seen
    timestamp instead of duplicating rows - the pattern the UI needs to
    show "discovered N days ago, still present" vs "appeared once".
    """

    __tablename__ = "subdomains"
    # DB-level uniqueness prevents two concurrent scans from both racing
    # past the SELECT-then-INSERT check in `enumerate_subdomains`. The
    # application already dedupes, but relying on app code alone is the
    # classic TOCTOU mistake - let the DB enforce it.
    __table_args__ = (UniqueConstraint("target_id", "fqdn", name="uq_subdomains_target_fqdn"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    fqdn: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    target: Mapped[Target] = relationship(back_populates="subdomains")


class Service(Base):
    """Open port / banner observed on a subdomain's resolved IP."""

    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subdomain_id: Mapped[int] = mapped_column(ForeignKey("subdomains.id", ondelete="CASCADE"))
    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    banner: Mapped[str] = mapped_column(Text, default="")
    cves: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Finding(Base):
    """Analyst-visible issue raised by a scan - CVE exposure, SPF gap, etc.

    Carries severity so the UI can sort, a category for filter chips,
    and a free-form description. Findings outlive scans: a scan
    completes, but findings persist until remediated.

    ``status`` carries triage state: ``open`` (default, fresh from a
    scan), ``acknowledged`` (seen by analyst but not yet worked),
    ``resolved`` (underlying issue fixed), ``false_positive`` (the scan
    flagged it but it was never a real exposure). ``resolved_at`` is
    set whenever the status transitions out of ``open``/``acknowledged``
    so the UI can show when remediation landed.
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    severity: Mapped[str] = mapped_column(String(16), default="info")
    category: Mapped[str] = mapped_column(String(64), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    target: Mapped[Target] = relationship(back_populates="findings")
