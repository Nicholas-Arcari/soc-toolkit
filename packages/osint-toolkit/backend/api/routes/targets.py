"""CRUD for scan targets.

A `Target` is an authorized-to-scan perimeter. Because this toolkit is
intended for public open-source release, the authorization acknowledgment
is enforced **server-side** - a client that skips the UI checkbox and
POSTs directly still cannot create a target without flipping the flag.
That's the single knob separating "research tool" from "abuse tool".
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Target
from db.session import get_session

router = APIRouter()


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    # Contact string, not a login identifier - kept as free-form so local
    # single-user installs don't need a real address.
    owner_email: str = Field(default="", max_length=255)
    scope_domains: list[str] = Field(default_factory=list)
    # Must be True to create. The API rejects False explicitly (400) so
    # accidentally omitting the checkbox fails loud, not silent.
    authorized_to_scan: bool

    @field_validator("scope_domains")
    @classmethod
    def _normalize_scope(cls, value: list[str]) -> list[str]:
        """Lowercase + dedupe domains; reject obvious non-domains."""
        cleaned: list[str] = []
        for raw in value:
            domain = raw.strip().lower().rstrip(".")
            if not domain or "/" in domain or " " in domain:
                raise ValueError(f"invalid scope domain: {raw!r}")
            if domain not in cleaned:
                cleaned.append(domain)
        return cleaned


class TargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    owner_email: str | None = Field(default=None, max_length=255)
    scope_domains: list[str] | None = None
    active: bool | None = None

    @field_validator("scope_domains")
    @classmethod
    def _normalize_scope(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        cleaned: list[str] = []
        for raw in value:
            domain = raw.strip().lower().rstrip(".")
            if not domain or "/" in domain or " " in domain:
                raise ValueError(f"invalid scope domain: {raw!r}")
            if domain not in cleaned:
                cleaned.append(domain)
        return cleaned


class TargetOut(BaseModel):
    id: int
    name: str
    owner_email: str
    scope_domains: list[str]
    authorized_to_scan: bool
    active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


def _to_out(target: Target) -> TargetOut:
    return TargetOut.model_validate(target)


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreate,
    session: AsyncSession = Depends(get_session),
) -> TargetOut:
    """Register a new scannable perimeter.

    The `authorized_to_scan=True` gate is mandatory - the whole project
    presumes written authorization to scan. Rejecting False here is the
    server-side enforcement of the UI checkbox.
    """
    if not payload.authorized_to_scan:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "authorized_to_scan must be True - confirm you have written "
                "authorization to scan this perimeter before creating the target."
            ),
        )
    target = Target(
        name=payload.name,
        owner_email=payload.owner_email,
        scope_domains=payload.scope_domains,
        authorized_to_scan=True,
        active=True,
    )
    session.add(target)
    await session.flush()
    await session.refresh(target)
    return _to_out(target)


@router.get("", response_model=list[TargetOut])
async def list_targets(
    include_inactive: bool = False,
    session: AsyncSession = Depends(get_session),
) -> list[TargetOut]:
    """List targets, active-only by default."""
    stmt = select(Target).order_by(Target.created_at.desc())
    if not include_inactive:
        stmt = stmt.where(Target.active.is_(True))
    result = await session.execute(stmt)
    return [_to_out(t) for t in result.scalars().all()]


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> TargetOut:
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    return _to_out(target)


@router.patch("/{target_id}", response_model=TargetOut)
async def update_target(
    target_id: int,
    payload: TargetUpdate,
    session: AsyncSession = Depends(get_session),
) -> TargetOut:
    """Partial update. `authorized_to_scan` is deliberately not editable:
    re-authorizing a scope requires deleting and re-creating the target,
    which forces the operator back through the gate.
    """
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")

    data = payload.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(target, field, value)

    await session.flush()
    await session.refresh(target)
    return _to_out(target)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: int,
    session: AsyncSession = Depends(get_session),
) -> None:
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")
    await session.delete(target)
