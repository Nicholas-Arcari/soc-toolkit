"""Server-side OSINT investigation history (persist + list)."""

import pytest
from sqlalchemy import select

from api.routes.investigate import _save_investigation
from db.models import Investigation
from db.session import init_db, new_session


@pytest.mark.asyncio
async def test_save_investigation_persists() -> None:
    await init_db()  # idempotent; the app lifespan does this in production
    await _save_investigation(
        "fingerprint", "https://hist.test", "2 technologies", {"ok": True}
    )
    async with new_session() as session:
        rows = (
            (
                await session.execute(
                    select(Investigation).where(
                        Investigation.query == "https://hist.test"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert any(row.summary == "2 technologies" for row in rows)
    assert any(row.kind == "fingerprint" for row in rows)
