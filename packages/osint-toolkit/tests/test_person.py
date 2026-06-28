"""Person OSINT orchestration: pure helpers + mocked async sources."""

from unittest.mock import AsyncMock, patch

import pytest

from core.investigate.breach_search import BreachSearchResult
from core.investigate.person import (
    GravatarProfile,
    PersonValidationError,
    dork_links,
    investigate_person,
    username_candidates,
)
from core.investigate.username_search import UsernameHit, UsernameSearchResult


def test_username_candidates_from_email_and_name() -> None:
    candidates = username_candidates("john.doe@acme.com", "John Doe", "")
    assert "john.doe" in candidates
    assert "johndoe" in candidates
    assert "jdoe" in candidates
    # an explicit handle is preferred (comes first)
    assert username_candidates("a@b.com", "", "kingpin")[0] == "kingpin"


def test_dork_links_embed_disambiguators() -> None:
    links = dork_links("", "John Doe", "Acme Corp", "Berlin")
    google = next(link for link in links if link.label == "Google")
    assert "John+Doe" in google.url
    assert any("linkedin.com" in link.url for link in links)
    assert any("Acme" in link.url for link in links)
    # nothing to search on → no links
    assert dork_links("", "", "", "") == []


@pytest.mark.asyncio
async def test_requires_email_or_name() -> None:
    with pytest.raises(PersonValidationError):
        await investigate_person()


@pytest.mark.asyncio
async def test_orchestration_builds_graph_from_mocked_sources() -> None:
    username_result = UsernameSearchResult(
        username="johndoe",
        hits=[
            UsernameHit(
                platform="GitHub",
                category="dev",
                url="https://github.com/johndoe",
                status="present",
                http_status=200,
            )
        ],
        checked=1,
        present_count=1,
    )
    breaches = BreachSearchResult(
        query="john.doe@acme.com", kind="email", available=True, breaches=[], note=""
    )
    gravatar = GravatarProfile(
        found=True,
        avatar_url="https://www.gravatar.com/avatar/x",
        profile_url="https://www.gravatar.com/x",
        display_name="John Doe",
    )

    with (
        patch("core.investigate.person._gravatar", AsyncMock(return_value=gravatar)),
        patch("core.investigate.person._has_mx", AsyncMock(return_value=True)),
        patch(
            "core.investigate.person.search_username",
            AsyncMock(return_value=username_result),
        ),
        patch(
            "core.investigate.person.search_breaches",
            AsyncMock(return_value=breaches),
        ),
    ):
        result = await investigate_person(
            email="john.doe@acme.com", name="John Doe", org="Acme", location="Berlin"
        )

    assert result.gravatar is not None and result.gravatar.found
    assert result.email_hygiene is not None and result.email_hygiene.has_mx is True
    assert result.username_result is not None
    assert result.username_result.present_count == 1
    assert result.dorks

    node_types = {node.type for node in result.graph.nodes}
    assert {"email", "profile", "username", "platform", "org", "location"} <= node_types
    assert any(edge.label == "uses_handle" for edge in result.graph.edges)
