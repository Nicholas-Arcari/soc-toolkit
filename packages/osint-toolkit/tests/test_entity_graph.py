"""Entity-graph normalizer tests.

Shape-focused: cytoscape expects specific keys (``data.id``,
``data.source``, ``data.target``). These tests guard the output shape
so renaming an internal field doesn't silently break the frontend.
"""
from __future__ import annotations

from core.investigate.breach_search import BreachRecord, BreachSearchResult
from core.investigate.entity_graph import (
    graph_from_breaches,
    graph_from_image,
    graph_from_username,
)
from core.investigate.image_metadata import GPSCoords, ImageMetadataResult
from core.investigate.username_search import (
    UsernameHit,
    UsernameSearchResult,
)


def _username_result(hits: list[UsernameHit]) -> UsernameSearchResult:
    return UsernameSearchResult(
        username="alice",
        hits=hits,
        checked=len(hits),
        present_count=sum(1 for h in hits if h.status == "present"),
    )


def test_username_graph_has_username_root_and_platform_children() -> None:
    result = _username_result(
        [
            UsernameHit(
                platform="GitHub",
                category="code",
                url="https://github.com/alice",
                status="present",
                http_status=200,
            ),
            UsernameHit(
                platform="GitLab",
                category="code",
                url="https://gitlab.com/alice",
                status="absent",
                http_status=404,
            ),
        ]
    )
    graph = graph_from_username(result)

    node_ids = {n.id for n in graph.nodes}
    assert "username:alice" in node_ids
    assert "platform:github" in node_ids
    # Absent hits must NOT be rendered - a "maybe" edge is worse than none.
    assert "platform:gitlab" not in node_ids

    edge_labels = {(e.source, e.target, e.label) for e in graph.edges}
    assert ("username:alice", "platform:github", "account_on") in edge_labels


def test_username_graph_skips_inconclusive() -> None:
    """Rate-limited probes must not land on the graph."""
    result = _username_result(
        [
            UsernameHit(
                platform="Cloudy",
                category="test",
                url="https://x.test/alice",
                status="inconclusive",
                http_status=403,
                note="blocked",
            ),
        ]
    )
    graph = graph_from_username(result)

    assert len(graph.nodes) == 1
    assert graph.edges == []


def test_breach_graph_degraded_mode_emits_note_node() -> None:
    """Unavailable state still gets a graph so the UI isn't blank."""
    result = BreachSearchResult(
        query="user@example.com",
        kind="email",
        available=False,
        note="HIBP unavailable",
    )
    graph = graph_from_breaches(result)

    node_types = {n.type for n in graph.nodes}
    assert node_types == {"email", "note"}


def test_breach_graph_populated_case() -> None:
    result = BreachSearchResult(
        query="user@example.com",
        kind="email",
        available=True,
        breaches=[
            BreachRecord(
                name="Adobe",
                title="Adobe",
                domain="adobe.com",
                breach_date="2013-10-04",
                pwn_count=100,
                data_classes=["Email addresses"],
            ),
        ],
    )
    graph = graph_from_breaches(result)

    breach_nodes = [n for n in graph.nodes if n.type == "breach"]
    assert len(breach_nodes) == 1
    assert breach_nodes[0].meta["domain"] == "adobe.com"


def test_image_graph_emits_location_camera_software_nodes() -> None:
    result = ImageMetadataResult(
        filename="trip.jpg",
        format="JPEG",
        size_px=(100, 100),
        size_bytes=1234,
        exif={
            "camera_make": "Canon",
            "camera_model": "EOS R5",
            "software": "Lightroom",
        },
        gps=GPSCoords(latitude=48.85, longitude=2.35),
    )
    graph = graph_from_image(result)

    types = {n.type for n in graph.nodes}
    assert {"image", "location", "camera", "software"} <= types


def test_image_graph_without_gps_or_camera_still_has_root() -> None:
    """Stripped image → only the filename node survives."""
    result = ImageMetadataResult(
        filename="stripped.png",
        format="PNG",
        size_px=(4, 4),
        size_bytes=100,
        exif={},
        gps=None,
    )
    graph = graph_from_image(result)

    assert [n.id for n in graph.nodes] == ["image:stripped.png"]
    assert graph.edges == []


def test_graph_dedupes_repeat_nodes() -> None:
    """Same platform claimed twice shouldn't double the node or edge."""
    result = _username_result(
        [
            UsernameHit(
                platform="GitHub",
                category="code",
                url="https://github.com/alice",
                status="present",
                http_status=200,
            ),
            UsernameHit(
                platform="GitHub",
                category="code",
                url="https://github.com/alice",
                status="present",
                http_status=200,
            ),
        ]
    )
    graph = graph_from_username(result)

    assert len(graph.nodes) == 2  # username + platform
    assert len(graph.edges) == 1
