"""Normalize investigative OSINT results into a cytoscape-compatible graph.

The frontend renders results with react-cytoscapejs, which expects
``{ nodes: [{data: {id, label, type}}], edges: [{data: {source, target, label}}] }``.
Keeping the normalization server-side means the frontend graph
component doesn't need investigation-specific knowledge - it's a
generic graph viewer that gets fed whatever shape the backend produces.

Node IDs are ``type:value`` composites so the same email across two
lookups coalesces to one node. Edges are deduped per ``(source,
target, label)`` triple for the same reason.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.investigate.breach_search import BreachSearchResult
from core.investigate.image_metadata import GPSCoords, ImageMetadataResult
from core.investigate.username_search import UsernameSearchResult


def _gps_meta(gps: GPSCoords) -> dict[str, str]:
    meta = {
        "latitude": f"{gps.latitude}",
        "longitude": f"{gps.longitude}",
    }
    if gps.altitude is not None:
        meta["altitude"] = f"{gps.altitude}"
    return meta


@dataclass
class GraphNode:
    id: str
    label: str
    type: str  # "username" | "email" | "domain" | "image" | "platform" | "breach" | "location"
    meta: dict[str, str] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    label: str


@dataclass
class EntityGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def _add_node(self, node: GraphNode) -> None:
        if not any(n.id == node.id for n in self.nodes):
            self.nodes.append(node)

    def _add_edge(self, edge: GraphEdge) -> None:
        if not any(
            e.source == edge.source and e.target == edge.target and e.label == edge.label
            for e in self.edges
        ):
            self.edges.append(edge)


def _nid(kind: str, value: str) -> str:
    return f"{kind}:{value.lower()}"


def graph_from_username(result: UsernameSearchResult) -> EntityGraph:
    """Root = username node. Platform nodes for each 'present' hit.

    Inconclusive hits are deliberately **not** rendered as edges -
    painting a "maybe" edge is misleading. The UI shows those in a
    separate list under the graph.
    """
    graph = EntityGraph()
    root_id = _nid("username", result.username)
    graph._add_node(
        GraphNode(id=root_id, label=result.username, type="username")
    )

    for hit in result.hits:
        if hit.status != "present":
            continue
        platform_id = _nid("platform", hit.platform)
        graph._add_node(
            GraphNode(
                id=platform_id,
                label=hit.platform,
                type="platform",
                meta={"category": hit.category, "url": hit.url},
            )
        )
        graph._add_edge(GraphEdge(source=root_id, target=platform_id, label="account_on"))

    return graph


def graph_from_breaches(result: BreachSearchResult) -> EntityGraph:
    """Root = email or domain. One breach node per HIBP record.

    In degraded mode (``available=False``) only the root is emitted,
    plus a synthetic "unavailable" note node so the UI still renders
    something rather than a blank canvas.
    """
    graph = EntityGraph()
    root_id = _nid(result.kind, result.query)
    graph._add_node(GraphNode(id=root_id, label=result.query, type=result.kind))

    if not result.available:
        note_id = f"note:{result.kind}:{result.query}"
        graph._add_node(
            GraphNode(
                id=note_id,
                label="HIBP unavailable",
                type="note",
                meta={"reason": result.note},
            )
        )
        graph._add_edge(GraphEdge(source=root_id, target=note_id, label="note"))
        return graph

    for breach in result.breaches:
        breach_id = _nid("breach", breach.name or breach.title)
        graph._add_node(
            GraphNode(
                id=breach_id,
                label=breach.title or breach.name,
                type="breach",
                meta={
                    "domain": breach.domain,
                    "breach_date": breach.breach_date,
                    "pwn_count": str(breach.pwn_count),
                    "data_classes": ",".join(breach.data_classes),
                },
            )
        )
        graph._add_edge(GraphEdge(source=root_id, target=breach_id, label="exposed_in"))

    return graph


def graph_from_image(result: ImageMetadataResult) -> EntityGraph:
    """Root = filename. Nodes for location (if GPS), camera, software."""
    graph = EntityGraph()
    root_id = _nid("image", result.filename)
    graph._add_node(
        GraphNode(
            id=root_id,
            label=result.filename,
            type="image",
            meta={"format": result.format, "size_bytes": str(result.size_bytes)},
        )
    )

    if result.gps:
        loc_id = _nid("location", f"{result.gps.latitude:.5f},{result.gps.longitude:.5f}")
        graph._add_node(
            GraphNode(
                id=loc_id,
                label=f"{result.gps.latitude:.5f}, {result.gps.longitude:.5f}",
                type="location",
                meta=_gps_meta(result.gps),
            )
        )
        graph._add_edge(GraphEdge(source=root_id, target=loc_id, label="taken_at"))

    camera_bits = [
        result.exif.get("camera_make", ""),
        result.exif.get("camera_model", ""),
    ]
    camera_label = " ".join(b for b in camera_bits if b).strip()
    if camera_label:
        cam_id = _nid("camera", camera_label)
        graph._add_node(GraphNode(id=cam_id, label=camera_label, type="camera"))
        graph._add_edge(GraphEdge(source=root_id, target=cam_id, label="captured_by"))

    software = result.exif.get("software", "")
    if software:
        sw_id = _nid("software", software)
        graph._add_node(GraphNode(id=sw_id, label=software, type="software"))
        graph._add_edge(GraphEdge(source=root_id, target=sw_id, label="processed_by"))

    return graph
