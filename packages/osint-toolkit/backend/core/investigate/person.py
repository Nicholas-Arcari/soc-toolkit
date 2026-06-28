"""Person-centric OSINT orchestration.

Combines free, no-key public sources around an email and/or name (plus
optional disambiguators - org, location, known handle) into one profile and
entity graph. The disambiguators tailor the search-engine "dork" links so the
operator narrows in on the right person rather than a same-name collision.

Interactive, no persistence (like the rest of investigate). Dork links are
emitted for the operator to click, never scraped, so we stay within search
engines' ToS. Public-info-only - the route surfaces the lawful-basis note.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import quote_plus

import dns.asyncresolver
import dns.exception
import httpx
from sec_common.integrations import HIBPClient

from config import settings
from core.investigate.breach_search import BreachSearchResult, search_breaches
from core.investigate.entity_graph import (
    EntityGraph,
    GraphEdge,
    GraphNode,
    graph_from_breaches,
    graph_from_username,
)
from core.investigate.username_search import (
    UsernameSearchResult,
    UsernameValidationError,
    search_username,
)

_DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "trashmail.com", "getnada.com",
    "temp-mail.org", "sharklasers.com", "maildrop.cc", "fakeinbox.com",
}
_ROLE_LOCALPARTS = {
    "admin", "administrator", "info", "support", "sales", "contact", "help",
    "noreply", "no-reply", "webmaster", "postmaster", "hostmaster", "abuse",
    "security", "marketing", "hr", "billing", "office", "team",
}


class PersonValidationError(ValueError):
    """Raised when neither an email nor a name is supplied."""


@dataclass
class GravatarProfile:
    found: bool
    avatar_url: str
    profile_url: str
    display_name: str


@dataclass
class EmailHygiene:
    email: str
    domain: str
    has_mx: bool
    disposable: bool
    role_account: bool


@dataclass
class DorkLink:
    label: str
    url: str


@dataclass
class PersonResult:
    email: str
    name: str
    org: str
    location: str
    gravatar: GravatarProfile | None
    email_hygiene: EmailHygiene | None
    username_candidates: list[str]
    username_result: UsernameSearchResult | None
    breaches: BreachSearchResult | None
    dorks: list[DorkLink] = field(default_factory=list)
    graph: EntityGraph = field(default_factory=EntityGraph)
    note: str = ""


_NOTE = (
    "Public, free sources only. Verify identity before acting - same-name "
    "collisions are common. A lawful basis is required (GDPR Art. 6); do not "
    "use for harassment, stalking or any unlawful purpose."
)


async def _gravatar(email: str) -> GravatarProfile:
    digest = hashlib.md5(
        email.strip().lower().encode(), usedforsecurity=False
    ).hexdigest()
    avatar_url = f"https://www.gravatar.com/avatar/{digest}"
    profile_url = f"https://www.gravatar.com/{digest}"
    found = False
    display_name = ""
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            avatar = await client.get(f"{avatar_url}?d=404&s=80")
            found = avatar.status_code == 200
            profile = await client.get(f"{profile_url}.json")
            if profile.status_code == 200:
                entry = (profile.json().get("entry") or [{}])[0]
                display_name = entry.get("displayName", "") or entry.get(
                    "preferredUsername", ""
                )
                found = True
    except (httpx.HTTPError, ValueError):
        pass
    return GravatarProfile(
        found=found,
        avatar_url=avatar_url,
        profile_url=profile_url,
        display_name=display_name,
    )


async def _has_mx(domain: str) -> bool:
    if not domain:
        return False
    try:
        answers = await dns.asyncresolver.resolve(domain, "MX")
        return len(answers) > 0
    except dns.exception.DNSException:
        return False


async def _email_hygiene(email: str) -> EmailHygiene:
    local, _, domain = email.partition("@")
    domain = domain.strip().lower()
    return EmailHygiene(
        email=email,
        domain=domain,
        has_mx=await _has_mx(domain),
        disposable=domain in _DISPOSABLE_DOMAINS,
        role_account=local.strip().lower() in _ROLE_LOCALPARTS,
    )


def username_candidates(email: str, name: str, handle: str) -> list[str]:
    """Plausible handles derived from the email local-part + name."""
    candidates: list[str] = []
    if handle.strip():
        candidates.append(handle.strip())
    if email:
        local = email.split("@", 1)[0]
        candidates.append(local)
        candidates.append(re.sub(r"[^a-z0-9]", "", local.lower()))
    parts = [p for p in re.split(r"\s+", name.strip().lower()) if p]
    if parts:
        candidates.append("".join(parts))
        if len(parts) >= 2:
            candidates.append(f"{parts[0]}.{parts[-1]}")
            candidates.append(f"{parts[0][0]}{parts[-1]}")
            candidates.append(f"{parts[0]}_{parts[-1]}")

    seen: set[str] = set()
    out: list[str] = []
    for candidate in candidates:
        cleaned = candidate.strip()
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            out.append(cleaned)
    return out[:8]


def dork_links(email: str, name: str, org: str, location: str) -> list[DorkLink]:
    """Ready-made search-engine queries embedding the disambiguators."""
    terms = [f'"{t}"' for t in (name, org, location) if t.strip()]
    base = " ".join(terms) or (f'"{email}"' if email else "")
    if not base:
        return []
    query = quote_plus(base)
    links = [
        DorkLink("Google", f"https://www.google.com/search?q={query}"),
        DorkLink(
            "Google · LinkedIn",
            f"https://www.google.com/search?q={query}+site:linkedin.com",
        ),
        DorkLink(
            "Google · GitHub",
            f"https://www.google.com/search?q={query}+site:github.com",
        ),
        DorkLink("Bing", f"https://www.bing.com/search?q={query}"),
        DorkLink("DuckDuckGo", f"https://duckduckgo.com/?q={query}"),
    ]
    if email:
        links.append(
            DorkLink(
                "Google · email",
                f"https://www.google.com/search?q={quote_plus(chr(34) + email + chr(34))}",
            )
        )
    return links


def _person_graph(
    email: str,
    name: str,
    org: str,
    location: str,
    gravatar: GravatarProfile | None,
    username_result: UsernameSearchResult | None,
    breaches: BreachSearchResult | None,
) -> EntityGraph:
    graph = EntityGraph()
    if email:
        root_id = f"email:{email.lower()}"
        _push_node(graph, GraphNode(id=root_id, label=email, type="email"))
    else:
        root_id = f"person:{name.lower()}"
        _push_node(graph, GraphNode(id=root_id, label=name, type="person"))

    if name and email:
        person_id = f"person:{name.lower()}"
        _push_node(graph, GraphNode(id=person_id, label=name, type="person"))
        _push_edge(graph, GraphEdge(root_id, person_id, "identity"))

    if gravatar and gravatar.found:
        gid = f"gravatar:{root_id}"
        _push_node(
            graph,
            GraphNode(
                id=gid,
                label=gravatar.display_name or "Gravatar profile",
                type="profile",
                meta={"url": gravatar.profile_url},
            ),
        )
        _push_edge(graph, GraphEdge(root_id, gid, "has_profile"))

    if username_result:
        _merge(graph, graph_from_username(username_result))
        _push_edge(
            graph,
            GraphEdge(
                root_id,
                f"username:{username_result.username.lower()}",
                "uses_handle",
            ),
        )

    if breaches:
        _merge(graph, graph_from_breaches(breaches))

    for value, node_type, label in (
        (org, "org", "works_at"),
        (location, "location", "located_in"),
    ):
        if value.strip():
            nid = f"{node_type}:{value.lower()}"
            _push_node(graph, GraphNode(id=nid, label=value, type=node_type))
            _push_edge(graph, GraphEdge(root_id, nid, label))

    return graph


def _push_node(graph: EntityGraph, node: GraphNode) -> None:
    if not any(n.id == node.id for n in graph.nodes):
        graph.nodes.append(node)


def _push_edge(graph: EntityGraph, edge: GraphEdge) -> None:
    if not any(
        e.source == edge.source and e.target == edge.target and e.label == edge.label
        for e in graph.edges
    ):
        graph.edges.append(edge)


def _merge(into: EntityGraph, other: EntityGraph) -> None:
    for node in other.nodes:
        _push_node(into, node)
    for edge in other.edges:
        _push_edge(into, edge)


async def investigate_person(
    *,
    email: str = "",
    name: str = "",
    org: str = "",
    location: str = "",
    handle: str = "",
) -> PersonResult:
    email = email.strip()
    name = name.strip()
    org = org.strip()
    location = location.strip()
    handle = handle.strip()
    if not email and not name:
        raise PersonValidationError("provide at least an email or a name")

    gravatar = await _gravatar(email) if email else None
    hygiene = await _email_hygiene(email) if email else None
    candidates = username_candidates(email, name, handle)

    probe = handle or (candidates[0] if candidates else "")
    username_result: UsernameSearchResult | None = None
    if probe:
        try:
            username_result = await search_username(probe)
        except UsernameValidationError:
            username_result = None

    breaches: BreachSearchResult | None = None
    if email:
        breaches = await search_breaches(
            email, client=HIBPClient(api_key=settings.get_api_key("hibp"))
        )

    dorks = dork_links(email, name, org, location)
    graph = _person_graph(
        email, name, org, location, gravatar, username_result, breaches
    )

    return PersonResult(
        email=email,
        name=name,
        org=org,
        location=location,
        gravatar=gravatar,
        email_hygiene=hygiene,
        username_candidates=candidates,
        username_result=username_result,
        breaches=breaches,
        dorks=dorks,
        graph=graph,
        note=_NOTE,
    )
