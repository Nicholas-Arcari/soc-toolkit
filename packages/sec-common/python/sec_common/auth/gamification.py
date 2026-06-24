"""XP / level rules for the gamified analyst experience.

Server-authoritative: the award amounts live here, not on the client, so
XP can't be forged by hand-posting to the endpoint. The level curve is a
pure function of cumulative XP - we never store a level, we derive it.
"""
from __future__ import annotations

import math

# Level N begins at 50*N*(N-1) XP, so the gap to reach each new level grows
# by 100 each time (L2 @ 100, L3 @ 300, L4 @ 600, ...). Gentle early, slower
# later - the usual progression feel.


def level_for_xp(xp: int) -> int:
    if xp <= 0:
        return 1
    return max(1, int((50 + math.sqrt(2500 + 200 * xp)) / 100))


def level_floor_xp(level: int) -> int:
    """Total XP required to be at the start of ``level``."""
    return 50 * level * (level - 1)


def level_progress(xp: int) -> tuple[int, int, int]:
    """Return ``(level, xp_into_level, xp_to_next_level)`` for a total XP."""
    xp = max(0, xp)
    level = level_for_xp(xp)
    into = xp - level_floor_xp(level)
    to_next = level_floor_xp(level + 1) - xp
    return level, into, to_next


# Base XP per analysis action + a capped per-finding bonus, so a fruitful
# investigation is worth more than an empty one without enabling farming.
_XP_PER_ACTION = {
    "phishing": 12,
    "logs": 12,
    "ioc": 10,
    "ioc-pivot": 12,
    "yara": 10,
    "sigma": 10,
    "misp": 8,
    "file": 12,
    "qr": 10,
    "link": 10,
}
_XP_DEFAULT = 8
_XP_PER_FINDING = 4
_XP_MAX_FINDING_BONUS = 10


def xp_for_event(action: str, findings: int) -> int:
    base = _XP_PER_ACTION.get(action, _XP_DEFAULT)
    bonus = _XP_PER_FINDING * min(max(findings, 0), _XP_MAX_FINDING_BONUS)
    return base + bonus


# Achievement badges earned at level milestones (derived, never stored).
_BADGES: tuple[tuple[int, str, str], ...] = (
    (2, "apprentice", "Apprentice"),
    (5, "analyst", "Analyst"),
    (10, "veteran", "Veteran"),
    (20, "elite", "Elite Hunter"),
)


def badges_for(level: int) -> list[dict[str, str]]:
    """Badges earned at ``level`` (cumulative milestones)."""
    return [
        {"id": badge_id, "label": label}
        for threshold, badge_id, label in _BADGES
        if level >= threshold
    ]


__all__ = [
    "badges_for",
    "level_floor_xp",
    "level_for_xp",
    "level_progress",
    "xp_for_event",
]
