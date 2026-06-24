"""Profile-image storage.

Routes depend only on the ``AvatarStorage`` protocol, so the local-disk
implementation here can be swapped for an object-store backend (S3, GCS)
at deploy time without touching the auth router - the "host-agnostic now,
pick storage at deploy" stance.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

# Stored filenames are always ``{user_id}.{ext}`` where user_id is a uuid4
# hex string, so this pattern both validates the extension and blocks path
# traversal (no slashes or dots beyond the single extension separator).
_NAME_RE = re.compile(r"^[a-f0-9]{1,64}\.(png|jpg|jpeg|webp|gif)$")
_ALLOWED_EXT = {"png", "jpg", "jpeg", "webp", "gif"}


class AvatarStorage(Protocol):
    """Save / serve / delete a single avatar per user."""

    def save(self, user_id: str, data: bytes, ext: str) -> str:
        """Persist the image and return its public URL."""
        ...

    def remove(self, user_id: str) -> None:
        """Delete the user's avatar if one exists (no-op otherwise)."""
        ...

    def resolve(self, name: str) -> Path | None:
        """Map a public filename to an on-disk path, or None if invalid/missing."""
        ...


class LocalAvatarStorage:
    """Avatars on the local filesystem, served under ``url_prefix``."""

    def __init__(
        self, directory: Path, url_prefix: str = "/api/auth/avatars"
    ) -> None:
        self.dir = directory
        self.url_prefix = url_prefix.rstrip("/")
        self.dir.mkdir(parents=True, exist_ok=True)

    def save(self, user_id: str, data: bytes, ext: str) -> str:
        ext = ext.lower().lstrip(".")
        if ext == "jpeg":
            ext = "jpg"
        if ext not in _ALLOWED_EXT:
            raise ValueError(f"unsupported image type: {ext or '(none)'}")
        # One avatar per user: drop any previous extension before writing.
        self._remove_files(user_id)
        (self.dir / f"{user_id}.{ext}").write_bytes(data)
        return f"{self.url_prefix}/{user_id}.{ext}"

    def remove(self, user_id: str) -> None:
        self._remove_files(user_id)

    def resolve(self, name: str) -> Path | None:
        if not _NAME_RE.match(name):
            return None
        path = self.dir / name
        return path if path.is_file() else None

    def _remove_files(self, user_id: str) -> None:
        for ext in _ALLOWED_EXT:
            candidate = self.dir / f"{user_id}.{ext}"
            if candidate.exists():
                candidate.unlink()


__all__ = ["AvatarStorage", "LocalAvatarStorage"]
