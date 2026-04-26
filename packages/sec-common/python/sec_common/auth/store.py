"""JSON-file-backed user store.

Single-tenant local install is the primary target - a DB-backed store
would force schema migrations on the SOC toolkit's disposable cache DB
and add a SQLAlchemy session dependency to every auth call path. A
flat JSON file is good enough for <10 users and stays portable across
both toolkits (SOC uses its DB as a cache, OSINT has its own schema).

Writes are atomic: temp-file + ``os.replace`` guarantees a reader never
sees a torn half-written file even under concurrent requests.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class User:
    id: str
    username: str
    password_hash: str
    role: str
    created_at: str


class UserStore:
    """Thread-safe JSON user store.

    The lock is process-local - fine for a single uvicorn worker. If you
    scale out to multiple workers, swap this for a DB-backed store.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self) -> list[User]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text())
        except json.JSONDecodeError:
            # Corrupt store - treat as empty rather than crashing the
            # whole app on startup. An operator can delete and recreate.
            return []
        return [User(**u) for u in data.get("users", [])]

    def _write(self, users: list[User]) -> None:
        tmp = self.path.with_suffix(".tmp")
        payload = {"users": [asdict(u) for u in users]}
        tmp.write_text(json.dumps(payload, indent=2))
        os.replace(tmp, self.path)

    def is_empty(self) -> bool:
        with self._lock:
            return not self._read()

    def list_users(self) -> list[User]:
        with self._lock:
            return self._read()

    def get_by_username(self, username: str) -> User | None:
        with self._lock:
            for u in self._read():
                if u.username == username:
                    return u
            return None

    def create(self, *, username: str, password_hash: str, role: str) -> User:
        with self._lock:
            users = self._read()
            if any(u.username == username for u in users):
                raise ValueError(f"username already exists: {username}")
            user = User(
                id=uuid.uuid4().hex,
                username=username,
                password_hash=password_hash,
                role=role,
                created_at=dt.datetime.now(dt.UTC).isoformat(),
            )
            users.append(user)
            self._write(users)
            return user


__all__ = ["User", "UserStore"]
