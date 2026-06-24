"""SQLite-backed user store (stdlib ``sqlite3``, WAL mode).

Replaces the earlier flat-JSON store so several uvicorn workers can share one
auth database without losing concurrent writes: SQLite serialises writers and
WAL keeps readers non-blocking. Still zero extra dependencies and a single
portable file. A legacy ``users.json`` sitting next to the DB is imported once
on first start, then renamed aside.

The public surface (the ``User`` dataclass + every ``UserStore`` method) is
unchanged, so call sites and tests are untouched.
"""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
import threading
import uuid
from contextlib import closing
from dataclasses import dataclass, fields
from pathlib import Path


@dataclass
class User:
    id: str
    username: str
    password_hash: str
    role: str
    created_at: str
    # Subscription plan. "unlimited" = no expiry (self-host admins and the
    # SaaS operator); "trial" = time-boxed, see `trial_ends_at`. Defaults keep
    # legacy rows (written before a field existed) readable on import.
    plan: str = "unlimited"
    trial_ends_at: str | None = None
    # Public URL of the uploaded profile image (served by the avatar route).
    avatar: str | None = None
    # Cumulative experience points; the level is derived from this (see
    # gamification.py).
    xp: int = 0
    # SaaS email + verification (anti-abuse: one account per verified email).
    email: str = ""
    email_verified: bool = False
    verify_token: str = ""
    # Password-reset token + its expiry (ISO 8601); cleared after use.
    reset_token: str = ""
    reset_expires_at: str | None = None
    # Redeemed SaaS license key, kept so login can re-validate it against the
    # license-server and downgrade a revoked/expired paid plan.
    license_key: str = ""


# Column order mirrors the dataclass so inserts line up by position.
_COLUMNS: tuple[str, ...] = tuple(f.name for f in fields(User))
_FIELD_NAMES = frozenset(_COLUMNS)
# Stored as INTEGER 0/1 in SQLite, surfaced as bool on the dataclass.
_BOOL_COLUMNS = frozenset({"email_verified"})


class UserStore:
    """Thread-safe SQLite user store.

    Reads run lock-free (WAL allows concurrent readers); writes take a
    process-local lock to avoid in-process ``SQLITE_BUSY`` churn, while
    cross-process contention is handled by ``busy_timeout``.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._write_lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._maybe_import_legacy_json()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        with closing(self._connect()) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    plan TEXT NOT NULL DEFAULT 'unlimited',
                    trial_ends_at TEXT,
                    avatar TEXT,
                    xp INTEGER NOT NULL DEFAULT 0,
                    email TEXT NOT NULL DEFAULT '',
                    email_verified INTEGER NOT NULL DEFAULT 0,
                    verify_token TEXT NOT NULL DEFAULT '',
                    reset_token TEXT NOT NULL DEFAULT '',
                    reset_expires_at TEXT,
                    license_key TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)"
            )

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> User:
        data = dict(row)
        data["email_verified"] = bool(data["email_verified"])
        return User(**data)

    @staticmethod
    def _row_values(user: User) -> tuple[object, ...]:
        return tuple(
            int(getattr(user, col)) if col in _BOOL_COLUMNS else getattr(user, col)
            for col in _COLUMNS
        )

    def _insert(self, conn: sqlite3.Connection, user: User) -> None:
        placeholders = ", ".join("?" * len(_COLUMNS))
        conn.execute(
            f"INSERT INTO users ({', '.join(_COLUMNS)}) VALUES ({placeholders})",
            self._row_values(user),
        )

    def _maybe_import_legacy_json(self) -> None:
        legacy = self.path.parent / "users.json"
        if legacy == self.path or not legacy.exists():
            return
        with self._write_lock, closing(self._connect()) as conn, conn:
            if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None:
                return
            try:
                rows = json.loads(legacy.read_text()).get("users", [])
            except (json.JSONDecodeError, OSError):
                return
            for raw in rows:
                user = User(**{k: v for k, v in raw.items() if k in _FIELD_NAMES})
                self._insert(conn, user)
        legacy.rename(legacy.with_name("users.json.migrated"))

    def _get_one(self, where: str, params: tuple[object, ...]) -> User | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                f"SELECT * FROM users WHERE {where} LIMIT 1", params
            ).fetchone()
        return self._row_to_user(row) if row else None

    def is_empty(self) -> bool:
        with closing(self._connect()) as conn:
            return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None

    def list_users(self) -> list[User]:
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
        return [self._row_to_user(row) for row in rows]

    def get_by_username(self, username: str) -> User | None:
        return self._get_one("username = ?", (username,))

    def get_by_id(self, user_id: str) -> User | None:
        return self._get_one("id = ?", (user_id,))

    def get_by_email(self, email: str) -> User | None:
        target = email.strip().lower()
        if not target:
            return None
        return self._get_one("LOWER(email) = ?", (target,))

    def get_by_verify_token(self, token: str) -> User | None:
        if not token:
            return None
        return self._get_one("verify_token = ?", (token,))

    def get_by_reset_token(self, token: str) -> User | None:
        if not token:
            return None
        return self._get_one("reset_token = ?", (token,))

    def create(
        self,
        *,
        username: str,
        password_hash: str,
        role: str,
        plan: str = "unlimited",
        trial_ends_at: str | None = None,
        email: str = "",
        email_verified: bool = False,
        verify_token: str = "",
    ) -> User:
        user = User(
            id=uuid.uuid4().hex,
            username=username,
            password_hash=password_hash,
            role=role,
            created_at=dt.datetime.now(dt.UTC).isoformat(),
            plan=plan,
            trial_ends_at=trial_ends_at,
            email=email,
            email_verified=email_verified,
            verify_token=verify_token,
        )
        with self._write_lock, closing(self._connect()) as conn, conn:
            try:
                self._insert(conn, user)
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"username already exists: {username}") from exc
        return user

    def update(self, user_id: str, **changes: object) -> User | None:
        """Patch fields on an existing user. Unknown field names raise."""
        for key in changes:
            if key not in _FIELD_NAMES:
                raise AttributeError(f"unknown user field: {key}")
        if not changes:
            return self.get_by_id(user_id)
        assignments = ", ".join(f"{key} = ?" for key in changes)
        values = [
            int(bool(value)) if key in _BOOL_COLUMNS else value
            for key, value in changes.items()
        ]
        with self._write_lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                f"UPDATE users SET {assignments} WHERE id = ?",
                (*values, user_id),
            )
            if cur.rowcount == 0:
                return None
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return self._row_to_user(row) if row else None


__all__ = ["User", "UserStore"]
