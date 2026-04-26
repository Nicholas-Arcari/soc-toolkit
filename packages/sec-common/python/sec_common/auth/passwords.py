"""Password hashing with bcrypt.

Thin wrapper over the bcrypt library. Cost factor 12 is the bcrypt
default in 2026 - takes ~250ms on a modern CPU, which is the sweet
spot between login latency and offline-crack resistance.
"""
from __future__ import annotations

import bcrypt

_COST = 12


def hash_password(plaintext: str) -> str:
    if not plaintext:
        raise ValueError("password must not be empty")
    salt = bcrypt.gensalt(rounds=_COST)
    return bcrypt.hashpw(plaintext.encode("utf-8"), salt).decode("utf-8")


def verify_password(plaintext: str, hashed: str) -> bool:
    """Constant-time verify. Returns False rather than raising on bad hashes -
    callers should treat "invalid hash in store" the same as "wrong password"
    so an attacker can't distinguish via error signals.
    """
    if not plaintext or not hashed:
        return False
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


__all__ = ["hash_password", "verify_password"]
