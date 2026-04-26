"""Minimal JWT encode/decode wrapper.

Wraps PyJWT with project defaults - HS256, typed claims model, a single
``decode_token`` call site that raises a typed error regardless of the
underlying PyJWT exception. Downstream middleware can ``except
TokenError`` without importing jwt's exception tree.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

import jwt as pyjwt

_ALGORITHM = "HS256"


class TokenError(Exception):
    """Raised for any token validation failure (expired, malformed, wrong sig)."""


@dataclass(frozen=True)
class TokenClaims:
    sub: str
    username: str
    role: str
    exp: int  # unix seconds


def encode_token(
    *,
    subject: str,
    username: str,
    role: str,
    secret: str,
    ttl_minutes: int = 60,
    now: dt.datetime | None = None,
) -> str:
    """Issue a JWT. ``now`` exists for testability - real callers omit it."""
    issued = now or dt.datetime.now(dt.UTC)
    exp = issued + dt.timedelta(minutes=ttl_minutes)
    payload = {
        "sub": subject,
        "username": username,
        "role": role,
        "iat": int(issued.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return pyjwt.encode(payload, secret, algorithm=_ALGORITHM)


def decode_token(token: str, *, secret: str) -> TokenClaims:
    """Validate signature + expiry and return typed claims.

    Swallows PyJWT's exception hierarchy into a single ``TokenError`` so
    middleware code can pattern-match without a fragile import of the
    library's internals.
    """
    try:
        payload = pyjwt.decode(token, secret, algorithms=[_ALGORITHM])
    except pyjwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc

    try:
        return TokenClaims(
            sub=str(payload["sub"]),
            username=str(payload["username"]),
            role=str(payload["role"]),
            exp=int(payload["exp"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise TokenError("malformed token payload") from exc


__all__ = ["TokenClaims", "TokenError", "decode_token", "encode_token"]
