"""Signed session cookie. HMAC, no external dependencies."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

COOKIE_NAME = "xpc_session"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(payload: dict, secret: str, *, ttl: int = 86400, now: float | None = None) -> str:
    body = dict(payload, exp=int((now or time.time()) + ttl))
    raw = _b64(json.dumps(body, separators=(",", ":")).encode())
    mac = _b64(hmac.new(secret.encode(), raw.encode(), hashlib.sha256).digest())
    return f"{raw}.{mac}"


def verify(token: str, secret: str, *, now: float | None = None) -> dict | None:
    try:
        raw, mac = token.split(".", 1)
    except ValueError:
        return None
    want = _b64(hmac.new(secret.encode(), raw.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(want, mac):
        return None
    try:
        body = json.loads(_unb64(raw))
    except (ValueError, json.JSONDecodeError):
        return None
    if body.get("exp", 0) < (now or time.time()):
        return None
    return body
