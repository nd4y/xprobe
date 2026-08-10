"""Minimal OIDC authorization-code flow for administrator sign-in.

Metadata comes from `.well-known`; the code-for-token exchange and the profile
fetch are plain requests. No dedicated library: the flow is short and the
service keeps its dependency list small.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx


@dataclass
class OIDC:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str

    def __post_init__(self) -> None:
        meta = httpx.get(f"{self.issuer.rstrip('/')}/.well-known/openid-configuration",
                         timeout=15).json()
        self.authorization_endpoint = meta["authorization_endpoint"]
        self.token_endpoint = meta["token_endpoint"]
        self.userinfo_endpoint = meta["userinfo_endpoint"]

    def auth_url(self, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": "openid profile groups",
            "redirect_uri": self.redirect_uri,
            "state": state,
        }
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    def exchange(self, code: str) -> dict[str, Any]:
        r = httpx.post(self.token_endpoint, data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }, timeout=15)
        r.raise_for_status()
        access = r.json()["access_token"]
        info = httpx.get(self.userinfo_endpoint,
                         headers={"Authorization": f"Bearer {access}"}, timeout=15)
        info.raise_for_status()
        return info.json()


def new_state() -> str:
    return secrets.token_urlsafe(16)
