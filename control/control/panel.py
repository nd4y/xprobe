"""Remnawave API client — only what the probe control plane needs.

Contract quirks (verified against remnawave/backend sources and a live panel;
none of this is documented):

* a user is addressed by `username` or numeric `id`; there is no `uuid` field,
  and `shortUuid` is the subscription-link key, not a record identifier;
* `activeInternalSquads` in `PATCH /api/users` replaces the whole set;
* a host is visible in a squad when its inbound belongs to the squad AND the
  squad is not listed in the host's `excludedInternalSquads`. Both are read
  here only to migrate points whose target sets still live in panel squads.

**This client cannot modify hosts, by design.** Target sets are applied by
filtering configs in the control plane, so nothing about monitoring needs to
write to a live host object — and `PATCH /api/hosts` silently resets every
field absent from the body, which made that the sharpest edge in the system.
The methods that could do it were removed rather than left unused.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


class PanelError(RuntimeError):
    def __init__(self, method: str, path: str, status: int, body: str) -> None:
        super().__init__(f"{method} {path} -> {status}: {body[:300]}")
        self.status = status


@dataclass
class Host:
    uuid: str
    remark: str
    inbound_uuid: str
    excluded: list[str] = field(default_factory=list)   # squad uuids
    disabled: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Squad:
    uuid: str
    name: str
    inbounds: list[str] = field(default_factory=list)    # inbound uuids


class Panel:
    def __init__(self, base_url: str, token: str, *, client: httpx.Client | None = None,
                 sub_client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(
            timeout=30.0, headers={"Authorization": f"Bearer {token}"}
        )
        # Subscriptions are fetched WITHOUT the admin token: the subscription
        # host need not be the API host, and an admin token has no business
        # travelling anywhere it is not required.
        self._sub_client = sub_client or httpx.Client(timeout=30.0)

    def _resp(self, method: str, path: str, **kw: Any) -> Any:
        r = self._client.request(method, f"{self.base_url}{path}", **kw)
        if r.status_code >= 400:
            raise PanelError(method, path, r.status_code, r.text)
        return r.json()["response"]

    # ── reads ─────────────────────────────────────────────────────────────────

    def inbound_names(self) -> dict[str, str]:
        """Inbound uuid → "profile/tag". For readable target-set labels in the UI."""
        names: dict[str, str] = {}
        for prof in self._resp("GET", "/api/config-profiles")["configProfiles"]:
            for i in prof.get("inbounds", []):
                names[i["uuid"]] = f"{prof.get('name')}/{i.get('tag')}"
        return names

    def subscription(self, url: str, *, user_agent: str = "v2rayNG/1.8.0") -> list[dict[str, Any]]:
        """Fetch a subscription and return its configs.

        The control plane reads subscriptions itself and hands probes only the
        configs their target set names — so a probe never talks to the panel
        and never receives configs it has no business holding.

        The subscription must come back in xray-json form; a share-link body
        loses the XHTTP `extra` block, and such a config cannot work behind a
        CDN.
        """
        r = self._sub_client.get(url, headers={"User-Agent": user_agent})
        if r.status_code >= 400:
            raise PanelError("GET", "<subscription>", r.status_code, r.text)
        body = r.json()
        if not isinstance(body, list):
            raise PanelError("GET", "<subscription>", 200, "not a config list")
        return [c for c in body if c.get("outbounds")]

    def squads(self) -> list[Squad]:
        data = self._resp("GET", "/api/internal-squads")
        out = []
        for s in data.get("internalSquads") or []:
            inbounds = [i["uuid"] if isinstance(i, dict) else i for i in s.get("inbounds") or []]
            out.append(Squad(uuid=s["uuid"], name=s["name"], inbounds=inbounds))
        return out

    def hosts(self) -> list[Host]:
        out = []
        for h in self._resp("GET", "/api/hosts"):
            inbound = h.get("inbound") or {}
            inbound_uuid = inbound.get("configProfileInboundUuid") or h.get("inboundUuid") or ""
            out.append(Host(
                uuid=h.get("uuid", ""),
                remark=h.get("remark", ""),
                inbound_uuid=inbound_uuid,
                excluded=list(h.get("excludedInternalSquads") or []),
                disabled=bool(h.get("isDisabled")),
                raw=h,
            ))
        return out

    def user(self, username: str) -> dict[str, Any] | None:
        r = self._client.get(f"{self.base_url}/api/users/by-username/{username}")
        if r.status_code == 404:
            return None
        if r.status_code >= 400:
            raise PanelError("GET", f"/api/users/by-username/{username}", r.status_code, r.text)
        return r.json()["response"]

    # ── writes ────────────────────────────────────────────────────────────────

    def create_squad(self, name: str, inbounds: list[str]) -> str:
        resp = self._resp("POST", "/api/internal-squads",
                          json={"name": name, "inbounds": inbounds})
        # The response is sometimes wrapped in internalSquad and sometimes
        # flat — take whichever is there.
        squad = resp.get("internalSquad") or resp
        return squad["uuid"]

    def create_user(
        self, *, username: str, squads: list[str], tag: str, description: str,
        expire_at: str = "2099-01-01T00:00:00.000Z",
    ) -> dict[str, Any]:
        return self._resp("POST", "/api/users", json={
            "username": username,
            "status": "ACTIVE",
            "expireAt": expire_at,
            "trafficLimitBytes": 0,          # monitoring accounts have no quota
            "activeInternalSquads": squads,
            "tag": tag,
            "description": description,
        })

    def delete_user(self, user_id: int) -> None:
        self._resp("DELETE", f"/api/users/{user_id}")
