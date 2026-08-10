"""Remnawave API client — only what the probe control plane needs.

Contract quirks (verified against remnawave/backend sources and a live panel;
none of this is documented):

* a user is addressed by `username` or numeric `id`; there is no `uuid` field,
  and `shortUuid` is the subscription-link key, not a record identifier;
* `activeInternalSquads` in `PATCH /api/users` replaces the whole set;
* `PATCH /api/hosts` RESETS fields absent from the body — so a host is written
  whole: read the object, change one field, write it back;
* a host is visible in a squad when its inbound belongs to the squad AND the
  squad is not listed in the host's `excludedInternalSquads`. Both levers are
  needed because one inbound serves several hosts.
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
    def __init__(self, base_url: str, token: str, *, client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(
            timeout=30.0, headers={"Authorization": f"Bearer {token}"}
        )

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

    def set_squad_inbounds(self, uuid: str, inbounds: list[str]) -> None:
        self._resp("PATCH", "/api/internal-squads", json={"uuid": uuid, "inbounds": inbounds})

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

    def patch_host(self, host: Host) -> None:
        """Write the host whole: PATCH resets everything absent from the body."""
        body = dict(host.raw)
        body["excludedInternalSquads"] = host.excluded
        self._resp("PATCH", "/api/hosts", json=body)


def plan_squad_membership(
    squad_uuid: str, hosts: list[Host], desired_remarks: set[str]
) -> tuple[list[str], dict[str, list[str]]]:
    """What it takes for the squad to expose exactly the desired_remarks hosts.

    A pure function: it decides and performs nothing — which is why it is the
    thing to test exhaustively; it is the only place that could show a point
    the wrong target set.

    Returns (squad inbounds, {host_uuid: new excludedInternalSquads}) — only
    for hosts whose exclusion list actually changes.
    """
    desired = [h for h in hosts if h.remark in desired_remarks]
    inbounds = sorted({h.inbound_uuid for h in desired if h.inbound_uuid})

    changed: dict[str, list[str]] = {}
    for h in hosts:
        if not h.inbound_uuid:
            continue
        in_squad_inbounds = h.inbound_uuid in inbounds
        wanted = h.remark in desired_remarks
        has_exclusion = squad_uuid in h.excluded
        # A host shows up in the squad when its inbound is in the set AND no
        # exclusion exists. Adjust the exclusion so visibility matches intent.
        if in_squad_inbounds and wanted and has_exclusion:
            changed[h.uuid] = [s for s in h.excluded if s != squad_uuid]
        elif in_squad_inbounds and not wanted and not has_exclusion:
            changed[h.uuid] = [*h.excluded, squad_uuid]
    return inbounds, changed
