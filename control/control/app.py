"""Probe fleet control plane: config documents for probes, admin UI for the operator.

Two trust boundaries — served as two SEPARATE applications on different ports:

* the points app — `/api/points/*` and `/api/enroll`: probes call these,
  authenticating with the point name and its secret (the same secret they later
  push metrics with). This app is published to the internet as-is; there are no
  admin routes on this port at all, so a proxy misconfiguration cannot expose
  the admin UI;

* the admin app — the UI and `/api/admin/*`: administrator only. The primary
  mode is a local account (HTTP Basic via XPC_ADMIN_USER/XPC_ADMIN_PASSWORD);
  forward-auth headers and OIDC remain available as fallback modes.
"""

from __future__ import annotations

import base64
import contextlib
import hmac
import logging
import re
import secrets
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from . import db, sessions
from .config import Config
from .document import build_document
from .oidc import OIDC, new_state
from .panel import Panel

log = logging.getLogger("xprobe-control")
STATIC = Path(__file__).parent / "static"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")


class Deps:
    def __init__(self, cfg: Config, *, conn=None, panel: Panel | None = None,
                 oidc: OIDC | None = None, http: httpx.Client | None = None) -> None:
        self.cfg = cfg
        self.conn = conn or db.connect(cfg.db_path)
        self.panel = panel or Panel(cfg.panel.base_url, cfg.panel.token)
        self.oidc = oidc
        # Dedicated client for relaying metrics to the store; swapped in tests.
        self.http = http or httpx.Client(timeout=30.0)


def create_apps(deps: Deps) -> tuple[FastAPI, FastAPI]:
    """Build the (points, admin) pair. State is shared between the two."""
    points = FastAPI(title="xprobe-control points")
    admin = FastAPI(title="xprobe-control admin")
    cfg = deps.cfg
    # point name -> (fetched_at, configs). In memory only: it is a cache of
    # someone else's data, and losing it on restart costs one fetch.
    _sub_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
    # (point, check) -> targets the account's subscription does not contain.
    # Filled when configs are served; surfaced in the point's admin view.
    _missing_targets: dict[tuple[str, str], list[str]] = {}

    # ── administrator sign-in ───────────────────────────────────────────────

    def current(request: Request) -> dict:
        # Local account is the primary mode: a login/password pair from the
        # environment, HTTP Basic. There is a single administrator, so the
        # owner group is implied.
        if cfg.admin_user:
            auth = request.headers.get("authorization", "")
            user = pw = ""
            if auth.startswith("Basic "):
                with contextlib.suppress(ValueError, UnicodeDecodeError):
                    user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            # Always compare both parts so timing does not reveal which one
            # failed to match.
            user_ok = hmac.compare_digest(user, cfg.admin_user)
            pw_ok = hmac.compare_digest(pw, cfg.admin_password)
            if not (user_ok and pw_ok):
                raise HTTPException(401, "authentication required",
                                    headers={"WWW-Authenticate": 'Basic realm="xprobe-admin"'})
            return {"sub": user, "name": user, "groups": [cfg.owner_group]}
        # Behind an edge gateway the identity arrives in forward-auth headers:
        # in this mode the service has no sign-in form of its own.
        if cfg.edge_secret:
            if request.headers.get("x-xpc-edge", "") != cfg.edge_secret:
                raise HTTPException(401, "request did not pass through the gateway")
            groups = [g.strip() for g in
                      (request.headers.get("x-auth-request-groups") or "").split(",") if g.strip()]
            return {
                "sub": request.headers.get("x-auth-request-user", ""),
                "name": request.headers.get("x-auth-request-preferred-username")
                        or request.headers.get("x-auth-request-email", ""),
                "groups": groups,
            }
        token = request.cookies.get(sessions.COOKIE_NAME, "")
        data = sessions.verify(token, cfg.session_secret)
        if not data:
            raise HTTPException(401, "authentication required")
        return data

    def require_owner(session: dict = Depends(current)) -> dict:
        # An edge gateway only proves "realm user" — the group is checked here.
        # Compare without the leading slash: the groups mapper emits the short
        # name (`admins`) while configs habitually use the full path (`/admins`).
        want = cfg.owner_group.lstrip("/")
        have = {g.lstrip("/") for g in (session.get("groups") or [])}
        if want not in have:
            raise HTTPException(403, "administrator only")
        return session

    def ui_guard(request: Request) -> None:
        # In local-account mode the static UI sits behind Basic auth too: the
        # browser prompts on first load and then attaches the header to fetch
        # calls by itself. In other modes the page stays open — the UI renders
        # its own sign-in button, and the edge gates from outside.
        if cfg.admin_user:
            current(request)

    @admin.get("/auth/login")
    def login() -> RedirectResponse:
        if deps.oidc is None:
            raise HTTPException(503, "sign-in is not configured")
        state = new_state()
        r = RedirectResponse(deps.oidc.auth_url(state))
        # The state goes into a signed cookie and is checked on the callback —
        # CSRF protection.
        r.set_cookie("xpc_state", sessions.sign({"state": state}, cfg.session_secret, ttl=600),
                     httponly=True, secure=True, samesite="lax")
        return r

    @admin.get("/auth/callback")
    def callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
        if deps.oidc is None:
            raise HTTPException(503, "sign-in is not configured")
        saved = sessions.verify(request.cookies.get("xpc_state", ""), cfg.session_secret)
        if not saved or saved.get("state") != state:
            raise HTTPException(400, "state mismatch")
        info = deps.oidc.exchange(code)
        groups = info.get("groups") or info.get("roles") or []
        payload = {
            "sub": info.get("sub", ""),
            "name": info.get("name") or info.get("preferred_username", ""),
            "groups": groups,
        }
        r = RedirectResponse(cfg.base_url + "/" if cfg.base_url else "/")
        r.set_cookie(sessions.COOKIE_NAME, sessions.sign(payload, cfg.session_secret),
                     httponly=True, secure=True, samesite="lax")
        r.delete_cookie("xpc_state")
        return r

    @admin.get("/auth/logout")
    def logout() -> RedirectResponse:
        r = RedirectResponse(cfg.base_url + "/" if cfg.base_url else "/")
        r.delete_cookie(sessions.COOKIE_NAME)
        return r

    @admin.get("/api/me")
    def me(request: Request) -> dict:
        try:
            data = current(request)
        except HTTPException:
            return {"authenticated": False}
        want = cfg.owner_group.lstrip("/")
        have = {g.lstrip("/") for g in (data.get("groups") or [])}
        return {"authenticated": True, "name": data.get("name", ""), "owner": want in have}

    # ── config document for a probe ─────────────────────────────────────────

    @points.get("/api/points/{point}/config")
    def point_config(point: str, request: Request) -> JSONResponse:
        """The point's document. Auth: point name and its secret (HTTP Basic).

        No panel calls and a single DB row: this path is hot (probes poll it
        frequently) and the subscription links were saved when the point was
        provisioned or edited.
        """
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Basic "):
            return _basic_challenge()
        try:
            user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            return _basic_challenge()
        stored = db.get_secret_hash(deps.conn, point)
        # The name in the URL and the login must match: one point's secret must
        # not fetch another point's document.
        if user != point or stored is None or not db.check_secret(pw, stored):
            return _basic_challenge()
        p = db.get_point(deps.conn, point)
        if p is None:
            raise HTTPException(404, "point does not exist")
        # A disabled point still gets its document, carrying enabled=false.
        # Refusing would be indistinguishable from an outage, and a probe is
        # built to ride those out by carrying on with what it has — so the
        # only way to make it stop is to tell it.
        return JSONResponse(build_document(p, cfg.defaults, base_url=cfg.base_url))

    @points.get("/api/points/{point}/configs/{kind}")
    def point_configs(point: str, kind: str, request: Request) -> JSONResponse:
        """The configs one check of one point should probe.

        The control plane reads the point's subscription and returns only the
        configs its target set names. A probe therefore never talks to the
        panel, never holds a subscription link, and never receives a config
        outside its own set.
        """
        p = _auth_point(point, request)
        if kind not in ("tcp", "status", "download"):
            raise HTTPException(404, "unknown check")
        if not p.enabled:
            raise HTTPException(404, "point is disabled")
        if not p.check_sub_url:
            raise HTTPException(409, "the point has no subscription yet")
        wanted = set(_targets_of(p).get(kind) or [])
        try:
            configs = _subscription(p)
        except Exception as exc:  # noqa: BLE001 — panel/network, one failure mode
            raise HTTPException(502, f"subscription unavailable: {exc}") from exc
        chosen = [c for c in configs if c.get("remarks") in wanted]
        # A target the account cannot see yields silently fewer configs than
        # asked for — the check then looks healthy while probing less. Say so
        # loudly, and remember it for the UI.
        missing = sorted(wanted - {c.get("remarks") for c in configs})
        _missing_targets[(p.name, kind)] = missing
        if missing:
            log.warning("point %s / %s: %d target(s) absent from its subscription: %s",
                        p.name, kind, len(missing), ", ".join(missing))
        return JSONResponse(chosen)

    # ── enroll: zero-touch node registration ────────────────────────────────

    @points.post("/api/enroll")
    def enroll(payload: dict[str, Any]) -> dict[str, Any]:
        """A node presents its own token and receives its point's identity.

        One token per node, not one for the fleet: a fleet-wide token cannot
        be taken back from a single operator, because disabling their point
        still leaves them able to enroll a fresh one. Revoking this token ends
        that node's access and nobody else's.

        The token is bound to a point on first use, so re-enrolling — which is
        what a node on storage that does not survive a restart does every time
        it comes back — returns the same point with a fresh secret. From then
        on the node works with the secret; the token is only ever used to get
        a new one.
        """
        presented = str(payload.get("token") or "")
        token = db.find_enroll_token(deps.conn, presented) if presented else None
        if token is None:
            raise HTTPException(403, "enroll token is invalid or revoked")
        node_id = str(payload.get("node_id") or "").strip()
        geo = payload.get("geo") or {}
        secret = secrets.token_urlsafe(24)

        if token.point:
            existing = db.get_point(deps.conn, token.point)
            if existing is None:
                # The point was deleted but the token was not: refuse rather
                # than quietly provisioning a replacement the owner did not ask
                # for. Revoking the token is the deliberate way to end this.
                raise HTTPException(409, "the point this token belongs to no longer exists")
            db.rotate_secret(deps.conn, existing.name, secret)
            db.touch_enroll_token(deps.conn, token.id, node_id)
            log.info("enroll: %s re-enrolled with token %s", existing.name, token.id)
            return {"point": existing.name, "secret": secret}

        # First use of an unbound token: name from the city the probe reported,
        # or from the token's label.
        base = _slug(geo.get("city") or "") or _slug(token.label) or f"node-{token.id}"
        name = _unique_name(base)
        # Its own account in the shared squad — exactly like manual
        # provisioning, so an enrolled node can be cut off on its own.
        prov = _provision(name, {
            "tcp": list(cfg.default_check_remarks),
            "status": list(cfg.default_check_remarks),
            "download": list(cfg.default_load_remarks),
        })
        point = db.Point(
            name=name, node_id=node_id, vantage="home",
            country=str(geo.get("country") or ""), city=str(geo.get("city") or ""),
            isp=str(geo.get("isp") or ""), ip=str(geo.get("ip") or ""),
            modes={"tcp": True, "status": True, "download": False},
            note=f"enrolled with token {token.id}" + (f" ({token.label})" if token.label else ""),
            **prov,
        )
        db.create_point(deps.conn, point, secret)
        db.bind_enroll_token(deps.conn, token.id, name)
        db.touch_enroll_token(deps.conn, token.id, node_id)
        log.info("enroll: new point %s from token %s", name, token.id)
        return {"point": name, "secret": secret}

    @points.post("/api/points/{point}/geo")
    def report_geo(point: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """The probe reports its address/city/ISP. The IP is stored, never exposed."""
        p = _auth_point(point, request)
        db.update_geo(deps.conn, p.name,
                      country=str(payload.get("country") or ""),
                      city=str(payload.get("city") or ""),
                      isp=str(payload.get("isp") or ""),
                      ip=str(payload.get("ip") or ""))
        return {"ok": True}

    # ── metrics relay ───────────────────────────────────────────────────────

    @points.post("/api/points/{point}/metrics")
    async def relay_metrics(point: str, request: Request) -> Response:
        """Metrics from a point — forwarded to VictoriaMetrics.

        Through the control plane rather than straight to the store: a new
        point then requires no metrics-infrastructure changes. Auth is the
        point's secret; a point can only write as itself.
        """
        p = _auth_point(point, request)
        if not p.enabled:
            # Belt and braces: a probe that has not polled yet would still be
            # pushing. Disabling takes effect on the next sample, not on the
            # next poll.
            raise HTTPException(403, "point is disabled")
        if cfg.relay is None:
            raise HTTPException(503, "relay is not configured")
        body = await request.body()
        auth = None
        if cfg.relay.username:
            auth = (cfg.relay.username, cfg.relay.password)
        try:
            r = deps.http.post(cfg.relay.write_url, content=body,
                               headers={"Content-Type": "text/plain"}, auth=auth)
        except Exception as exc:  # noqa: BLE001 — network; every failure is equal here
            raise HTTPException(502, f"relay unavailable: {exc}") from exc
        if r.status_code >= 400:
            raise HTTPException(502, f"metrics store rejected the write: {r.status_code}")
        _ = p  # point verified; the body is forwarded as-is
        return Response(status_code=204)

    # ── admin: points ───────────────────────────────────────────────────────

    @admin.get("/api/admin/points")
    def admin_points(_: dict = Depends(require_owner)) -> list[dict]:
        return [p.public() for p in db.list_points(deps.conn)]

    @admin.get("/api/admin/points/{name}")
    def admin_point(name: str, _: dict = Depends(require_owner)) -> dict:
        p = db.get_point(deps.conn, name)
        if p is None:
            raise HTTPException(404, "point not found")
        out = p.public()
        t = _targets_of(p)
        out["tcp_remarks"] = t.get("tcp") or []
        out["check_remarks"] = t.get("status") or []
        out["load_remarks"] = t.get("download") or []
        # Targets the point's account cannot actually see, as observed the
        # last time it asked for configs. Empty until it does.
        out["missing_targets"] = sorted({
            name for (pt, _), names in _missing_targets.items() if pt == p.name
            for name in names
        })
        return out

    @admin.patch("/api/admin/points/{name}")
    def admin_update(name: str, payload: dict[str, Any], _: dict = Depends(require_owner)) -> dict:
        if db.get_point(deps.conn, name) is None:
            raise HTTPException(404, "point not found")
        version = db.update_point(deps.conn, name, payload)
        return {"ok": True, "version": version}

    @admin.post("/api/admin/points/{name}/set")
    def admin_set(name: str, payload: dict[str, Any], _: dict = Depends(require_owner)) -> dict:
        """Set the point's target sets. Writes nothing to the panel: the sets
        are a control-plane concept, applied when configs are filtered."""
        p = db.get_point(deps.conn, name)
        if p is None:
            raise HTTPException(404, "point not found")
        targets = {
            "tcp": sorted(set(payload.get("tcp_remarks") or [])),
            "status": sorted(set(payload.get("check_remarks") or [])),
            "download": sorted(set(payload.get("load_remarks") or [])),
        }
        # Bump the version so the change is visible from the control plane
        # without waiting for the probe's behaviour to shift.
        version = db.update_point(deps.conn, name, {"targets": targets})
        return {"ok": True, "version": version}

    @admin.post("/api/admin/points/{name}/rotate-secret")
    def admin_rotate(name: str, _: dict = Depends(require_owner)) -> dict:
        """Issue a fresh secret and the matching run commands.

        Only the hash is stored, so a run command for an existing point can
        only be produced together with a rotation — the old secret cannot be
        shown again.
        """
        if db.get_point(deps.conn, name) is None:
            raise HTTPException(404, "point not found")
        secret = secrets.token_urlsafe(24)
        db.rotate_secret(deps.conn, name, secret)
        return {"ok": True, "secret": secret, "install": _install_commands(name, secret),
                "hint": "the secret is shown only once"}

    @admin.delete("/api/admin/points/{name}")
    def admin_delete(name: str, _: dict = Depends(require_owner)) -> dict:
        # Only the control-plane record is removed: panel accounts and squads
        # stay — metrics may still reference them, and tearing them down is a
        # separate, deliberate action.
        return {"deleted": db.delete_point(deps.conn, name)}

    @admin.post("/api/admin/points")
    def admin_create(payload: dict[str, Any], _: dict = Depends(require_owner)) -> dict:
        """Provision a point: an account in the shared squad, a control-plane
        record, and an install command."""
        name = str(payload.get("name") or "").strip()
        if not NAME_RE.match(name):
            raise HTTPException(400, "name: lowercase latin/digits/hyphen, 2-31 chars")
        if db.get_point(deps.conn, name) is not None:
            raise HTTPException(409, "a point with this name already exists")

        check_remarks = set(payload.get("check_remarks") or [])
        load_remarks = set(payload.get("load_remarks") or [])
        tcp_remarks = set(payload.get("tcp_remarks") or []) or check_remarks
        hosts = deps.panel.hosts()
        known = {h.remark for h in hosts}
        unknown = (check_remarks | load_remarks | tcp_remarks) - known
        if unknown:
            raise HTTPException(400, f"unknown hosts: {', '.join(sorted(unknown))}")

        prov = _provision(name, {
            "tcp": sorted(tcp_remarks),
            "status": sorted(check_remarks),
            "download": sorted(load_remarks),
        })

        # The point's secret: the probe both fetches the document and pushes
        # metrics with it.
        secret = secrets.token_urlsafe(24)
        point = db.Point(
            name=name,
            vantage=str(payload.get("vantage") or "home"),
            country=str(payload.get("country") or ""),
            city=str(payload.get("city") or ""),
            isp=str(payload.get("isp") or ""),
            modes={"tcp": True, "status": True, "download": True},
            note=str(payload.get("note") or ""),
            **prov,
        )
        db.create_point(deps.conn, point, secret)

        return {
            "ok": True, "name": name, "secret": secret,
            "install": _install_commands(name, secret),
            "hint": "the secret is shown only once — save it",
        }

    # ── admin: panel ────────────────────────────────────────────────────────

    @admin.get("/api/admin/panel/hosts")
    def admin_hosts(_: dict = Depends(require_owner)) -> list[dict]:
        names = deps.panel.inbound_names()
        return [
            {"remark": h.remark, "inbound": names.get(h.inbound_uuid, "?"),
             "disabled": h.disabled}
            for h in deps.panel.hosts() if h.remark
        ]

    # ── enroll token: show and rotate ───────────────────────────────────────

    @admin.get("/api/admin/enroll-tokens")
    def list_tokens(_: dict = Depends(require_owner)) -> list[dict]:
        return [t.public() for t in db.list_enroll_tokens(deps.conn)]

    @admin.post("/api/admin/enroll-tokens")
    def issue_token(payload: dict[str, Any], _: dict = Depends(require_owner)) -> dict:
        """Issue a token for one node. Shown once; only its hash is kept.

        Binding it to an existing point is the usual case — the point is set
        up here first, and the operator gets a credential that can only ever
        be that point.
        """
        point = str(payload.get("point") or "").strip()
        if point and db.get_point(deps.conn, point) is None:
            raise HTTPException(404, "point not found")
        secret = secrets.token_urlsafe(24)
        token = db.create_enroll_token(deps.conn, secret,
                                       label=str(payload.get("label") or ""), point=point)
        return {"ok": True, "id": token.id, "token": secret,
                "control_url": cfg.base_url,
                "env": f"CONTROL_URL={cfg.base_url}\nENROLL_TOKEN={secret}",
                "kubectl": _enroll_manifest(secret),
                "hint": "the token is shown only once"}

    @admin.post("/api/admin/enroll-tokens/{token_id}/revoke")
    def revoke_token(token_id: str, _: dict = Depends(require_owner)) -> dict:
        """End one node's ability to enroll. Others are untouched.

        The point keeps running on the secret it already holds — revoking the
        token stops it coming back, not what is happening now. Disable the
        point as well to stop it immediately.
        """
        if not db.revoke_enroll_token(deps.conn, token_id):
            raise HTTPException(404, "token not found")
        return {"ok": True}

    # ── helpers ─────────────────────────────────────────────────────────────

    def _subscription(p: db.Point) -> list[dict[str, Any]]:
        """The point's configs, briefly cached.

        Probes ask far more often than the panel's answer changes, and each
        point has its own credentials, so the cache is per point.
        """
        now = time.time()
        hit = _sub_cache.get(p.name)
        if hit is not None and now - hit[0] < cfg.defaults.subscription_interval:
            return hit[1]
        configs = deps.panel.subscription(p.check_sub_url)
        _sub_cache[p.name] = (now, configs)
        return configs

    def _auth_point(point: str, request: Request):
        """Verify the point's basic auth and return its row. 401 otherwise."""
        auth = request.headers.get("authorization", "")
        creds = ("", "")
        if auth.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
                creds = (user, pw)
            except (ValueError, UnicodeDecodeError):
                pass
        stored = db.get_secret_hash(deps.conn, point)
        if creds[0] != point or stored is None or not db.check_secret(creds[1], stored):
            raise HTTPException(401, "invalid point secret",
                                headers={"WWW-Authenticate": 'Basic realm="xprobe"'})
        p = db.get_point(deps.conn, point)
        if p is None:
            raise HTTPException(404, "point not found")
        return p

    def _shared_squad() -> str:
        """The one squad every monitoring account belongs to, holding every inbound.

        One squad instead of one per point and per check: what a point probes
        is decided by the control plane when it filters configs, so the panel
        needs no per-point structure at all — and target edits stop writing to
        the panel entirely, which is where the sharp edges were (a host PATCH
        drops fields absent from the body, and hosts sharing an inbound had to
        be hidden with exclusions).
        """
        want = cfg.shared_squad_name
        for s in deps.panel.squads():
            if s.name == want:
                return s.uuid
        inbounds = sorted({h.inbound_uuid for h in deps.panel.hosts() if h.inbound_uuid})
        squad = deps.panel.create_squad(want, inbounds)
        log.info("created the shared monitoring squad %s with %d inbounds", want, len(inbounds))
        return squad

    def _provision(name: str, targets: dict[str, list[str]]) -> dict[str, Any]:
        """Give the point its own account in the shared squad.

        Shared between manual provisioning and auto-enroll. One account per
        point rather than one for the whole fleet: probes run on machines
        other people control, and a per-point identity is what makes it
        possible to cut off one point — or read its traffic — without
        touching the rest.
        """
        squad = _shared_squad()
        user = deps.panel.create_user(
            username=f"monitor_{name}", squads=[squad], tag="MONITOR",
            description=f"xprobe {name}")
        return {
            "check_account": user["username"],
            "check_squad": squad,
            "check_sub_url": user.get("subscriptionUrl") or "",
            "targets": targets,
        }

    def _slug(text: str) -> str:
        out = "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")
        return out[:24]

    def _unique_name(base: str) -> str:
        base = base or "node"
        if db.get_point(deps.conn, base) is None:
            return base
        for n in range(2, 100):
            cand = f"{base}-{n}"
            if db.get_point(deps.conn, cand) is None:
                return cand
        return f"{base}-{secrets.token_hex(3)}"

    def _squad_remarks(squad_uuid: str) -> list[str]:
        """Hosts a legacy per-check squad exposes. Only used to migrate a point
        whose targets still live in the panel rather than in `targets`."""
        if not squad_uuid:
            return []
        squads = {s.uuid: s for s in deps.panel.squads()}
        squad = squads.get(squad_uuid)
        if squad is None:
            return []
        inbounds = set(squad.inbounds)
        return sorted(
            h.remark for h in deps.panel.hosts()
            if h.inbound_uuid in inbounds and squad_uuid not in h.excluded and h.remark
        )

    def _targets_of(p: db.Point) -> dict[str, list[str]]:
        """The point's target sets, migrating a legacy point on first read.

        Points provisioned before the control plane filtered configs kept
        their sets as squad membership. Reading them back once, here, means
        the switch needs no migration step and no downtime.
        """
        if p.targets:
            return {k: list(v) for k, v in p.targets.items()}
        http = _squad_remarks(p.check_squad)
        return {
            "tcp": _squad_remarks(p.tcp_squad) or http,
            "status": http,
            "download": _squad_remarks(p.load_squad),
        }

    def _enroll_manifest(token: str) -> str:
        """Zero-touch on Kubernetes, with nothing persisted.

        The token is the node's identity, and it lives in the manifest — so a
        rescheduled pod re-enrolls as the same point and an emptyDir is
        enough. (This is why the token is per node: it is a credential the
        node keeps, and one that can be taken back from that node alone.)
        """
        url = cfg.base_url or "https://<control-url>"
        return f"""cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xprobe
  labels: {{ app: xprobe }}
spec:
  replicas: 1
  selector: {{ matchLabels: {{ app: xprobe }} }}
  template:
    metadata: {{ labels: {{ app: xprobe }} }}
    spec:
      containers:
        - name: xprobe
          image: ghcr.io/nd4y/xprobe:latest
          env:
            - {{ name: CONTROL_URL, value: "{url}" }}
            - {{ name: ENROLL_TOKEN, value: "{token}" }}
          volumeMounts:
            - {{ name: data, mountPath: /var/lib/xprobe }}
      volumes:
        - name: data
          emptyDir: {{}}
EOF"""

    def _install_commands(name: str, secret: str) -> dict[str, str]:
        """Ready-to-paste run commands for the point, docker and kubernetes."""
        url = cfg.base_url or "https://<control-url>"
        docker = (
            "docker run -d --name xprobe --restart unless-stopped \\\n"
            "  -v xprobe-data:/var/lib/xprobe \\\n"
            f"  -e POINT={name} \\\n"
            f"  -e CONTROL_URL={url} \\\n"
            f"  -e CONTROL_TOKEN={secret} \\\n"
            "  ghcr.io/nd4y/xprobe:latest"
        )
        # A single self-contained apply: the identity comes from env, so an
        # emptyDir is enough — a rescheduled pod re-reads its config from the
        # control plane and only loses the metrics spool.
        kubectl = f"""cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xprobe
  labels: {{ app: xprobe }}
spec:
  replicas: 1
  selector: {{ matchLabels: {{ app: xprobe }} }}
  template:
    metadata: {{ labels: {{ app: xprobe }} }}
    spec:
      containers:
        - name: xprobe
          image: ghcr.io/nd4y/xprobe:latest
          env:
            - {{ name: POINT, value: "{name}" }}
            - {{ name: CONTROL_URL, value: "{url}" }}
            - {{ name: CONTROL_TOKEN, value: "{secret}" }}
          volumeMounts:
            - {{ name: data, mountPath: /var/lib/xprobe }}
      volumes:
        - name: data
          emptyDir: {{}}
EOF"""
        return {"docker": docker, "kubectl": kubectl}

    # ── health and UI ───────────────────────────────────────────────────────

    @points.get("/healthz")
    @admin.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @admin.get("/")
    def index(_: None = Depends(ui_guard)) -> FileResponse:
        return FileResponse(STATIC / "app.html")

    @admin.get("/app.js")
    def appjs(_: None = Depends(ui_guard)) -> FileResponse:
        return FileResponse(STATIC / "app.js", media_type="application/javascript")

    @admin.get("/app.css")
    def appcss(_: None = Depends(ui_guard)) -> FileResponse:
        return FileResponse(STATIC / "app.css", media_type="text/css")

    return points, admin


def create_points_app(deps: Deps) -> FastAPI:
    return create_apps(deps)[0]


def create_admin_app(deps: Deps) -> FastAPI:
    return create_apps(deps)[1]


def _basic_challenge() -> Response:
    return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="xprobe"'})
