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
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from . import db, sessions
from .config import Config
from .document import build_document
from .oidc import OIDC, new_state
from .panel import Panel, plan_squad_membership

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
        if p is None or not p.enabled:
            raise HTTPException(404, "point is disabled or does not exist")
        return JSONResponse(build_document(p, cfg.defaults, base_url=cfg.base_url))

    # ── enroll: zero-touch node registration ────────────────────────────────

    @points.post("/api/enroll")
    def enroll(payload: dict[str, Any]) -> dict[str, Any]:
        """A node registers with a one-time token and receives its identity.

        The token is fleet-wide and rotatable: regenerating it revokes the old
        one. The token is exchanged for the point's permanent identity (name +
        secret) bound to the node's `node_id`; re-enrolling the same node (e.g.
        after losing the volume) returns the same point with a fresh secret.
        From then on the node authenticates with the secret, not the token.
        """
        if payload.get("token") != _enroll_token():
            raise HTTPException(403, "invalid enroll token")
        node_id = str(payload.get("node_id") or "").strip()
        if not node_id:
            raise HTTPException(400, "node_id is required")
        geo = payload.get("geo") or {}
        secret = secrets.token_urlsafe(24)

        existing = db.get_point_by_node(deps.conn, node_id)
        if existing is not None:
            db.rotate_secret(deps.conn, existing.name, secret)
            return {"point": existing.name, "secret": secret}

        # New node: name from the city (if the probe reported one) or from the
        # node_id, suffixed for uniqueness. The geo report will refine it.
        base = _slug(geo.get("city") or "") or f"node-{node_id[:6]}"
        name = _unique_name(base)
        # Every point gets its own pair of squads and accounts — exactly like
        # manual provisioning. A shared subscription would tie the inbound sets
        # of unrelated points together.
        prov = _provision(name, set(cfg.default_check_remarks), set(cfg.default_load_remarks))
        point = db.Point(
            name=name, node_id=node_id, vantage="home",
            country=str(geo.get("country") or ""), city=str(geo.get("city") or ""),
            isp=str(geo.get("isp") or ""), ip=str(geo.get("ip") or ""),
            modes={"tcp": True, "status": True, "download": False},
            note="enrolled automatically",
            **prov,
        )
        db.create_point(deps.conn, point, secret)
        log.info("enroll: new point %s (node %s)", name, node_id[:8])
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
        # The current target set is computed from the panel so the checkboxes
        # in the UI reflect reality, not whatever was recorded once.
        out["check_remarks"] = _squad_remarks(p.check_squad)
        out["load_remarks"] = _squad_remarks(p.load_squad)
        return out

    @admin.patch("/api/admin/points/{name}")
    def admin_update(name: str, payload: dict[str, Any], _: dict = Depends(require_owner)) -> dict:
        if db.get_point(deps.conn, name) is None:
            raise HTTPException(404, "point not found")
        version = db.update_point(deps.conn, name, payload)
        return {"ok": True, "version": version}

    @admin.post("/api/admin/points/{name}/set")
    def admin_set(name: str, payload: dict[str, Any], _: dict = Depends(require_owner)) -> dict:
        """Set the point's target set: edits its squads' membership in the panel."""
        p = db.get_point(deps.conn, name)
        if p is None:
            raise HTTPException(404, "point not found")
        check = set(payload.get("check_remarks") or [])
        load = set(payload.get("load_remarks") or [])
        _apply_set(p.check_squad, check)
        _apply_set(p.load_squad, load)
        # Bump the version: the set changed. The probe re-reads the subscription
        # on its own, but the document version is how the control plane can see
        # the change went out.
        version = db.update_point(deps.conn, name, {"note": p.note})
        return {"ok": True, "version": version}

    @admin.post("/api/admin/points/{name}/rotate-secret")
    def admin_rotate(name: str, _: dict = Depends(require_owner)) -> dict:
        if db.get_point(deps.conn, name) is None:
            raise HTTPException(404, "point not found")
        secret = secrets.token_urlsafe(24)
        db.rotate_secret(deps.conn, name, secret)
        return {"ok": True, "secret": secret, "hint": "the secret is shown only once"}

    @admin.delete("/api/admin/points/{name}")
    def admin_delete(name: str, _: dict = Depends(require_owner)) -> dict:
        # Only the control-plane record is removed: panel accounts and squads
        # stay — metrics may still reference them, and tearing them down is a
        # separate, deliberate action.
        return {"deleted": db.delete_point(deps.conn, name)}

    @admin.post("/api/admin/points")
    def admin_create(payload: dict[str, Any], _: dict = Depends(require_owner)) -> dict:
        """Provision a point: panel squads and accounts, a control-plane record,
        and an install command."""
        name = str(payload.get("name") or "").strip()
        if not NAME_RE.match(name):
            raise HTTPException(400, "name: lowercase latin/digits/hyphen, 2-31 chars")
        if db.get_point(deps.conn, name) is not None:
            raise HTTPException(409, "a point with this name already exists")

        check_remarks = set(payload.get("check_remarks") or [])
        load_remarks = set(payload.get("load_remarks") or [])
        hosts = deps.panel.hosts()
        known = {h.remark for h in hosts}
        unknown = (check_remarks | load_remarks) - known
        if unknown:
            raise HTTPException(400, f"unknown hosts: {', '.join(sorted(unknown))}")

        prov = _provision(name, check_remarks, load_remarks)

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
            "install": _install_snippet(name, secret),
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

    @admin.get("/api/admin/enroll-token")
    def show_token(_: dict = Depends(require_owner)) -> dict:
        # control_url is the PUBLIC points URL: the admin UI runs on another
        # host, so its own origin would be wrong in the operator's .env.
        return {"token": _enroll_token(), "control_url": cfg.base_url}

    @admin.post("/api/admin/enroll-token/rotate")
    def rotate_token(_: dict = Depends(require_owner)) -> dict:
        # Regeneration revokes the old token: already-enrolled nodes are not
        # affected (they authenticate with their secrets), while a new enroll
        # with the old token will fail.
        token = secrets.token_urlsafe(24)
        db.set_setting(deps.conn, "enroll_token", token)
        return {"token": token}

    # ── helpers ─────────────────────────────────────────────────────────────

    def _enroll_token() -> str:
        token = db.get_setting(deps.conn, "enroll_token")
        if not token:
            # First access: seed the token so enrolling works right away.
            token = secrets.token_urlsafe(24)
            db.set_setting(deps.conn, "enroll_token", token)
        return token

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

    def _provision(name: str, check_remarks: set[str], load_remarks: set[str]) -> dict[str, Any]:
        """Create the point's own monitoring squads and accounts in the panel.

        Shared between manual provisioning and auto-enroll: every point gets
        its own target set and its own subscription — a shared one would tie
        the inbound sets of unrelated points together, which is exactly what
        separate sets exist to avoid.
        """
        hosts = deps.panel.hosts()
        check_inbounds, _ = plan_squad_membership("", hosts, check_remarks)
        load_inbounds, _ = plan_squad_membership("", hosts, load_remarks)
        check_squad = deps.panel.create_squad(f"Monitor-{name}-check", check_inbounds)
        load_squad = deps.panel.create_squad(f"Monitor-{name}-load", load_inbounds)
        # Exclusions are applied once the squad uuid is known.
        _apply_set(check_squad, check_remarks)
        _apply_set(load_squad, load_remarks)

        check_user = deps.panel.create_user(
            username=f"monitor_{name}", squads=[check_squad], tag="MONITOR",
            description=f"xprobe {name} check")
        load_user = deps.panel.create_user(
            username=f"monitor_{name}_load", squads=[load_squad], tag="MONITOR",
            description=f"xprobe {name} load")
        return {
            "check_account": check_user["username"], "load_account": load_user["username"],
            "check_squad": check_squad, "load_squad": load_squad,
            "check_sub_url": check_user.get("subscriptionUrl") or "",
            "load_sub_url": load_user.get("subscriptionUrl") or "",
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

    def _apply_set(squad_uuid: str, remarks: set[str]) -> None:
        hosts = deps.panel.hosts()
        inbounds, changed = plan_squad_membership(squad_uuid, hosts, remarks)
        deps.panel.set_squad_inbounds(squad_uuid, inbounds)
        by_uuid = {h.uuid: h for h in hosts}
        for host_uuid, excluded in changed.items():
            host = by_uuid[host_uuid]
            host.excluded = excluded
            deps.panel.patch_host(host)

    def _install_snippet(name: str, secret: str) -> str:
        url = cfg.base_url or "https://<control-url>"
        return (
            "docker run -d --name xprobe --restart unless-stopped \\\n"
            "  -v xprobe-data:/var/lib/xprobe \\\n"
            f"  -e POINT={name} \\\n"
            f"  -e CONTROL_URL={url} \\\n"
            f"  -e CONTROL_TOKEN={secret} \\\n"
            "  ghcr.io/nd4y/xprobe:latest"
        )

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
