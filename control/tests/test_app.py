import base64

import httpx
from fastapi.testclient import TestClient

from control import db, sessions
from control.app import Deps, create_apps
from control.config import Config, Defaults, PanelConfig, RelayConfig
from control.panel import Host, Squad

SECRET = "test-session-secret"
OWNER = "/admins"


class FakePanel:
    """An in-memory panel: exactly the operations the service calls."""

    def __init__(self):
        self.hosts_ = [
            Host(uuid="h1", remark="RU · TLS", inbound_uuid="i-tls"),
            Host(uuid="h2", remark="RU · XHTTP", inbound_uuid="i-xhttp"),
        ]
        self.squads_ = []
        self.users = {}
        self._sq = 0

    def inbound_names(self):
        return {"i-tls": "pr3/RU-TLS", "i-xhttp": "pr3/RU-XHTTP"}

    def hosts(self):
        return self.hosts_

    def squads(self):
        return self.squads_

    def create_squad(self, name, inbounds):
        self._sq += 1
        uuid = f"sq-{self._sq}"
        self.squads_.append(Squad(uuid=uuid, name=name, inbounds=list(inbounds)))
        return uuid

    def set_squad_inbounds(self, uuid, inbounds):
        for s in self.squads_:
            if s.uuid == uuid:
                s.inbounds = list(inbounds)

    def create_user(self, *, username, squads, tag, description, expire_at="x"):
        u = {"username": username, "id": len(self.users) + 1,
             "subscriptionUrl": f"https://sub/{username}"}
        self.users[username] = u
        return u

    def patch_host(self, host):
        for i, h in enumerate(self.hosts_):
            if h.uuid == host.uuid:
                self.hosts_[i] = host


def build(tmp_path, *, panel=None, relay_capture=None, edge_secret="",
          admin_user="", admin_password=""):
    """Returns (points client, admin client, deps) — the two apps as deployed."""
    cfg = Config(
        panel=PanelConfig(base_url="http://panel", token="t"),
        db_path=str(tmp_path / "t.sqlite3"),
        session_secret=SECRET, owner_group=OWNER, oidc=None,
        base_url="https://xprobe.example",
        relay=RelayConfig(write_url="http://vm:8428/api/v1/import/prometheus"),
        edge_secret=edge_secret,
        admin_user=admin_user, admin_password=admin_password,
        default_check_remarks=("RU · TLS", "RU · XHTTP"),
        default_load_remarks=("RU · XHTTP",),
        defaults=Defaults(),
    )
    # The relay forwards via deps.http — swapped for a transport that records
    # the body.
    def relay_handler(request: httpx.Request) -> httpx.Response:
        if relay_capture is not None:
            relay_capture.append(request.content)
        return httpx.Response(204)

    http = httpx.Client(transport=httpx.MockTransport(relay_handler))
    deps = Deps(cfg, conn=db.connect(cfg.db_path), panel=panel or FakePanel(), http=http)
    points, admin = create_apps(deps)
    return TestClient(points), TestClient(admin), deps


def owner_cookie():
    return {sessions.COOKIE_NAME: sessions.sign(
        {"sub": "s", "name": "Alex", "groups": [OWNER]}, SECRET)}


def basic(user, pw):
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


# ── config document for a probe ───────────────────────────────────────────────


def test_probe_fetches_its_document_with_its_secret(tmp_path):
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", check_sub_url="https://s/c",
                                        load_sub_url="https://s/l"), "sec")
    r = points.get("/api/points/yar/config", headers=basic("yar", "sec"))
    assert r.status_code == 200
    assert r.json()["point"] == "yar"
    assert r.json()["subscriptions"]["check"] == "https://s/c"


def test_foreign_secret_fetches_no_document(tmp_path):
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar"), "sec")
    assert points.get("/api/points/yar/config", headers=basic("yar", "wrong")).status_code == 401
    # A valid secret under another point's name is no good either.
    assert points.get("/api/points/yar/config", headers=basic("tlt", "sec")).status_code == 401


def test_disabled_point_serves_no_config(tmp_path):
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", enabled=False), "sec")
    assert points.get("/api/points/yar/config", headers=basic("yar", "sec")).status_code == 404


# ── port separation: no admin routes on the points app and vice versa ─────────


def test_points_app_has_no_admin_routes(tmp_path):
    # The points port is published to the internet: even a fully authorized
    # admin request must find nothing there.
    points, _, _ = build(tmp_path, admin_user="root", admin_password="pw")
    assert points.get("/api/admin/points", headers=basic("root", "pw")).status_code == 404
    assert points.get("/", headers=basic("root", "pw")).status_code == 404
    assert points.get("/api/me").status_code == 404


def test_admin_app_has_no_points_routes(tmp_path):
    _, admin, deps = build(tmp_path, admin_user="root", admin_password="pw")
    db.create_point(deps.conn, db.Point(name="yar"), "sec")
    assert admin.get("/api/points/yar/config", headers=basic("yar", "sec")).status_code == 404
    assert admin.post("/api/enroll", json={"token": "x", "node_id": "n"},
                      headers=basic("root", "pw")).status_code == 404


# ── local account (primary mode) ──────────────────────────────────────────────


def test_local_account_signs_in(tmp_path):
    _, admin, _ = build(tmp_path, admin_user="root", admin_password="pw")
    assert admin.get("/api/admin/points", headers=basic("root", "pw")).status_code == 200
    me = admin.get("/api/me", headers=basic("root", "pw")).json()
    assert me == {"authenticated": True, "name": "root", "owner": True}


def test_local_account_rejects_bad_credentials(tmp_path):
    _, admin, _ = build(tmp_path, admin_user="root", admin_password="pw")
    r = admin.get("/api/admin/points", headers=basic("root", "wrong"))
    assert r.status_code == 401
    # The Basic challenge is what makes the browser prompt for a password.
    assert "Basic" in r.headers.get("www-authenticate", "")
    assert admin.get("/api/admin/points", headers=basic("who", "pw")).status_code == 401
    assert admin.get("/api/admin/points").status_code == 401


def test_local_mode_guards_the_static_ui(tmp_path):
    # Without the guard the page would load but every fetch would 401 without
    # a browser prompt — the UI would just look broken.
    _, admin, _ = build(tmp_path, admin_user="root", admin_password="pw")
    assert admin.get("/").status_code == 401
    assert admin.get("/", headers=basic("root", "pw")).status_code == 200


def test_local_mode_overrides_session_cookies(tmp_path):
    # When the local account is configured, a signed cookie must not bypass it.
    _, admin, _ = build(tmp_path, admin_user="root", admin_password="pw")
    assert admin.get("/api/admin/points", cookies=owner_cookie()).status_code == 401


# ── admin API ─────────────────────────────────────────────────────────────────


def test_admin_api_is_owner_only(tmp_path):
    _, admin, _ = build(tmp_path)
    assert admin.get("/api/admin/points").status_code == 401
    guest = {sessions.COOKIE_NAME: sessions.sign({"sub": "s", "groups": []}, SECRET)}
    assert admin.get("/api/admin/points", cookies=guest).status_code == 403


def test_provisioning_creates_squads_accounts_and_secret(tmp_path):
    panel = FakePanel()
    _, admin, deps = build(tmp_path, panel=panel)
    r = admin.post("/api/admin/points", cookies=owner_cookie(), json={
        "name": "yaroslavl", "country": "RU", "city": "Yaroslavl",
        "check_remarks": ["RU · TLS", "RU · XHTTP"], "load_remarks": ["RU · XHTTP"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["secret"]
    assert "docker run" in body["install"]["docker"]
    assert "kubectl apply" in body["install"]["kubectl"]
    # Three squads and three accounts: tcp, http (check) and download (load).
    assert len(panel.squads_) == 3
    assert set(panel.users) == {"monitor_yaroslavl", "monitor_yaroslavl_load",
                                "monitor_yaroslavl_tcp"}
    # The point landed in the control plane with its subscription links saved.
    p = db.get_point(deps.conn, "yaroslavl")
    assert p.check_sub_url == "https://sub/monitor_yaroslavl"
    assert p.tcp_sub_url == "https://sub/monitor_yaroslavl_tcp"


def test_run_command_for_existing_point_rotates_and_returns_both_flavors(tmp_path):
    # Only a hash is stored, so a run command can only come with a fresh
    # secret — the endpoint rotates and hands back docker + kubectl.
    _, admin, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar"), "old")
    before = db.get_secret_hash(deps.conn, "yar")
    r = admin.post("/api/admin/points/yar/rotate-secret", cookies=owner_cookie())
    assert r.status_code == 200
    body = r.json()
    assert "yar" in body["install"]["docker"] and body["secret"] in body["install"]["docker"]
    assert "kubectl apply" in body["install"]["kubectl"]
    assert db.get_secret_hash(deps.conn, "yar") != before   # rotated


def test_legacy_point_gains_a_tcp_set_on_first_save(tmp_path):
    # A point created before the tcp set existed has empty tcp_* columns; the
    # first target save must provision the tcp squad and migrate it.
    panel = FakePanel()
    _, admin, deps = build(tmp_path, panel=panel)
    db.create_point(deps.conn, db.Point(name="yar", check_squad="", load_squad=""), "sec")
    assert db.get_point(deps.conn, "yar").tcp_squad == ""
    r = admin.post("/api/admin/points/yar/set", cookies=owner_cookie(),
                   json={"tcp_remarks": ["RU · TLS"], "check_remarks": ["RU · TLS"],
                         "load_remarks": []})
    assert r.status_code == 200
    p = db.get_point(deps.conn, "yar")
    assert p.tcp_squad and p.tcp_account == "monitor_yar_tcp"
    assert p.tcp_sub_url == "https://sub/monitor_yar_tcp"


def test_malformed_point_name_is_rejected(tmp_path):
    _, admin, _ = build(tmp_path)
    r = admin.post("/api/admin/points", cookies=owner_cookie(),
                   json={"name": "Yaroslavl!", "check_remarks": [], "load_remarks": []})
    assert r.status_code == 400


def test_unknown_host_in_target_set_is_rejected(tmp_path):
    _, admin, _ = build(tmp_path)
    r = admin.post("/api/admin/points", cookies=owner_cookie(), json={
        "name": "yar", "check_remarks": ["no such host"], "load_remarks": [],
    })
    assert r.status_code == 400


# ── edge-gateway mode: identity from forward-auth headers (fallback) ──────────


def edge_headers(groups="admins", secret="edge-sec"):
    return {"X-XPC-Edge": secret, "X-Auth-Request-Groups": groups,
            "X-Auth-Request-Preferred-Username": "alex"}


def test_behind_edge_the_header_group_admits(tmp_path):
    # The mapper emits the short name (admins) while the config uses the full
    # path (/admins) — the comparison must match without the leading slash.
    _, admin, _ = build(tmp_path, edge_secret="edge-sec")
    assert admin.get("/api/admin/points", headers=edge_headers()).status_code == 200


def test_behind_edge_no_secret_no_entry(tmp_path):
    # The service port is visible to neighboring containers: without the
    # secret any of them could forge the groups header and reach the admin API.
    _, admin, _ = build(tmp_path, edge_secret="edge-sec")
    r = admin.get("/api/admin/points",
                  headers={"X-Auth-Request-Groups": "admins"})
    assert r.status_code == 401
    assert admin.get("/api/admin/points",
                     headers=edge_headers(secret="wrong-secret")).status_code == 401


def test_behind_edge_foreign_group_gets_403(tmp_path):
    _, admin, _ = build(tmp_path, edge_secret="edge-sec")
    assert admin.get("/api/admin/points",
                     headers=edge_headers(groups="users")).status_code == 403


def test_point_config_needs_no_gateway_secret(tmp_path):
    # Probes authenticate with basic auth and never pass through the gateway.
    points, _, deps = build(tmp_path, edge_secret="edge-sec")
    db.create_point(deps.conn, db.Point(name="yar"), "sec")
    assert points.get("/api/points/yar/config", headers=basic("yar", "sec")).status_code == 200


# ── zero-touch: enroll, relay, geo ────────────────────────────────────────────


def _token(admin):
    return admin.get("/api/admin/enroll-token", cookies=owner_cookie()).json()["token"]


def test_node_enrolls_and_gets_its_own_squads_and_subscriptions(tmp_path):
    # Zero-touch: the operator configures nothing, so the control plane
    # provisions EVERYTHING for the point — its own pair of squads and
    # accounts with the default target set. A shared subscription would tie
    # the inbound sets of unrelated points together.
    panel = FakePanel()
    points, admin, deps = build(tmp_path, panel=panel)
    r = points.post("/api/enroll", json={"token": _token(admin), "node_id": "abc123"})
    assert r.status_code == 200
    body = r.json()
    p = db.get_point(deps.conn, body["point"])
    assert p.node_id == "abc123"
    assert p.check_account == f"monitor_{body['point']}"
    assert p.check_sub_url and p.load_sub_url and p.tcp_sub_url  # subs exist right away
    assert len(panel.squads_) == 3                 # tcp + http + download


def test_two_nodes_get_different_subscriptions(tmp_path):
    panel = FakePanel()
    points, admin, deps = build(tmp_path, panel=panel)
    tok = _token(admin)
    a = points.post("/api/enroll", json={"token": tok, "node_id": "n-a"}).json()
    b = points.post("/api/enroll", json={"token": tok, "node_id": "n-b"}).json()
    pa, pb = db.get_point(deps.conn, a["point"]), db.get_point(deps.conn, b["point"])
    assert pa.name != pb.name
    assert pa.check_sub_url != pb.check_sub_url


def test_same_node_gets_the_same_point_with_a_new_secret(tmp_path):
    points, admin, _ = build(tmp_path)
    tok = _token(admin)
    first = points.post("/api/enroll", json={"token": tok, "node_id": "n1"}).json()
    second = points.post("/api/enroll", json={"token": tok, "node_id": "n1"}).json()
    assert first["point"] == second["point"]      # the same point
    assert first["secret"] != second["secret"]    # the secret was rotated


def test_invalid_enroll_token_is_rejected(tmp_path):
    points, _, _ = build(tmp_path)
    assert points.post("/api/enroll", json={"token": "foreign", "node_id": "n"}).status_code == 403


def test_token_rotation_revokes_the_old_one(tmp_path):
    points, admin, _ = build(tmp_path)
    old = _token(admin)
    new = admin.post("/api/admin/enroll-token/rotate", cookies=owner_cookie()).json()["token"]
    assert new != old
    assert points.post("/api/enroll", json={"token": old, "node_id": "n"}).status_code == 403
    assert points.post("/api/enroll", json={"token": new, "node_id": "n"}).status_code == 200


def test_enroll_token_response_carries_the_public_url(tmp_path):
    # The admin UI runs on another host, so its own origin would be wrong in
    # the operator's .env — the public points URL comes from the backend.
    _, admin, _ = build(tmp_path)
    body = admin.get("/api/admin/enroll-token", cookies=owner_cookie()).json()
    assert body["control_url"] == "https://xprobe.example"


def test_metrics_are_relayed_to_the_store(tmp_path):
    captured: list = []
    points, _, deps = build(tmp_path, relay_capture=captured)
    db.create_point(deps.conn, db.Point(name="yar"), "sec")
    r = points.post("/api/points/yar/metrics", headers=basic("yar", "sec"),
                    content=b"xray_proxy_status{name=\"x\"} 1\n")
    assert r.status_code == 204
    assert captured and b"xray_proxy_status" in captured[0]


def test_foreign_secret_relays_nothing(tmp_path):
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar"), "sec")
    assert points.post("/api/points/yar/metrics", headers=basic("yar", "wrong"),
                       content=b"x 1").status_code == 401


def test_geo_report_updates_the_city_but_not_the_version(tmp_path):
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar"), "sec")
    before = db.get_point(deps.conn, "yar").version
    r = points.post("/api/points/yar/geo", headers=basic("yar", "sec"),
                    json={"country": "RU", "city": "Yaroslavl", "isp": "ER-Telecom",
                          "ip": "1.2.3.4"})
    assert r.status_code == 200
    p = db.get_point(deps.conn, "yar")
    assert p.city == "Yaroslavl" and p.isp == "ER-Telecom"
    assert p.ip == "1.2.3.4"           # the ip is stored
    assert "ip" not in p.public()      # but never exposed
    assert p.version == before         # an address change restarts no probe


def test_pinned_geo_is_not_overridden_by_reports(tmp_path):
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", city="Tolyatti", pin_geo=True), "sec")
    points.post("/api/points/yar/geo", headers=basic("yar", "sec"),
                json={"city": "Yaroslavl", "ip": "5.6.7.8"})
    p = db.get_point(deps.conn, "yar")
    assert p.city == "Tolyatti"        # pinned by the administrator — reports do not touch it
    assert p.ip == "5.6.7.8"           # the ip is still updated
