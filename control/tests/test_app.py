import base64
import json

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
        self.sub_fetches: list[str] = []
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

    def subscription(self, url, *, user_agent="v2rayNG/1.8.0"):
        # Every account is in the one shared squad, so every subscription
        # carries every host; the control plane is what narrows it down.
        self.sub_fetches.append(url)
        return [{"remarks": h.remark, "outbounds": [{"protocol": "vless"}]}
                for h in self.hosts_]

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
    db.create_point(deps.conn, db.Point(name="yar", check_sub_url="https://s/c"), "sec")
    r = points.get("/api/points/yar/config", headers=basic("yar", "sec"))
    assert r.status_code == 200
    doc = r.json()
    assert doc["point"] == "yar"
    assert doc["probes"]["tcp"]["configs_url"].endswith("/api/points/yar/configs/tcp")


def test_foreign_secret_fetches_no_document(tmp_path):
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar"), "sec")
    assert points.get("/api/points/yar/config", headers=basic("yar", "wrong")).status_code == 401
    # A valid secret under another point's name is no good either.
    assert points.get("/api/points/yar/config", headers=basic("tlt", "sec")).status_code == 401


def test_a_disabled_point_is_told_to_stand_down(tmp_path):
    # Not refused: a probe treats an unreachable control plane as an outage
    # and carries on with what it has, so the only way to make it stop is to
    # answer and say so.
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", enabled=False), "sec")
    r = points.get("/api/points/yar/config", headers=basic("yar", "sec"))
    assert r.status_code == 200
    assert r.json()["enabled"] is False


def test_liveness_follows_the_point_s_own_cadence(tmp_path):
    # A fixed threshold would call every point on a slower schedule late, so
    # the expectation comes from what this point was told to do.
    points, admin, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", check_sub_url="https://s/c"), "sec")

    fresh = admin.get("/api/admin/points/yar", cookies=owner_cookie()).json()
    assert fresh["health"]["state"] == "never"      # nothing has been heard yet

    points.get("/api/points/yar/config", headers=basic("yar", "sec"))
    seen = admin.get("/api/admin/points/yar", cookies=owner_cookie()).json()["health"]
    # Heard from, but it has delivered nothing — that is not "online".
    assert seen["state"] == "no metrics"
    assert seen["seen_ago"] < 5

    points.post("/api/points/yar/metrics", headers=basic("yar", "sec"), content=b"x 1\n")
    live = admin.get("/api/admin/points/yar", cookies=owner_cookie()).json()["health"]
    assert live["state"] == "online"
    assert live["expect_every"] == Defaults().push_interval


def test_a_point_that_owes_no_metrics_is_not_called_dead(tmp_path):
    # Every check off, or the point disabled: it keeps polling and sends
    # nothing. Calling that offline would train the operator to ignore the
    # field.
    points, admin, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", modes={"tcp": False, "tunnel": False,
                                                           "status": False, "download": False}),
                    "sec")
    points.get("/api/points/yar/config", headers=basic("yar", "sec"))
    h = admin.get("/api/admin/points/yar", cookies=owner_cookie()).json()["health"]
    assert h["state"] == "standing by"
    assert h["expects_metrics"] is False


def test_a_version_that_is_not_a_plain_tag_never_enters_the_catalogue(tmp_path):
    # On the node a version is a path component under the core cache. With
    # relaying on, "../.." would let the control plane choose where the file
    # lands — the exact reach the fixed download URL exists to deny.
    _, admin, _ = build(tmp_path)
    for bad in ("../evil", "v1/..", "a\\b", ".hidden", ""):
        r = admin.post("/api/admin/cores", cookies=owner_cookie(),
                       json={"version": bad, "sha256": "a" * 64})
        assert r.status_code == 400, bad


def test_malformed_edit_payloads_are_rejected_at_the_door(tmp_path):
    # A wrong-shaped value would not fail on the PATCH — it would fail later,
    # as a 500 on every document build for this point.
    _, admin, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar"), "sec")
    for bad in ({"modes": "tcp"}, {"modes": {"tcp": "yes"}},
                {"intervals": {"tcp": "fast"}}, {"cores": {"status": 1}},
                {"targets": {"tcp": "RU · TLS"}}):
        r = admin.patch("/api/admin/points/yar", cookies=owner_cookie(), json=bad)
        assert r.status_code == 400, bad
    # A string instead of a list would be exploded into letters by set().
    r = admin.post("/api/admin/points/yar/set", cookies=owner_cookie(),
                   json={"tcp_remarks": "RU · TLS"})
    assert r.status_code == 400
    assert db.get_point(deps.conn, "yar").version == 1     # nothing was written


def test_enroll_slug_stays_ascii(tmp_path):
    # The slug becomes a point name and a panel username; a city reported in
    # another alphabet must fall through, not produce a name the panel rejects.
    points, admin, deps = build(tmp_path)
    tok = _issue(admin, label="")["token"]
    r = points.post("/api/enroll", json={"token": tok, "node_id": "n1",
                                         "geo": {"city": "Ярославль"}})
    assert r.status_code == 200
    name = r.json()["point"]
    assert name.isascii()
    assert db.get_point(deps.conn, name) is not None


def test_core_catalogue_requires_a_checksum(tmp_path):
    # The checksum is the only reason fetching a binary is safe at all, so a
    # version without one cannot enter the catalogue.
    _, admin, _ = build(tmp_path)
    bad = admin.post("/api/admin/cores", cookies=owner_cookie(),
                     json={"version": "v26.7.28", "sha256": "nope"})
    assert bad.status_code == 400
    good = admin.post("/api/admin/cores", cookies=owner_cookie(),
                      json={"version": "v26.7.28", "sha256": "a" * 64})
    assert good.status_code == 200
    listed = admin.get("/api/admin/cores", cookies=owner_cookie()).json()
    assert listed["cores"] == [{"version": "v26.7.28", "sha256": "a" * 64}]
    assert listed["relay"] is False        # off unless the owner turns it on


def test_the_document_carries_the_catalogue_not_a_location(tmp_path):
    # The download location lives in the probe. If the control plane could
    # name one, it could point the fleet anywhere.
    points, admin, deps = build(tmp_path)
    admin.post("/api/admin/cores", cookies=owner_cookie(),
               json={"version": "v26.7.28", "sha256": "b" * 64})
    db.create_point(deps.conn, db.Point(name="yar", check_sub_url="https://s/c"), "sec")
    doc = points.get("/api/points/yar/config", headers=basic("yar", "sec")).json()
    assert doc["cores"] == [{"version": "v26.7.28", "sha256": "b" * 64}]
    assert "http" not in json.dumps(doc["cores"])


def test_core_relay_is_refused_until_it_is_enabled(tmp_path):
    points, admin, deps = build(tmp_path)
    admin.post("/api/admin/cores", cookies=owner_cookie(),
               json={"version": "v26.7.28", "sha256": "c" * 64})
    db.create_point(deps.conn, db.Point(name="yar"), "sec")
    r = points.get("/api/points/yar/core/v26.7.28", headers=basic("yar", "sec"))
    assert r.status_code == 403
    admin.post("/api/admin/cores/relay", cookies=owner_cookie(), json={"enabled": True})
    # Now allowed through the gate — and refused by the catalogue for an
    # unknown version rather than fetched blindly.
    assert points.get("/api/points/yar/core/v1.2.3",
                      headers=basic("yar", "sec")).status_code == 404


def test_a_disabled_point_cannot_push_metrics(tmp_path):
    # Takes effect on the next sample rather than the next poll — a probe that
    # has not yet asked is still pushing.
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", enabled=False), "sec")
    r = points.post("/api/points/yar/metrics", headers=basic("yar", "sec"), content=b"x 1")
    assert r.status_code == 403


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


def test_provisioning_creates_one_account_in_the_shared_squad(tmp_path):
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
    # One squad for the whole fleet, one account for this point.
    assert [s.name for s in panel.squads_] == ["Monitor"]
    assert set(panel.users) == {"monitor_yaroslavl"}
    # Target sets live in the control plane, not in panel squads.
    p = db.get_point(deps.conn, "yaroslavl")
    assert p.check_sub_url == "https://sub/monitor_yaroslavl"
    assert p.targets["status"] == ["RU · TLS", "RU · XHTTP"]
    assert p.targets["download"] == ["RU · XHTTP"]


def test_second_point_reuses_the_shared_squad(tmp_path):
    panel = FakePanel()
    _, admin, _ = build(tmp_path, panel=panel)
    for name in ("yar", "tlt"):
        r = admin.post("/api/admin/points", cookies=owner_cookie(),
                       json={"name": name, "check_remarks": ["RU · TLS"], "load_remarks": []})
        assert r.status_code == 200, r.text
    assert len(panel.squads_) == 1
    assert set(panel.users) == {"monitor_yar", "monitor_tlt"}


def test_configs_endpoint_returns_only_the_check_s_targets(tmp_path):
    panel = FakePanel()
    points, admin, deps = build(tmp_path, panel=panel)
    admin.post("/api/admin/points", cookies=owner_cookie(), json={
        "name": "yar", "tcp_remarks": ["RU · TLS", "RU · XHTTP"],
        "check_remarks": ["RU · TLS"], "load_remarks": ["RU · XHTTP"]})
    secret = "s3cret"
    db.rotate_secret(deps.conn, "yar", secret)

    got = {}
    for kind in ("tcp", "tunnel", "status", "download"):
        r = points.get(f"/api/points/yar/configs/{kind}", headers=basic("yar", secret))
        assert r.status_code == 200, r.text
        got[kind] = [c["remarks"] for c in r.json()]
    assert got["tcp"] == ["RU · TLS", "RU · XHTTP"]
    assert got["status"] == ["RU · TLS"]
    assert got["download"] == ["RU · XHTTP"]
    assert got["tunnel"] == []          # not asked for, so not probed


def test_a_target_the_account_cannot_see_is_reported(tmp_path):
    # Filtering against a subscription that lacks the host yields fewer
    # configs than asked for. Silently, the check would look healthy while
    # probing less — so the control plane records it and the UI shows it.
    panel = FakePanel()
    points, admin, deps = build(tmp_path, panel=panel)
    admin.post("/api/admin/points", cookies=owner_cookie(),
               json={"name": "yar", "check_remarks": ["RU · TLS"], "load_remarks": []})
    db.rotate_secret(deps.conn, "yar", "sec")
    # A host that exists in the panel but not in this account's subscription.
    panel.hosts_ = [h for h in panel.hosts_ if h.remark != "RU · TLS"]

    r = points.get("/api/points/yar/configs/status", headers=basic("yar", "sec"))
    assert r.status_code == 200
    assert r.json() == []
    detail = admin.get("/api/admin/points/yar", cookies=owner_cookie()).json()
    assert detail["missing_targets"] == ["RU · TLS"]


def test_configs_are_not_served_to_a_foreign_secret(tmp_path):
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", check_sub_url="https://s/c"), "sec")
    assert points.get("/api/points/yar/configs/tcp",
                      headers=basic("yar", "wrong")).status_code == 401


def test_a_disabled_point_gets_no_configs(tmp_path):
    points, _, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", enabled=False,
                                        check_sub_url="https://s/c"), "sec")
    assert points.get("/api/points/yar/configs/tcp",
                      headers=basic("yar", "sec")).status_code == 404


def test_subscription_is_cached_between_checks(tmp_path):
    # Three checks poll far more often than the panel's answer changes.
    panel = FakePanel()
    points, admin, deps = build(tmp_path, panel=panel)
    admin.post("/api/admin/points", cookies=owner_cookie(),
               json={"name": "yar", "check_remarks": ["RU · TLS"], "load_remarks": []})
    db.rotate_secret(deps.conn, "yar", "sec")
    for kind in ("tcp", "status", "download"):
        points.get(f"/api/points/yar/configs/{kind}", headers=basic("yar", "sec"))
    assert len(panel.sub_fetches) == 1


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


def test_legacy_point_targets_are_read_from_its_old_squads(tmp_path):
    # A point provisioned before the control plane filtered configs kept its
    # sets as squad membership. Reading them back on first use is what lets
    # the fleet switch over without a migration step.
    panel = FakePanel()
    _, admin, deps = build(tmp_path, panel=panel)
    http_squad = panel.create_squad("Monitor-yar-check", ["i-tls"])
    load_squad = panel.create_squad("Monitor-yar-load", ["i-xhttp"])
    db.create_point(deps.conn, db.Point(name="yar", check_squad=http_squad,
                                        load_squad=load_squad), "sec")
    r = admin.get("/api/admin/points/yar", cookies=owner_cookie())
    assert r.status_code == 200
    body = r.json()
    assert body["check_remarks"] == ["RU · TLS"]
    assert body["load_remarks"] == ["RU · XHTTP"]
    assert body["tcp_remarks"] == ["RU · TLS"]     # tcp inherits http


def test_saving_targets_writes_nothing_to_the_panel(tmp_path):
    # The whole point of the switch: target edits stop touching live host
    # objects in the panel.
    panel = FakePanel()
    _, admin, deps = build(tmp_path, panel=panel)
    db.create_point(deps.conn, db.Point(name="yar"), "sec")
    before = [list(s.inbounds) for s in panel.squads_]
    hosts_before = [(h.uuid, list(h.excluded)) for h in panel.hosts_]
    r = admin.post("/api/admin/points/yar/set", cookies=owner_cookie(),
                   json={"tcp_remarks": ["RU · TLS"], "check_remarks": ["RU · XHTTP"],
                         "load_remarks": []})
    assert r.status_code == 200
    assert [list(s.inbounds) for s in panel.squads_] == before
    assert [(h.uuid, list(h.excluded)) for h in panel.hosts_] == hosts_before
    p = db.get_point(deps.conn, "yar")
    assert p.targets == {"tcp": ["RU · TLS"], "tunnel": [],
                         "status": ["RU · XHTTP"], "download": []}


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


def _issue(admin, **body):
    r = admin.post("/api/admin/enroll-tokens", cookies=owner_cookie(), json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_node_enrolls_and_gets_its_own_account(tmp_path):
    # Zero-touch: the operator configures nothing, so the control plane
    # provisions everything. Its own account rather than a fleet-wide one —
    # that is what lets one node be cut off without disturbing the others.
    panel = FakePanel()
    points, admin, deps = build(tmp_path, panel=panel)
    tok = _issue(admin, label="Ivan's NAS")["token"]
    r = points.post("/api/enroll", json={"token": tok, "node_id": "abc123"})
    assert r.status_code == 200
    body = r.json()
    p = db.get_point(deps.conn, body["point"])
    assert p.node_id == "abc123"
    assert p.check_account == f"monitor_{body['point']}"
    assert p.check_sub_url                          # its own subscription
    assert p.targets["status"] == list(("RU · TLS", "RU · XHTTP"))
    assert [s.name for s in panel.squads_] == ["Monitor"]


def test_each_node_has_its_own_token(tmp_path):
    panel = FakePanel()
    points, admin, deps = build(tmp_path, panel=panel)
    a = points.post("/api/enroll", json={"token": _issue(admin, label="a")["token"],
                                         "node_id": "n-a"}).json()
    b = points.post("/api/enroll", json={"token": _issue(admin, label="b")["token"],
                                         "node_id": "n-b"}).json()
    pa, pb = db.get_point(deps.conn, a["point"]), db.get_point(deps.conn, b["point"])
    assert pa.name != pb.name
    assert pa.check_sub_url != pb.check_sub_url


def test_a_token_bound_to_a_point_always_returns_that_point(tmp_path):
    # This is how a node comes back after losing its storage — and why the
    # token has to keep working rather than be single-use.
    points, admin, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", check_sub_url="https://s/c"), "old")
    tok = _issue(admin, label="yaroslavl", point="yar")["token"]
    first = points.post("/api/enroll", json={"token": tok, "node_id": "n1"}).json()
    second = points.post("/api/enroll", json={"token": tok, "node_id": "n2"}).json()
    assert first["point"] == second["point"] == "yar"
    assert first["secret"] != second["secret"]    # a fresh secret each time


def test_a_token_for_an_unknown_point_is_refused(tmp_path):
    _, admin, _ = build(tmp_path)
    r = admin.post("/api/admin/enroll-tokens", cookies=owner_cookie(),
                   json={"label": "x", "point": "nope"})
    assert r.status_code == 404


def test_invalid_enroll_token_is_rejected(tmp_path):
    points, _, _ = build(tmp_path)
    assert points.post("/api/enroll", json={"token": "foreign", "node_id": "n"}).status_code == 403


def test_revoking_one_token_leaves_the_others_working(tmp_path):
    # The reason tokens are per node: cutting one operator off must not mean
    # re-keying everyone else.
    points, admin, _ = build(tmp_path)
    doomed = _issue(admin, label="going away")
    kept = _issue(admin, label="staying")
    assert admin.post(f"/api/admin/enroll-tokens/{doomed['id']}/revoke",
                      cookies=owner_cookie()).status_code == 200
    assert points.post("/api/enroll", json={"token": doomed["token"],
                                            "node_id": "n"}).status_code == 403
    assert points.post("/api/enroll", json={"token": kept["token"],
                                            "node_id": "n"}).status_code == 200


def test_a_revoked_token_cannot_bring_its_point_back(tmp_path):
    # Revoking is what actually ends access: without it, disabling a point
    # only stops that point while the node enrolls itself a new one.
    points, admin, deps = build(tmp_path)
    db.create_point(deps.conn, db.Point(name="yar", check_sub_url="https://s/c"), "old")
    issued = _issue(admin, label="yaroslavl", point="yar")
    assert points.post("/api/enroll", json={"token": issued["token"],
                                            "node_id": "n"}).status_code == 200
    admin.post(f"/api/admin/enroll-tokens/{issued['id']}/revoke", cookies=owner_cookie())
    assert points.post("/api/enroll", json={"token": issued["token"],
                                            "node_id": "n"}).status_code == 403


def test_tokens_are_listed_without_ever_showing_them(tmp_path):
    _, admin, _ = build(tmp_path)
    issued = _issue(admin, label="Ivan's NAS")
    listed = admin.get("/api/admin/enroll-tokens", cookies=owner_cookie()).json()
    assert [t["label"] for t in listed] == ["Ivan's NAS"]
    assert issued["token"] not in json.dumps(listed)


def test_issued_token_comes_with_ready_artifacts(tmp_path):
    # The token is the node's identity and lives in the manifest, so nothing
    # has to be persisted for it to come back — an emptyDir is enough.
    _, admin, _ = build(tmp_path)
    issued = _issue(admin, label="Ivan's NAS")
    assert issued["control_url"] == "https://xprobe.example"
    assert f"ENROLL_TOKEN={issued['token']}" in issued["env"]
    assert "CONTROL_URL=https://xprobe.example" in issued["env"]
    assert "kubectl apply" in issued["kubectl"]
    assert issued["token"] in issued["kubectl"]


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
