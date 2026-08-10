"""Point storage. SQLite: the fleet is tens of points, not millions.

Only what the control plane itself manages lives here: point names, secret
hashes, labels, modes, intervals and subscription links. The target set (which
servers a point checks) lives in the panel — only the uuids of the squads it
is pinned to are stored. Usage, node status, metrics — not here: those are
other systems' data, and duplicating them would create a second answer to the
same question.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS points (
    name              TEXT PRIMARY KEY,
    secret_hash       TEXT NOT NULL,
    node_id           TEXT UNIQUE,               -- auto-enrolled node identity, for re-enroll
    vantage           TEXT NOT NULL DEFAULT 'home',
    country           TEXT NOT NULL DEFAULT '',
    city              TEXT NOT NULL DEFAULT '',
    isp               TEXT NOT NULL DEFAULT '',
    ip                TEXT NOT NULL DEFAULT '',    -- stored, NEVER exposed
    pin_geo           INTEGER NOT NULL DEFAULT 0,  -- geo pinned by the administrator
    check_account     TEXT NOT NULL DEFAULT '',    -- the http check's account/squad/link
    load_account      TEXT NOT NULL DEFAULT '',
    tcp_account       TEXT NOT NULL DEFAULT '',
    check_squad       TEXT NOT NULL DEFAULT '',
    load_squad        TEXT NOT NULL DEFAULT '',
    tcp_squad         TEXT NOT NULL DEFAULT '',
    check_sub_url     TEXT NOT NULL DEFAULT '',
    load_sub_url      TEXT NOT NULL DEFAULT '',
    tcp_sub_url       TEXT NOT NULL DEFAULT '',
    modes             TEXT NOT NULL DEFAULT '{}',   -- {"tcp":true,...}
    intervals         TEXT NOT NULL DEFAULT '{}',   -- per-check interval overrides
    targets           TEXT NOT NULL DEFAULT '{}',   -- {"tcp":[names],"status":[],"download":[]}
    cores             TEXT NOT NULL DEFAULT '{}',   -- {"status":"v26.7.28",...} per check
    xray_versions     TEXT NOT NULL DEFAULT '[]',   -- what the probe reports it carries
    last_seen_at      REAL NOT NULL DEFAULT 0,      -- any authenticated call from the probe
    last_metrics_at   REAL NOT NULL DEFAULT 0,      -- the last sample it delivered
    download_url      TEXT NOT NULL DEFAULT '',     -- volume test source, empty = fleet default
    download_min_bytes INTEGER NOT NULL DEFAULT 0,  -- volume that must get through
    exit_expectations TEXT NOT NULL DEFAULT '',     -- json or empty (fleet defaults)
    push_enabled      INTEGER NOT NULL DEFAULT 1,
    enabled           INTEGER NOT NULL DEFAULT 1,
    version           INTEGER NOT NULL DEFAULT 1,
    note              TEXT NOT NULL DEFAULT '',
    created_at        REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- One token per node, not one for the fleet. A fleet-wide token cannot be
-- taken back from one operator: disabling their point only stops that point,
-- while the token still lets them enroll a fresh one. Revoking here ends that
-- node's access and touches nobody else.
CREATE TABLE IF NOT EXISTS enroll_tokens (
    id           TEXT PRIMARY KEY,            -- short, for referring to it in the UI
    token_hash   TEXT NOT NULL,               -- the token itself is never stored
    label        TEXT NOT NULL DEFAULT '',    -- whose node this is
    point        TEXT NOT NULL DEFAULT '',    -- bound on first use
    revoked      INTEGER NOT NULL DEFAULT 0,
    created_at   REAL NOT NULL DEFAULT 0,
    last_used_at REAL NOT NULL DEFAULT 0,
    last_node_id TEXT NOT NULL DEFAULT ''     -- diagnostic: spots a shared token
);
"""


@dataclass
class Point:
    name: str
    node_id: str = ""
    vantage: str = "home"
    country: str = ""
    city: str = ""
    isp: str = ""
    # Last known external address of the probe. Kept for diagnostics, but NEVER
    # exposed (not in the document, not in any UI): there is no reason to show
    # a vantage node's address. It can change without a probe restart — the geo
    # report updates it.
    ip: str = ""
    # Geo set manually by the administrator wins over the probe's
    # self-detection. When unset, whatever the probe detected is shown
    # (country/city/isp above).
    pin_geo: bool = False
    # Three independent target sets, one per check: check_* feeds http,
    # tcp_* feeds tcp, load_* feeds download. (check_* kept its historical
    # name — renaming a live sqlite column buys nothing.)
    check_account: str = ""
    load_account: str = ""
    tcp_account: str = ""
    check_squad: str = ""
    load_squad: str = ""
    tcp_squad: str = ""
    check_sub_url: str = ""
    load_sub_url: str = ""
    tcp_sub_url: str = ""
    modes: dict[str, bool] = None  # type: ignore[assignment]
    intervals: dict[str, int] = None  # type: ignore[assignment]
    # Which hosts each check probes, by config name. Lives here rather than in
    # panel squads: the control plane filters the configs itself, so target
    # edits never write to the panel.
    targets: dict[str, list[str]] = None  # type: ignore[assignment]
    # Which xray core each check runs with, e.g. {"status": "v26.7.28"}. Empty
    # means the probe image's default. Per check because the answer differs by
    # core: a config that works on one version can fail silently on another,
    # which is the whole reason this tool exists.
    cores: dict[str, str] = None  # type: ignore[assignment]
    # Cores the probe reports it carries. Reported, never configured — the
    # image decides, and this is how the UI can warn before a check is set to
    # a version the node does not have.
    xray_versions: list[str] = None  # type: ignore[assignment]
    # When the probe was last heard from at all, and when it last delivered a
    # sample. Two clocks because they fail apart: a probe that is standing
    # down, or whose checks are all off, still polls but sends nothing.
    last_seen_at: float = 0.0
    last_metrics_at: float = 0.0
    # Volume-tolerance test settings; empty/0 means the fleet default. Per
    # point because how much a network lets through is a property of that
    # network, not of the fleet.
    download_url: str = ""
    download_min_bytes: int = 0
    exit_expectations: dict[str, str] | None = None
    push_enabled: bool = True
    enabled: bool = True
    version: int = 1
    note: str = ""
    created_at: float = 0.0

    def __post_init__(self) -> None:
        if self.modes is None:
            self.modes = {"tcp": True, "status": True, "download": True}
        if self.intervals is None:
            self.intervals = {}
        if self.targets is None:
            self.targets = {}
        if self.cores is None:
            self.cores = {}
        if self.xray_versions is None:
            self.xray_versions = []

    def public(self) -> dict[str, Any]:
        """The point as the UI sees it — without the secret and the node IP.

        The IP is deliberately withheld even from the administrator's list:
        there is no reason to display a vantage node's address, and it is only
        stored for diagnostics.
        """
        return {
            "name": self.name, "vantage": self.vantage, "country": self.country,
            "city": self.city, "isp": self.isp, "pin_geo": self.pin_geo,
            "check_account": self.check_account, "load_account": self.load_account,
            "tcp_account": self.tcp_account,
            "check_squad": self.check_squad, "load_squad": self.load_squad,
            "tcp_squad": self.tcp_squad,
            "has_check_sub": bool(self.check_sub_url), "has_load_sub": bool(self.load_sub_url),
            "modes": self.modes, "intervals": self.intervals,
            "targets": self.targets, "cores": self.cores,
            "xray_versions": self.xray_versions,
            "last_seen_at": self.last_seen_at, "last_metrics_at": self.last_metrics_at,
            "download_url": self.download_url,
            "download_min_bytes": self.download_min_bytes,
            "exit_expectations": self.exit_expectations,
            "push_enabled": self.push_enabled, "enabled": self.enabled,
            "auto": bool(self.node_id), "version": self.version, "note": self.note,
        }


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    # The tcp set arrived after the first deployments: databases created by
    # older versions lack its columns. CREATE IF NOT EXISTS does not extend
    # an existing table, so add them here.
    have = {r["name"] for r in conn.execute("PRAGMA table_info(points)")}
    for col in ("tcp_account", "tcp_squad", "tcp_sub_url", "download_url"):
        if col not in have:
            conn.execute(f"ALTER TABLE points ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
    if "targets" not in have:
        conn.execute("ALTER TABLE points ADD COLUMN targets TEXT NOT NULL DEFAULT '{}'")
    if "cores" not in have:
        conn.execute("ALTER TABLE points ADD COLUMN cores TEXT NOT NULL DEFAULT '{}'")
    if "xray_versions" not in have:
        conn.execute("ALTER TABLE points ADD COLUMN xray_versions TEXT NOT NULL DEFAULT '[]'")
    for col in ("last_seen_at", "last_metrics_at"):
        if col not in have:
            conn.execute(f"ALTER TABLE points ADD COLUMN {col} REAL NOT NULL DEFAULT 0")
    if "download_min_bytes" not in have:
        conn.execute("ALTER TABLE points ADD COLUMN download_min_bytes INTEGER NOT NULL DEFAULT 0")
    conn.commit()
    return conn


def hash_secret(secret: str) -> str:
    """Point secrets are stored hashed only: a database leak yields no tokens."""
    salt = secrets.token_hex(8)
    digest = hashlib.sha256((salt + secret).encode()).hexdigest()
    return f"{salt}${digest}"


def check_secret(secret: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    want = hashlib.sha256((salt + secret).encode()).hexdigest()
    return hmac.compare_digest(want, digest)


def _row_to_point(r: sqlite3.Row) -> Point:
    return Point(
        name=r["name"], node_id=r["node_id"] or "", vantage=r["vantage"],
        country=r["country"], city=r["city"], isp=r["isp"], ip=r["ip"],
        pin_geo=bool(r["pin_geo"]),
        check_account=r["check_account"], load_account=r["load_account"],
        tcp_account=r["tcp_account"],
        check_squad=r["check_squad"], load_squad=r["load_squad"],
        tcp_squad=r["tcp_squad"],
        check_sub_url=r["check_sub_url"], load_sub_url=r["load_sub_url"],
        tcp_sub_url=r["tcp_sub_url"],
        modes=json.loads(r["modes"] or "{}"), intervals=json.loads(r["intervals"] or "{}"),
        targets=json.loads(r["targets"] or "{}"), cores=json.loads(r["cores"] or "{}"),
        xray_versions=json.loads(r["xray_versions"] or "[]"),
        last_seen_at=r["last_seen_at"], last_metrics_at=r["last_metrics_at"],
        download_url=r["download_url"], download_min_bytes=r["download_min_bytes"],
        exit_expectations=json.loads(r["exit_expectations"]) if r["exit_expectations"] else None,
        push_enabled=bool(r["push_enabled"]), enabled=bool(r["enabled"]),
        version=r["version"], note=r["note"], created_at=r["created_at"],
    )


def get_point_by_node(conn: sqlite3.Connection, node_id: str) -> Point | None:
    r = conn.execute("SELECT * FROM points WHERE node_id = ?", (node_id,)).fetchone()
    return _row_to_point(r) if r else None


def get_point(conn: sqlite3.Connection, name: str) -> Point | None:
    r = conn.execute("SELECT * FROM points WHERE name = ?", (name,)).fetchone()
    return _row_to_point(r) if r else None


def get_secret_hash(conn: sqlite3.Connection, name: str) -> str | None:
    r = conn.execute("SELECT secret_hash FROM points WHERE name = ?", (name,)).fetchone()
    return r["secret_hash"] if r else None


def list_points(conn: sqlite3.Connection) -> list[Point]:
    return [_row_to_point(r) for r in conn.execute("SELECT * FROM points ORDER BY name")]


def create_point(conn: sqlite3.Connection, point: Point, secret: str) -> None:
    conn.execute(
        """INSERT INTO points
           (name, secret_hash, node_id, vantage, country, city, isp, ip, pin_geo,
            check_account, load_account, tcp_account, check_squad, load_squad,
            tcp_squad, check_sub_url, load_sub_url, tcp_sub_url, modes, intervals,
            targets, cores, xray_versions, download_url, download_min_bytes,
            exit_expectations, push_enabled, enabled, version, note, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (point.name, hash_secret(secret), point.node_id or None, point.vantage,
         point.country, point.city, point.isp, point.ip, int(point.pin_geo),
         point.check_account, point.load_account, point.tcp_account,
         point.check_squad, point.load_squad, point.tcp_squad,
         point.check_sub_url, point.load_sub_url, point.tcp_sub_url,
         json.dumps(point.modes), json.dumps(point.intervals),
         json.dumps(point.targets), json.dumps(point.cores),
         json.dumps(point.xray_versions),
         point.download_url, point.download_min_bytes,
         json.dumps(point.exit_expectations) if point.exit_expectations else "",
         int(point.push_enabled), int(point.enabled), 1, point.note, time.time()),
    )
    conn.commit()


# Fields the UI may change. Changing ANY of them bumps the version — that is
# how the probe learns about the edit and restarts, instead of diffing content.
EDITABLE = {
    "vantage", "country", "city", "isp", "pin_geo", "check_squad", "load_squad",
    "tcp_squad", "check_sub_url", "load_sub_url", "tcp_sub_url", "modes",
    "intervals", "exit_expectations", "push_enabled", "enabled", "note",
    "check_account", "load_account", "tcp_account",
    "download_url", "download_min_bytes", "targets", "cores",
}
_JSON_FIELDS = {"modes", "intervals", "exit_expectations", "targets", "cores"}


def update_point(conn: sqlite3.Connection, name: str, changes: dict[str, Any]) -> int:
    """Update point fields and bump the version. Returns the new version."""
    fields = {k: v for k, v in changes.items() if k in EDITABLE}
    if not fields:
        r = conn.execute("SELECT version FROM points WHERE name = ?", (name,)).fetchone()
        return r["version"] if r else 0
    sets, values = [], []
    for k, v in fields.items():
        sets.append(f"{k} = ?")
        if k in _JSON_FIELDS:
            values.append(json.dumps(v) if v else "")
        elif isinstance(v, bool):
            values.append(int(v))
        else:
            values.append(v)
    sets.append("version = version + 1")
    values.append(name)
    conn.execute(f"UPDATE points SET {', '.join(sets)} WHERE name = ?", values)
    conn.commit()
    r = conn.execute("SELECT version FROM points WHERE name = ?", (name,)).fetchone()
    return r["version"] if r else 0


def rotate_secret(conn: sqlite3.Connection, name: str, secret: str) -> None:
    conn.execute("UPDATE points SET secret_hash = ?, version = version + 1 WHERE name = ?",
                 (hash_secret(secret), name))
    conn.commit()


def delete_point(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute("DELETE FROM points WHERE name = ?", (name,))
    conn.commit()
    return cur.rowcount > 0


def touch_point(conn: sqlite3.Connection, name: str, *, metrics: bool = False) -> None:
    """Record that the probe was heard from. Does NOT bump the version — the
    point has not changed, we merely learned it is alive."""
    now = time.time()
    if metrics:
        conn.execute("UPDATE points SET last_seen_at = ?, last_metrics_at = ? WHERE name = ?",
                     (now, now, name))
    else:
        conn.execute("UPDATE points SET last_seen_at = ? WHERE name = ?", (now, name))
    conn.commit()


def update_xray_versions(conn: sqlite3.Connection, name: str, versions: list[str]) -> None:
    """What the probe says it carries. Reported, never configured — and it does
    not bump the version: learning about the image is not a config change."""
    conn.execute("UPDATE points SET xray_versions = ? WHERE name = ?",
                 (json.dumps(sorted(set(versions))), name))
    conn.commit()


def update_geo(conn: sqlite3.Connection, name: str, *, country: str, city: str,
               isp: str, ip: str) -> None:
    """Geo as reported by the probe. Does NOT bump the version: the node's
    address may change on the fly, and restarting the probe over it would be
    pointless. The probe sets metric labels itself; this copy exists only for
    the UI. Pinned geo is left untouched.
    """
    r = conn.execute("SELECT pin_geo FROM points WHERE name = ?", (name,)).fetchone()
    if r is None or r["pin_geo"]:
        # The IP is always updated (never displayed, but useful for
        # diagnostics); country/city/ISP only when not pinned.
        conn.execute("UPDATE points SET ip = ? WHERE name = ?", (ip, name))
        conn.commit()
        return
    conn.execute(
        "UPDATE points SET country = ?, city = ?, isp = ?, ip = ? WHERE name = ?",
        (country, city, isp, ip, name),
    )
    conn.commit()


# ── settings (enroll token) ──────────────────────────────────────────────────


@dataclass
class EnrollToken:
    id: str
    label: str = ""
    point: str = ""
    revoked: bool = False
    created_at: float = 0.0
    last_used_at: float = 0.0
    last_node_id: str = ""

    def public(self) -> dict[str, Any]:
        """Never carries the token — only its hash is stored anyway."""
        return {
            "id": self.id, "label": self.label, "point": self.point,
            "revoked": self.revoked, "created_at": self.created_at,
            "last_used_at": self.last_used_at, "used": bool(self.last_used_at),
        }


def create_enroll_token(conn: sqlite3.Connection, secret: str, *, label: str = "",
                        point: str = "") -> EnrollToken:
    token = EnrollToken(id=secrets.token_hex(4), label=label, point=point,
                        created_at=time.time())
    conn.execute(
        "INSERT INTO enroll_tokens(id, token_hash, label, point, created_at) "
        "VALUES(?,?,?,?,?)",
        (token.id, hash_secret(secret), label, point, token.created_at))
    conn.commit()
    return token


def _row_to_token(r: sqlite3.Row) -> EnrollToken:
    return EnrollToken(
        id=r["id"], label=r["label"], point=r["point"], revoked=bool(r["revoked"]),
        created_at=r["created_at"], last_used_at=r["last_used_at"],
        last_node_id=r["last_node_id"])


def list_enroll_tokens(conn: sqlite3.Connection) -> list[EnrollToken]:
    return [_row_to_token(r) for r in
            conn.execute("SELECT * FROM enroll_tokens ORDER BY created_at DESC")]


def find_enroll_token(conn: sqlite3.Connection, secret: str) -> EnrollToken | None:
    """The token presented by a node, if it is one of ours and still valid.

    Every row is checked because only hashes are stored — there are tens of
    tokens at most, and a lookup that cannot be done by index is a small price
    for not keeping the tokens themselves.
    """
    for r in conn.execute("SELECT * FROM enroll_tokens"):
        if check_secret(secret, r["token_hash"]):
            token = _row_to_token(r)
            return None if token.revoked else token
    return None


def bind_enroll_token(conn: sqlite3.Connection, token_id: str, point: str) -> None:
    conn.execute("UPDATE enroll_tokens SET point = ? WHERE id = ?", (point, token_id))
    conn.commit()


def touch_enroll_token(conn: sqlite3.Connection, token_id: str, node_id: str) -> None:
    conn.execute("UPDATE enroll_tokens SET last_used_at = ?, last_node_id = ? WHERE id = ?",
                 (time.time(), node_id, token_id))
    conn.commit()


def revoke_enroll_token(conn: sqlite3.Connection, token_id: str) -> bool:
    cur = conn.execute("UPDATE enroll_tokens SET revoked = 1 WHERE id = ?", (token_id,))
    conn.commit()
    return cur.rowcount > 0


def get_setting(conn: sqlite3.Connection, key: str) -> str | None:
    r = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return r["value"] if r else None


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()
