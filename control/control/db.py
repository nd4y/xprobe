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
    check_account     TEXT NOT NULL DEFAULT '',
    load_account      TEXT NOT NULL DEFAULT '',
    check_squad       TEXT NOT NULL DEFAULT '',
    load_squad        TEXT NOT NULL DEFAULT '',
    check_sub_url     TEXT NOT NULL DEFAULT '',
    load_sub_url      TEXT NOT NULL DEFAULT '',
    modes             TEXT NOT NULL DEFAULT '{}',   -- {"tcp":true,...}
    intervals         TEXT NOT NULL DEFAULT '{}',   -- per-check interval overrides
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
    check_account: str = ""
    load_account: str = ""
    check_squad: str = ""
    load_squad: str = ""
    check_sub_url: str = ""
    load_sub_url: str = ""
    modes: dict[str, bool] = None  # type: ignore[assignment]
    intervals: dict[str, int] = None  # type: ignore[assignment]
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
            "check_squad": self.check_squad, "load_squad": self.load_squad,
            "has_check_sub": bool(self.check_sub_url), "has_load_sub": bool(self.load_sub_url),
            "modes": self.modes, "intervals": self.intervals,
            "exit_expectations": self.exit_expectations,
            "push_enabled": self.push_enabled, "enabled": self.enabled,
            "auto": bool(self.node_id), "version": self.version, "note": self.note,
        }


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
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
        check_squad=r["check_squad"], load_squad=r["load_squad"],
        check_sub_url=r["check_sub_url"], load_sub_url=r["load_sub_url"],
        modes=json.loads(r["modes"] or "{}"), intervals=json.loads(r["intervals"] or "{}"),
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
            check_account, load_account, check_squad, load_squad, check_sub_url,
            load_sub_url, modes, intervals, exit_expectations, push_enabled, enabled,
            version, note, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (point.name, hash_secret(secret), point.node_id or None, point.vantage,
         point.country, point.city, point.isp, point.ip, int(point.pin_geo),
         point.check_account, point.load_account, point.check_squad,
         point.load_squad, point.check_sub_url, point.load_sub_url,
         json.dumps(point.modes), json.dumps(point.intervals),
         json.dumps(point.exit_expectations) if point.exit_expectations else "",
         int(point.push_enabled), int(point.enabled), 1, point.note, time.time()),
    )
    conn.commit()


# Fields the UI may change. Changing ANY of them bumps the version — that is
# how the probe learns about the edit and restarts, instead of diffing content.
EDITABLE = {
    "vantage", "country", "city", "isp", "pin_geo", "check_squad", "load_squad",
    "check_sub_url", "load_sub_url", "modes", "intervals", "exit_expectations",
    "push_enabled", "enabled", "note", "check_account", "load_account",
}
_JSON_FIELDS = {"modes", "intervals", "exit_expectations"}


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
