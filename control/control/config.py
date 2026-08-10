"""Service settings. Secrets appear only as environment variable NAMES, never values."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class ConfigError(ValueError):
    pass


def _env(name: str, *, required: bool = False, default: str = "") -> str:
    val = os.environ.get(name, "").strip()
    if not val and required:
        raise ConfigError(f"environment variable {name} is required")
    return val or default


@dataclass(frozen=True)
class PanelConfig:
    base_url: str
    token: str


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    client_id: str
    client_secret: str


@dataclass(frozen=True)
class Defaults:
    """Defaults for new points — shared across the fleet.

    Kept in code rather than the database: these are not knobs turned daily
    but a sensible starting point that individual points diverge from.
    """

    # Fallback push target when the service has no public base URL configured.
    # Normally empty: with XPC_BASE_URL set, documents point probes at the
    # control-plane relay.
    push_url: str = ""
    push_interval: int = 60
    subscription_interval: int = 300
    # tcp and http run concurrently on the same 5-minute schedule; the
    # bandwidth check every 30 minutes.
    tcp_interval: int = 300
    # The same schedule as tcp: the two are meant to be read side by side, and
    # comparing them is only fair on samples taken at the same rate.
    tunnel_interval: int = 300
    status_interval: int = 300
    download_interval: int = 1800
    status_url: str = "http://cp.cloudflare.com/generate_204"
    # Where the tunnel check performs its handshake. TLS, because completing
    # one is what proves the tunnel actually carries traffic.
    tunnel_url: str = "https://cp.cloudflare.com"
    # The download check is a volume-tolerance test, not a speed test: DPI can
    # let a tunnel open and kill it after N bytes, so what matters is how much
    # gets through. The file therefore has to be at least as large as the
    # volume worth proving, and the source is per-deployment.
    download_url: str = "https://proof.ovh.net/files/1Mb.dat"
    download_min_bytes: int = 524288
    # Timing camouflage applied to every check: the round period varies by
    # ±jitter and the configs of one round are scattered over `spread` of it.
    # A probe firing on the dot in a fixed order is trivially distinguishable
    # from a person using the same tunnels.
    jitter: float = 0.2
    spread: float = 0.5
    ip_url: str = "https://api.ipify.org"
    # Ask for the point's whole location at once: country, city, ISP and its
    # own address. Without country/city/query the probe would get the ISP
    # alone, leaving the city and address empty — and the point would show up
    # in the UI unlabeled.
    isp_url: str = "http://ip-api.com/json/?fields=status,country,city,isp,query"
    # Fleet-wide expected exit addresses: {config-name regex: address prefixes}.
    # Empty by default — deployments set their own, and individual points can
    # override theirs.
    exit_expectations: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RelayConfig:
    """Where the control plane forwards metrics received from points.

    Metrics flow through the control plane (a relay) rather than straight to
    the store: provisioning a new point then requires no changes to the
    metrics infrastructure at all — one channel for the whole fleet.
    """

    write_url: str
    username: str = ""
    password: str = ""


@dataclass(frozen=True)
class Config:
    panel: PanelConfig
    db_path: str
    session_secret: str
    owner_group: str
    oidc: OIDCConfig | None
    base_url: str
    relay: RelayConfig | None
    # "Behind an edge gateway" mode: forward-auth has already verified a realm
    # user and passed the group list in a header. The shared secret exists
    # because the service port is published on the LAN and visible to
    # neighboring containers — without it any of them could forge the header
    # and reach the admin API.
    edge_secret: str
    # Local admin account (HTTP Basic) — the primary mode. When set, it takes
    # precedence over both edge and OIDC: the admin app has its own port, so
    # no SSO plumbing is needed.
    admin_user: str = ""
    admin_password: str = ""
    # The one panel squad every monitoring account belongs to. It holds every
    # inbound; what a point actually probes is decided here, when configs are
    # filtered — so the panel needs no per-point structure.
    shared_squad_name: str = "Monitor"
    # Default target set for auto-enrolled nodes: panel host remarks, comma
    # separated. Every point still gets its OWN account in the shared squad —
    # a shared identity would make it impossible to cut one node off, which
    # is exactly what per-point accounts exist to allow.
    default_check_remarks: tuple[str, ...] = ()
    default_load_remarks: tuple[str, ...] = ()
    defaults: Defaults = field(default_factory=Defaults)

    @classmethod
    def load(cls) -> Config:
        admin_user = _env("XPC_ADMIN_USER")
        admin_password = _env("XPC_ADMIN_PASSWORD")
        # Half a pair is almost certainly an environment typo, not intent:
        # silently ignoring it would leave the admin app on another auth mode.
        if bool(admin_user) != bool(admin_password):
            raise ConfigError("XPC_ADMIN_USER and XPC_ADMIN_PASSWORD must be set together")
        oidc = None
        if _env("XPC_OIDC_ISSUER"):
            oidc = OIDCConfig(
                issuer=_env("XPC_OIDC_ISSUER", required=True),
                client_id=_env("XPC_OIDC_CLIENT_ID", required=True),
                client_secret=_env("XPC_OIDC_CLIENT_SECRET", required=True),
            )
        return cls(
            panel=PanelConfig(
                base_url=_env("XPC_PANEL_URL", required=True).rstrip("/"),
                token=_env("XPC_PANEL_TOKEN", required=True),
            ),
            db_path=_env("XPC_DB_PATH", default="/data/xprobe-control.sqlite3"),
            session_secret=_env("XPC_SESSION_SECRET", required=True),
            owner_group=_env("XPC_OWNER_GROUP", default="/admins"),
            oidc=oidc,
            base_url=_env("XPC_BASE_URL", default="").rstrip("/"),
            relay=RelayConfig(
                write_url=_env("XPC_RELAY_WRITE_URL", required=True),
                username=_env("XPC_RELAY_USER"),
                password=_env("XPC_RELAY_PASSWORD"),
            ) if _env("XPC_RELAY_WRITE_URL") else None,
            edge_secret=_env("XPC_EDGE_SECRET"),
            admin_user=admin_user,
            admin_password=admin_password,
            shared_squad_name=_env("XPC_SHARED_SQUAD", default="Monitor"),
            default_check_remarks=_csv(_env("XPC_DEFAULT_CHECK_REMARKS")),
            default_load_remarks=_csv(_env("XPC_DEFAULT_LOAD_REMARKS")),
        )


def _csv(raw: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in raw.split(",") if x.strip())
