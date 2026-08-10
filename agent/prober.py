"""Probes subscription configs with a real Xray core.

Why build our own when xray-checker exists: that one compiles xray-core in as
a library, and its core (26.3.27 in v1.3.1) does not match the core running on
the nodes. XHTTP is incompatible between those versions — every XHTTP config
fails silently, with nothing in the log, and it looks exactly like broken
configs. Here the core is a plain binary pinned in the image to the node
version: any divergence is visible in a single Dockerfile line.

The second thing ready-made checkers lack: **exit-address verification**. A
dead WARP is masked by the DIRECT fallback — the config keeps working and "did
the connection come up" answers "yes". The only way to tell is the address the
traffic actually left from.

The modes (tcp | status | download) run **concurrently, in one process**, each
with its own subscription, interval and target set. Together they answer AT
WHICH STAGE things broke: no connect — network or address blocking; TCP up but
no TLS — SNI-based filtering; status red — protocol; download red — the
channel collapses under load.

## Where the configuration comes from

Two models, chosen by the presence of CONTROL_URL:

* **control plane** (CONTROL_URL set) — the probe fetches its whole document
  from xprobe-control using its name and secret, and pushes metrics itself to
  the push.url from that document. This is the fleet mode: the point has three
  environment lines (POINT, CONTROL_URL, CONTROL_TOKEN) and everything else
  arrives and is edited centrally. The last good document is cached on disk: a
  control plane outage only blinds a NEW point; a running one survives it
  silently.

  Configs themselves come from the control plane too, already filtered to this
  point's target set, and are held **in memory only**. They carry working
  credentials for someone else's tunnels, and the probe runs on machines its
  operator does not own — so nothing config-shaped is ever written to that
  machine's disk, not even transiently: the core is fed through a pipe.

* **environment** (CONTROL_URL empty) — the legacy mode: subscriptions,
  intervals and labels come from variables, metrics are exposed on /metrics
  for an external scraper. Kept for locally-scraped deployments and tests.

The metric names match xray-checker (`xray_proxy_status`,
`xray_proxy_latency_ms`) DELIBERATELY: dashboards and the status page already
depend on them, and swapping the checker must not break anything.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer

XRAY = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
# Where the last successfully applied document is kept. Survives a container
# restart (volume), but does not have to survive re-creation: by then the
# config gets re-read from the control plane anyway.
CACHE_PATH = os.environ.get("CONFIG_CACHE", "/var/lib/xprobe/config.json")
SPOOL_PATH = os.environ.get("SPOOL_PATH", "/var/lib/xprobe/spool")
# The enrolled node's identity: node_id is permanent (generated once), identity
# = the point name and secret issued by the control plane. Both live in the
# volume and survive restarts.
NODE_ID_PATH = os.environ.get("NODE_ID_PATH", "/var/lib/xprobe/node-id")
IDENTITY_PATH = os.environ.get("IDENTITY_PATH", "/var/lib/xprobe/identity.json")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def env_int(name: str, default: int) -> int:
    raw = env(name)
    return int(raw) if raw else default


@dataclass(frozen=True)
class Probe:
    """One mode: its own config source, interval and port range."""

    kind: str                      # tcp | status | download
    # Where this check's configs come from. In control-plane mode this is the
    # centre's per-check endpoint, which returns configs already filtered to
    # this point's target set; in the legacy environment mode it is a panel
    # subscription URL.
    subscription_url: str
    interval: int
    start_port: int
    timeout: int
    url: str                       # what to request through the config
    min_bytes: int = 0             # download: how many bytes count as success
    subscription_interval: int = 300
    # Timing camouflage. `jitter` varies the round period; `spread` is the
    # fraction of the period the configs of one round are scattered over.
    # Both exist because a probe that fires on the dot, in a fixed order, is
    # trivially distinguishable from a person using the same tunnels.
    jitter: float = 0.2
    spread: float = 0.5
    # Credentials for the centre's config endpoint (point name + secret).
    auth: tuple[str, str] | None = None


@dataclass(frozen=True)
class Push:
    """Where the probe pushes metrics itself (control-plane model)."""

    url: str
    interval: int = 60
    username: str = ""
    password: str = ""
    spool_max_files: int = 2000
    spool_max_bytes: int = 200 * 1024 * 1024


@dataclass(frozen=True)
class Config:
    probes: tuple[Probe, ...]
    version: int = 0
    ip_url: str = "https://api.ipify.org"
    # Who serves the vantage point itself. The query is about our own external
    # address, so no address needs passing — the service sees it by itself.
    # Ask for the whole location at once: country, city, ISP, own address. A
    # trimmed field set would leave the city and address empty and the point
    # unlabeled in the UI.
    isp_url: str = "http://ip-api.com/json/?fields=status,country,city,isp,query"
    listen_port: int = 8080
    user_agent: str = "v2rayNG/1.8.0"
    # Expected exit address: {config-name regex: address prefix}. Several
    # prefixes — comma separated. A config matching no regex is not
    # address-checked at all: silence is more honest than a guess.
    expectations: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = ()
    labels: tuple[tuple[str, str], ...] = ()
    push: Push | None = None

    # ── from the environment (legacy mode) ────────────────────────────────────

    @classmethod
    def from_env(cls) -> Config:
        probes: list[Probe] = []
        sub_interval = env_int("SUBSCRIPTION_INTERVAL", 300)
        if env("TCP_SUBSCRIPTION_URL"):
            probes.append(Probe(
                kind="tcp",
                subscription_url=env("TCP_SUBSCRIPTION_URL"),
                interval=env_int("TCP_INTERVAL", 300),
                start_port=0,          # no Xray is started for this mode at all
                timeout=env_int("TCP_TIMEOUT", 10),
                url="",
                subscription_interval=sub_interval,
            ))
        if env("SUBSCRIPTION_URL"):
            probes.append(Probe(
                kind="status",
                subscription_url=env("SUBSCRIPTION_URL"),
                interval=env_int("CHECK_INTERVAL", 300),
                start_port=env_int("START_PORT", 20000),
                timeout=env_int("TIMEOUT", 30),
                url=env("CHECK_URL") or "http://cp.cloudflare.com/generate_204",
                subscription_interval=sub_interval,
            ))
        if env("DOWNLOAD_SUBSCRIPTION_URL"):
            probes.append(Probe(
                kind="download",
                subscription_url=env("DOWNLOAD_SUBSCRIPTION_URL"),
                interval=env_int("DOWNLOAD_INTERVAL", 1800),
                start_port=env_int("DOWNLOAD_START_PORT", 20500),
                timeout=env_int("DOWNLOAD_TIMEOUT", 60),
                url=env("DOWNLOAD_URL") or "https://proof.ovh.net/files/1Mb.dat",
                min_bytes=env_int("DOWNLOAD_MIN_BYTES", 524288),
                subscription_interval=sub_interval,
            ))
        if not probes:
            sys.exit("need at least one of TCP_/DOWNLOAD_ subscriptions or SUBSCRIPTION_URL")

        labels = []
        for pair in (env("EXTRA_LABELS") or "").split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                # `probe` is set by the probe itself — nothing outside may
                # override it.
                if k.strip() != "probe":
                    labels.append((k.strip(), v.strip()))

        return cls(
            probes=tuple(probes),
            ip_url=env("IP_URL") or cls.ip_url,
            isp_url=env("ISP_URL") or cls.isp_url,
            listen_port=env_int("LISTEN_PORT", 8080),
            user_agent=env("USER_AGENT") or cls.user_agent,
            expectations=_parse_expectations(env("EXIT_EXPECTATIONS")),
            labels=tuple(labels),
        )

    # ── from the control-plane document ───────────────────────────────────────

    @classmethod
    def from_document(cls, doc: dict, *, point: str = "", push_password: str = "") -> Config:
        """Parse the document served by xprobe-control.

        The document is the only contract between the control plane and the
        probe; whatever is not parsed here does not exist for the probe. A
        malformed document must not take down an already running point —
        validity is the caller's concern, this only parses known fields.
        """
        defaults = {
            "tcp": {"interval": 300, "timeout": 10, "start_port": 0},
            "status": {"interval": 300, "timeout": 30, "start_port": 20000,
                       "url": "http://cp.cloudflare.com/generate_204"},
            "download": {"interval": 1800, "timeout": 60, "start_port": 20500,
                         "min_bytes": 524288,
                         "url": "https://proof.ovh.net/files/1Mb.dat"},
        }
        sub_interval = int(doc.get("subscription_interval") or 300)
        auth = (point, push_password) if point else None
        probes: list[Probe] = []
        for kind in ("tcp", "status", "download"):
            spec = (doc.get("probes") or {}).get(kind) or {}
            if not spec.get("enabled", False):
                continue
            d = defaults[kind]
            configs_url = str(spec.get("configs_url") or "")
            if not configs_url:
                # A mode is enabled but has nowhere to read configs from —
                # that is a document error, not a workable situation.
                raise ValueError(f"mode {kind}: no configs_url")
            probes.append(Probe(
                kind=kind,
                subscription_url=configs_url,
                interval=int(spec.get("interval") or d["interval"]),
                start_port=int(spec.get("start_port") or d["start_port"]),
                timeout=int(spec.get("timeout") or d["timeout"]),
                url="" if kind == "tcp" else str(spec.get("url") or d.get("url", "")),
                min_bytes=int(spec.get("min_bytes") or d.get("min_bytes", 0)),
                subscription_interval=sub_interval,
                jitter=float(spec.get("jitter", doc.get("jitter", 0.2))),
                spread=float(spec.get("spread", doc.get("spread", 0.5))),
                auth=auth,
            ))
        if not probes:
            raise ValueError("the document has no enabled modes")

        labels = tuple(
            (str(k), str(v)) for k, v in (doc.get("labels") or {}).items() if k != "probe"
        )
        exp = doc.get("exit_expectations") or {}
        expectations = _parse_expectations(json.dumps(exp) if isinstance(exp, dict) else exp)

        push = None
        pd = doc.get("push") or {}
        if pd.get("url"):
            push = Push(
                url=str(pd["url"]),
                interval=int(pd.get("interval") or 60),
                # Push credentials are the same ones the probe fetched the
                # document with: one secret per point, not two.
                username=str(pd.get("username") or point),
                password=str(pd.get("password") or push_password),
                spool_max_files=int(pd.get("spool_max_files") or 2000),
                spool_max_bytes=int(pd.get("spool_max_bytes") or 200 * 1024 * 1024),
            )

        return cls(
            probes=tuple(probes),
            version=int(doc.get("version") or 0),
            ip_url=str(doc.get("ip_url") or cls.ip_url),
            isp_url=str(doc.get("isp_url") or cls.isp_url),
            listen_port=int(doc.get("listen_port") or 8080),
            user_agent=str(doc.get("user_agent") or cls.user_agent),
            expectations=expectations,
            labels=labels,
            push=push,
        )


def _parse_expectations(raw: str) -> tuple[tuple[re.Pattern[str], tuple[str, ...]], ...]:
    if not raw:
        return ()
    out = []
    for pattern, prefixes in json.loads(raw).items():
        parts = tuple(p.strip() for p in str(prefixes).split(",") if p.strip())
        out.append((re.compile(pattern), parts))
    return tuple(out)


@dataclass
class Result:
    kind: str
    name: str
    up: bool = False
    latency_ms: float = 0.0
    bytes_got: int = 0
    speed_bps: float = 0.0
    exit_ip: str = ""
    exit_expected: tuple[str, ...] = ()
    checked_at: float = 0.0
    # tcp: record separately whether the exchange got as far as a completed
    # TLS handshake. The difference between "the port accepted a connection"
    # and "the handshake succeeded" is exactly the failure stage we report.
    tls_ok: bool | None = None

    @property
    def exit_checked(self) -> bool:
        return bool(self.exit_expected)

    @property
    def exit_ok(self) -> bool:
        return any(self.exit_ip.startswith(p) for p in self.exit_expected)


@dataclass
class State:
    """What /metrics serves. Both loops write it; the http thread reads it."""

    results: dict[tuple[str, str], Result] = field(default_factory=dict)
    configs: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    # Where the probe itself sits: ISP, country, city and external address.
    # Detected from its own external address and attached to metrics as labels
    # (except ip — that never leaves the node). Refreshed on the fly: the
    # node's address can change without a restart.
    isp: str = ""
    country: str = ""
    city: str = ""
    ip: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock)


def resolve_geo(cfg: Config, timeout: int = 10) -> dict:
    """Where the probe sits: country, city, ISP, external address.

    Requested DIRECTLY, not through a config under test: we need the point's
    own address, not a proxy exit. On failure — empty: a location label is no
    reason to take the probe down.
    """
    try:
        req = urllib.request.Request(cfg.isp_url,
                                     headers={"User-Agent": cfg.user_agent})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 — network / non-JSON, all failures equal
        print(f"could not resolve point location: {type(exc).__name__}: {exc}", flush=True)
        return {}
    if body.get("status") != "success":
        return {}
    return {
        "country": str(body.get("country") or ""),
        "city": str(body.get("city") or ""),
        "isp": str(body.get("isp") or ""),
        "ip": str(body.get("query") or ""),
    }


def geo_loop(state: State, cfg: Config, report=None) -> None:
    """Keep our location fresh. Hourly rather than daily: the node's address
    can change without a restart, and the labels/UI must catch up. On change —
    report to the control plane (when configured)."""
    while True:
        geo = resolve_geo(cfg)
        if geo:
            with state.lock:
                changed = (state.isp, state.city, state.country, state.ip) != (
                    geo["isp"], geo["city"], geo["country"], geo["ip"])
                state.isp, state.city = geo["isp"], geo["city"]
                state.country, state.ip = geo["country"], geo["ip"]
            if changed:
                print(f"point location: {geo['city']}, {geo['isp']} ({geo['ip']})", flush=True)
                if report is not None:
                    report(geo)
        # An hour on success (the address may change on the fly), 10 minutes
        # on failure.
        time.sleep(3600 if geo else 600)


def fetch_subscription(url: str, cfg: Config, timeout: int,
                       auth: tuple[str, str] | None = None) -> list[dict]:
    """The configs this check should probe.

    In control-plane mode the URL is the centre's per-check endpoint and the
    answer is already filtered to this point's target set. The configs are
    returned to the caller and kept in memory only — they carry credentials
    and have no business being written to the node's disk.
    """
    req = urllib.request.Request(url, headers={"User-Agent": cfg.user_agent})
    if auth is not None:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.loads(r.read().decode("utf-8"))
    if not isinstance(body, list):
        raise ValueError("config source did not return a list — xray-json format required")
    return [c for c in body if c.get("outbounds")]


def wait_port(port: int, deadline: float) -> bool:
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def socks5_open(proxy_port: int, host: str, port: int, timeout: float) -> socket.socket:
    """Connect to host:port through a local unauthenticated SOCKS5 proxy.

    Hand-rolled rather than curl: the image's only external dependency is xray
    itself, so the probe can be assembled from stock images anywhere — even on
    a cluster with no way to build images.

    The proxy resolves the name itself (ATYP=3): resolving locally would
    measure our own DNS instead of the config's.
    """
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close()
        raise OSError("socks5: handshake rejected")
    name = host.encode("idna") if not host.replace(".", "").isdigit() else host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
    head = s.recv(4)
    if len(head) < 4 or head[1] != 0:
        s.close()
        raise OSError(f"socks5: refused {head[1] if len(head) > 1 else '?'}")
    # Drain the bound address, or it would arrive inside the response body.
    if head[3] == 1:
        s.recv(4)
    elif head[3] == 3:
        s.recv(s.recv(1)[0])
    elif head[3] == 4:
        s.recv(16)
    s.recv(2)
    return s


def http_get(url: str, proxy_port: int, timeout: int, keep_body: bool) -> dict:
    """GET through the proxy. Measures status code, time, volume and speed."""
    parsed = urllib.parse.urlparse(url)
    https = parsed.scheme == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if https else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    started = time.time()
    deadline = started + timeout
    try:
        sock = socks5_open(proxy_port, host, port, timeout)
    except OSError:
        return {"ok": False}
    try:
        if https:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: xprobe\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        sock.sendall(req.encode())

        chunks: list[bytes] = []
        total = 0
        first: bytes = b""
        while True:
            sock.settimeout(max(0.1, deadline - time.time()))
            try:
                data = sock.recv(65536)
            except (TimeoutError, ssl.SSLError, OSError):
                break
            if not data:
                break
            total += len(data)
            if not first:
                first = data[:64]
            # The body is accumulated only when needed (exit address). The
            # bandwidth check reads megabytes — no reason to hold them in
            # memory.
            if keep_body and sum(len(c) for c in chunks) < 65536:
                chunks.append(data)
            if time.time() >= deadline:
                break
    except (ssl.SSLError, OSError):
        return {"ok": False}
    finally:
        with contextlib.suppress(OSError):
            sock.close()

    if not first:
        return {"ok": False}
    try:
        code = int(first.split(b" ")[1])
    except (IndexError, ValueError):
        return {"ok": False}
    elapsed = max(0.001, time.time() - started)
    body = b"".join(chunks)
    text = ""
    if keep_body:
        _, _, raw = body.partition(b"\r\n\r\n")
        text = raw.decode("utf-8", "replace").strip()
    return {"ok": True, "code": code, "ms": elapsed * 1000, "bytes": total,
            "speed": total / elapsed, "body": text}


def client_config(entry: dict, port: int) -> dict:
    """The subscription config as-is, plus a socks inbound on our port.

    As-is on purpose: what must be checked is exactly what a user receives,
    not a reassembled approximation of it.
    """
    client = json.loads(json.dumps(entry))
    client["log"] = {"loglevel": "none"}
    inbounds = [i for i in client.get("inbounds") or [] if i.get("protocol") == "socks"]
    if inbounds:
        first = inbounds[0]
        first["port"] = port
        first["listen"] = "127.0.0.1"
        client["inbounds"] = [first]
    else:
        client["inbounds"] = [{
            "protocol": "socks", "listen": "127.0.0.1", "port": port,
            "settings": {"udp": False},
        }]
    return client


def endpoint_of(entry: dict) -> tuple[str, int, str]:
    """Where the client actually connects: address, port and SNI name."""
    out = (entry.get("outbounds") or [{}])[0]
    stream = out.get("streamSettings") or {}
    vnext = ((out.get("settings") or {}).get("vnext") or [{}])[0]
    addr = str(vnext.get("address") or "")
    port = int(vnext.get("port") or 0)
    tls = stream.get("tlsSettings") or stream.get("realitySettings") or {}
    return addr, port, str(tls.get("serverName") or addr)


def probe_tcp(entry: dict, probe: Probe, cfg: Config) -> Result:
    """Probe the endpoint itself, without Xray.

    Answers "at which stage is the problem": if this does not connect, the
    issue is the network or address blocking, and digging into the protocol is
    pointless. If TCP works but TLS does not come up — SNI filtering or
    handshake interference.
    """
    name = entry.get("remarks") or "?"
    res = Result(kind=probe.kind, name=name, checked_at=time.time())
    addr, port, sni = endpoint_of(entry)
    if not addr or not port:
        return res

    started = time.time()
    try:
        with socket.create_connection((addr, port), timeout=probe.timeout) as sock:
            res.up = True
            res.latency_ms = (time.time() - started) * 1000
            ctx = ssl.create_default_context()
            # No certificate verification: what matters is whether the
            # handshake completes, and REALITY inbounds are not expected to
            # match the name anyway.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock.settimeout(probe.timeout)
                with ctx.wrap_socket(sock, server_hostname=sni):
                    res.tls_ok = True
            except (ssl.SSLError, OSError):
                res.tls_ok = False
    except OSError:
        return res
    return res


def probe_one(entry: dict, port: int, probe: Probe, cfg: Config) -> Result:
    name = entry.get("remarks") or "?"
    res = Result(kind=probe.kind, name=name, checked_at=time.time())
    for pattern, prefixes in cfg.expectations:
        if pattern.search(name):
            res.exit_expected = prefixes
            break

    # The config goes to the core through a pipe, never through a file. A
    # config carries working credentials for someone else's tunnel, and the
    # probe runs on machines the operator does not own; encrypting a temp file
    # would be theatre, since the core has to be handed plaintext anyway.
    # Nothing here touches the filesystem, so there is nothing to leak, to
    # forget to delete, or to find in a backup.
    proc = subprocess.Popen(
        [XRAY, "run", "-c", "stdin:"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        with proc.stdin as sink:
            sink.write(json.dumps(client_config(entry, port)).encode())
        if not wait_port(port, time.time() + 10):
            return res
        r = http_get(probe.url, port, probe.timeout, keep_body=False)
        if not r.get("ok"):
            return res
        res.latency_ms, res.bytes_got, res.speed_bps = r["ms"], r["bytes"], r["speed"]
        if probe.kind == "download":
            # Success is the volume that arrived, not the status code: a
            # throttled channel returns 200 and cuts off within the first
            # kilobytes.
            res.up = r["bytes"] >= probe.min_bytes
        else:
            res.up = 200 <= r["code"] < 400

        if res.up and res.exit_checked:
            ip = http_get(cfg.ip_url, port, probe.timeout, keep_body=True)
            if ip.get("ok") and ip.get("body"):
                res.exit_ip = ip["body"].split()[0]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return res


def run_probe(probe: Probe, state: State, cfg: Config, stop: threading.Event) -> None:
    """One mode's loop. Modes run concurrently, each in its own thread."""
    entries: list[dict] = []
    fetched_at = 0.0
    while not stop.is_set():
        started = time.time()
        if started - fetched_at >= probe.subscription_interval:
            try:
                entries = fetch_subscription(probe.subscription_url, cfg, probe.timeout,
                                             probe.auth)
                fetched_at = started
                with state.lock:
                    state.configs[probe.kind] = len(entries)
                    state.errors[probe.kind] = ""
                    # A config that vanished from the subscription must not
                    # stay green in the metrics forever.
                    alive = {e.get("remarks") for e in entries}
                    state.results = {
                        k: v for k, v in state.results.items()
                        if k[0] != probe.kind or k[1] in alive
                    }
            except Exception as exc:  # network, non-JSON — all the same here
                with state.lock:
                    state.errors[probe.kind] = f"{type(exc).__name__}: {exc}"
                print(f"[{probe.kind}] failed to read subscription: {exc}", flush=True)

        # Configs are visited in a random order and with a random gap between
        # them, rather than back-to-back in a fixed rotation. Back-to-back is
        # what makes a round look machine-made from the outside: a burst of N
        # handshakes within seconds, in the same sequence, on the dot. The gap
        # budget stays inside the round so the interval still means what it
        # says.
        order = list(range(len(entries)))
        random.shuffle(order)
        gap = 0.0
        if order:
            gap = probe.interval * probe.spread / len(order)
        for n in order:
            if stop.is_set():
                return
            entry = entries[n]
            if probe.kind == "tcp":
                res = probe_tcp(entry, probe, cfg)
            else:
                # The port stays tied to the config's index: concurrent modes
                # must not land on the same port.
                res = probe_one(entry, probe.start_port + n, probe, cfg)
            with state.lock:
                state.results[(probe.kind, res.name)] = res
            if gap and stop.wait(random.uniform(0, 2 * gap)):
                return

        # A round takes time by itself — sleep the remainder of the interval,
        # not on top of it. The remainder carries the jitter: without it every
        # round would start on the same second forever.
        target = probe.interval * random.uniform(1 - probe.jitter, 1 + probe.jitter)
        stop.wait(max(5.0, target - (time.time() - started)))


def escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def render(state: State, cfg: Config) -> str:
    # An ISP given in the labels wins over the address-detected one: for home
    # points the operator knows the provider better than a geo database does
    # ("Beeline" vs "OJSC Vimpel-Communications"). Document labels (set by the
    # administrator) win over self-detected ones: pinned geo is used when
    # present, otherwise whatever the probe found via its own address. The ip
    # is never emitted as a label — a vantage node's address is not shown.
    labels = list(cfg.labels)
    have = {k for k, _ in labels}
    with state.lock:
        detected = {"isp": state.isp, "city": state.city, "country": state.country}
    for k, v in detected.items():
        if k not in have and v:
            labels.append((k, v))
    extra = "".join(f',{k}="{escape(v)}"' for k, v in labels)
    out = [
        "# HELP xray_proxy_status 1 — the probe passed, 0 — it did not",
        "# TYPE xray_proxy_status gauge",
        "# HELP xray_proxy_latency_ms request duration through the config",
        "# TYPE xray_proxy_latency_ms gauge",
        "# HELP xray_proxy_exit_ok exit address matched the expected one (where set)",
        "# TYPE xray_proxy_exit_ok gauge",
        "# HELP xray_proxy_tls_ok TLS handshake with the inbound completed (tcp mode)",
        "# TYPE xray_proxy_tls_ok gauge",
        "# HELP xray_proxy_download_bytes bytes received (download mode)",
        "# TYPE xray_proxy_download_bytes gauge",
        "# HELP xray_proxy_download_speed_bytes download speed (download mode)",
        "# TYPE xray_proxy_download_speed_bytes gauge",
        "# HELP xray_proxy_checked_timestamp_seconds time of the last check",
        "# TYPE xray_proxy_checked_timestamp_seconds gauge",
    ]
    with state.lock:
        results = list(state.results.values())
        configs = dict(state.configs)
        errors = dict(state.errors)
    for r in results:
        lbl = f'name="{escape(r.name)}",probe="{r.kind}"{extra}'
        out.append(f"xray_proxy_status{{{lbl}}} {1 if r.up else 0}")
        out.append(f"xray_proxy_latency_ms{{{lbl}}} {r.latency_ms:.1f}")
        out.append(f"xray_proxy_checked_timestamp_seconds{{{lbl}}} {r.checked_at:.0f}")
        if r.exit_checked:
            out.append(f"xray_proxy_exit_ok{{{lbl}}} {1 if r.exit_ok else 0}")
        if r.kind == "download":
            out.append(f"xray_proxy_download_bytes{{{lbl}}} {r.bytes_got}")
            out.append(f"xray_proxy_download_speed_bytes{{{lbl}}} {r.speed_bps:.0f}")
        if r.tls_ok is not None:
            out.append(f"xray_proxy_tls_ok{{{lbl}}} {1 if r.tls_ok else 0}")
    out.append("# HELP xprobe_configs configs in this mode's subscription")
    out.append("# TYPE xprobe_configs gauge")
    out.append("# HELP xprobe_subscription_ok 1 — the subscription was read")
    out.append("# TYPE xprobe_subscription_ok gauge")
    for probe in cfg.probes:
        lbl = f'probe="{probe.kind}"{extra}'
        out.append(f"xprobe_configs{{{lbl}}} {configs.get(probe.kind, 0)}")
        out.append(f"xprobe_subscription_ok{{{lbl}}} {0 if errors.get(probe.kind) else 1}")
    # The applied document version, and the fact one is applied at all: the
    # control plane can see an edit reached the point without waiting for a
    # behavior change.
    base = extra.lstrip(",")
    out.append("# HELP xprobe_config_ok 1 — a configuration is applied")
    out.append("# TYPE xprobe_config_ok gauge")
    out.append(f"xprobe_config_ok{{{base}}} 1")
    out.append("# HELP xprobe_config_version version of the applied document")
    out.append("# TYPE xprobe_config_version gauge")
    out.append(f"xprobe_config_version{{{base}}} {cfg.version}")
    return "\n".join(out) + "\n"


def serve(state: State, cfg: Config) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 — name fixed by the base class
            if self.path.rstrip("/") not in ("/metrics", ""):
                self.send_response(404)
                self.end_headers()
                return
            body = render(state, cfg).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # scraped once a minute — logging is noise
            pass

    HTTPServer(("0.0.0.0", cfg.listen_port), Handler).serve_forever()


# ── the probe pushing metrics itself (control-plane model) ────────────────────


def _spool_write(body: bytes) -> None:
    """Delivery failed — store on disk, resend later. Names sort by time so the
    backlog is resent in order of appearance."""
    try:
        os.makedirs(SPOOL_PATH, exist_ok=True)
        name = f"{time.time():017.6f}.prom"
        with open(os.path.join(SPOOL_PATH, name), "wb") as f:
            f.write(body)
    except OSError as exc:
        print(f"spool unavailable: {exc}", flush=True)


def _spool_trim(push: Push) -> None:
    """Keep the spool bounded: the channel may stay down for long, the disk is
    not infinite."""
    try:
        files = sorted(os.path.join(SPOOL_PATH, n) for n in os.listdir(SPOOL_PATH))
    except OSError:
        return
    total = 0
    # Count from the end (fresh entries matter more) and drop everything past
    # the limit.
    keep: list[str] = []
    for path in reversed(files):
        try:
            total += os.path.getsize(path)
        except OSError:
            continue
        if len(keep) >= push.spool_max_files or total > push.spool_max_bytes:
            with contextlib.suppress(OSError):
                os.unlink(path)
        else:
            keep.append(path)


def _post_metrics(push: Push, body: bytes, timeout: int = 30) -> bool:
    req = urllib.request.Request(push.url, data=body, method="POST")
    req.add_header("Content-Type", "text/plain")
    if push.username or push.password:
        token = base64.b64encode(f"{push.username}:{push.password}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _spool_flush(push: Push) -> None:
    """Resend the backlog oldest-first; stop at the first failure."""
    try:
        files = sorted(os.path.join(SPOOL_PATH, n) for n in os.listdir(SPOOL_PATH))
    except OSError:
        return
    for path in files:
        try:
            with open(path, "rb") as f:
                body = f.read()
        except OSError:
            continue
        if not _post_metrics(push, body):
            return
        with contextlib.suppress(OSError):
            os.unlink(path)


def push_loop(state: State, cfg: Config, stop: threading.Event) -> None:
    """Every push.interval, render the metrics and send them ourselves.

    The import/prometheus format matches /metrics — the same text a scraper
    would have collected. Delivery failed — to disk; on the next success the
    backlog is resent.
    """
    push = cfg.push
    assert push is not None
    while not stop.is_set():
        started = time.time()
        body = render(state, cfg).encode("utf-8")
        if _post_metrics(push, body):
            _spool_flush(push)
        else:
            _spool_write(body)
            _spool_trim(push)
        stop.wait(max(5.0, push.interval - (time.time() - started)))


# ── life cycle: one configuration, until the version changes ──────────────────


def fetch_document(control_url: str, point: str, token: str, timeout: int = 20) -> dict:
    """Fetch the point's document from the control plane. Credentials: the
    point name and its secret."""
    url = control_url.rstrip("/") + f"/api/points/{urllib.parse.quote(point)}/config"
    req = urllib.request.Request(url)
    creds = base64.b64encode(f"{point}:{token}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def load_cache() -> dict | None:
    try:
        with open(CACHE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_cache(doc: dict) -> None:
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        tmp = CACHE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        os.replace(tmp, CACHE_PATH)  # atomic: a corrupt cache cannot exist
    except OSError as exc:
        print(f"cache not saved: {exc}", flush=True)


def watch_control(control_url: str, point: str, token: str, current: int,
                  interval: int, stop: threading.Event) -> None:
    """Watch the document version. On change — save it and request a restart.

    A restart, not a hot reload: chasing consistency across live loops to save
    a single round is not worth it, while a container restart rebuilds the
    configuration from scratch, predictably.
    """
    while not stop.is_set():
        stop.wait(interval)
        if stop.is_set():
            return
        try:
            doc = fetch_document(control_url, point, token)
        except Exception as exc:
            print(f"control plane unreachable: {type(exc).__name__}: {exc}", flush=True)
            continue
        if int(doc.get("version") or 0) != current:
            print(f"document version {current} -> {doc.get('version')}, restarting", flush=True)
            save_cache(doc)
            stop.set()
            return


def node_id() -> str:
    """The node's permanent identity, used only when enrolling.

    The control plane recognises a returning node by it and hands back the
    same point instead of creating a new one — so this value MUST be stable
    across restarts, or every restart enrolls a brand new point and litters
    the fleet.

    Order: an explicit `NODE_ID` from the environment, then the volume, then a
    fresh random one. The environment comes first because it is the only
    option that survives storage which does not: on Kubernetes an emptyDir
    disappears when the pod is rescheduled, and pinning NODE_ID (from the pod
    name via the downward API, say) makes enrolment work with no persistence
    at all.
    """
    fixed = env("NODE_ID")
    if fixed:
        return fixed
    try:
        with open(NODE_ID_PATH, encoding="utf-8") as f:
            nid = f.read().strip()
            if nid:
                return nid
    except OSError:
        pass
    import uuid
    nid = uuid.uuid4().hex
    try:
        os.makedirs(os.path.dirname(NODE_ID_PATH), exist_ok=True)
        with open(NODE_ID_PATH, "w", encoding="utf-8") as f:
            f.write(nid)
    except OSError as exc:
        # Without a stable id every restart becomes a new point. Say so
        # plainly rather than letting the fleet grow a duplicate per restart.
        print(f"node-id NOT persisted ({exc}) — set NODE_ID to a stable value, "
              f"or this node will enroll as a NEW point on every restart", flush=True)
    return nid


def load_identity() -> dict | None:
    try:
        with open(IDENTITY_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if data.get("point") and data.get("secret"):
            return data
    except (OSError, ValueError):
        pass
    return None


def save_identity(identity: dict) -> None:
    try:
        os.makedirs(os.path.dirname(IDENTITY_PATH), exist_ok=True)
        tmp = IDENTITY_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(identity, f)
        os.replace(tmp, IDENTITY_PATH)
    except OSError as exc:
        print(f"identity not saved: {exc}", flush=True)


def enroll(control_url: str, enroll_token: str, nid: str, timeout: int = 20) -> dict:
    """Exchange the enroll token for the point's permanent identity (name + secret)."""
    url = control_url.rstrip("/") + "/api/enroll"
    body = json.dumps({"token": enroll_token, "node_id": nid}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    if not data.get("point") or not data.get("secret"):
        raise ValueError("enroll returned no identity")
    return {"point": data["point"], "secret": data["secret"]}


def report_geo(control_url: str, point: str, secret: str, geo: dict) -> None:
    """Report our location to the control plane. Failure is tolerable: this is
    for display, not for operation."""
    url = control_url.rstrip("/") + f"/api/points/{urllib.parse.quote(point)}/geo"
    body = json.dumps(geo).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    creds = base64.b64encode(f"{point}:{secret}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")
    try:
        urllib.request.urlopen(req, timeout=15).close()
    except Exception as exc:  # noqa: BLE001 — network, failure is not critical
        print(f"geo report not delivered: {exc}", flush=True)


def resolve_identity(control_url: str) -> tuple[str, str]:
    """Who we are to the control plane: cached identity, enroll, or explicit
    POINT/TOKEN.

    Priority: saved identity (an enrolled node) → enroll by token → explicit
    POINT+CONTROL_TOKEN (points provisioned manually).
    """
    identity = load_identity()
    if identity is not None:
        return identity["point"], identity["secret"]

    enroll_token = env("ENROLL_TOKEN")
    if enroll_token:
        identity = enroll(control_url, enroll_token, node_id())
        save_identity(identity)
        print(f"enrolled with the control plane as point {identity['point']}", flush=True)
        return identity["point"], identity["secret"]

    point, token = env("POINT"), env("CONTROL_TOKEN")
    if point and token:
        return point, token
    sys.exit("control mode: no identity, no ENROLL_TOKEN and no POINT+CONTROL_TOKEN")


def build_config(control_url: str) -> tuple[Config, str, str]:
    """Assemble the configuration: from the control plane, the cache, or the
    environment.

    Returns (cfg, point, secret) — the name and secret are needed by the
    version watcher and the geo report. Source order: the control plane is the
    truth; the cache keeps a running point alive while the control plane is
    down; the environment is the legacy mode for local scraping and tests.
    """
    if not control_url:
        return Config.from_env(), "", ""

    point, secret = resolve_identity(control_url)
    try:
        doc = fetch_document(control_url, point, secret)
        save_cache(doc)
        print(f"configuration from the control plane, version {doc.get('version')}", flush=True)
        return Config.from_document(doc, point=point, push_password=secret), point, secret
    except Exception as exc:  # noqa: BLE001 — network / non-JSON, all failures equal
        print(f"control plane unreachable at startup: {exc}", flush=True)
    cached = load_cache()
    if cached is not None:
        print(f"configuration from cache, version {cached.get('version')}", flush=True)
        return Config.from_document(cached, point=point, push_password=secret), point, secret
    sys.exit("control plane unreachable and no cache — the point is not configured")


def main() -> None:
    control_url = env("CONTROL_URL")
    control_interval = env_int("CONTROL_INTERVAL", 60)

    cfg, point, secret = build_config(control_url)
    state = State()
    stop = threading.Event()

    # Report geo to the control plane on every address change (control mode only).
    reporter = None
    if control_url and point:
        reporter = lambda geo: report_geo(control_url, point, secret, geo)  # noqa: E731

    threading.Thread(target=serve, args=(state, cfg), daemon=True).start()
    threading.Thread(target=geo_loop, args=(state, cfg, reporter), daemon=True).start()
    if cfg.push is not None:
        print(f"pushing metrics to {cfg.push.url} every {cfg.push.interval} s", flush=True)
        threading.Thread(target=push_loop, args=(state, cfg, stop), daemon=True).start()
    for probe in cfg.probes:
        print(f"xprobe[{probe.kind}]: a round every {probe.interval} s, "
              f"ports from {probe.start_port}", flush=True)
        threading.Thread(target=run_probe, args=(probe, state, cfg, stop), daemon=True).start()

    if control_url:
        # A separate thread watches the document version; a change means the
        # process exits.
        threading.Thread(
            target=watch_control,
            args=(control_url, point, secret, cfg.version, control_interval, stop),
            daemon=True,
        ).start()

    # Hold the process until a restart is requested (version change) or a signal.
    try:
        while not stop.wait(3600):
            pass
    except KeyboardInterrupt:
        pass
    # A clean exit: the container's restart policy brings it back up, and it
    # picks the new version from the cache (watch_control saved it) or from
    # the control plane again.
    print("exiting to apply the new configuration", flush=True)


if __name__ == "__main__":
    main()
