"""Renderer for the document a probe fetches.

The document is the only contract between the control plane and the probe.
Everything the probe needs to know is assembled here from the point's row and
the fleet-wide defaults; beyond that, the probe knows nothing about the
control plane.

The format is stable: the probe parses known fields and ignores unknown ones,
so adding a field cannot break older probes — but changing the meaning of an
existing field can, and is therefore forbidden.
"""

from __future__ import annotations

from typing import Any

from .config import Defaults
from .db import Point

# The ladder of checks, cheapest first. `tcp` and `tunnel` ask the same
# question — does the handshake complete — differing only in whether a core
# is in the path, which is what makes a core implementation change visible.
MODES = ("tcp", "tunnel", "status", "download")


def build_document(point: Point, defaults: Defaults, *, base_url: str = "") -> dict[str, Any]:
    d = defaults
    interval_default = {
        "tcp": d.tcp_interval, "tunnel": d.tunnel_interval,
        "status": d.status_interval, "download": d.download_interval,
    }

    probes: dict[str, Any] = {}
    for kind in MODES:
        enabled = bool(point.modes.get(kind, False))
        spec: dict[str, Any] = {
            "enabled": enabled,
            "interval": int(point.intervals.get(kind) or interval_default[kind]),
            # Which core this check runs with; empty means the image default.
            # The tcp check ignores it — it opens a socket and a TLS handshake
            # itself, with no core in the path.
            "xray_version": point.cores.get(kind, ""),
            # Where the check's configs come from. The control plane filters
            # them by the point's target set, so a probe never holds a
            # subscription link and never sees a config outside its own set.
            "configs_url": (f"{base_url}/api/points/{point.name}/configs/{kind}"
                            if base_url else ""),
        }
        if kind == "tunnel":
            spec["start_port"] = 21000
            spec["timeout"] = 20
            # A TLS endpoint: the check completes a handshake through the
            # tunnel, which is the cheapest exchange that forces real traffic
            # both ways. Merely opening the connection proves nothing — the
            # core answers that before it dials anything.
            spec["url"] = d.tunnel_url
        elif kind == "status":
            spec["start_port"] = 20000
            spec["timeout"] = 30
            spec["url"] = d.status_url
        elif kind == "download":
            spec["start_port"] = 20500
            spec["timeout"] = 60
            # Volume tolerance: how much has to get through before DPI cuts
            # the tunnel. Per point, because the answer differs by network.
            spec["min_bytes"] = point.download_min_bytes or d.download_min_bytes
            spec["url"] = point.download_url or d.download_url
        else:  # tcp
            spec["timeout"] = 10
        probes[kind] = spec

    # Geo goes into the document ONLY when the administrator pinned it
    # (pin_geo): that label then wins over the probe's self-detection.
    # Otherwise country/city/ISP labels are omitted entirely — the probe sets
    # them itself from its own address and refreshes them on the fly if the
    # address changes without a restart.
    labels = {"point": point.name, "vantage": point.vantage}
    if point.pin_geo:
        if point.country:
            labels["country"] = point.country
        if point.city:
            labels["city"] = point.city
        if point.isp:
            labels["isp"] = point.isp

    doc: dict[str, Any] = {
        "version": point.version,
        "point": point.name,
        # A disabled point is told so rather than cut off: the probe has to
        # learn it should stop, and refusing to answer looks exactly like an
        # outage — which the probe is built to ride out by carrying on.
        "enabled": point.enabled,
        "labels": labels,
        "subscription_interval": d.subscription_interval,
        "probes": probes,
        "ip_url": d.ip_url,
        "isp_url": d.isp_url,
        "exit_expectations": point.exit_expectations or d.exit_expectations,
        "jitter": d.jitter,
        "spread": d.spread,
    }
    if point.push_enabled:
        # Metrics go to the control-plane relay, not to the store directly:
        # provisioning a point then touches no metrics infrastructure. The
        # probe reuses the credentials it fetched the document with (point
        # name + secret), so none are embedded in the body.
        relay = f"{base_url}/api/points/{point.name}/metrics" if base_url else d.push_url
        # No base URL and no fallback target — omit push rather than hand the
        # probe an empty URL to fail against.
        if relay:
            doc["push"] = {"url": relay, "interval": d.push_interval}
    return doc
