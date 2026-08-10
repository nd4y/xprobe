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

MODES = ("tcp", "status", "download")


def build_document(point: Point, defaults: Defaults, *, base_url: str = "") -> dict[str, Any]:
    d = defaults
    interval_default = {
        "tcp": d.tcp_interval, "status": d.status_interval, "download": d.download_interval,
    }

    # Subscriptions: check feeds tcp and status, load feeds download. The keys
    # in the document are exactly the ones the modes reference.
    subscriptions: dict[str, str] = {}
    if point.check_sub_url:
        subscriptions["check"] = point.check_sub_url
    if point.load_sub_url:
        subscriptions["load"] = point.load_sub_url

    probes: dict[str, Any] = {}
    for kind in MODES:
        enabled = bool(point.modes.get(kind, False))
        spec: dict[str, Any] = {
            "enabled": enabled,
            "interval": int(point.intervals.get(kind) or interval_default[kind]),
            "subscription": "load" if kind == "download" else "check",
        }
        if kind == "status":
            spec["start_port"] = 20000
            spec["timeout"] = 30
            spec["url"] = d.status_url
        elif kind == "download":
            spec["start_port"] = 20500
            spec["timeout"] = 60
            spec["min_bytes"] = d.download_min_bytes
            spec["url"] = d.download_url
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
        "labels": labels,
        "subscriptions": subscriptions,
        "subscription_interval": d.subscription_interval,
        "probes": probes,
        "ip_url": d.ip_url,
        "isp_url": d.isp_url,
        "exit_expectations": point.exit_expectations or d.exit_expectations,
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
