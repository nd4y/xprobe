# xprobe-control

Control plane for a fleet of [xprobe](../agent) probes. Probes run at
different operators in different cities; this service centrally defines
**which probe checks which servers, in which modes, at what intervals, and
where the metrics go**.

## How it works

```
        ┌─ fetches its document      (basic auth: point name + secret)
probe ──┼─ fetches its configs       (already filtered to its target set)
   ▲    └─ pushes metrics to the relay (same secret)
   │
   │  document version changed → probe exits → the restart applies the change
   ▼
xprobe-control ──reads──> Remnawave panel (one squad, one account per point)
   │
   └─ administrator UI: point list, target sets as checkboxes, "+ Add point"
```

## The panel holds identities, the control plane holds policy

One squad — `Monitor`, containing every inbound — and one account per point.
Nothing else. What a point actually probes is decided here, when the control
plane filters that point's subscription down to the target set of the check
asking for it.

That split is deliberate. Target edits used to rewrite squad membership and
patch live host objects, which is where the sharp edges were: `PATCH
/api/hosts` silently drops every field absent from the body, and hosts sharing
an inbound had to be hidden from each other with exclusion lists. None of that
exists now — the panel client has no method that can modify a host.

An account per point rather than one for the fleet: probes run on machines
other people control, so a point must be revocable on its own. Disable its
account and that point stops, and only that point.

## Two ports: public and administrative

The service runs **two independent HTTP applications** in one process:

* **points** (`XPC_POINTS_PORT`, default 8080) — `/api/points/*` and
  `/api/enroll`. Published to the internet: probes call it. There are **no
  admin routes at all** on this port — a proxy misconfiguration cannot expose
  the admin UI;
* **admin** (`XPC_ADMIN_PORT`, default 8081) — the UI and `/api/admin/*`.
  Published separately, on the internal network.

Admin sign-in is a **local account**: `XPC_ADMIN_USER` + `XPC_ADMIN_PASSWORD`
(HTTP Basic; the two variables must be set together). Fallback modes when the
local pair is not set: forward-auth headers (`XPC_EDGE_SECRET`) or OIDC
(`XPC_OIDC_*`).

## Zero-touch: an external node needs no configuration

The point operator receives **two environment lines** — `CONTROL_URL` and
`ENROLL_TOKEN`. Nothing else. On first start the probe:

1. generates a permanent `node_id` (lives in the volume);
2. exchanges the enroll token for **its identity** — the point name and
   secret — and caches them;
3. detects its **location** (country, city, ISP, external address) from its
   own address and reports it to the control plane;
4. fetches its document and starts pushing metrics **through the control-plane
   relay**.

## One token per node, because access has to be revocable

Each node gets **its own** enroll token, issued from the UI and shown once
(only its hash is kept). A token is bound to a point on first use, so
presenting it again — which is what a node does whenever it comes back
without its storage — returns the same point with a fresh secret.

A fleet-wide token could not be taken back from one operator: disabling their
point stops that point, but the token still lets them enroll a new one and
carry on. Revoking a per-node token ends that node's access and touches
nobody else.

The two levers do different things, and both are per node:

* **revoke the token** — the node cannot come back after a restart. What is
  running right now keeps running on the secret it already holds;
* **disable the point** — it stops receiving configs immediately.

Use both to cut an operator off for good.

Because the token itself is the node's identity and it lives in the manifest,
nothing needs to be persisted: an `emptyDir` is enough, and a rescheduled pod
re-enrolls as the same point.

**City and ISP are visible in the UI; the node's address is not.** The probe
sets the `city`/`isp` labels itself and refreshes them on the fly if the
address changes without a restart; the `ip` is stored in the control plane for
diagnostics but never exposed. The administrator can **pin** the geo manually
(`pin_geo`) — the pinned value then wins over self-detection.

## Metrics through the relay

The probe pushes metrics not to the store directly but to the control plane
(`POST /api/points/{point}/metrics`, authenticated with the point's secret);
the control plane forwards them to VictoriaMetrics (`XPC_RELAY_WRITE_URL`).
**Provisioning a new point therefore requires no metrics-infrastructure
changes at all** — one channel for the whole fleet.

**The control plane keeps no copy of the measurements.** Samples live in
VictoriaMetrics and nowhere else; the UI shows liveness, not results.
Duplicating them would create a second answer to the same question.

## The control plane's own metrics

Some facts about the fleet exist only on this side: whether a point has
been heard from at all, which document version it should be running, and
whether its checks have anything to probe. A probe cannot report them —
it reports from inside its own run, and a probe that is down reports
nothing. The control plane therefore pushes them to the same store, on the
same cadence as the points (`push_interval`), through the same relay
target. Nothing on the store side needs to know the control plane exists.

| Series | Meaning |
|---|---|
| `xprobe_point_state{point,state}` | `1` for the current liveness state: `never`, `offline`, `standing by`, `idle`, `no metrics`, `late`, `online` |
| `xprobe_point_enabled{point}` | the point is switched on |
| `xprobe_point_document_version{point}` | the version the point should be on; compare with the probe's own `xprobe_config_version` |
| `xprobe_point_seen_timestamp_seconds{point}` / `…_metrics_timestamp_seconds` | the two liveness clocks |
| `xprobe_point_targets{point,probe}` / `…_served_configs` / `…_missing_targets` | how many hosts a check was asked to probe, how many it was actually given, and how many its account cannot see |

The same text is available at `GET /metrics` on the admin port (admin
credentials) for setups that prefer to scrape.

**`idle` is a warning, not a resting state.** It means every enabled check
was handed zero configs — an empty target set, or one whose every name is
absent from the point's subscription. By its clocks alone such a point is
"online": it is up and pushing its own gauges. That reading is exactly the
one an operator must not see next to a point that measures nothing, which
is why the state exists. A single idle check on an otherwise working point
is listed in `health.idle` and marked in the UI.

## Explicit binding (without enroll)

A point can be provisioned in the UI beforehand and the node given `POINT` +
`CONTROL_TOKEN` explicitly — that is how nodes managed by the administrator
connect. Everything else is identical: the document comes from the control
plane, metrics go through the relay.

## Provisioning a point

The "+ Add point" button in the UI, in one step:

1. creates the shared `Monitor` squad if it does not exist yet;
2. creates the point's account `monitor_<point>` in it, tagged `MONITOR`;
3. saves its subscription link and its per-check target sets in its own DB;
4. generates the point's secret and shows **ready run commands** — `docker
   run` and `kubectl apply` — to hand to the point operator.

Only a hash of the secret is stored, so the same commands can be re-issued
for an existing point at any time — that rotates the secret, and the running
probe has to be restarted with the new command.

Points provisioned before the per-check target sets existed keep working: tcp
falls back to the http set until their targets are saved once, which
provisions the missing tcp squad.

## Deployment

The service is light: FastAPI + httpx + sqlite. Prebuilt image:
`ghcr.io/nd4y/xprobe-control` (see [deploy/control.compose.yml](../deploy/control.compose.yml)).
Key variables: `XPC_BASE_URL` — the public URL of the points side,
`XPC_RELAY_WRITE_URL` — where to forward metrics,
`XPC_DEFAULT_CHECK_REMARKS` / `XPC_DEFAULT_LOAD_REMARKS` — the default target
set for auto-enrolled points.

Publishing:

* the points port — externally, on the public reverse proxy;
* the admin port — internal network only, under a separate name on the
  internal proxy. The public name has no administrative paths.

## Development

```bash
python -m pytest -q     # tests (require fastapi + httpx)
ruff check .
```

Document parsing is verified with the very code that runs on points
(`tests/test_prober.py` imports `../agent/prober.py`): the contract between
the control plane and the probe must not drift.
