# xprobe-control

Control plane for a fleet of [xprobe](../agent) probes. Probes run at
different operators in different cities; this service centrally defines
**which probe checks which servers, in which modes, at what intervals, and
where the metrics go**.

## How it works

```
        ┌─ fetches its document (basic auth: point name + secret)
probe ──┤
   ▲    └─ pushes metrics itself to push.url (same secret)
   │
   │  document version changed → probe exits → the restart applies the change
   ▼
xprobe-control ──reads/writes──> Remnawave panel (squads, hosts, accounts)
   │
   └─ administrator UI: point list, target sets as checkboxes, "+ Add point"
```

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

From then on the probe lives on the issued secret; the enroll token is no
longer needed. The token is **one-time per node and rotatable**: regenerating
it in the UI revokes the old one, while already-connected nodes are unaffected
(they authenticate with their secrets). If a node loses its volume, re-enroll
with the same `node_id` returns the same point with a fresh secret.

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

**The control plane keeps no copy of other systems' data.** The target set
lives in the panel (the DB holds only squad uuids), metrics live in
VictoriaMetrics. Duplicating them would create a second answer to the same
question.

## Explicit binding (without enroll)

A point can be provisioned in the UI beforehand and the node given `POINT` +
`CONTROL_TOKEN` explicitly — that is how nodes managed by the administrator
connect. Everything else is identical: the document comes from the control
plane, metrics go through the relay.

## Provisioning a point

The "+ Add point" button in the UI, in one step:

1. creates three panel squads `Monitor-<point>-tcp` / `-check` / `-load`, one
   per check, and fills them with the selected hosts (via
   `excludedInternalSquads`, as everywhere);
2. creates three monitoring accounts `monitor_<point>_tcp` / `monitor_<point>`
   / `_load` tagged `MONITOR`;
3. saves their subscription links into its own DB (the hot path makes no panel
   calls);
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
