# xprobe

Distributed availability monitoring for [Remnawave](https://remna.st)
deployments: lightweight probes at many vantage points, one control plane.

Every probe brings each subscription config up with a **real `xray` binary** —
and with the core version you choose, per check, because a config that works
on one core can fail silently on another. It verifies the **exit address** (a
dead WARP masked by a DIRECT fallback stays invisible to ordinary checkers)
and reports **at which stage** a config broke: network, TLS handshake, tunnel,
protocol, or bandwidth.

The control plane makes the fleet manageable: which probe checks which
servers, in which modes, at what intervals — all edited centrally, applied to
probes automatically.

## Components

| Directory | What it is | Image |
|---|---|---|
| [`agent/`](agent) | the probe: one Python file + an xray binary | `ghcr.io/nd4y/xprobe` |
| [`control/`](control) | the control plane: FastAPI + sqlite, talks to the Remnawave panel | `ghcr.io/nd4y/xprobe-control` |
| [`deploy/`](deploy) | ready-to-use compose files for both | — |

## Zero-touch vantage points

A new vantage point needs **two environment lines** — `CONTROL_URL` and
`ENROLL_TOKEN` — and `docker compose up -d`. The probe enrolls itself,
receives its identity and target set, detects its own city/ISP, and starts
pushing metrics through the control-plane relay. Everything else is managed
from the control-plane UI.

The token is issued **per node** and can be revoked for that node alone —
without it, cutting one operator off would mean re-keying every other one.
It also doubles as the node's identity, so nothing has to be persisted: a
rescheduled pod on an `emptyDir` re-enrolls as the same point.

## Security model

Probes run on machines their operator does not own, and every config they
handle is a working credential for someone else's tunnel. The design follows
from that.

* **Configs never touch a probe's disk.** The control plane hands each check
  only the configs its target set names; they are held in memory and fed to
  the core through a pipe. Nothing config-shaped is written to the node, so
  there is nothing to leak, to forget to delete, or to find in a backup.
  Encrypting a temp file would be theatre — the core has to be given
  plaintext either way.
* **One identity per point.** Each point has its own panel account, so a
  single point can be cut off — or its traffic read — without disturbing the
  rest of the fleet.
* **The panel is read-only.** Target sets live in the control plane and are
  applied by filtering, so no monitoring change ever writes to a live host or
  squad.
* The control plane serves **two ports**: a public one for probes
  (`/api/points/*`, `/api/enroll` — per-point secrets) and an internal one for
  the admin UI (local account, HTTP Basic). The public port has no admin
  routes at all.
* Point secrets are stored hashed; each point can only fetch its own document,
  its own configs, and push its own metrics.
* Probes never learn the metrics store's address or credentials — metrics go
  through the control-plane relay with the same per-point secret.
* A vantage node's IP is stored for diagnostics but never exposed — not in
  documents, not in the UI, not in metric labels.

What this does **not** protect against: whoever has root on the machine a
probe runs on can read its memory and its traffic. Nothing running on that
machine can prevent that, which is why per-point revocation matters more than
obfuscation.

## Development

```bash
cd control
python -m pytest -q     # tests (require fastapi + httpx + uvicorn)
ruff check . ../agent
```

CI builds and publishes both images on every push to `main`.
