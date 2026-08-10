# xprobe — a subscription-config probe

Takes a panel subscription, brings every config up with a **real `xray`
binary** and exposes Prometheus metrics.

## Why, when xray-checker exists

That one compiles `xray-core` in as a library. In `v1.3.1` it is **26.3.27**,
while nodes run 26.7.28, and XHTTP is incompatible between those versions: the
config does not come up, the log shows nothing, the metric is simply red. It
looks exactly like broken configs and takes half a day to chase.

Here the core is a plain binary with the version set by a single `Dockerfile`
line (`ARG XRAY_VERSION`). Node upgrade → image rebuild, and a divergence is
plainly visible.

Second: **exit-address verification**. A WARP failure is masked by the
`DIRECT` fallback — the connection comes up, the response arrives, every
checker stays green. The only way to see it is the address the traffic
actually left from.

## Three modes, concurrently

All run in one process, each in its own thread, with separate subscriptions,
intervals, timeouts and port ranges:

| Mode | What it does | Interval | Target set |
|---|---|---|---|
| `tcp` | TCP connect and TLS handshake to the inbound, no Xray | 300 s | its own |
| `status` (shown as **http** in the UI) | HTTP request through the config | 300 s | its own |
| `download` | downloads a file, measures volume and speed | 1800 s | its own — keep it short |

`tcp` and `status` share a schedule and run concurrently, so a failing stage
is always compared against a same-age result from the stage below it. Each
mode has an independent target set: the cheap checks can cover everything
while the bandwidth check stays on a couple of configs.

The three modes answer different questions, and together they show **at which
stage** things broke:

* `tcp` red — the inbound is unreachable: network, routing, address blocking;
* `tcp` green, `tls_ok` red — the handshake is being cut, most likely by SNI;
* both green, `status` red — the endpoint is alive but the protocol itself
  fails (client/server mismatch, inbound down, credential invalid);
* everything green, `download` red — the channel exists but collapses under load.

Separate subscriptions exist because the sets differ: the bandwidth check
downloads through **every** config it has, and keeping its set short is
essential. `download` success is the volume that arrived, not the status code:
a throttled channel returns 200 and cuts off within the first kilobytes.

The `status` mode keeps its wire name in the document, the metric label and
the environment variables — dashboards depend on it. Only the UI calls it
`http`, which is what it actually does.

## Metrics

The names match xray-checker deliberately — dashboards and status pages
already depend on them, and swapping the probe must not break anything.

```
xray_proxy_status{name,probe}                 1 — the probe passed
xray_proxy_latency_ms{name,probe}             request duration
xray_proxy_exit_ok{name,probe}                exit address matched the expected one
xray_proxy_tls_ok{name,probe}                 TLS handshake with the inbound completed
xray_proxy_download_bytes{name,probe}         bytes received
xray_proxy_download_speed_bytes{name,probe}   download speed
xray_proxy_checked_timestamp_seconds{name,probe}
xprobe_configs{probe} / xprobe_subscription_ok{probe}
```

The `probe` label (`status` | `download`) is set by the probe itself. The
point's other labels come from `EXTRA_LABELS`.

## Two configuration models

**From the control plane** ([xprobe-control](../control)) — the fleet
mode. Three environment lines; everything else arrives in the document and is
edited centrally:

| Variable | Meaning |
|---|---|
| `POINT` | point name (also the `point` label and the push login) |
| `CONTROL_URL` | control-plane address |
| `CONTROL_TOKEN` | the point's secret: metrics are pushed with it too |
| `CONTROL_INTERVAL` | how often to check the document version (60 s) |
| `ENROLL_TOKEN` | zero-touch alternative to POINT+CONTROL_TOKEN |
| `NODE_ID` | stable node identity for enrolment — see below |

## Restarts, and storage that does not survive them

With `POINT` + `CONTROL_TOKEN` the identity is in the environment, so the
probe reconnects with **nothing persisted at all**: the volume then holds only
the metrics spool and the document cache, and losing them costs undelivered
samples and one extra fetch.

Enrolment is different. The control plane recognises a returning node by its
`NODE_ID`, so that value has to survive a restart — otherwise each restart
enrols a **brand new point**, and the fleet grows a duplicate (plus a panel
account) every time. By default the id is generated once and kept in the
volume, which is enough for Docker.

On Kubernetes an `emptyDir` disappears when the pod is rescheduled, so pin the
id instead: run a StatefulSet and take `NODE_ID` from the pod name via the
downward API. The name is stable, re-enrolment returns the same point, and no
storage is needed. The control plane's enrol dialog hands out exactly that
manifest.

Configs come from the control plane too, already filtered to this point's
target set, and are **held in memory only** — they carry working credentials
for someone else's tunnels, and the probe runs on a machine its operator does
not own. The core is fed through a pipe (`xray run -c stdin:`), so no config
reaches that machine's disk even transiently.

In this mode the probe **pushes metrics itself** to the document's `push.url`
(no scraper needed); on delivery failure it spools to disk (`SPOOL_PATH`) and
resends. The last good document is cached (`CONFIG_CACHE`) — settings only, no
credentials — so a control-plane outage does not disturb an already running
point. A document version change =
a clean process exit; the restart rebuilds the configuration.

**From the environment** — the legacy mode (for locally scraped deployments
and tests). `CONTROL_URL` is empty and metrics are exposed on `/metrics`:

| Variable | Meaning |
|---|---|
| `TCP_SUBSCRIPTION_URL` | the `tcp` mode's subscription (mode off without it) |
| `TCP_INTERVAL`, `TCP_TIMEOUT` | its settings |
| `SUBSCRIPTION_URL` | the `status` mode's subscription (mode off without it) |
| `CHECK_INTERVAL`, `CHECK_URL`, `START_PORT`, `TIMEOUT` | its settings |
| `DOWNLOAD_SUBSCRIPTION_URL` | the `download` mode's subscription |
| `DOWNLOAD_INTERVAL`, `DOWNLOAD_URL`, `DOWNLOAD_MIN_BYTES`, `DOWNLOAD_TIMEOUT`, `DOWNLOAD_START_PORT` | its settings |
| `SUBSCRIPTION_INTERVAL` | how often to re-read the subscriptions |
| `IP_URL` | how to learn the exit address |
| `EXIT_EXPECTATIONS` | `{"config-name regex": "prefix,prefix"}` |
| `EXTRA_LABELS` | `key=value,key=value` — vantage-point labels |

The subscription must be served **in xray-json format**: a share link loses
the XHTTP `extra` block, and such a config does not work through a CDN.
