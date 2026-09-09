"""Service entry point: two uvicorn servers in one process.

The ports are split deliberately: the points port is published to the internet
(probes call it), while the admin port stays on the internal network and is
published separately. With this split a proxy misconfiguration cannot expose
the admin UI — the public port simply has no admin routes.
"""

from __future__ import annotations

import asyncio
import os
import signal
from collections.abc import Callable

import uvicorn

from .app import Deps, create_apps
from .config import Config
from .oidc import OIDC


class _Server(uvicorn.Server):
    # Signal handlers are installed by us, once, for both servers: the stock
    # installation from the second serve() would overwrite the first server's
    # handlers, and that server would never learn about the shutdown.
    def install_signal_handlers(self) -> None:
        pass


def build() -> tuple[tuple[uvicorn.Server, uvicorn.Server], Callable[[], bool], int]:
    cfg = Config.load()
    oidc = None
    if cfg.oidc is not None:
        redirect = (cfg.base_url or "") + "/auth/callback"
        oidc = OIDC(cfg.oidc.issuer, cfg.oidc.client_id, cfg.oidc.client_secret, redirect)
    points, admin = create_apps(Deps(cfg, oidc=oidc))
    points_port = int(os.environ.get("XPC_POINTS_PORT", "8080"))
    admin_port = int(os.environ.get("XPC_ADMIN_PORT", "8081"))
    servers = (
        _Server(uvicorn.Config(points, host="0.0.0.0", port=points_port)),
        _Server(uvicorn.Config(admin, host="0.0.0.0", port=admin_port)),
    )
    return servers, admin.state.push_fleet_metrics, cfg.defaults.push_interval


async def push_fleet(push: Callable[[], bool], every: int,
                     servers: tuple[uvicorn.Server, ...]) -> None:
    """The fleet's state goes to the store on the probes' own cadence.

    The same period as a point's push, so one liveness rule reads both: a
    point that fell silent and a control plane that did look alike in the
    store, and both deserve the alert.
    """
    while not any(s.should_exit for s in servers):
        # The relay call blocks; off the loop so the servers keep serving.
        await asyncio.to_thread(push)
        for _ in range(every):
            if any(s.should_exit for s in servers):
                return
            await asyncio.sleep(1)


async def serve() -> None:
    servers, push, every = build()

    def stop(*_args) -> None:
        for s in servers:
            s.should_exit = True

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop)
        except NotImplementedError:  # Windows during local development
            signal.signal(sig, stop)

    await asyncio.gather(*(s.serve() for s in servers), push_fleet(push, every, servers))


if __name__ == "__main__":
    asyncio.run(serve())
