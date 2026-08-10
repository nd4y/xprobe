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


def build() -> tuple[uvicorn.Server, uvicorn.Server]:
    cfg = Config.load()
    oidc = None
    if cfg.oidc is not None:
        redirect = (cfg.base_url or "") + "/auth/callback"
        oidc = OIDC(cfg.oidc.issuer, cfg.oidc.client_id, cfg.oidc.client_secret, redirect)
    points, admin = create_apps(Deps(cfg, oidc=oidc))
    points_port = int(os.environ.get("XPC_POINTS_PORT", "8080"))
    admin_port = int(os.environ.get("XPC_ADMIN_PORT", "8081"))
    return (
        _Server(uvicorn.Config(points, host="0.0.0.0", port=points_port)),
        _Server(uvicorn.Config(admin, host="0.0.0.0", port=admin_port)),
    )


async def serve() -> None:
    servers = build()

    def stop(*_args) -> None:
        for s in servers:
            s.should_exit = True

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop)
        except NotImplementedError:  # Windows during local development
            signal.signal(sig, stop)

    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    asyncio.run(serve())
