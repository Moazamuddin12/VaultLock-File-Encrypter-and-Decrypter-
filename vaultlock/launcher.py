"""Start the local API server on a free loopback port (in a background thread)."""

from __future__ import annotations

import logging
import secrets
import socket
import threading
from dataclasses import dataclass
from typing import Any

from werkzeug.serving import make_server

from .server.app import create_app


@dataclass
class RunningServer:
    url: str
    token: str
    app: Any
    _srv: Any
    _thread: threading.Thread

    def stop(self) -> None:
        try:
            self._srv.shutdown()
        finally:
            self.app.config["VL_JOBS"].cancel_all()
            self.app.config["VL_STAGING"].purge_all()
            for buf, _ in list(self.app.config["VL_PREVIEWS"].values()):
                from .core.memory import wipe

                wipe(buf)
            self.app.config["VL_PREVIEWS"].clear()

    def wait(self) -> None:
        self._thread.join()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(*, native_bridge: Any = None, port: int = 0, **app_kwargs) -> RunningServer:
    # Request logs would include URLs; keep the console quiet (and token-free).
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    port = port or _free_port()
    token = secrets.token_urlsafe(32)
    app = create_app(token=token, native_bridge=native_bridge, expected_host=f"127.0.0.1:{port}", **app_kwargs)
    srv = make_server("127.0.0.1", port, app, threaded=True)
    app.config["VL_SHUTDOWN"] = lambda: threading.Thread(target=srv.shutdown, daemon=True).start()
    th = threading.Thread(target=srv.serve_forever, name="vaultlock-http", daemon=True)
    th.start()
    return RunningServer(f"http://127.0.0.1:{port}/", token, app, srv, th)
