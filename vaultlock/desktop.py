"""Desktop shell: PyWebView window around the local server.

Falls back to the default web browser when PyWebView (or a GUI toolkit) is
unavailable, so ``python -m vaultlock`` works everywhere.
"""

from __future__ import annotations

import sys
import webbrowser

from .launcher import start_server


class NativeBridge:
    """Native file dialogs exposed to the UI through the server (``/api/native/pick``)."""

    def __init__(self) -> None:
        self.window = None

    def pick(self, mode: str, file_filter=None) -> list[str]:
        import webview

        if self.window is None:
            return []
        kinds = {"files": webview.OPEN_DIALOG, "folder": webview.FOLDER_DIALOG, "save": webview.SAVE_DIALOG}
        dialog = kinds.get(mode, webview.OPEN_DIALOG)
        types = tuple(file_filter) if isinstance(file_filter, list) else ()
        res = self.window.create_file_dialog(dialog, allow_multiple=(mode == "files"), file_types=types)
        if not res:
            return []
        return [str(p) for p in (res if isinstance(res, (list, tuple)) else [res])]


def run(browser: bool = False, port: int = 0) -> int:
    bridge = None
    if not browser:
        import logging

        logging.getLogger("pywebview").setLevel(logging.CRITICAL)  # no tracebacks if a GUI backend is missing
        try:
            import webview  # noqa: F401

            bridge = NativeBridge()
        except Exception:
            browser = True

    server = start_server(native_bridge=bridge, port=port)
    url = f"{server.url}?t={server.token}"  # token is consumed by the page and removed from the URL

    if browser or bridge is None:
        print(f"VaultLock is running at {server.url}")
        print("Opening your browser... press Ctrl+C here to quit.")
        webbrowser.open(url)
        try:
            server.wait()
        except KeyboardInterrupt:
            pass
        finally:
            server.stop()
        return 0

    import webview

    window = webview.create_window(
        "VaultLock", url, width=1240, height=820, min_size=(980, 680), background_color="#07090f", text_select=False
    )
    bridge.window = window
    try:
        webview.start(private_mode=True)  # private_mode: no persistent cookies / cache on disk
    except Exception as e:  # no usable GUI backend
        print(f"Native window unavailable ({e}); falling back to the browser.", file=sys.stderr)
        webbrowser.open(url)
        try:
            server.wait()
        except KeyboardInterrupt:
            pass
    finally:
        server.stop()
    return 0
