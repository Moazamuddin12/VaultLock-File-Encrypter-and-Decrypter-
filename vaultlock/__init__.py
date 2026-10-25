"""VaultLock - a local-first, streaming, authenticated file-encryption system.

Layers (each depends only on the ones above it):

    core/      cryptographic primitives and the ``.vault`` container format
    services/  shredder, password strength, job runner, file browser, staging
    server/    hardened localhost-only Flask API
    web/       the glassmorphism single-page UI
    desktop    PyWebView shell that wraps server + UI in a native window
    cli        the same engine from a terminal
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
