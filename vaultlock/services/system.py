"""Tiny OS integration helpers (reveal a file in the system file manager)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from ..core.errors import VaultLockError


def reveal(path: str) -> None:
    """Show ``path`` in Explorer / Finder / the default Linux file manager."""
    p = Path(path)
    if not p.exists():
        raise VaultLockError("That file no longer exists.")
    try:
        if sys.platform == "win32":
            if p.is_dir():
                os.startfile(str(p))  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["explorer", f"/select,{p}"])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", str(p)])
        else:
            subprocess.Popen(["xdg-open", str(p if p.is_dir() else p.parent)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, FileNotFoundError):
        raise VaultLockError("Could not open the system file manager here.") from None
