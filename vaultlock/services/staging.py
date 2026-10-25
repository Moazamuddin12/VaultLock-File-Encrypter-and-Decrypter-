"""Staging area for files dropped into a *browser* window.

A web page cannot read real filesystem paths, so in plain-browser mode a
dropped file is streamed to a private, owner-only inbox on disk (never held in
RAM, so multi-GB files are fine).  The staged copy is **shredded** as soon as
the job that used it finishes - success or failure - and anything left over
from a crash is purged on start-up and on exit.

In desktop (PyWebView) mode real paths are available and staging is not used.
"""

from __future__ import annotations

import os
import re
import secrets
import threading
from pathlib import Path
from typing import Optional

from ..core.fsutil import safe_filename
from . import shredder

_ID = re.compile(r"^[0-9a-f]{24}$")


class StagingArea:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        self._lock = threading.Lock()

    def new(self, filename: str) -> tuple[str, Path]:
        """Reserve a slot.  Returns ``(staged_id, destination_path)``; caller writes the file."""
        sid = secrets.token_hex(12)
        d = self.root / sid
        d.mkdir(mode=0o700)
        return sid, d / safe_filename(filename, "upload")

    def resolve(self, sid: str) -> Optional[Path]:
        if not isinstance(sid, str) or not _ID.match(sid):
            return None
        d = self.root / sid
        if not d.is_dir():
            return None
        files = [p for p in d.iterdir() if p.is_file()]
        return files[0] if len(files) == 1 else None

    def discard(self, sid: str) -> None:
        if not isinstance(sid, str) or not _ID.match(sid):
            return
        d = self.root / sid
        if d.exists():
            try:
                shredder.shred_path(d, passes=1)
            except Exception:
                import shutil

                shutil.rmtree(d, ignore_errors=True)

    def purge_all(self) -> int:
        n = 0
        for d in list(self.root.iterdir()):
            if d.is_dir() and _ID.match(d.name):
                self.discard(d.name)
                n += 1
        return n
