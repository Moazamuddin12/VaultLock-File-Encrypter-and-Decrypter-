"""A tiny server-side file explorer.

PyWebView gives us native dialogs, but a plain browser tab does not - and the
UI must work in both.  This module powers the in-app "Browse" dialog: it lists
directories of the machine VaultLock runs on (which, by design, is the user's
own machine - the server only listens on 127.0.0.1 and requires a per-session
token).
"""

from __future__ import annotations

import os
import stat
import string
import sys
from pathlib import Path

from ..core.errors import VaultLockError

MAX_ENTRIES = 5000


def _is_hidden(name: str, st: os.stat_result) -> bool:
    if name.startswith("."):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & 0x2)  # FILE_ATTRIBUTE_HIDDEN on Windows


def roots() -> list[dict]:
    """Sensible starting points: home folders and (on Windows) drive letters."""
    home = Path.home()
    out: list[dict] = [{"name": "Home", "path": str(home), "icon": "home"}]
    for label, sub, icon in (
        ("Desktop", "Desktop", "monitor"),
        ("Documents", "Documents", "file-text"),
        ("Downloads", "Downloads", "download"),
        ("Pictures", "Pictures", "image"),
        ("Videos", "Videos", "film"),
        ("VaultLock", "VaultLock", "shield"),
    ):
        p = home / sub
        if p.is_dir():
            out.append({"name": label, "path": str(p), "icon": icon})
    if sys.platform == "win32":
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                out.append({"name": f"Drive {letter}:", "path": drive, "icon": "hard-drive"})
    else:
        out.append({"name": "Computer", "path": "/", "icon": "hard-drive"})
        for mount_root in ("/Volumes", "/media", "/mnt"):
            mr = Path(mount_root)
            if mr.is_dir():
                try:
                    for child in sorted(mr.iterdir())[:12]:
                        if child.is_dir():
                            out.append({"name": child.name, "path": str(child), "icon": "usb"})
                except OSError:
                    pass
    return out


def list_dir(path: str | None, show_hidden: bool = False) -> dict:
    p = Path(path).expanduser() if path else Path.home()
    p = Path(os.path.abspath(p))
    try:
        it = list(os.scandir(p))
    except FileNotFoundError:
        raise VaultLockError("That folder does not exist.") from None
    except NotADirectoryError:
        raise VaultLockError("That path is not a folder.") from None
    except PermissionError:
        raise VaultLockError("Permission denied for that folder.") from None
    except OSError as e:
        raise VaultLockError(f"Cannot open folder: {e.strerror or e}") from None

    entries: list[dict] = []
    truncated = False
    for e in it:
        try:
            st = e.stat(follow_symlinks=False)
            is_link = stat.S_ISLNK(st.st_mode)
            if is_link:
                try:
                    st = e.stat(follow_symlinks=True)
                except OSError:
                    pass
            hidden = _is_hidden(e.name, st)
            if hidden and not show_hidden:
                continue
            is_dir = stat.S_ISDIR(st.st_mode)
            entries.append(
                {
                    "name": e.name,
                    "path": e.path,
                    "kind": "dir" if is_dir else "file",
                    "size": 0 if is_dir else st.st_size,
                    "mtime": st.st_mtime,
                    "link": is_link,
                    "hidden": hidden,
                    "vault": (not is_dir) and e.name.lower().endswith(".vault"),
                    "key": (not is_dir) and e.name.lower().endswith(".key"),
                }
            )
        except OSError:
            continue
        if len(entries) >= MAX_ENTRIES:
            truncated = True
            break

    entries.sort(key=lambda x: (x["kind"] != "dir", x["name"].lower()))
    parent = str(p.parent) if p.parent != p else None
    crumbs = []
    cur = p
    while True:
        crumbs.append({"name": cur.name or str(cur), "path": str(cur)})
        if cur.parent == cur:
            break
        cur = cur.parent
    crumbs.reverse()
    return {"path": str(p), "parent": parent, "breadcrumbs": crumbs, "entries": entries, "truncated": truncated}


def make_dir(parent: str, name: str) -> str:
    from ..core.fsutil import safe_filename

    clean = safe_filename(name, "")
    if not clean:
        raise VaultLockError("Please enter a valid folder name.")
    target = Path(parent).expanduser() / clean
    try:
        target.mkdir(parents=False, exist_ok=False)
    except FileExistsError:
        raise VaultLockError("A folder with that name already exists.") from None
    except OSError as e:
        raise VaultLockError(f"Cannot create folder: {e.strerror or e}") from None
    return str(target)
