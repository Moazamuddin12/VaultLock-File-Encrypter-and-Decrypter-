"""Small, careful filesystem helpers shared by the engine and the services."""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path
from typing import BinaryIO

from .errors import OutputExistsError

_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED_WIN = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def safe_filename(name: str, fallback: str = "restored") -> str:
    """Make an untrusted name safe to create on any mainstream OS.

    The name comes out of an *authenticated* vault, but defence in depth is
    cheap: strip separators and control characters, neutralise ``.``/``..`` and
    Windows device names, and cap the length at 255 UTF-8 bytes.
    """
    name = _BAD_CHARS.sub("_", name or "").strip().rstrip(". ")
    if not name or name in {".", ".."}:
        return fallback
    if name.split(".")[0].upper() in _RESERVED_WIN:
        name = "_" + name
    raw = name.encode("utf-8")
    if len(raw) > 255:
        stem, dot, ext = name.rpartition(".")
        keep = 255 - len(ext.encode()) - 1 if dot and len(ext) < 16 else 255
        name = raw[: max(keep, 1)].decode("utf-8", "ignore") + (dot + ext if dot and len(ext) < 16 else "")
    return name


def unique_path(directory: Path, name: str) -> Path:
    """``name``, or ``stem (1).ext``, ``stem (2).ext`` ... whichever is free."""
    candidate = directory / name
    if not os.path.lexists(candidate):
        return candidate
    p = Path(name)
    stem, suffix = p.stem, p.suffix
    n = 1
    while True:
        candidate = directory / f"{stem} ({n}){suffix}"
        if not os.path.lexists(candidate):
            return candidate
        n += 1


def random_token(nbytes: int = 6) -> str:
    return secrets.token_hex(nbytes)


def partial_path(target: Path) -> Path:
    """A hidden sibling used while a file is being written (atomic publish later)."""
    return target.with_name(f".{target.name}.{random_token()}.partial")


def open_exclusive(path: Path, mode: int = 0o600) -> BinaryIO:
    """Create ``path`` for writing; fail if it exists; owner-only permissions."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, mode)
    return os.fdopen(fd, "wb")


def fsync_dir(path: Path) -> None:
    """Persist a directory entry change (no-op where unsupported, e.g. Windows)."""
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def publish(tmp: Path, target: Path, overwrite: bool = False) -> Path:
    """Atomically move ``tmp`` to ``target``.

    Without ``overwrite`` this never clobbers an existing file, even if one
    appeared between the existence check and now (hard-link + unlink on POSIX,
    ``rename`` semantics on Windows).
    """
    if overwrite:
        os.replace(tmp, target)
    else:
        try:
            os.link(tmp, target)
        except FileExistsError:
            raise OutputExistsError(f"{target.name} already exists.") from None
        except (OSError, NotImplementedError, AttributeError):
            # Filesystem without hard links (FAT/exFAT/SMB...): fall back to rename.
            if os.path.lexists(target):
                raise OutputExistsError(f"{target.name} already exists.") from None
            os.rename(tmp, target)
            fsync_dir(target.parent)
            return target
        os.unlink(tmp)
    fsync_dir(target.parent)
    return target


def remove_quietly(path: Path) -> None:
    try:
        if path.is_dir() and not path.is_symlink():
            import shutil

            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass
