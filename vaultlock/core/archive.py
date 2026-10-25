"""Folder vaults: stream a directory tree through ``tarfile`` into the encryptor.

Nothing is staged on disk - the tar stream is generated on the fly and flows
straight into ``EncryptWriter`` - so an unencrypted archive never exists, not
even briefly.  On the way out, members are validated *strictly* (we only ever
write regular files and directories, so we refuse everything else) before
being handed to ``tarfile``'s own ``data`` filter.
"""

from __future__ import annotations

import os
import stat
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO, Optional

from .errors import ArchiveError, CancelledError
from .stream import CancelToken

MAX_ENTRIES = 2_000_000


@dataclass
class Entry:
    path: Path
    arcname: str
    is_dir: bool
    size: int = 0


@dataclass
class Collected:
    entries: list[Entry] = field(default_factory=list)
    files: int = 0
    dirs: int = 0
    total_size: int = 0
    skipped: list[str] = field(default_factory=list)  # symlinks, sockets, unreadable ...

    @property
    def tar_estimate(self) -> int:
        """Bytes the tar stream will contain (headers + padded data + EOF marker)."""
        total = 1024
        for e in self.entries:
            total += 512
            if not e.is_dir:
                total += (e.size + 511) // 512 * 512
        return total


def _unique_arcname(name: str, used: set[str]) -> str:
    if name not in used:
        return name
    n = 2
    while f"{name} ({n})" in used:
        n += 1
    return f"{name} ({n})"


def collect(sources: list[Path], cancel: Optional[CancelToken] = None) -> Collected:
    """Walk ``sources`` (files and/or folders) into a flat, deterministic entry list.

    Symlinks are *skipped*, never followed: following them could silently pull
    data from outside the chosen folder into the vault.
    """
    out = Collected()
    used_roots: set[str] = set()
    for src in sources:
        src = Path(src)
        if src.is_symlink():
            out.skipped.append(f"{src.name} (symlink)")
            continue
        root = _unique_arcname(src.name or "root", used_roots)
        used_roots.add(root)
        if src.is_dir():
            out.entries.append(Entry(src, root, True))
            out.dirs += 1
            for dirpath, dirnames, filenames in os.walk(src, followlinks=False, onerror=lambda e: out.skipped.append(f"{e.filename} (unreadable)")):
                if cancel is not None and cancel.is_set():
                    raise CancelledError("Cancelled.")
                dirnames.sort()
                filenames.sort()
                rel_dir = Path(dirpath).relative_to(src)
                keep = []
                for d in dirnames:
                    full = Path(dirpath) / d
                    if full.is_symlink():
                        out.skipped.append(f"{(rel_dir / d).as_posix()} (symlink)")
                        continue
                    keep.append(d)
                    out.entries.append(Entry(full, f"{root}/{(rel_dir / d).as_posix()}".replace("/./", "/"), True))
                    out.dirs += 1
                dirnames[:] = keep
                for f in filenames:
                    full = Path(dirpath) / f
                    if full.is_symlink():
                        out.skipped.append(f"{(rel_dir / f).as_posix()} (symlink)")
                        continue
                    try:
                        st = full.lstat()
                    except OSError:
                        out.skipped.append(f"{f} (unreadable)")
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        out.skipped.append(f"{(rel_dir / f).as_posix()} (not a regular file)")
                        continue
                    arc = f"{root}/{(rel_dir / f).as_posix()}".replace("/./", "/")
                    out.entries.append(Entry(full, arc, False, st.st_size))
                    out.files += 1
                    out.total_size += st.st_size
                if len(out.entries) > MAX_ENTRIES:
                    raise ArchiveError("Folder contains too many entries.")
        else:
            try:
                st = src.lstat()
            except OSError as e:
                raise ArchiveError(f"Cannot read {src.name}: {e.strerror or e}") from None
            if not stat.S_ISREG(st.st_mode):
                out.skipped.append(f"{src.name} (not a regular file)")
                continue
            out.entries.append(Entry(src, root, False, st.st_size))
            out.files += 1
            out.total_size += st.st_size
    return out


def pack(collected: Collected, sink: BinaryIO, cancel: Optional[CancelToken] = None) -> None:
    """Write the tar stream for ``collected`` into ``sink`` (does not close it)."""
    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as tf:
        for e in collected.entries:
            if cancel is not None and cancel.is_set():
                raise CancelledError("Cancelled.")
            info = tf.gettarinfo(str(e.path), arcname=e.arcname)
            if info is None:  # pragma: no cover
                continue
            # Don't leak local account names / numeric ids into the vault.
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if info.isdir():
                tf.addfile(info)
            elif info.isreg():
                with open(e.path, "rb") as fh:
                    tf.addfile(info, fh)


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------

def _validate_member(m: tarfile.TarInfo) -> None:
    name = m.name
    if not name or "\x00" in name:
        raise ArchiveError("Archive contains an invalid entry name.")
    if not (m.isreg() or m.isdir()):
        raise ArchiveError(f"Archive contains a disallowed entry type ({name!r}).")
    posix = PurePosixPath(name)
    win = PureWindowsPath(name)
    if posix.is_absolute() or win.is_absolute() or win.drive or win.root:
        raise ArchiveError(f"Archive contains an absolute path ({name!r}).")
    if ".." in posix.parts or ".." in win.parts:
        raise ArchiveError(f"Archive tries to escape the destination folder ({name!r}).")


def unpack(stream: BinaryIO, dest: Path, cancel: Optional[CancelToken] = None) -> int:
    """Extract a tar stream into the (already created, empty) directory ``dest``.

    Returns the number of members extracted.  Caller is responsible for
    draining ``stream`` to EOF afterwards so the final AEAD chunk is verified.
    """
    dest = Path(dest)
    root = os.path.realpath(dest)
    count = 0
    try:
        with tarfile.open(fileobj=stream, mode="r|") as tf:
            for m in tf:
                if cancel is not None and cancel.is_set():
                    raise CancelledError("Cancelled.")
                _validate_member(m)
                target = os.path.realpath(os.path.join(root, m.name))
                if os.path.commonpath([root, target]) != root:
                    raise ArchiveError(f"Archive tries to escape the destination folder ({m.name!r}).")
                if hasattr(tarfile, "data_filter"):
                    tf.extract(m, root, filter="data")
                else:  # pragma: no cover - Python < 3.11.4
                    tf.extract(m, root)
                count += 1
                if count > MAX_ENTRIES:
                    raise ArchiveError("Archive contains too many entries.")
    except tarfile.TarError as e:
        raise ArchiveError(f"The archive inside the vault is malformed ({e}).") from None
    return count


def iter_members(stream: BinaryIO, limit: int = 100_000):
    """Yield ``(TarInfo, tarfile)`` for each member of a tar stream (for the secure viewer)."""
    try:
        with tarfile.open(fileobj=stream, mode="r|") as tf:
            for i, m in enumerate(tf):
                if i >= limit:
                    raise ArchiveError("Archive has too many entries to list.")
                yield m, tf
    except tarfile.TarError as e:
        raise ArchiveError(f"The archive inside the vault is malformed ({e}).") from None
