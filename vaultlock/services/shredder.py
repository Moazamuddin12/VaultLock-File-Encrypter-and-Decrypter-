"""Emergency Shredder: overwrite-then-delete.

Pass schedules
--------------
``1``  zeros                                          (modern drives: one pass is plenty)
``3``  zeros, ones, random  - the DoD 5220.22-M "short" schedule
``7``  zeros, ones, random, zeros, ones, random, random  (extended)

After the last pass the file is truncated to zero length, renamed to a random
name (scrubbing the original name from the directory entry) and unlinked.

.. warning:: Overwriting in place only works when the filesystem writes new data
   over the old blocks.  It does **not** reliably destroy data on SSDs / flash
   (wear-levelling remaps blocks), on journaling or copy-on-write filesystems
   (APFS, btrfs, ZFS, NTFS with shadow copies), or on files that are synced to
   cloud storage / backups.  For those, rely on full-disk encryption and
   TRIM / ATA Secure Erase.  This is stated in the UI as well.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers import Cipher as _C, algorithms as _alg

from ..core.errors import CancelledError, VaultLockError
from ..core.stream import CancelToken

BLOCK = 1024 * 1024
ZERO, ONES, RANDOM = "zero", "ones", "random"
SCHEDULES: dict[int, list[str]] = {
    1: [ZERO],
    3: [ZERO, ONES, RANDOM],
    7: [ZERO, ONES, RANDOM, ZERO, ONES, RANDOM, RANDOM],
}

ProgressFn = Callable[[int], None]


@dataclass
class ShredReport:
    files: int = 0
    dirs: int = 0
    bytes: int = 0
    passes: int = 0
    warnings: list[str] = field(default_factory=list)


class _RandomStream:
    """Fast CSPRNG byte source: ChaCha20 keystream under a fresh random key."""

    def __init__(self) -> None:
        self._enc = _C(_alg.ChaCha20(os.urandom(32), os.urandom(16)), mode=None).encryptor()
        self._zeros = bytes(BLOCK)

    def read(self, n: int) -> bytes:
        return self._enc.update(self._zeros[:n])


def plan(paths, passes: int) -> int:
    """Total bytes of overwrite work (for progress): sum(size) x passes."""
    total = 0
    for p in paths:
        p = Path(p)
        if p.is_symlink():
            continue
        if p.is_dir():
            for root, _dirs, files in os.walk(p, followlinks=False):
                for f in files:
                    fp = Path(root) / f
                    try:
                        if stat.S_ISREG(fp.lstat().st_mode):
                            total += fp.lstat().st_size
                    except OSError:
                        pass
        else:
            try:
                total += p.lstat().st_size
            except OSError:
                pass
    return total * passes


def _write_all(fd: int, data) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _scrub_name(path: Path, is_dir: bool = False) -> Path:
    new = path.with_name(os.urandom(8).hex())
    try:
        os.rename(path, new)
        return new
    except OSError:
        return path


def shred_file(
    path: Path | str,
    passes: int = 3,
    *,
    on_bytes: Optional[ProgressFn] = None,
    cancel: Optional[CancelToken] = None,
    report: Optional[ShredReport] = None,
) -> ShredReport:
    schedule = SCHEDULES.get(passes)
    if schedule is None:
        raise VaultLockError("Passes must be 1, 3 or 7.")
    rep = report or ShredReport()
    rep.passes = passes
    p = Path(path)

    try:
        st = p.lstat()
    except FileNotFoundError:
        raise VaultLockError(f"'{p.name}' no longer exists.") from None
    if stat.S_ISLNK(st.st_mode):
        os.unlink(p)  # never follow links: only remove the link itself
        rep.files += 1
        return rep
    if not stat.S_ISREG(st.st_mode):
        raise VaultLockError(f"'{p.name}' is not a regular file.")
    if st.st_nlink > 1:
        rep.warnings.append(f"'{p.name}' has {st.st_nlink - 1} other hard link(s); their contents are overwritten too.")

    try:
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)  # clear read-only flags
    except OSError:
        pass

    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(p, flags)
    except OSError as e:
        raise VaultLockError(f"Cannot open '{p.name}' for shredding: {e.strerror or e}") from None
    try:
        size = os.fstat(fd).st_size
        rng = _RandomStream()
        zeros, ones = bytes(BLOCK), b"\xff" * BLOCK
        for pattern in schedule:
            os.lseek(fd, 0, os.SEEK_SET)
            left = size
            while left > 0:
                if cancel is not None and cancel.is_set():
                    raise CancelledError("Cancelled - the file was only partially overwritten and still exists.")
                n = min(BLOCK, left)
                block = zeros[:n] if pattern == ZERO else ones[:n] if pattern == ONES else rng.read(n)
                _write_all(fd, block)
                left -= n
                if on_bytes:
                    on_bytes(n)
            os.fsync(fd)
        os.ftruncate(fd, 0)
        os.fsync(fd)
    finally:
        os.close(fd)

    scrubbed = _scrub_name(p)
    os.unlink(scrubbed)
    rep.files += 1
    rep.bytes += size
    return rep


def shred_path(
    path: Path | str,
    passes: int = 3,
    *,
    on_bytes: Optional[ProgressFn] = None,
    cancel: Optional[CancelToken] = None,
    report: Optional[ShredReport] = None,
) -> ShredReport:
    """Shred a file, or a whole directory tree (files first, then empty dirs)."""
    rep = report or ShredReport()
    rep.passes = passes
    p = Path(path)
    if p.is_symlink() or not p.is_dir():
        return shred_file(p, passes, on_bytes=on_bytes, cancel=cancel, report=rep)

    for root, dirs, files in os.walk(p, topdown=False, followlinks=False):
        for f in files:
            shred_file(Path(root) / f, passes, on_bytes=on_bytes, cancel=cancel, report=rep)
        for d in dirs:
            dp = Path(root) / d
            try:
                if dp.is_symlink():
                    os.unlink(dp)
                    continue
                os.rmdir(_scrub_name(dp, True))
                rep.dirs += 1
            except OSError:
                pass
    try:
        os.rmdir(_scrub_name(p, True))
        rep.dirs += 1
    except OSError as e:
        rep.warnings.append(f"Could not remove folder '{p.name}': {e.strerror or e}")
    return rep
