"""Best-effort "zero-trace" memory hygiene.

Python is a garbage-collected language with immutable ``bytes`` and ``str``
objects, so *perfect* secret erasure is impossible from pure Python.  What we
can do - and do here - is shrink the window in which secrets live in RAM:

* Secrets are held in mutable ``bytearray`` buffers (``SecretBytes``) and are
  overwritten with zeros the moment they are no longer needed.
* Buffers holding key material are ``mlock``-ed (``VirtualLock`` on Windows)
  so the OS will not page them out to swap.  Failure is non-fatal.
* Short-lived *immutable* ``bytes`` objects that we ourselves created (derived
  keys returned by a KDF, decrypted chunks) are zeroed in place using a
  CPython-specific ctypes trick.  The trick is **self-verified at import
  time**: if the object layout is not exactly what we expect, it is disabled
  and ``wipe_bytes`` becomes a no-op rather than risking memory corruption.

The residual risks (``str`` passwords, interpreter free-lists, OS-level
copies) are documented in ``docs/SECURITY.md``.
"""

from __future__ import annotations

import ctypes
import os
import sys
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]

# --------------------------------------------------------------------------
# In-place zeroing of immutable ``bytes`` (CPython only, self-verified)
# --------------------------------------------------------------------------

#: ``bytes`` objects shorter than this are never touched.  CPython caches the
#: empty bytes object and all 1-byte objects as singletons; scrubbing one of
#: those would corrupt the interpreter.  Anything >= 16 bytes that came out of
#: a KDF / AEAD call is a fresh, privately owned object.
_MIN_WIPE_LEN = 16


def _probe_bytes_layout() -> int | None:
    """Return the offset of the data buffer inside a ``bytes`` object, or
    ``None`` if it cannot be verified on this interpreter."""
    if sys.implementation.name != "cpython":
        return None
    try:
        offset = bytes.__basicsize__ - 1  # ob_sval[0]; header size differs per version
        probe = bytes(bytearray(os.urandom(32)))  # fresh object, not interned
        seen = ctypes.string_at(id(probe) + offset, len(probe))
        if seen != probe:
            return None
        # Verify the scrub itself works on a throw-away object.
        ctypes.memset(id(probe) + offset, 0, len(probe))
        if probe != bytes(32):
            return None
        return offset
    except Exception:  # pragma: no cover - exotic interpreters
        return None


_BYTES_OFFSET = _probe_bytes_layout()
CAN_WIPE_IMMUTABLE = _BYTES_OFFSET is not None


def wipe_bytes(data: bytes) -> bool:
    """Zero an immutable ``bytes`` object in place.  Returns True if scrubbed.

    Only call this on objects you created and exclusively own (e.g. the
    return value of an AEAD ``decrypt`` or a KDF ``derive``).
    """
    if _BYTES_OFFSET is None or type(data) is not bytes or len(data) < _MIN_WIPE_LEN:
        return False
    ctypes.memset(id(data) + _BYTES_OFFSET, 0, len(data))
    return True


def wipe(buf: BytesLike | None) -> None:
    """Zero any bytes-like object we are allowed to scrub (best effort)."""
    if buf is None:
        return
    if isinstance(buf, bytearray):
        n = len(buf)
        if n:
            arr = (ctypes.c_char * n).from_buffer(buf)
            ctypes.memset(arr, 0, n)
            del arr  # release the buffer export so the bytearray can resize again
    elif isinstance(buf, memoryview):
        if not buf.readonly:
            buf[:] = bytes(len(buf))
    elif isinstance(buf, bytes):
        wipe_bytes(buf)


def wipe_prefix(buf: bytearray, n: int) -> None:
    """Zero the first ``n`` bytes of a bytearray (used before discarding consumed data)."""
    n = min(n, len(buf))
    if n > 0:
        arr = (ctypes.c_char * n).from_buffer(buf)
        ctypes.memset(arr, 0, n)
        del arr


# --------------------------------------------------------------------------
# Page locking
# --------------------------------------------------------------------------

def _lock_region(addr: int, size: int) -> bool:
    try:
        if os.name == "nt":
            return bool(ctypes.windll.kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(size)))  # type: ignore[attr-defined]
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size)) == 0
    except Exception:
        return False


def _unlock_region(addr: int, size: int) -> None:
    try:
        if os.name == "nt":
            ctypes.windll.kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))  # type: ignore[attr-defined]
        else:
            ctypes.CDLL(None).munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
    except Exception:
        pass


class SecretBytes:
    """A fixed-size, mlock-ed, self-wiping byte buffer for key material.

    Use as a context manager, or call :meth:`wipe` explicitly.  Instances
    refuse to be pickled, copied or printed.
    """

    __slots__ = ("_buf", "_addr", "_locked", "_alive")

    def __init__(self, data: BytesLike | int):
        if isinstance(data, int):
            self._buf = bytearray(data)
        else:
            self._buf = bytearray(data)
        self._alive = True
        self._locked = False
        self._addr = 0
        if len(self._buf):
            arr = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
            self._addr = ctypes.addressof(arr)
            del arr
            self._locked = _lock_region(self._addr, len(self._buf))

    # -- constructors ---------------------------------------------------
    @classmethod
    def take(cls, data: bytes | bytearray) -> "SecretBytes":
        """Move ``data`` into a protected buffer and scrub the original."""
        sb = cls(data)
        wipe(data)
        return sb

    # -- access ----------------------------------------------------------
    def view(self) -> memoryview:
        """A *writable* memoryview onto the live buffer (do not keep it)."""
        if not self._alive:
            raise ValueError("secret already wiped")
        return memoryview(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

    def __bytes__(self) -> bytes:  # explicit copy - callers must wipe_bytes() it
        if not self._alive:
            raise ValueError("secret already wiped")
        return bytes(self._buf)

    # -- lifecycle -------------------------------------------------------
    def wipe(self) -> None:
        if not self._alive:
            return
        wipe(self._buf)
        if self._locked:
            _unlock_region(self._addr, len(self._buf))
            self._locked = False
        self._alive = False

    def __enter__(self) -> "SecretBytes":
        return self

    def __exit__(self, *exc) -> None:
        self.wipe()

    def __del__(self) -> None:  # pragma: no cover - interpreter shutdown ordering
        try:
            self.wipe()
        except Exception:
            pass

    # -- hygiene ---------------------------------------------------------
    def __repr__(self) -> str:
        return f"<SecretBytes len={len(self._buf)} {'wiped' if not self._alive else 'live'}>"

    def __reduce__(self):
        raise TypeError("SecretBytes cannot be pickled")

    def __copy__(self):
        raise TypeError("SecretBytes cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("SecretBytes cannot be copied")


def take_secret(data: bytes) -> SecretBytes:
    """Convenience: move an immutable KDF result into a SecretBytes and scrub it."""
    sb = SecretBytes(data)
    wipe_bytes(data)
    return sb
