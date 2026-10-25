"""Keyfiles: the optional second authentication factor.

*Any* file can be used as a keyfile (a photo, a PDF, a hardware-token dump...) -
its SHA-512 digest is what matters.  VaultLock can also generate a dedicated
keyfile containing 64 bytes from the OS CSPRNG, stored as a small text file so
it survives copy/paste, email attachments and cloud sync without corruption.

A keyfile is *not* stored in or referenced by the vault; lose it and the vault
is unrecoverable.  Keep at least one offline copy.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from pathlib import Path

from .errors import MissingCredentialError, OutputExistsError, VaultLockError
from .memory import SecretBytes, wipe

KEYFILE_HEADER = "VAULTLOCK-KEYFILE-V1"
KEYFILE_BYTES = 64
_READ_BLOCK = 1024 * 1024


def generate_keyfile(path: str | os.PathLike, *, overwrite: bool = False) -> str:
    """Create a new random keyfile at ``path`` (mode 0600).  Returns its fingerprint."""
    p = Path(path).expanduser()
    if p.exists() and not overwrite:
        raise OutputExistsError(f"{p.name} already exists.")
    p.parent.mkdir(parents=True, exist_ok=True)

    raw = bytearray(secrets.token_bytes(KEYFILE_BYTES))
    try:
        body = f"{KEYFILE_HEADER}\n{base64.b64encode(raw).decode()}\n".encode()
    finally:
        wipe(raw)

    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL) | getattr(os, "O_BINARY", 0)
    fd = os.open(p, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        try:
            p.unlink()
        except OSError:
            pass
        raise
    return fingerprint(p)


def digest_keyfile(path: str | os.PathLike) -> SecretBytes:
    """SHA-512 of the whole keyfile (streamed), returned in a protected buffer."""
    if not path:
        raise MissingCredentialError("No keyfile was provided.")
    p = Path(path).expanduser()
    try:
        h = hashlib.sha512()
        with open(p, "rb") as fh:
            size = 0
            while True:
                block = fh.read(_READ_BLOCK)
                if not block:
                    break
                size += len(block)
                h.update(block)
    except FileNotFoundError:
        raise VaultLockError(f"Keyfile not found: {p.name}") from None
    except OSError as e:
        raise VaultLockError(f"Cannot read keyfile {p.name}: {e.strerror or e}") from None
    if size == 0:
        raise VaultLockError("The keyfile is empty.")
    return SecretBytes.take(bytearray(h.digest()))


def fingerprint(path: str | os.PathLike) -> str:
    """A short, non-reversible identifier so you can tell keyfiles apart, e.g. ``7F3A-91C2-BB04``."""
    with digest_keyfile(path) as d:
        raw = bytes(d)
    fp = hashlib.sha256(b"VaultLock keyfile fingerprint\x00" + raw).hexdigest()[:12].upper()
    return "-".join(fp[i : i + 4] for i in range(0, 12, 4))
