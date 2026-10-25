"""The ``.vault`` container format, version 1.  Byte-level spec: docs/FORMAT.md.

::

    +-----------------------------+  offset 0
    | Header                100 B |  magic, version, cipher, kdf, flags, chunk size,
    |                             |  KDF params, salt(32), nonce base(12), key-check(32)
    +-----------------------------+  offset 100
    | Metadata chunk      4112 B  |  AEAD(4096 B padded JSON) + 16 B tag   (chunk #0)
    +-----------------------------+  offset 4212
    | Data chunk #1               |  AEAD(<= chunk_size plaintext) + 16 B tag
    | Data chunk #2               |
    | ...                         |
    | Data chunk #N  (final)      |  authenticated with the "last chunk" bit set
    +-----------------------------+

Every chunk is sealed independently (STREAM construction, Hoang et al. 2015):
the nonce encodes the chunk index and the AAD binds the *whole header*, the
index and a final-chunk flag.  Consequences: chunks cannot be reordered,
dropped, duplicated or truncated, and the header cannot be altered, without
the very next authentication check failing.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

from .errors import FormatError, UnsupportedVersionError
from .kdf import KdfId, KdfParams

MAGIC = b"VLCK"
VERSION = 1

HEADER_SIZE = 100
PREFIX_SIZE = 68          # bytes covered by the key-check MAC
CHECK_LEN = 32
SALT_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16

META_PLAIN_LEN = 4096     # fixed so the file name length is not leaked
META_SEALED_LEN = META_PLAIN_LEN + TAG_LEN

MIN_CHUNK = 4 * 1024
MAX_CHUNK = 16 * 1024 * 1024
DEFAULT_CHUNK = 1024 * 1024
MAX_CHUNKS = 2 ** 40      # nonce counter headroom (>1 EB at the smallest chunk size)

_HEADER_STRUCT = struct.Struct(">4sBBBBIIIB3x32s12s")
assert _HEADER_STRUCT.size == PREFIX_SIZE


class Cipher(IntEnum):
    AES_256_GCM = 1
    CHACHA20_POLY1305 = 2

    @property
    def label(self) -> str:
        return {1: "AES-256-GCM", 2: "ChaCha20-Poly1305"}[int(self)]


CIPHER_BY_NAME = {"aes-256-gcm": Cipher.AES_256_GCM, "chacha20-poly1305": Cipher.CHACHA20_POLY1305}

FLAG_KEYFILE = 0x01
_KNOWN_FLAGS = FLAG_KEYFILE


@dataclass(frozen=True)
class Header:
    cipher: Cipher
    kdf: KdfParams
    flags: int
    chunk_size: int
    salt: bytes
    nonce_base: bytes
    check: bytes = bytes(CHECK_LEN)
    version: int = VERSION

    @property
    def uses_keyfile(self) -> bool:
        return bool(self.flags & FLAG_KEYFILE)

    # -- (de)serialisation ------------------------------------------------
    def prefix(self) -> bytes:
        """The first 68 bytes (everything the key-check MAC covers)."""
        return _HEADER_STRUCT.pack(
            MAGIC,
            self.version,
            int(self.cipher),
            int(self.kdf.kdf),
            self.flags,
            self.chunk_size,
            self.kdf.a,
            self.kdf.b,
            self.kdf.c,
            self.salt,
            self.nonce_base,
        )

    def pack(self) -> bytes:
        if len(self.check) != CHECK_LEN:
            raise ValueError("key-check must be 32 bytes")
        return self.prefix() + self.check

    def with_check(self, check: bytes) -> "Header":
        return replace(self, check=bytes(check))

    @classmethod
    def parse(cls, raw: bytes) -> "Header":
        if len(raw) < HEADER_SIZE:
            raise FormatError("File is too short to be a VaultLock container.")
        raw = bytes(raw[:HEADER_SIZE])
        (magic, version, cipher_id, kdf_id, flags, chunk_size, a, b, c, salt, nonce_base) = _HEADER_STRUCT.unpack(
            raw[:PREFIX_SIZE]
        )
        if magic != MAGIC:
            raise FormatError("Not a VaultLock container (bad magic bytes).")
        if version != VERSION:
            raise UnsupportedVersionError(f"Unsupported vault version {version}; this build understands v{VERSION}.")
        if raw[21:24] != b"\x00\x00\x00":
            raise UnsupportedVersionError("Vault uses reserved header fields from a newer version.")
        if flags & ~_KNOWN_FLAGS:
            raise UnsupportedVersionError("Vault uses features from a newer version of VaultLock.")
        try:
            cipher = Cipher(cipher_id)
            kdf = KdfId(kdf_id)
        except ValueError:
            raise UnsupportedVersionError("Vault uses an unknown cipher or KDF.") from None
        if not (MIN_CHUNK <= chunk_size <= MAX_CHUNK):
            raise FormatError("Corrupt header: invalid chunk size.")
        params = KdfParams(kdf, a, b, c)
        params.validate_bounds()
        return cls(cipher, params, flags, chunk_size, salt, nonce_base, raw[PREFIX_SIZE:HEADER_SIZE], version)


# ---------------------------------------------------------------------------
# Per-chunk nonce / AAD
# ---------------------------------------------------------------------------

def chunk_nonce(nonce_base: bytes, index: int) -> bytes:
    """``base XOR index`` as 96-bit big-endian (the TLS 1.3 construction)."""
    if index >= MAX_CHUNKS:
        raise FormatError("Too many chunks.")
    return (int.from_bytes(nonce_base, "big") ^ index).to_bytes(NONCE_LEN, "big")


def chunk_aad(header_bytes: bytes, index: int, last: bool) -> bytes:
    """Bind header, position and finality into every chunk's authentication tag."""
    return header_bytes + struct.pack(">QB", index, 1 if last else 0)


# ---------------------------------------------------------------------------
# Metadata block (encrypted, fixed 4096 bytes)
# ---------------------------------------------------------------------------

def encode_metadata(meta: dict[str, Any]) -> bytearray:
    body = json.dumps(meta, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > META_PLAIN_LEN - 2:
        raise FormatError("Metadata too large (file name too long?).")
    out = bytearray(META_PLAIN_LEN)
    out[0:2] = struct.pack(">H", len(body))
    out[2 : 2 + len(body)] = body
    return out


def decode_metadata(block: bytes | bytearray) -> dict[str, Any]:
    (n,) = struct.unpack(">H", block[:2])
    if n > META_PLAIN_LEN - 2:
        raise FormatError("Corrupt metadata block.")
    try:
        meta = json.loads(bytes(block[2 : 2 + n]).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise FormatError("Corrupt metadata block.") from None
    if not isinstance(meta, dict):
        raise FormatError("Corrupt metadata block.")
    return meta


def make_metadata(
    *,
    name: str,
    kind: str,
    size: int,
    mtime: float | None,
    mode: int | None,
    compress: bool,
    entries: int = 1,
    app: str = "",
) -> dict[str, Any]:
    return {
        "v": 1,
        "name": name,
        "kind": kind,  # "file" | "dir" | "bundle"
        "size": int(size),
        "entries": int(entries),
        "mtime": mtime,
        "mode": mode,
        "compress": "zlib" if compress else "none",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "app": app,
    }
