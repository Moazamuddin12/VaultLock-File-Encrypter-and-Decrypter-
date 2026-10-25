"""Streaming authenticated encryption / decryption (``EncryptWriter`` / ``DecryptReader``).

Both classes are plain file-like objects, which is what makes the rest of the
system composable: a ``tarfile`` can write *straight into* an ``EncryptWriter``
(folder vaults never touch the disk in plaintext), and a ``DecryptReader`` can
feed ``tarfile``, ``zlib`` or a simple ``shutil.copyfileobj``.

Memory use is O(chunk_size) regardless of file size: at most two chunks of
ciphertext plus one of plaintext are alive at any moment.
"""

from __future__ import annotations

import hmac
import io
import os
from typing import BinaryIO, Callable, Optional, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac as c_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .errors import AuthenticationError, CancelledError, FormatError, IntegrityError
from .format import (
    DEFAULT_CHUNK,
    FLAG_KEYFILE,
    HEADER_SIZE,
    META_SEALED_LEN,
    MAX_CHUNKS,
    MAX_CHUNK,
    MIN_CHUNK,
    NONCE_LEN,
    SALT_LEN,
    TAG_LEN,
    Cipher,
    Header,
    chunk_aad,
    chunk_nonce,
    decode_metadata,
    encode_metadata,
)
from .kdf import DerivedKeys, KdfParams, derive_keys
from .memory import SecretBytes, wipe, wipe_bytes, wipe_prefix

ProgressFn = Callable[[int], None]


class CancelToken(Protocol):
    def is_set(self) -> bool: ...


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_aead(cipher: Cipher, key: SecretBytes):
    view = key.view()
    if cipher == Cipher.AES_256_GCM:
        return AESGCM(view)
    if cipher == Cipher.CHACHA20_POLY1305:
        return ChaCha20Poly1305(view)
    raise FormatError("Unknown cipher.")  # pragma: no cover


def compute_check(mac_key: SecretBytes, prefix: bytes) -> bytes:
    """Key-check value: HMAC-SHA256 over the first 68 header bytes."""
    h = c_hmac.HMAC(mac_key.view(), hashes.SHA256())
    h.update(prefix)
    return h.finalize()


def _read_upto(src: BinaryIO, n: int) -> bytes:
    """Read exactly ``n`` bytes unless EOF intervenes (handles short reads)."""
    first = src.read(n)
    if first is None:
        first = b""
    if len(first) == n or not first:
        return first
    parts = [first]
    got = len(first)
    while got < n:
        more = src.read(n - got)
        if not more:
            break
        parts.append(more)
        got += len(more)
    return b"".join(parts)


def read_header(src: BinaryIO) -> Header:
    """Parse the plaintext header (no password needed)."""
    raw = _read_upto(src, HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        raise FormatError("File is too short to be a VaultLock container.")
    return Header.parse(raw)


def _check_cancel(cancel: Optional[CancelToken]) -> None:
    if cancel is not None and cancel.is_set():
        raise CancelledError("Cancelled.")


# ---------------------------------------------------------------------------
# Encrypt
# ---------------------------------------------------------------------------

class EncryptWriter(io.RawIOBase):
    """Write-only file object: plaintext in, ``.vault`` bytes out.

    The header and the encrypted metadata block are written immediately by the
    constructor.  Call :meth:`close` (or leave the ``with`` block normally) to
    seal the final chunk; if an exception escapes the block the writer is
    aborted and *no* final chunk is written, so the partial file can never be
    mistaken for a complete vault.
    """

    def __init__(
        self,
        dst: BinaryIO,
        *,
        secret: SecretBytes,
        cipher: Cipher,
        kdf: KdfParams,
        metadata: dict,
        uses_keyfile: bool = False,
        chunk_size: int = DEFAULT_CHUNK,
        cancel: Optional[CancelToken] = None,
        on_bytes: Optional[ProgressFn] = None,
    ):
        super().__init__()
        # Safe defaults first, so close()/__del__ work even if validation below raises.
        self._keys: DerivedKeys | None = None
        self._aead = None
        self._buf = bytearray()
        self._done = False
        if not (MIN_CHUNK <= chunk_size <= MAX_CHUNK):
            raise ValueError("chunk_size out of range")
        kdf.validate_secure()

        self._dst = dst
        self._cs = chunk_size
        self._cancel = cancel
        self._on_bytes = on_bytes
        self._index = 1  # chunk 0 is the metadata block
        self._bytes_in = 0
        self._bytes_out = 0

        salt = os.urandom(SALT_LEN)
        header = Header(
            cipher=cipher,
            kdf=kdf,
            flags=FLAG_KEYFILE if uses_keyfile else 0,
            chunk_size=chunk_size,
            salt=salt,
            nonce_base=os.urandom(NONCE_LEN),
        )
        self._keys = derive_keys(kdf, secret, salt)
        try:
            header = header.with_check(compute_check(self._keys.mac, header.prefix()))
            self._header = header
            self._hdr_bytes = header.pack()
            self._aead = make_aead(cipher, self._keys.enc)

            dst.write(self._hdr_bytes)
            meta = encode_metadata(metadata)
            try:
                self._write_sealed(0, meta, last=False)
            finally:
                wipe(meta)
            self._bytes_out += HEADER_SIZE
        except BaseException:
            self._release()
            raise

    # -- public ----------------------------------------------------------
    @property
    def header(self) -> Header:
        return self._header

    @property
    def bytes_in(self) -> int:
        return self._bytes_in

    @property
    def bytes_out(self) -> int:
        return self._bytes_out

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:  # type: ignore[override]
        if self._done or self.closed:
            raise ValueError("write to closed EncryptWriter")
        mv = memoryview(data).cast("B")
        n = len(mv)
        self._buf += mv
        # Strictly greater: the final chunk is always held back so that it can
        # be sealed with the "last" flag even when the data ends on a boundary.
        while len(self._buf) > self._cs:
            self._seal_from_buffer(self._cs, last=False)
        self._bytes_in += n
        if self._on_bytes:
            self._on_bytes(self._bytes_in)
        return n

    def close(self) -> None:
        if self.closed:
            return
        try:
            if not self._done and self._aead is not None:
                self._seal_from_buffer(len(self._buf), last=True)
                self._dst.flush()
                self._done = True
                if self._on_bytes:
                    self._on_bytes(self._bytes_in)
        finally:
            self._release()
            super().close()

    def abort(self) -> None:
        """Discard everything without writing a final chunk."""
        self._release()
        if not self.closed:
            super().close()

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.abort()
            return False
        self.close()
        return False

    # -- internals -------------------------------------------------------
    def _write_sealed(self, index: int, plaintext, last: bool) -> None:
        _check_cancel(self._cancel)
        sealed = self._aead.encrypt(
            chunk_nonce(self._header.nonce_base, index),
            plaintext,
            chunk_aad(self._hdr_bytes, index, last),
        )
        self._dst.write(sealed)
        self._bytes_out += len(sealed)

    def _seal_from_buffer(self, n: int, last: bool) -> None:
        if self._index >= MAX_CHUNKS:
            raise FormatError("Too many chunks.")
        mv = memoryview(self._buf)
        part = mv[:n]
        try:
            self._write_sealed(self._index, part, last)
        finally:
            part.release()
            mv.release()
        self._index += 1
        wipe_prefix(self._buf, n)  # scrub plaintext before dropping it
        del self._buf[:n]

    def _release(self) -> None:
        wipe(self._buf)
        self._buf = bytearray()
        if self._keys is not None:
            self._keys.wipe()
            self._keys = None
        self._aead = None


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------

class DecryptReader(io.RawIOBase):
    """Read-only file object: ``.vault`` bytes in, authenticated plaintext out.

    Construction derives the keys, verifies the key-check (-> immediate,
    precise "wrong password / keyfile" error) and decrypts the metadata block
    (available as ``.metadata``).  Each data chunk is authenticated *before*
    any of its plaintext is returned.  Truncation is only detectable once the
    final chunk is reached, so callers that write to disk must write to a
    temporary file and publish it only after EOF was read without error.
    """

    def __init__(
        self,
        src: BinaryIO,
        *,
        secret: SecretBytes,
        cancel: Optional[CancelToken] = None,
        on_bytes: Optional[ProgressFn] = None,
        header: Optional[Header] = None,
    ):
        super().__init__()
        self._src = src
        self._cancel = cancel
        self._on_bytes = on_bytes
        self._plain: bytes = b""
        self._pos = 0
        self._index = 1
        self._bytes_in = 0
        self._eof = False
        self._keys: DerivedKeys | None = None
        self._aead = None
        self._cur: Optional[bytes] = None

        try:
            if header is None:
                header = read_header(src)
                self._bytes_in = HEADER_SIZE
            else:  # caller already consumed the header
                self._bytes_in = HEADER_SIZE
            self._header = header
            self._hdr_bytes = header.pack()
            self._sealed_len = header.chunk_size + TAG_LEN

            self._keys = derive_keys(header.kdf, secret, header.salt)
            expected = compute_check(self._keys.mac, header.prefix())
            if not hmac.compare_digest(expected, header.check):
                raise AuthenticationError(
                    "Incorrect password or keyfile - or the vault header has been modified."
                )
            self._aead = make_aead(header.cipher, self._keys.enc)

            sealed_meta = _read_upto(src, META_SEALED_LEN)
            if len(sealed_meta) != META_SEALED_LEN:
                raise FormatError("Vault is truncated (metadata block missing).")
            self._bytes_in += len(sealed_meta)
            try:
                meta_plain = self._aead.decrypt(
                    chunk_nonce(header.nonce_base, 0), sealed_meta, chunk_aad(self._hdr_bytes, 0, False)
                )
            except InvalidTag:
                raise IntegrityError("Vault metadata failed authentication (file is corrupted).") from None
            try:
                self.metadata = decode_metadata(meta_plain)
            finally:
                wipe_bytes(meta_plain)

            self._cur = _read_upto(src, self._sealed_len)
            if not self._cur:
                raise IntegrityError("Vault is truncated (no data chunks).")
        except BaseException:
            self._release()
            raise

    # -- public ----------------------------------------------------------
    @property
    def header(self) -> Header:
        return self._header

    @property
    def bytes_in(self) -> int:
        """Ciphertext bytes consumed so far (for progress)."""
        return self._bytes_in

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:  # type: ignore[override]
        mv = memoryview(b).cast("B")
        want = len(mv)
        total = 0
        while total < want:
            if self._pos >= len(self._plain):
                wipe_bytes(self._plain)
                self._plain = b""
                self._pos = 0
                if not self._advance():
                    break
            take = min(want - total, len(self._plain) - self._pos)
            mv[total : total + take] = memoryview(self._plain)[self._pos : self._pos + take]
            self._pos += take
            total += take
        return total

    def close(self) -> None:
        if not self.closed:
            wipe_bytes(self._plain)
            self._plain = b""
            self._release()
        super().close()

    # -- internals -------------------------------------------------------
    def _advance(self) -> bool:
        """Authenticate + decrypt the next chunk.  False at clean EOF."""
        if self._eof or self._cur is None:
            return False
        _check_cancel(self._cancel)

        cur = self._cur
        nxt = _read_upto(self._src, self._sealed_len)
        last = len(nxt) == 0
        self._bytes_in += len(nxt)

        if len(cur) < TAG_LEN:
            raise IntegrityError("Vault is truncated (incomplete final chunk).")
        try:
            plain = self._aead.decrypt(
                chunk_nonce(self._header.nonce_base, self._index),
                cur,
                chunk_aad(self._hdr_bytes, self._index, last),
            )
        except InvalidTag:
            if last:
                msg = "Integrity check failed: the end of the vault was cut off or extra data was appended. It is corrupted or has been tampered with."
            else:
                msg = f"Integrity check failed at data block {self._index}: the vault is corrupted or has been tampered with."
            raise IntegrityError(msg) from None

        self._index += 1
        self._plain = plain
        self._pos = 0
        if last:
            self._cur = None
            self._eof = True
        else:
            self._cur = nxt
        if self._on_bytes:
            self._on_bytes(self._bytes_in)
        return True

    def _release(self) -> None:
        if self._keys is not None:
            self._keys.wipe()
            self._keys = None
        self._aead = None
        self._cur = None
