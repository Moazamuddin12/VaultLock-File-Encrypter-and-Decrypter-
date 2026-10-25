"""High-level operations built from the streaming primitives.

    encrypt()        file / folder / bundle  ->  .vault
    decrypt()        .vault                  ->  file / folder
    verify()         authenticate every byte of a vault without writing anything
    read_in_memory() decrypt into RAM only (secure viewer)
    list_entries()   list the contents of a folder vault (RAM only)
    inspect()        read the public header (no password needed)

All writers use the same safety pattern: write to a hidden ``.partial`` sibling,
fsync, and only then atomically publish under the final name.  A crash,
cancel, wrong password or tampered vault therefore never leaves a half-written
file behind under a real name, and never overwrites an existing file unless
asked to.
"""

from __future__ import annotations

import io
import math
import os
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from .. import __version__
from . import archive, kdf as kdfmod
from .errors import (
    FormatError,
    IntegrityError,
    MissingCredentialError,
    NotPreviewableError,
    TooLargeError,
    VaultLockError,
)
from .format import (
    DEFAULT_CHUNK,
    HEADER_SIZE,
    META_SEALED_LEN,
    TAG_LEN,
    Cipher,
    Header,
    make_metadata,
)
from .fsutil import open_exclusive, partial_path, publish, remove_quietly, safe_filename, unique_path
from .keyfile import digest_keyfile
from .kdf import KdfParams, build_secret
from .memory import SecretBytes, wipe
from .stream import CancelToken, DecryptReader, EncryptWriter, ProgressFn, read_header

IO_BLOCK = 1024 * 1024
VAULT_EXT = ".vault"


# ---------------------------------------------------------------------------
# credentials
# ---------------------------------------------------------------------------

@dataclass
class Credentials:
    """What the user typed / chose: a password and optionally a keyfile path."""

    password: Optional[str]
    keyfile: Optional[str] = None

    def for_encrypt(self) -> tuple[SecretBytes, bool]:
        kf = digest_keyfile(self.keyfile) if self.keyfile else None
        try:
            return build_secret(self.password, kf), kf is not None
        finally:
            if kf is not None:
                kf.wipe()

    def for_decrypt(self, header: Header) -> SecretBytes:
        if header.uses_keyfile and not self.keyfile:
            raise MissingCredentialError("This vault was locked with a keyfile - please select it.")
        kf = digest_keyfile(self.keyfile) if (header.uses_keyfile and self.keyfile) else None
        try:
            return build_secret(self.password, kf)
        finally:
            if kf is not None:
                kf.wipe()


# ---------------------------------------------------------------------------
# optional compression layer (sits *inside* the encryption)
# ---------------------------------------------------------------------------

class _ZlibWriter(io.RawIOBase):
    def __init__(self, sink, on_bytes: Optional[ProgressFn] = None, level: int = 6):
        super().__init__()
        self._sink = sink
        self._c = zlib.compressobj(level)
        self._on = on_bytes
        self._n = 0

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:  # type: ignore[override]
        mv = memoryview(data).cast("B")
        out = self._c.compress(mv)
        if out:
            self._sink.write(out)
        self._n += len(mv)
        if self._on:
            self._on(self._n)
        return len(mv)

    def finish(self) -> None:
        out = self._c.flush()
        if out:
            self._sink.write(out)


class _ZlibReader(io.RawIOBase):
    _IN = 64 * 1024
    _OUT = 4 * 1024 * 1024

    def __init__(self, src):
        super().__init__()
        self._src = src
        self._d = zlib.decompressobj()
        self._pending = b""
        self._pos = 0
        self._tail = b""
        self._done = False

    def readable(self) -> bool:
        return True

    def _refill(self) -> bool:
        while True:
            if self._done:
                return False
            data = self._tail
            if not data:
                data = self._src.read(self._IN)
                if not data:
                    try:
                        out = self._d.flush()
                    except zlib.error as e:
                        raise IntegrityError(f"Corrupt compressed stream ({e}).") from None
                    self._done = True
                    self._pending, self._pos = out, 0
                    return bool(out)
            try:
                out = self._d.decompress(data, self._OUT)
            except zlib.error as e:
                raise IntegrityError(f"Corrupt compressed stream ({e}).") from None
            self._tail = self._d.unconsumed_tail
            if self._d.eof:
                self._done = True
            if out:
                self._pending, self._pos = out, 0
                return True
            if self._done:
                return False

    def readinto(self, b) -> int:  # type: ignore[override]
        mv = memoryview(b).cast("B")
        want, total = len(mv), 0
        while total < want:
            if self._pos >= len(self._pending):
                if not self._refill():
                    break
            take = min(want - total, len(self._pending) - self._pos)
            mv[total : total + take] = memoryview(self._pending)[self._pos : self._pos + take]
            self._pos += take
            total += take
        return total


def _drain(f) -> int:
    """Read to EOF, discarding data.  Forces the final AEAD chunk to be verified."""
    buf = bytearray(IO_BLOCK)
    n = 0
    try:
        while True:
            got = f.readinto(buf)
            if not got:
                return n
            n += got
    finally:
        wipe(buf)


# ---------------------------------------------------------------------------
# encrypt
# ---------------------------------------------------------------------------

@dataclass
class EncryptReport:
    output: Path
    kind: str
    name: str
    bytes_in: int
    bytes_out: int
    entries: int
    skipped: list[str] = field(default_factory=list)
    header: Optional[Header] = None


def plan_encrypt(sources: Sequence[Path | str], cancel: Optional[CancelToken] = None):
    """Classify the sources and pre-compute sizes (also used for progress totals)."""
    srcs = [Path(s) for s in sources]
    if not srcs:
        raise VaultLockError("Nothing to encrypt.")
    for s in srcs:
        if not os.path.lexists(s):
            raise VaultLockError(f"'{s.name}' does not exist.")
    if len(srcs) == 1 and srcs[0].is_file():
        st = srcs[0].stat()
        return srcs, "file", None, st.st_size, st.st_size
    col = archive.collect(srcs, cancel)
    if not col.entries:
        raise VaultLockError("There is nothing readable to encrypt here.")
    kind = "dir" if (len(srcs) == 1 and srcs[0].is_dir()) else "bundle"
    return srcs, kind, col, col.total_size, col.tar_estimate


def default_vault_name(sources: Sequence[Path | str], obfuscate: bool = False, bundle_name: str | None = None) -> str:
    if obfuscate:
        return f"vault-{os.urandom(5).hex()}{VAULT_EXT}"
    srcs = [Path(s) for s in sources]
    if len(srcs) == 1:
        return safe_filename(srcs[0].name, "vault") + VAULT_EXT
    return safe_filename(bundle_name or "Bundle", "Bundle") + VAULT_EXT


def encrypt(
    sources: Sequence[Path | str],
    dest: Path | str,
    creds: Credentials,
    *,
    cipher: Cipher = Cipher.AES_256_GCM,
    kdf: Optional[KdfParams] = None,
    chunk_size: int = DEFAULT_CHUNK,
    compress: bool = False,
    bundle_name: Optional[str] = None,
    overwrite: bool = False,
    on_bytes: Optional[ProgressFn] = None,
    cancel: Optional[CancelToken] = None,
    plan=None,
) -> EncryptReport:
    """Encrypt one file, one folder, or several items into a single ``.vault``.

    ``on_bytes(n)`` is called with the cumulative number of *plaintext* bytes
    consumed (tar framing included for folders; see ``plan_encrypt`` for the
    matching total).
    """
    srcs, kind, col, size, _total = plan or plan_encrypt(sources, cancel)
    dest = Path(dest)
    kdf = kdf or kdfmod.preset(kdfmod.DEFAULT_PRESET)
    kdf.validate_secure()

    if kind == "file":
        st = srcs[0].stat()
        name, mtime, mode, entries = srcs[0].name, st.st_mtime, st.st_mode & 0o777, 1
    else:
        name = srcs[0].name if kind == "dir" else (bundle_name or "Bundle")
        mtime = mode = None
        entries = col.files + col.dirs
    meta = make_metadata(
        name=name, kind=kind, size=size, mtime=mtime, mode=mode, compress=compress, entries=entries,
        app=f"VaultLock {__version__}",
    )

    secret, uses_kf = creds.for_encrypt()
    tmp = partial_path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open_exclusive(tmp) as out:
            writer = EncryptWriter(
                out,
                secret=secret,
                cipher=cipher,
                kdf=kdf,
                metadata=meta,
                uses_keyfile=uses_kf,
                chunk_size=chunk_size,
                cancel=cancel,
                on_bytes=None if compress else on_bytes,
            )
            secret.wipe()  # the derived keys live in the writer now
            with writer:
                sink = _ZlibWriter(writer, on_bytes) if compress else writer
                if kind == "file":
                    buf = bytearray(min(chunk_size, IO_BLOCK))
                    view = memoryview(buf)
                    try:
                        with open(srcs[0], "rb") as fh:
                            while True:
                                n = fh.readinto(buf)
                                if not n:
                                    break
                                sink.write(view[:n])
                    finally:
                        view.release()
                        wipe(buf)
                else:
                    archive.pack(col, sink, cancel)
                if compress:
                    sink.finish()  # type: ignore[union-attr]
            out.flush()
            os.fsync(out.fileno())
            report = EncryptReport(
                output=dest, kind=kind, name=name, bytes_in=writer.bytes_in, bytes_out=writer.bytes_out,
                entries=entries, skipped=list(col.skipped) if col else [], header=writer.header,
            )
        publish(tmp, dest, overwrite)
        return report
    except BaseException:
        remove_quietly(tmp)
        raise
    finally:
        secret.wipe()


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------

@dataclass
class DecryptReport:
    output: Path
    kind: str
    name: str
    bytes_out: int
    entries: int
    metadata: dict = field(default_factory=dict)


def _open_reader(fh, creds: Credentials, cancel, on_bytes) -> DecryptReader:
    header = read_header(fh)
    secret = creds.for_decrypt(header)
    try:
        return DecryptReader(fh, secret=secret, cancel=cancel, on_bytes=on_bytes, header=header)
    finally:
        secret.wipe()


def decrypt(
    src: Path | str,
    dest_dir: Path | str,
    creds: Credentials,
    *,
    overwrite: bool = False,
    on_bytes: Optional[ProgressFn] = None,
    cancel: Optional[CancelToken] = None,
) -> DecryptReport:
    src, dest_dir = Path(src), Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as fh:
        with _open_reader(fh, creds, cancel, on_bytes) as reader:
            meta = reader.metadata
            kind = str(meta.get("kind", "file"))
            name = safe_filename(str(meta.get("name") or src.stem), fallback=src.stem or "restored")
            stream = _ZlibReader(reader) if meta.get("compress") == "zlib" else reader
            if kind == "file":
                return _extract_file(stream, reader, dest_dir, name, meta, overwrite)
            if kind in ("dir", "bundle"):
                return _extract_tree(stream, reader, dest_dir, name, kind, meta, cancel)
            raise FormatError(f"Unknown vault content type '{kind}'.")


def _extract_file(stream, reader, dest_dir: Path, name: str, meta: dict, overwrite: bool) -> DecryptReport:
    target = (dest_dir / name) if overwrite and not (dest_dir / name).is_dir() else unique_path(dest_dir, name)
    tmp = partial_path(target)
    total = 0
    try:
        with open_exclusive(tmp) as out:
            buf = bytearray(IO_BLOCK)
            view = memoryview(buf)
            try:
                while True:
                    n = stream.readinto(buf)
                    if not n:
                        break
                    out.write(view[:n])
                    total += n
            finally:
                view.release()
                wipe(buf)
            _drain(reader)  # make sure the *final* chunk was authenticated too
            out.flush()
            os.fsync(out.fileno())
        mtime, mode = meta.get("mtime"), meta.get("mode")
        if isinstance(mode, int):
            try:
                os.chmod(tmp, mode & 0o777 | 0o600)
            except OSError:
                pass
        if isinstance(mtime, (int, float)):
            try:
                os.utime(tmp, (mtime, mtime))
            except OSError:
                pass
        publish(tmp, target, overwrite)
    except BaseException:
        remove_quietly(tmp)
        raise
    return DecryptReport(target, "file", name, total, 1, meta)


def _extract_tree(stream, reader, dest_dir: Path, name: str, kind: str, meta: dict, cancel) -> DecryptReport:
    target = unique_path(dest_dir, name)
    tmpdir = target.with_name(f".{target.name}.{os.urandom(6).hex()}.partial")
    tmpdir.mkdir(mode=0o700)
    try:
        count = archive.unpack(stream, tmpdir, cancel)
        _drain(stream)  # tar stops at its end marker; this authenticates everything after it
        _drain(reader)
        children = list(tmpdir.iterdir())
        if kind == "dir" and len(children) == 1 and children[0].is_dir():
            os.rename(children[0], target)
            tmpdir.rmdir()
        else:
            os.rename(tmpdir, target)
    except BaseException:
        remove_quietly(tmpdir)
        raise
    return DecryptReport(target, kind, name, int(meta.get("size", 0) or 0), count, meta)


# ---------------------------------------------------------------------------
# verify / inspect / in-memory access
# ---------------------------------------------------------------------------

def verify(
    path: Path | str,
    creds: Credentials,
    *,
    on_bytes: Optional[ProgressFn] = None,
    cancel: Optional[CancelToken] = None,
) -> dict:
    """Authenticate every chunk of a vault without writing anything.  Returns its metadata."""
    with open(path, "rb") as fh:
        with _open_reader(fh, creds, cancel, on_bytes) as reader:
            _drain(reader)
            return reader.metadata


def inspect(path: Path | str) -> dict:
    """Describe a vault from its public header alone (no password required)."""
    p = Path(path)
    size = p.stat().st_size
    with open(p, "rb") as fh:
        header = read_header(fh)
    body = max(size - HEADER_SIZE - META_SEALED_LEN, 0)
    per = header.chunk_size + TAG_LEN
    return {
        "version": header.version,
        "cipher": header.cipher.label,
        "kdf": header.kdf.kdf.name.lower(),
        "kdf_description": header.kdf.describe(),
        "kdf_weak": header.kdf.is_weak,
        "uses_keyfile": header.uses_keyfile,
        "chunk_size": header.chunk_size,
        "chunks": max(math.ceil(body / per), 1) if body else 0,
        "file_size": size,
        "overhead": HEADER_SIZE + META_SEALED_LEN + (math.ceil(body / per) * TAG_LEN if body else 0),
        "salt": header.salt.hex(),
        "nonce": header.nonce_base.hex(),
        "check": header.check.hex(),
    }


_PREVIEW_MIME_PREFIXES = ("image/", "text/", "audio/", "video/")
_PREVIEW_MIME_EXACT = {"application/pdf", "application/json", "application/xml", "application/javascript"}
_EXTRA_TEXT_EXT = {
    ".md", ".log", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".py", ".js", ".ts", ".tsx", ".jsx",
    ".rs", ".go", ".java", ".c", ".h", ".cpp", ".hpp", ".cs", ".sh", ".bat", ".ps1", ".sql", ".csv", ".tsv",
    ".env", ".gitignore", ".rb", ".php", ".kt", ".swift", ".lua", ".r", ".tex", ".rst",
}


def preview_kind(filename: str) -> tuple[Optional[str], str]:
    """Classify ``filename`` for the viewer -> (category, mime).  category is None if unsupported."""
    import mimetypes

    mime, _ = mimetypes.guess_type(filename)
    ext = Path(filename).suffix.lower()
    mime = mime or ("text/plain" if ext in _EXTRA_TEXT_EXT else "application/octet-stream")
    if ext in _EXTRA_TEXT_EXT or mime.startswith("text/") or mime in {"application/json", "application/xml", "application/javascript"}:
        if mime == "text/html":
            return "text", "text/plain"  # never render attacker-controlled HTML
        return "text", "text/plain; charset=utf-8"
    if mime == "image/svg+xml":
        return "image", mime
    if mime.startswith("image/") and mime in {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "image/avif"}:
        return "image", mime
    if mime == "application/pdf":
        return "pdf", mime
    if mime.startswith("audio/"):
        return "audio", mime
    if mime.startswith("video/"):
        return "video", mime
    return None, mime


def read_in_memory(
    path: Path | str,
    creds: Credentials,
    *,
    max_bytes: int,
    entry: Optional[str] = None,
    cancel: Optional[CancelToken] = None,
) -> tuple[dict, str, bytearray]:
    """Decrypt a single file (or one entry of a folder vault) into RAM only.

    Returns ``(vault_metadata, file_name, data)``.  The caller owns ``data``
    and should ``wipe()`` it when done.  Nothing is written to disk.
    """
    with open(path, "rb") as fh:
        with _open_reader(fh, creds, cancel, None) as reader:
            meta = reader.metadata
            stream = _ZlibReader(reader) if meta.get("compress") == "zlib" else reader
            kind = str(meta.get("kind", "file"))
            if kind == "file":
                fname = str(meta.get("name") or "file")
                if int(meta.get("size", 0) or 0) > max_bytes:
                    raise TooLargeError(f"This file is larger than the {max_bytes // (1024 * 1024)} MB in-memory preview limit.")
                return meta, fname, _read_capped(stream, max_bytes)

            if not entry:
                raise VaultLockError("Choose a file inside the vault to preview.")
            for member, tf in archive.iter_members(stream):
                if member.name == entry:
                    if not member.isreg():
                        raise NotPreviewableError("That entry is a folder.")
                    if member.size > max_bytes:
                        raise TooLargeError(f"This file is larger than the {max_bytes // (1024 * 1024)} MB in-memory preview limit.")
                    fobj = tf.extractfile(member)
                    return meta, member.name.rsplit("/", 1)[-1], _read_capped(fobj, max_bytes)
            raise VaultLockError("That file is not inside the vault.")


def _read_capped(f, max_bytes: int) -> bytearray:
    out = bytearray()
    buf = bytearray(IO_BLOCK)
    view = memoryview(buf)
    try:
        while True:
            n = f.readinto(buf) if hasattr(f, "readinto") else _readinto_fallback(f, buf)
            if not n:
                break
            if len(out) + n > max_bytes:
                wipe(out)
                raise TooLargeError(f"This file is larger than the {max_bytes // (1024 * 1024)} MB in-memory preview limit.")
            out += view[:n]
    finally:
        view.release()
        wipe(buf)
    return out


def _readinto_fallback(f, buf: bytearray) -> int:
    chunk = f.read(len(buf))
    buf[: len(chunk)] = chunk
    return len(chunk)


def list_entries(path: Path | str, creds: Credentials, *, cancel: Optional[CancelToken] = None) -> dict:
    """List a folder/bundle vault's contents without extracting anything."""
    with open(path, "rb") as fh:
        with _open_reader(fh, creds, cancel, None) as reader:
            meta = reader.metadata
            kind = str(meta.get("kind", "file"))
            if kind == "file":
                return {"meta": meta, "entries": [{"name": meta.get("name"), "size": meta.get("size", 0), "dir": False}]}
            stream = _ZlibReader(reader) if meta.get("compress") == "zlib" else reader
            entries = []
            for member, _tf in archive.iter_members(stream):
                entries.append({"name": member.name.rstrip("/"), "size": member.size if member.isreg() else 0, "dir": member.isdir()})
            _drain(stream)
            _drain(reader)
            return {"meta": meta, "entries": entries}


# ---------------------------------------------------------------------------
# rekey: change password / keyfile / cipher / KDF without touching plaintext on disk
# ---------------------------------------------------------------------------

def rekey(
    src: Path | str,
    dest: Path | str,
    old: Credentials,
    new: Credentials,
    *,
    cipher: Optional[Cipher] = None,
    kdf: Optional[KdfParams] = None,
    overwrite: bool = False,
    on_bytes: Optional[ProgressFn] = None,
    cancel: Optional[CancelToken] = None,
) -> EncryptReport:
    """Re-seal a vault under new credentials.

    Data flows reader -> writer in memory, one chunk at a time; the plaintext
    never touches the disk.  The inner stream (including any zlib layer) is
    copied verbatim, so the content and metadata are bit-for-bit preserved.
    Fresh salt and nonce are generated, so the new vault shares no key
    material with the old one.  The source is never modified.
    """
    src, dest = Path(src), Path(dest)
    if src.resolve() == dest.resolve():
        raise VaultLockError("Choose a different file name for the re-keyed vault.")
    kdf = kdf or kdfmod.preset(kdfmod.DEFAULT_PRESET)
    kdf.validate_secure()
    secret, uses_kf = new.for_encrypt()
    tmp = partial_path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(src, "rb") as fh, _open_reader(fh, old, cancel, on_bytes) as reader:
            with open_exclusive(tmp) as out:
                writer = EncryptWriter(
                    out, secret=secret, cipher=cipher or reader.header.cipher, kdf=kdf,
                    metadata=reader.metadata, uses_keyfile=uses_kf,
                    chunk_size=reader.header.chunk_size, cancel=cancel,
                )
                secret.wipe()
                with writer:
                    buf = bytearray(IO_BLOCK)
                    view = memoryview(buf)
                    try:
                        while True:
                            n = reader.readinto(buf)
                            if not n:
                                break
                            writer.write(view[:n])
                    finally:
                        view.release()
                        wipe(buf)
                out.flush()
                os.fsync(out.fileno())
                report = EncryptReport(
                    output=dest, kind=str(reader.metadata.get("kind", "file")), name=str(reader.metadata.get("name", "")),
                    bytes_in=writer.bytes_in, bytes_out=writer.bytes_out,
                    entries=int(reader.metadata.get("entries", 1) or 1), header=writer.header,
                )
        publish(tmp, dest, overwrite)
        return report
    except BaseException:
        remove_quietly(tmp)
        raise
    finally:
        secret.wipe()
