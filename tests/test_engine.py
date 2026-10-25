"""File / folder / bundle operations, atomicity and archive safety."""

import io
import os
import tarfile
from pathlib import Path

import pytest

from vaultlock.core import engine as E
from vaultlock.core import archive
from vaultlock.core.errors import ArchiveError, AuthenticationError, IntegrityError, OutputExistsError, TooLargeError
from vaultlock.core.format import Cipher
from vaultlock.core.fsutil import safe_filename

C = E.Credentials("correct horse battery staple")


def tree_map(root: Path):
    return {p.relative_to(root).as_posix(): (p.read_bytes() if p.is_file() else None) for p in sorted(root.rglob("*"))}


@pytest.mark.parametrize("compress", [False, True])
@pytest.mark.parametrize("cipher", list(Cipher))
def test_file_roundtrip_preserves_name_mtime(sample, tmp_path, fast, compress, cipher):
    os.utime(sample, (1_600_000_000, 1_600_000_000))
    r = E.encrypt([sample], tmp_path / "out" / "s.vault", C, kdf=fast, compress=compress, cipher=cipher, chunk_size=65536)
    d = E.decrypt(r.output, tmp_path / "back", C)
    assert d.output.name == "sample.bin" and d.output.read_bytes() == sample.read_bytes()
    assert int(d.output.stat().st_mtime) == 1_600_000_000


@pytest.mark.parametrize("compress", [False, True])
def test_folder_roundtrip(tree, tmp_path, fast, compress):
    r = E.encrypt([tree], tmp_path / "t.vault", C, kdf=fast, compress=compress)
    assert r.kind == "dir"
    d = E.decrypt(r.output, tmp_path / "back", C)
    assert tree_map(d.output) == tree_map(tree)  # includes the empty directory


def test_bundle_of_mixed_items(sample, tree, tmp_path, fast):
    r = E.encrypt([sample, tree], tmp_path / "b.vault", C, kdf=fast, bundle_name="Stuff")
    d = E.decrypt(r.output, tmp_path / "back", C)
    assert d.kind == "bundle" and d.output.name == "Stuff"
    assert (d.output / "sample.bin").read_bytes() == sample.read_bytes()
    assert (d.output / "proj" / "a.txt").exists()


def test_symlinks_are_skipped_not_followed(tree, tmp_path, fast):
    outside = tmp_path / "outside.txt"; outside.write_text("must not leak")
    os.symlink(outside, tree / "leak")
    os.symlink(tmp_path, tree / "dirleak")
    r = E.encrypt([tree], tmp_path / "t.vault", C, kdf=fast)
    assert len(r.skipped) == 2
    d = E.decrypt(r.output, tmp_path / "back", C)
    assert not (d.output / "leak").exists() and not (d.output / "dirleak").exists()


def test_wrong_password_leaves_nothing_behind(sample, tmp_path, fast):
    r = E.encrypt([sample], tmp_path / "s.vault", C, kdf=fast)
    with pytest.raises(AuthenticationError):
        E.decrypt(r.output, tmp_path / "back", E.Credentials("nope"))
    assert not list((tmp_path / "back").glob("*"))


def test_tampered_vault_never_publishes_partial_output(sample, tmp_path, fast):
    r = E.encrypt([sample], tmp_path / "s.vault", C, kdf=fast, chunk_size=4096)
    raw = bytearray(r.output.read_bytes()); raw[-50] ^= 1
    r.output.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        E.decrypt(r.output, tmp_path / "back", C)
    assert [p.name for p in (tmp_path / "back").iterdir()] == []   # no output, no .partial leftovers


def test_truncated_vault_never_publishes_partial_output(sample, tmp_path, fast):
    r = E.encrypt([sample], tmp_path / "s.vault", C, kdf=fast, chunk_size=4096)
    r.output.write_bytes(r.output.read_bytes()[:-(4096 + 16)])
    with pytest.raises(IntegrityError):
        E.decrypt(r.output, tmp_path / "back", C)
    assert [p.name for p in (tmp_path / "back").iterdir()] == []


def test_never_overwrites_existing_output(sample, tmp_path, fast):
    dest = tmp_path / "s.vault"; dest.write_text("precious")
    with pytest.raises(OutputExistsError):
        E.encrypt([sample], dest, C, kdf=fast)
    assert dest.read_text() == "precious"
    r = E.encrypt([sample], dest, C, kdf=fast, overwrite=True)
    assert r.output.stat().st_size > 100
    d1 = E.decrypt(r.output, tmp_path / "back", C); d2 = E.decrypt(r.output, tmp_path / "back", C)
    assert d1.output != d2.output  # second unlock gets "sample (1).bin"


def test_failed_encrypt_cleans_up(sample, tmp_path, fast):
    class Boom(Exception): ...
    def bad(n): raise Boom()
    with pytest.raises(Boom):
        E.encrypt([sample], tmp_path / "o" / "s.vault", C, kdf=fast, on_bytes=bad, chunk_size=4096)
    assert list((tmp_path / "o").iterdir()) == []


def test_inspect_needs_no_password(sample, tmp_path, fast):
    r = E.encrypt([sample], tmp_path / "s.vault", C, kdf=fast, cipher=Cipher.CHACHA20_POLY1305)
    info = E.inspect(r.output)
    assert info["cipher"] == "ChaCha20-Poly1305" and not info["uses_keyfile"] and info["chunks"] >= 1


def test_verify_detects_damage(sample, tmp_path, fast):
    r = E.encrypt([sample], tmp_path / "s.vault", C, kdf=fast, chunk_size=4096)
    assert E.verify(r.output, C)["name"] == "sample.bin"
    raw = bytearray(r.output.read_bytes()); raw[len(raw) // 2] ^= 1; r.output.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        E.verify(r.output, C)


def test_in_memory_preview_writes_nothing(tree, tmp_path, fast):
    before = {p for p in tmp_path.rglob("*")}
    r = E.encrypt([tree], tmp_path / "t.vault", C, kdf=fast)
    listing = E.list_entries(r.output, C)
    assert any(e["name"] == "proj/a.txt" for e in listing["entries"])
    meta, name, data = E.read_in_memory(r.output, C, max_bytes=10**7, entry="proj/a.txt")
    assert name == "a.txt" and bytes(data) == b"hello\n" * 500
    after = {p for p in tmp_path.rglob("*")} - before
    assert after == {r.output}   # nothing but the vault itself touched the disk
    with pytest.raises(TooLargeError):
        E.read_in_memory(r.output, C, max_bytes=100, entry="proj/sub/b.bin")


def test_preview_classification_never_renders_html():
    assert E.preview_kind("x.html")[0] == "text" and E.preview_kind("x.html")[1] == "text/plain"
    assert E.preview_kind("x.svg")[0] == "image"
    assert E.preview_kind("x.exe")[0] is None
    assert E.preview_kind("a.png") == ("image", "image/png")


# ----- hostile archives ----------------------------------------------------------

def _tar_with(*members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, payload in members:
            ti = tarfile.TarInfo(name)
            if kind == "sym":
                ti.type = tarfile.SYMTYPE; ti.linkname = payload; tf.addfile(ti)
            else:
                ti.size = len(payload); tf.addfile(ti, io.BytesIO(payload))
    buf.seek(0)
    return buf


@pytest.mark.parametrize("name", ["../evil.txt", "/etc/evil.txt", "a/../../evil.txt", "C:\\evil.txt", "..\\evil.txt"])
def test_extraction_rejects_traversal(tmp_path, name):
    dest = tmp_path / "d"; dest.mkdir()
    with pytest.raises(ArchiveError):
        archive.unpack(_tar_with((name, "file", b"x")), dest)
    assert not (tmp_path / "evil.txt").exists()


def test_extraction_rejects_symlinks_and_devices(tmp_path):
    dest = tmp_path / "d"; dest.mkdir()
    with pytest.raises(ArchiveError):
        archive.unpack(_tar_with(("link", "sym", "/etc/passwd")), dest)


def test_safe_filename_neutralises_dangerous_names():
    assert safe_filename("../../x") == ".._.._x" or "/" not in safe_filename("../../x")
    assert safe_filename("..") == "restored" and safe_filename("") == "restored"
    assert safe_filename("CON.txt").startswith("_")
    assert len(safe_filename("a" * 400 + ".txt").encode()) <= 255


# ----- rekey -------------------------------------------------------------------

def test_rekey_changes_credentials_and_preserves_content(tree, tmp_path, fast):
    from vaultlock.core.keyfile import generate_keyfile
    key = tmp_path / "new.key"; generate_keyfile(key)
    old_creds, new_creds = E.Credentials("old password 123!"), E.Credentials("new password 456!", str(key))
    r = E.encrypt([tree], tmp_path / "t.vault", old_creds, kdf=fast, compress=True)
    before = r.output.read_bytes()
    k = E.rekey(r.output, tmp_path / "t2.vault", old_creds, new_creds, cipher=Cipher.CHACHA20_POLY1305, kdf=fast)
    assert r.output.read_bytes() == before                         # source untouched
    assert k.header.cipher == Cipher.CHACHA20_POLY1305 and k.header.uses_keyfile
    assert k.header.salt != r.header.salt                          # no key material shared
    from vaultlock.core.errors import MissingCredentialError
    with pytest.raises(MissingCredentialError):
        E.decrypt(k.output, tmp_path / "x", old_creds)             # new vault demands the keyfile
    with pytest.raises(AuthenticationError):
        E.decrypt(k.output, tmp_path / "x", E.Credentials("old password 123!", str(key)))  # old password is dead
    d = E.decrypt(k.output, tmp_path / "back", new_creds)
    assert tree_map(d.output) == tree_map(tree)                    # incl. zlib layer + folder structure


def test_rekey_wrong_old_password_leaves_nothing(sample, tmp_path, fast):
    r = E.encrypt([sample], tmp_path / "s.vault", C, kdf=fast)
    with pytest.raises(AuthenticationError):
        E.rekey(r.output, tmp_path / "o" / "s2.vault", E.Credentials("nope"), E.Credentials("new new new 1!"), kdf=fast)
    assert not list((tmp_path / "o").iterdir())


def test_rekey_refuses_to_overwrite_source(sample, tmp_path, fast):
    from vaultlock.core.errors import VaultLockError
    r = E.encrypt([sample], tmp_path / "s.vault", C, kdf=fast)
    with pytest.raises(VaultLockError):
        E.rekey(r.output, r.output, C, C, kdf=fast)
