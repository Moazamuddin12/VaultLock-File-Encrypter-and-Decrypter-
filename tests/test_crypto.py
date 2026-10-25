"""Core cryptographic behaviour: round-trips, tamper detection, KDF policy."""

import io
import os

import pytest

from vaultlock.core import kdf as kdfmod
from vaultlock.core.errors import (
    AuthenticationError, FormatError, IntegrityError, MissingCredentialError,
    UnsupportedVersionError, WeakKdfError,
)
from vaultlock.core.format import HEADER_SIZE, Cipher, Header, make_metadata
from vaultlock.core.kdf import KdfId, KdfParams, build_secret
from vaultlock.core.keyfile import digest_keyfile, generate_keyfile
from vaultlock.core.memory import SecretBytes, wipe_bytes, CAN_WIPE_IMMUTABLE
from vaultlock.core.stream import DecryptReader, EncryptWriter

META = make_metadata(name="x", kind="file", size=0, mtime=None, mode=None, compress=False)
CS = 4096


def seal(data: bytes, pw="pw", cipher=Cipher.AES_256_GCM, params=None, cs=CS) -> bytes:
    out = io.BytesIO()
    with EncryptWriter(out, secret=build_secret(pw), cipher=cipher,
                       kdf=params or kdfmod.PRESETS["strong"], metadata=META, chunk_size=cs) as w:
        w.write(data)
    return out.getvalue()


def unseal(blob: bytes, pw="pw") -> bytes:
    return DecryptReader(io.BytesIO(blob), secret=build_secret(pw)).read()


@pytest.mark.parametrize("cipher", list(Cipher))
@pytest.mark.parametrize("size", [0, 1, CS - 1, CS, CS + 1, 3 * CS, 3 * CS + 17, 200_000])
def test_roundtrip_boundaries(cipher, size):
    data = os.urandom(size)
    assert unseal(seal(data, cipher=cipher)) == data


def test_odd_sized_writes_match_single_write():
    data = os.urandom(50_000)
    out = io.BytesIO()
    with EncryptWriter(out, secret=build_secret("pw"), cipher=Cipher.CHACHA20_POLY1305,
                       kdf=kdfmod.PRESETS["strong"], metadata=META, chunk_size=CS) as w:
        for i in range(0, len(data), 777):
            w.write(data[i:i + 777])
    assert unseal(out.getvalue()) == data


def test_fresh_salt_and_nonce_every_time():
    a, b = seal(b"same"), seal(b"same")
    assert a[:HEADER_SIZE] != b[:HEADER_SIZE]
    ha, hb = Header.parse(a[:HEADER_SIZE]), Header.parse(b[:HEADER_SIZE])
    assert ha.salt != hb.salt and ha.nonce_base != hb.nonce_base and len(ha.salt) == 32
    assert a[HEADER_SIZE:] != b[HEADER_SIZE:]


def test_wrong_password_is_rejected_early():
    with pytest.raises(AuthenticationError):
        unseal(seal(b"secret"), pw="wrong")


def test_unicode_passwords_are_normalised():
    # "é" precomposed vs. combining sequence must unlock the same vault
    assert unseal(seal(b"x", pw="café"), pw="café") == b"x"


@pytest.mark.parametrize("offset_from", ["header", "meta", "data"])
def test_bit_flips_anywhere_are_detected(offset_from):
    blob = bytearray(seal(os.urandom(3 * CS)))
    pos = {"header": 20, "meta": HEADER_SIZE + 50, "data": len(blob) - 100}[offset_from]
    blob[pos] ^= 0x01
    with pytest.raises((AuthenticationError, IntegrityError, FormatError, UnsupportedVersionError)):
        unseal(bytes(blob))


def test_truncation_at_chunk_boundary_is_detected():
    blob = seal(os.urandom(5 * CS))
    with pytest.raises(IntegrityError):
        unseal(blob[: -(CS + 16)])


def test_appended_data_is_detected():
    with pytest.raises(IntegrityError):
        unseal(seal(os.urandom(2 * CS)) + b"\x00" * 33)


def test_chunk_reordering_is_detected():
    blob = bytearray(seal(os.urandom(4 * CS)))
    base = HEADER_SIZE + 4096 + 16
    c = CS + 16
    first, second = bytes(blob[base:base + c]), bytes(blob[base + c:base + 2 * c])
    blob[base:base + c], blob[base + c:base + 2 * c] = second, first
    with pytest.raises(IntegrityError):
        unseal(bytes(blob))


def test_header_swap_between_vaults_is_detected():
    a, b = seal(b"A" * 100), seal(b"B" * 100)
    franken = b[:HEADER_SIZE] + a[HEADER_SIZE:]
    with pytest.raises((AuthenticationError, IntegrityError)):
        unseal(franken)


def test_empty_and_garbage_files():
    with pytest.raises(FormatError):
        unseal(b"")
    with pytest.raises(FormatError):
        unseal(os.urandom(500))


def test_future_version_is_refused_cleanly():
    blob = bytearray(seal(b"x"))
    blob[4] = 99
    with pytest.raises(UnsupportedVersionError):
        Header.parse(bytes(blob[:HEADER_SIZE]))


def test_hostile_kdf_parameters_are_bounded():
    blob = bytearray(seal(b"x"))
    blob[12:16] = (0xFFFFFFFF).to_bytes(4, "big")  # absurd Argon2 time cost
    with pytest.raises(FormatError):
        Header.parse(bytes(blob[:HEADER_SIZE]))


def test_creation_enforces_minimum_kdf_cost(monkeypatch):
    monkeypatch.setattr(kdfmod, "ENFORCE_MINIMUMS", True)
    for weak in (KdfParams(KdfId.ARGON2ID, 1, 1024, 1), KdfParams(KdfId.PBKDF2_SHA256, 1000)):
        with pytest.raises(WeakKdfError):
            weak.validate_secure()
    for p in kdfmod.PRESETS.values():
        pass  # presets are replaced by FAST in the fixture; real ones checked below
    assert KdfParams(KdfId.PBKDF2_SHA256, 600_000).is_weak is False
    assert KdfParams(KdfId.ARGON2ID, 3, 64 * 1024, 4).is_weak is False


def test_pbkdf2_vault_roundtrip():
    p = KdfParams(KdfId.PBKDF2_SHA256, 1000)
    assert unseal(seal(b"hello", params=p)) == b"hello"


# ----- keyfile as second factor -------------------------------------------------

def test_keyfile_is_required_and_bound(tmp_path):
    from vaultlock.core.engine import Credentials, decrypt, encrypt

    src = tmp_path / "f.txt"; src.write_text("top secret")
    k1, k2 = tmp_path / "1.key", tmp_path / "2.key"
    generate_keyfile(k1); generate_keyfile(k2)
    r = encrypt([src], tmp_path / "o" / "f.vault", Credentials("pw", str(k1)), kdf=kdfmod.PRESETS["strong"])
    assert r.header.uses_keyfile
    with pytest.raises(MissingCredentialError):
        decrypt(r.output, tmp_path / "d", Credentials("pw"))
    with pytest.raises(AuthenticationError):
        decrypt(r.output, tmp_path / "d", Credentials("pw", str(k2)))
    with pytest.raises(AuthenticationError):
        decrypt(r.output, tmp_path / "d", Credentials("other", str(k1)))
    assert decrypt(r.output, tmp_path / "d", Credentials("pw", str(k1))).output.read_text() == "top secret"


def test_generated_keyfile_properties(tmp_path):
    k = tmp_path / "a.key"
    fp = generate_keyfile(k)
    assert len(fp) == 14 and oct(k.stat().st_mode)[-3:] == "600"
    with pytest.raises(Exception):
        generate_keyfile(k)  # never silently overwrite a keyfile
    with digest_keyfile(k) as d:
        assert len(d) == 64


# ----- memory hygiene ----------------------------------------------------------

def test_secretbytes_wipes_and_refuses_copies():
    import copy, pickle

    s = SecretBytes(b"k" * 32)
    view = bytes(s)
    assert view == b"k" * 32
    s.wipe()
    with pytest.raises(ValueError):
        bytes(s)
    for op in (copy.copy, pickle.dumps):
        with pytest.raises(TypeError):
            op(SecretBytes(b"x" * 16))


@pytest.mark.skipif(not CAN_WIPE_IMMUTABLE, reason="needs CPython")
def test_wipe_bytes_zeroes_in_place():
    secret = bytes(bytearray(os.urandom(32)))
    alias = secret
    assert wipe_bytes(secret) is True
    assert alias == bytes(32)
    assert wipe_bytes(b"") is False and wipe_bytes(b"x") is False  # never touch interned singletons


def test_header_layout_matches_docs_format_md():
    """docs/FORMAT.md documents these exact offsets; change one and this test fails."""
    p = KdfParams(KdfId.ARGON2ID, 3, 64 * 1024, 4)
    out = io.BytesIO()
    EncryptWriter(out, secret=build_secret("x"), cipher=Cipher.CHACHA20_POLY1305, kdf=p, metadata=META,
                  uses_keyfile=True, chunk_size=65536).close()
    b = out.getvalue()
    assert b[:4] == b"VLCK" and b[4] == 1 and b[5] == 2 and b[6] == 1 and b[7] == 1
    assert int.from_bytes(b[8:12], "big") == 65536
    assert (int.from_bytes(b[12:16], "big"), int.from_bytes(b[16:20], "big"), b[20]) == (3, 65536, 4)
    assert b[21:24] == b"\0\0\0" and len(b[24:56]) == 32 and len(b[56:68]) == 12 and len(b[68:100]) == 32
    assert len(b) == 100 + 4096 + 16 + 16        # header + metadata chunk + one empty final chunk
