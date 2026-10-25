"""Key derivation.

Pipeline (see docs/FORMAT.md for the byte-level spec)::

    password  --NFKC/UTF-8-->  pw
    keyfile   --SHA-512----->  kf_digest                     (optional 2nd factor)

    secret   = b"P" || pw                                     (password only)
             = b"K" || HMAC-SHA256(key=kf_digest, msg=pw)     (password + keyfile)

    master   = Argon2id(secret, salt32, t, m, p) -> 32 bytes   (or PBKDF2-HMAC-SHA256)
    enc_key  = HKDF-Expand(master, "VaultLock v1 / encryption key", 32)
    mac_key  = HKDF-Expand(master, "VaultLock v1 / header MAC key", 32)

The keyfile is bound through an HMAC *keyed by the keyfile*, so an attacker who
has only the vault and a password guess cannot test the guess without also
possessing the keyfile.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass
from enum import IntEnum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .errors import FormatError, MissingCredentialError, VaultLockError, WeakKdfError
from .memory import SecretBytes, wipe, wipe_bytes

try:  # cryptography >= 45 with OpenSSL >= 3.2
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id as _CryptoArgon2id
except Exception:  # pragma: no cover - older cryptography
    _CryptoArgon2id = None

try:  # optional fallback
    from argon2.low_level import Type as _A2Type, hash_secret_raw as _a2_raw
except Exception:  # pragma: no cover
    _a2_raw = None
    _A2Type = None

ARGON2_AVAILABLE = _CryptoArgon2id is not None or _a2_raw is not None

#: Tests flip this off (monkeypatch) to use cheap parameters.  The public API
#: and CLI never expose a way to disable it.
ENFORCE_MINIMUMS = True

SALT_LEN = 32
KEY_LEN = 32


class KdfId(IntEnum):
    ARGON2ID = 1
    PBKDF2_SHA256 = 2


@dataclass(frozen=True)
class KdfParams:
    """KDF selection + cost parameters, exactly as stored in the vault header.

    ``a`` / ``b`` / ``c`` mean:

    ========= ============== ============== ===========
    KDF        a              b              c
    ========= ============== ============== ===========
    Argon2id   time cost t    memory (KiB)   parallelism
    PBKDF2     iterations     0              0
    ========= ============== ============== ===========
    """

    kdf: KdfId
    a: int
    b: int = 0
    c: int = 0

    # -- creation-time policy -------------------------------------------
    ARGON_MIN_T = 3
    ARGON_MIN_M_KIB = 64 * 1024  # 64 MiB  (RFC 9106 s4 "second recommended option")
    PBKDF2_MIN_ITER = 600_000    # OWASP 2023 guidance for HMAC-SHA256

    # -- parse-time sanity bounds (DoS protection against hostile files) --
    ARGON_MAX_T = 64
    ARGON_MAX_M_KIB = 2 * 1024 * 1024  # 2 GiB
    ARGON_MAX_P = 64
    PBKDF2_MAX_ITER = 500_000_000

    def validate_bounds(self) -> None:
        """Reject parameters that are nonsensical or would DoS the reader."""
        if self.kdf == KdfId.ARGON2ID:
            if not (1 <= self.a <= self.ARGON_MAX_T):
                raise FormatError("Invalid Argon2id time cost in vault header.")
            if not (1 <= self.c <= self.ARGON_MAX_P):
                raise FormatError("Invalid Argon2id parallelism in vault header.")
            if not (8 * self.c <= self.b <= self.ARGON_MAX_M_KIB):
                raise FormatError("Invalid Argon2id memory cost in vault header.")
        elif self.kdf == KdfId.PBKDF2_SHA256:
            if not (1 <= self.a <= self.PBKDF2_MAX_ITER) or self.b or self.c:
                raise FormatError("Invalid PBKDF2 parameters in vault header.")
        else:  # pragma: no cover - IntEnum conversion already fails earlier
            raise FormatError("Unknown key-derivation function.")

    def validate_secure(self) -> None:
        """Enforce the minimum work factor when *creating* a vault."""
        self.validate_bounds()
        if not ENFORCE_MINIMUMS:
            return
        if self.kdf == KdfId.ARGON2ID:
            if self.a < self.ARGON_MIN_T or self.b < self.ARGON_MIN_M_KIB:
                raise WeakKdfError(
                    f"Argon2id needs at least t={self.ARGON_MIN_T} and "
                    f"{self.ARGON_MIN_M_KIB // 1024} MiB of memory."
                )
        elif self.a < self.PBKDF2_MIN_ITER:
            raise WeakKdfError(f"PBKDF2 needs at least {self.PBKDF2_MIN_ITER:,} iterations.")

    @property
    def is_weak(self) -> bool:
        try:
            self.validate_secure()
            return False
        except WeakKdfError:
            return True

    def describe(self) -> str:
        if self.kdf == KdfId.ARGON2ID:
            return f"Argon2id (t={self.a}, m={self.b // 1024} MiB, p={self.c})"
        return f"PBKDF2-HMAC-SHA256 ({self.a:,} iterations)"


MiB = 1024  # KiB per MiB

#: Named security profiles shown in the UI / CLI.
PRESETS: dict[str, KdfParams] = {
    "standard": KdfParams(KdfId.ARGON2ID, 3, 64 * MiB, 4),
    "strong": KdfParams(KdfId.ARGON2ID, 4, 256 * MiB, 4),
    "paranoid": KdfParams(KdfId.ARGON2ID, 6, 1024 * MiB, 4),
    "pbkdf2": KdfParams(KdfId.PBKDF2_SHA256, 1_000_000),
}
DEFAULT_PRESET = "strong"


def preset(name: str) -> KdfParams:
    try:
        p = PRESETS[name]
    except KeyError:
        raise WeakKdfError(f"Unknown security profile '{name}'.") from None
    if p.kdf == KdfId.ARGON2ID and not ARGON2_AVAILABLE:
        raise WeakKdfError("Argon2id is not available in this Python build; use the 'pbkdf2' profile.")
    return p


# --------------------------------------------------------------------------
# Credential -> secret
# --------------------------------------------------------------------------

def normalize_password(password: str) -> bytearray:
    """NFKC-normalise (so the same password typed on different OSes matches)
    and encode as UTF-8 into a wipeable buffer."""
    return bytearray(unicodedata.normalize("NFKC", password).encode("utf-8"))


def build_secret(password: str | bytes | bytearray | None, keyfile_digest: SecretBytes | None = None) -> SecretBytes:
    """Combine password (+ optional keyfile digest) into the KDF input secret."""
    if password is None or len(password) == 0:
        raise MissingCredentialError("A password is required.")
    pw = normalize_password(password) if isinstance(password, str) else bytearray(password)
    try:
        if keyfile_digest is None:
            buf = bytearray(b"P")
            buf += pw
            return SecretBytes.take(buf)
        key = bytes(keyfile_digest)
        try:
            mac = hmac.new(key, bytes(pw), hashlib.sha256).digest()
        finally:
            wipe_bytes(key)
        buf = bytearray(b"K")
        buf += mac
        wipe_bytes(mac)
        return SecretBytes.take(buf)
    finally:
        wipe(pw)


# --------------------------------------------------------------------------
# Derivation
# --------------------------------------------------------------------------

@dataclass
class DerivedKeys:
    enc: SecretBytes
    mac: SecretBytes

    def wipe(self) -> None:
        self.enc.wipe()
        self.mac.wipe()

    def __enter__(self) -> "DerivedKeys":
        return self

    def __exit__(self, *exc) -> None:
        self.wipe()


def _master(params: KdfParams, secret: bytes, salt: bytes) -> bytes:
    try:
        return _master_unchecked(params, secret, salt)
    except (MemoryError, OSError) as e:
        raise VaultLockError(
            "Key derivation ran out of memory. Choose a lighter security profile "
            "(a vault created with a heavier profile needs that much free RAM to open)."
        ) from e


def _master_unchecked(params: KdfParams, secret: bytes, salt: bytes) -> bytes:
    if params.kdf == KdfId.ARGON2ID:
        if _CryptoArgon2id is not None:
            return _CryptoArgon2id(
                salt=salt, length=KEY_LEN, iterations=params.a, lanes=params.c, memory_cost=params.b
            ).derive(secret)
        if _a2_raw is not None:  # pragma: no cover - fallback path
            return _a2_raw(secret, salt, params.a, params.b, params.c, KEY_LEN, _A2Type.ID)
        raise WeakKdfError("Argon2id is not available in this Python build.")
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=params.a).derive(secret)


def derive_keys(params: KdfParams, secret: SecretBytes, salt: bytes) -> DerivedKeys:
    """Run the KDF and split the result into independent sub-keys."""
    if len(salt) != SALT_LEN:
        raise FormatError("Bad salt length.")
    raw_secret = bytes(secret)
    master = b""
    try:
        master = _master(params, raw_secret, salt)
        enc = HKDFExpand(hashes.SHA256(), KEY_LEN, b"VaultLock v1 / encryption key").derive(master)
        mac = HKDFExpand(hashes.SHA256(), KEY_LEN, b"VaultLock v1 / header MAC key").derive(master)
        return DerivedKeys(enc=SecretBytes.take(enc), mac=SecretBytes.take(mac))
    finally:
        wipe_bytes(raw_secret)
        wipe_bytes(master)
