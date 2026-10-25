"""Exception hierarchy.

Every error carries a short machine-readable ``code`` (used by the HTTP API and
the UI to pick an icon / colour) and a human-readable message.  Messages never
contain secrets.
"""

from __future__ import annotations


class VaultLockError(Exception):
    """Base class for all expected, user-facing errors."""

    code = "error"

    def __init__(self, message: str | None = None):
        super().__init__(message or self.__class__.__doc__ or self.code)


class FormatError(VaultLockError):
    """This file is not a VaultLock container (or its header is damaged)."""

    code = "bad_format"


class UnsupportedVersionError(FormatError):
    """This vault was written by a newer, incompatible version of VaultLock."""

    code = "unsupported_version"


class AuthenticationError(VaultLockError):
    """Wrong password or keyfile (or the vault header was modified)."""

    code = "bad_credentials"


class IntegrityError(VaultLockError):
    """The encrypted data failed authentication: corrupted, truncated or tampered with."""

    code = "integrity"


class CancelledError(VaultLockError):
    """The operation was cancelled."""

    code = "cancelled"


class ArchiveError(VaultLockError):
    """The folder archive inside the vault is unsafe or malformed."""

    code = "archive"


class OutputExistsError(VaultLockError):
    """The destination already exists and overwriting was not requested."""

    code = "exists"


class WeakKdfError(VaultLockError):
    """The requested key-derivation parameters are below the safe minimum."""

    code = "weak_kdf"


class WeakPasswordError(VaultLockError):
    """The password is too weak and no override was given."""

    code = "weak_password"


class TooLargeError(VaultLockError):
    """The content is too large for in-memory preview."""

    code = "too_large"


class NotPreviewableError(VaultLockError):
    """This file type cannot be previewed inside the secure viewer."""

    code = "not_previewable"


class MissingCredentialError(VaultLockError):
    """A password (and/or keyfile) is required for this operation."""

    code = "missing_credentials"
