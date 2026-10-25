"""Application paths and persisted (non-secret) settings.

Passwords, keys and keyfile contents are **never** written here - only UI /
behaviour preferences.  Settings are validated against a strict whitelist so a
corrupted or hand-edited file can never inject unexpected values.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable

APP_NAME = "VaultLock"


def app_home() -> Path:
    """Per-user config/state directory (override with ``VAULTLOCK_HOME``)."""
    override = os.environ.get("VAULTLOCK_HOME")
    if override:
        base = Path(override).expanduser()
    elif sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / APP_NAME
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "vaultlock"
    base.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    return base


def default_output_dir() -> Path:
    """Where results go for items that have no natural home (browser uploads)."""
    return Path.home() / "VaultLock"


# key -> (default, validator)
def _bool(v: Any) -> bool:
    if not isinstance(v, bool):
        raise ValueError("expected boolean")
    return v


def _choice(*opts: str) -> Callable[[Any], str]:
    def check(v: Any) -> str:
        if v not in opts:
            raise ValueError(f"expected one of {opts}")
        return v

    return check


def _int(lo: int, hi: int) -> Callable[[Any], int]:
    def check(v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int) or not (lo <= v <= hi):
            raise ValueError(f"expected integer {lo}..{hi}")
        return v

    return check


def _one_of_ints(*opts: int) -> Callable[[Any], int]:
    def check(v: Any) -> int:
        if isinstance(v, bool) or v not in opts:
            raise ValueError(f"expected one of {opts}")
        return v

    return check


def _path(v: Any) -> str:
    if not isinstance(v, str) or len(v) > 4096 or "\x00" in v:
        raise ValueError("expected path string")
    return v


SCHEMA: dict[str, tuple[Any, Callable[[Any], Any]]] = {
    "sounds": (True, _bool),
    "haptics": (True, _bool),
    "privacy_blur": (False, _bool),
    "reduce_motion": (False, _bool),
    "auto_clear_minutes": (5, _int(0, 120)),
    "accent": ("cyan", _choice("cyan", "violet", "emerald", "amber", "rose")),
    "profile": ("strong", _choice("standard", "strong", "paranoid", "pbkdf2")),
    "cipher": ("aes-256-gcm", _choice("aes-256-gcm", "chacha20-poly1305")),
    "chunk_kib": (1024, _int(64, 4096)),
    "compress": (False, _bool),
    "obfuscate_names": (False, _bool),
    "shred_passes": (3, _one_of_ints(1, 3, 7)),
    "preview_max_mb": (96, _int(1, 1024)),
    "default_output_dir": ("", _path),
    "show_hidden_files": (False, _bool),
}


class SettingsStore:
    """Thread-safe JSON settings file with whitelist validation and atomic writes."""

    def __init__(self, path: Path | None = None):
        self._path = path or (app_home() / "settings.json")
        self._lock = threading.Lock()
        self._values = {k: d for k, (d, _) in SCHEMA.items()}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(raw, dict):
            self._apply(raw, strict=False)

    def _apply(self, data: dict, strict: bool) -> None:
        for k, v in data.items():
            if k not in SCHEMA:
                if strict:
                    raise ValueError(f"Unknown setting '{k}'")
                continue
            try:
                self._values[k] = SCHEMA[k][1](v)
            except ValueError as e:
                if strict:
                    raise ValueError(f"Invalid value for '{k}': {e}") from None

    def get_all(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._values)

    def get(self, key: str) -> Any:
        with self._lock:
            return self._values[key]

    def update(self, data: dict) -> dict[str, Any]:
        with self._lock:
            trial = dict(self._values)
            backup = self._values
            self._values = trial
            try:
                self._apply(data, strict=True)
            except ValueError:
                self._values = backup
                raise
            self._save()
            return dict(self._values)

    def _save(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(self._values, indent=2), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError:
            pass  # settings are a convenience; never fail an operation over them

    def output_dir(self) -> Path:
        v = self.get("default_output_dir")
        return Path(v).expanduser() if v else default_output_dir()
