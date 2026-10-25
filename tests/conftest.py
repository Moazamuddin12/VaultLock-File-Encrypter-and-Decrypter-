import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vaultlock.core import kdf as kdfmod  # noqa: E402

#: Cheap Argon2id so the suite runs in seconds.  Production code never uses this.
FAST = kdfmod.KdfParams(kdfmod.KdfId.ARGON2ID, 1, 32, 4)


@pytest.fixture(autouse=True)
def _cheap_kdf(monkeypatch, tmp_path):
    monkeypatch.setattr(kdfmod, "ENFORCE_MINIMUMS", False)
    monkeypatch.setenv("VAULTLOCK_HOME", str(tmp_path / "home"))
    monkeypatch.setitem(kdfmod.PRESETS, "strong", FAST)
    monkeypatch.setitem(kdfmod.PRESETS, "standard", FAST)


@pytest.fixture
def fast():
    return FAST


@pytest.fixture
def sample(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(os.urandom(600_000))
    return f


@pytest.fixture
def tree(tmp_path):
    d = tmp_path / "proj"
    (d / "sub" / "deep").mkdir(parents=True)
    (d / "empty").mkdir()
    (d / "a.txt").write_text("hello\n" * 500)
    (d / "sub" / "b.bin").write_bytes(os.urandom(120_000))
    (d / "sub" / "deep" / "ünï.txt").write_text("unicode")
    return d
