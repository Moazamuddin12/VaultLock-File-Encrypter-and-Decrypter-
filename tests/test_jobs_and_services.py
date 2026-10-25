"""Job runner (verify-before-shred, cancel), shredder, strength meter, settings."""

import os
import threading
import time
from pathlib import Path

import pytest

from vaultlock.config import SettingsStore
from vaultlock.core import engine as E
from vaultlock.core.errors import VaultLockError, WeakPasswordError
from vaultlock.services import shredder, strength
from vaultlock.services.jobs import JobManager, JobOptions, Source

PW = "Correct-Horse-Battery-42!"


def manager(tmp_path):
    return JobManager(None, lambda: tmp_path / "out")


def run(jm, job):
    jm.run_sync(job)
    return job.snapshot()


def test_encrypt_verify_shred_then_decrypt(sample, tree, tmp_path, fast):
    jm = manager(tmp_path)
    original = sample.read_bytes()
    snap = run(jm, jm.submit_encrypt([Source(sample), Source(tree)], E.Credentials(PW),
                                     JobOptions(kdf=fast, verify=True, shred=True, shred_passes=1)))
    assert snap["status"] == "done" and snap["overall"]["percent"] == 100
    assert not sample.exists() and not tree.exists()          # originals destroyed
    assert all(i["shredded"] for i in snap["items"])
    vaults = sorted(tmp_path.glob("*.vault"))
    snap = run(jm, jm.submit_decrypt([Source(v) for v in vaults], E.Credentials(PW), JobOptions(output_dir=tmp_path / "back")))
    assert snap["status"] == "done"
    assert (tmp_path / "back" / "sample.bin").read_bytes() == original


def test_originals_survive_when_verification_fails(sample, tmp_path, fast, monkeypatch):
    def boom(*a, **k):
        from vaultlock.core.errors import IntegrityError
        raise IntegrityError("simulated disk corruption")
    monkeypatch.setattr(E, "verify", boom)
    jm = manager(tmp_path)
    snap = run(jm, jm.submit_encrypt([Source(sample)], E.Credentials(PW), JobOptions(kdf=fast, shred=True, shred_passes=1)))
    assert snap["status"] == "failed" and sample.exists()     # NEVER shred without a verified vault
    assert not list(tmp_path.glob("*.vault"))


def test_originals_kept_when_something_was_skipped(tree, tmp_path, fast):
    os.symlink(tree / "a.txt", tree / "link")
    jm = manager(tmp_path)
    snap = run(jm, jm.submit_encrypt([Source(tree)], E.Credentials(PW), JobOptions(kdf=fast, shred=True, shred_passes=1)))
    assert snap["status"] == "done" and tree.exists() and not snap["items"][0]["shredded"]
    assert any("nothing was shredded" in n for n in snap["items"][0]["notes"])


def test_vault_inside_shredded_folder_is_protected(tree, fast):
    jm = JobManager(None, lambda: tree)
    job = jm.submit_encrypt([Source(tree)], E.Credentials(PW), JobOptions(kdf=fast, output_dir=tree / "sub"))
    snap = run(jm, job)
    assert snap["status"] == "failed" and "inside a folder" in snap["items"][0]["error"]["message"]


def test_weak_password_gate(sample, tmp_path, fast):
    jm = manager(tmp_path)
    with pytest.raises(WeakPasswordError):
        jm.submit_encrypt([Source(sample)], E.Credentials("password"), JobOptions(kdf=fast))
    jm.submit_encrypt([Source(sample)], E.Credentials("password"), JobOptions(kdf=fast), allow_weak=True)


def test_wrong_password_reports_clean_error(sample, tmp_path, fast):
    jm = manager(tmp_path)
    run(jm, jm.submit_encrypt([Source(sample)], E.Credentials(PW), JobOptions(kdf=fast)))
    snap = run(jm, jm.submit_decrypt([Source(tmp_path / "sample.bin.vault")], E.Credentials("x" * 12),
                                     JobOptions(output_dir=tmp_path / "back")))
    assert snap["status"] == "failed" and snap["items"][0]["error"]["code"] == "bad_credentials"


def test_cancel_keeps_original_and_leaves_no_debris(tmp_path, fast):
    big = tmp_path / "big.bin"
    blk = os.urandom(1 << 20)
    with open(big, "wb") as f:
        for _ in range(150):
            f.write(blk)
    jm = manager(tmp_path)
    job = jm.submit_encrypt([Source(big)], E.Credentials(PW), JobOptions(kdf=fast, chunk_size=4096, shred=True, shred_passes=1))
    jm.start(job)
    time.sleep(0.25)
    jm.cancel(job.id)
    while job.status in ("queued", "running"):
        time.sleep(0.02)
    assert job.status == "cancelled" and big.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["big.bin"]


def test_credentials_are_dropped_after_job(sample, tmp_path, fast):
    creds = E.Credentials(PW)
    jm = manager(tmp_path)
    run(jm, jm.submit_encrypt([Source(sample)], creds, JobOptions(kdf=fast)))
    assert creds.password is None


# ------------------------------------------------------------------ shredder

@pytest.mark.parametrize("passes", [1, 3, 7])
def test_shred_overwrites_in_place_before_unlinking(tmp_path, passes):
    f = tmp_path / "s.txt"; f.write_bytes(b"TOP SECRET " * 100_000)
    twin = tmp_path / "twin"; os.link(f, twin)                 # keeps the inode alive so we can inspect it
    rep = shredder.shred_path(f, passes)
    assert not f.exists() and rep.files == 1 and rep.passes == passes
    assert b"TOP SECRET" not in twin.read_bytes()
    assert any("hard link" in w for w in rep.warnings)


def test_shred_directory_never_follows_symlinks(tmp_path):
    victim = tmp_path / "victim.txt"; victim.write_text("keep me")
    d = tmp_path / "d"; (d / "x").mkdir(parents=True); (d / "x" / "f").write_bytes(b"1" * 5000)
    os.symlink(victim, d / "link")
    shredder.shred_path(d, 1)
    assert not d.exists() and victim.read_text() == "keep me"


def test_shred_rejects_bad_pass_count(tmp_path):
    f = tmp_path / "f"; f.write_bytes(b"x")
    with pytest.raises(VaultLockError):
        shredder.shred_file(f, 5)
    assert f.exists()


def test_shred_cancel_keeps_file(tmp_path):
    f = tmp_path / "f"; f.write_bytes(b"x" * (4 << 20))
    ev = threading.Event(); ev.set()
    with pytest.raises(VaultLockError):
        shredder.shred_file(f, 3, cancel=ev)
    assert f.exists()


# ------------------------------------------------------------------ strength

@pytest.mark.parametrize("pw", ["password", "P@ssw0rd!", "Password1", "qwerty123", "abcdefgh", "aaaaaaaaaa", "iloveyou", "summer2024!"])
def test_common_patterns_score_very_weak(pw):
    assert strength.evaluate(pw).score == 0


@pytest.mark.parametrize("pw", ["X9#vK2$mQ7!zL4pR", "correct-horse-battery-staple-orbit-velvet"])
def test_strong_passwords_score_high(pw):
    assert strength.evaluate(pw).score >= 3


def test_generators_meet_their_own_bar():
    assert strength.evaluate(strength.generate_password(24)).score == 4
    p = strength.generate_passphrase(6)
    assert len(p.split("-")) == 6 and strength.evaluate(p).score >= 3
    assert strength.generate_password(24) != strength.generate_password(24)


def test_strength_handles_empty_and_huge_inputs():
    assert strength.evaluate("").score == 0
    t = time.time(); strength.evaluate("a1!" * 500)
    assert time.time() - t < 2


# ------------------------------------------------------------------ settings

def test_settings_whitelist(tmp_path):
    s = SettingsStore(tmp_path / "s.json")
    assert s.update({"accent": "rose", "shred_passes": 7})["accent"] == "rose"
    for bad in ({"shred_passes": 5}, {"nope": 1}, {"sounds": "yes"}, {"chunk_kib": 10**9}):
        with pytest.raises(ValueError):
            s.update(bad)
    assert SettingsStore(tmp_path / "s.json").get("accent") == "rose"   # persisted
    (tmp_path / "s.json").write_text('{"accent": "<script>", "junk": 1}')
    assert SettingsStore(tmp_path / "s.json").get("accent") == "cyan"   # corrupt values fall back to defaults
