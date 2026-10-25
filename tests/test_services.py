import os
import time

import pytest

from conftest import CHEAP, PW
from vaultlock.core import engine
from vaultlock.services import shredder, strength
from vaultlock.services.jobs import JobManager, JobOptions, Source


# ---- shredder ---------------------------------------------------------------
@pytest.mark.parametrize("passes", [1, 3, 7])
def test_shred_overwrites_contents_and_removes_file(tmp_path, passes):
    f = tmp_path / "s.txt"; f.write_bytes(b"TOP SECRET " * 100_000)
    keep = tmp_path / "alias"; os.link(f, keep)           # a second name for the same inode lets us inspect the data
    shredder.shred_path(f, passes)
    assert not f.exists() and keep.read_bytes() == b""     # truncated; no plaintext left behind


def test_shred_directory_and_symlink_safety(tmp_path):
    outside = tmp_path / "outside.txt"; outside.write_text("must survive")
    d = tmp_path / "d"; (d / "a").mkdir(parents=True); (d / "a" / "x").write_bytes(b"x" * 1000)
    os.symlink(outside, d / "lnk")
    rep = shredder.shred_path(d, 1)
    assert not d.exists() and outside.read_text() == "must survive" and rep.files == 2


def test_shred_cancel_keeps_file(tmp_path):
    import threading
    f = tmp_path / "big"; f.write_bytes(os.urandom(5_000_000)); ev = threading.Event(); ev.set()
    with pytest.raises(Exception):
        shredder.shred_file(f, 3, cancel=ev)
    assert f.exists()


def test_shred_rejects_bad_pass_count(tmp_path):
    f = tmp_path / "a"; f.write_text("x")
    with pytest.raises(Exception):
        shredder.shred_file(f, 5)


# ---- strength meter ---------------------------------------------------------
@pytest.mark.parametrize("pw", ["password", "P@ssw0rd!", "Password1", "qwerty123", "abcdefgh", "aaaaaaaaaa", "iloveyou", "summer2024!", "Zx9!"])
def test_weak_passwords_score_low(pw):
    assert strength.evaluate(pw).score <= 1


@pytest.mark.parametrize("pw", ["X9#vK2$mQ7!zL4pR", "correct-horse-battery-staple-orbit-velvet"])
def test_strong_passwords_score_high(pw):
    assert strength.evaluate(pw).score >= 3


def test_generators_are_strong_and_varied():
    pws = {strength.generate_password(24) for _ in range(20)}
    assert len(pws) == 20 and all(strength.evaluate(p).score == 4 for p in pws)
    assert strength.evaluate(strength.generate_passphrase(6)).score >= 3
    assert len(strength.generate_passphrase(6).split("-")) == 6


def test_empty_and_huge_input_do_not_crash():
    assert strength.evaluate("").score == 0
    t = time.time(); strength.evaluate("ab" * 5000); assert time.time() - t < 2


# ---- jobs -------------------------------------------------------------------
def run(mgr, job):
    mgr.run_sync(job); return job.snapshot()


def test_encrypt_verify_shred_pipeline(tmp_path, tree):
    f = tmp_path / "a.bin"; f.write_bytes(os.urandom(100_000))
    mgr = JobManager(None, lambda: tmp_path / "out")
    snap = run(mgr, mgr.submit_encrypt([Source(f), Source(tree)], engine.Credentials(PW),
                                       JobOptions(kdf=CHEAP, shred=True, shred_passes=1, verify=True)))
    assert snap["status"] == "done" and all(i["shredded"] for i in snap["items"])
    assert not f.exists() and not tree.exists() and (tmp_path / "a.bin.vault").exists()


def test_originals_survive_when_vault_cannot_be_verified(tmp_path, monkeypatch):
    f = tmp_path / "a.bin"; f.write_bytes(os.urandom(10_000))
    mgr = JobManager(None, lambda: tmp_path)
    from vaultlock.core.errors import IntegrityError
    monkeypatch.setattr(engine, "verify", lambda *a, **k: (_ for _ in ()).throw(IntegrityError("simulated corruption")))
    snap = run(mgr, mgr.submit_encrypt([Source(f)], engine.Credentials(PW), JobOptions(kdf=CHEAP, shred=True, shred_passes=1)))
    assert snap["status"] == "failed" and f.exists() and not (tmp_path / "a.bin.vault").exists()


def test_originals_kept_if_anything_was_skipped(tmp_path, tree):
    os.symlink(tree / "a.txt", tree / "lnk")
    mgr = JobManager(None, lambda: tmp_path)
    snap = run(mgr, mgr.submit_encrypt([Source(tree)], engine.Credentials(PW), JobOptions(kdf=CHEAP, shred=True, shred_passes=1)))
    assert snap["status"] == "done" and tree.exists() and not snap["items"][0]["shredded"]


def test_weak_password_refused_unless_confirmed(tmp_path):
    f = tmp_path / "a"; f.write_text("x"); mgr = JobManager(None, lambda: tmp_path)
    from vaultlock.core.errors import WeakPasswordError
    with pytest.raises(WeakPasswordError):
        mgr.submit_encrypt([Source(f)], engine.Credentials("password"), JobOptions(kdf=CHEAP))
    mgr.submit_encrypt([Source(f)], engine.Credentials("password"), JobOptions(kdf=CHEAP), allow_weak=True)


def test_cancel_removes_partial_output(tmp_path):
    f = tmp_path / "big"; f.write_bytes(os.urandom(60_000_000)); mgr = JobManager(None, lambda: tmp_path)
    job = mgr.submit_encrypt([Source(f)], engine.Credentials(PW), JobOptions(kdf=CHEAP, chunk_size=65536))
    mgr.start(job)
    while job.snapshot()["overall"]["done"] < 1_000_000 and job.status != "done": time.sleep(0.002)
    mgr.cancel(job.id)
    while job.status in ("queued", "running"): time.sleep(0.02)
    assert job.status in ("cancelled", "done")
    if job.status == "cancelled":
        assert not list(tmp_path.glob("*.vault")) and not list(tmp_path.glob(".*partial"))


def test_credentials_dropped_after_job(tmp_path):
    f = tmp_path / "a"; f.write_text("x"); mgr = JobManager(None, lambda: tmp_path)
    creds = engine.Credentials(PW)
    run(mgr, mgr.submit_encrypt([Source(f)], creds, JobOptions(kdf=CHEAP)))
    assert creds.password is None
