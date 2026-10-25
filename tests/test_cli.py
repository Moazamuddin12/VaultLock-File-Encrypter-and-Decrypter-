import os

from vaultlock import cli

PW = "Correct-Horse-Battery-42!"


def test_cli_lock_unlock_roundtrip(tmp_path, monkeypatch, capsys):
    from vaultlock.core import kdf
    monkeypatch.setattr(kdf.KdfParams, "validate_secure", lambda self: None)
    monkeypatch.setenv("VAULTLOCK_PASSWORD", PW)
    f = tmp_path / "a.txt"; f.write_text("hello")
    assert cli.main(["encrypt", str(f), "-o", str(tmp_path / "o"), "--profile", "standard"]) == cli.EXIT_OK
    v = tmp_path / "o" / "a.txt.vault"
    assert cli.main(["inspect", str(v)]) == 0 and "AES-256-GCM" in capsys.readouterr().out
    assert cli.main(["decrypt", str(v), "-o", str(tmp_path / "r")]) == 0
    assert (tmp_path / "r" / "a.txt").read_text() == "hello"
    monkeypatch.setenv("VAULTLOCK_PASSWORD", "wrong")
    assert cli.main(["decrypt", str(v), "-o", str(tmp_path / "r2")]) == cli.EXIT_AUTH


def test_cli_refuses_weak_password(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTLOCK_PASSWORD", "password")
    f = tmp_path / "a.txt"; f.write_text("x")
    assert cli.main(["encrypt", str(f), "-o", str(tmp_path / "o")]) == cli.EXIT_ERR
    assert not (tmp_path / "o").exists()
