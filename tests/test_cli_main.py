"""Command-line interface end to end."""

import pytest

from vaultlock import cli

PW = "Correct-Horse-Battery-42!"


@pytest.fixture(autouse=True)
def _pw(monkeypatch):
    monkeypatch.setenv("VAULTLOCK_PASSWORD", PW)


def test_lock_inspect_verify_unlock(tmp_path, capsys):
    f = tmp_path / "a.txt"; f.write_text("cli data")
    key = tmp_path / "k.key"
    assert cli.main(["keygen", str(key)]) == 0
    assert cli.main(["lock", str(f), "--keyfile", str(key), "--verify", "-o", str(tmp_path / "o")]) == 0
    v = tmp_path / "o" / "a.txt.vault"
    assert cli.main(["inspect", str(v)]) == 0 and "required" in capsys.readouterr().out
    assert cli.main(["verify", str(v), "--keyfile", str(key)]) == 0
    assert cli.main(["unlock", str(v), "--keyfile", str(key), "-o", str(tmp_path / "b")]) == 0
    assert (tmp_path / "b" / "a.txt").read_text() == "cli data"


def test_missing_keyfile_and_wrong_password_exit_nonzero(tmp_path, monkeypatch):
    f = tmp_path / "a.txt"; f.write_text("x")
    cli.main(["lock", str(f), "-o", str(tmp_path / "o")])
    v = str(tmp_path / "o" / "a.txt.vault")
    monkeypatch.setenv("VAULTLOCK_PASSWORD", "wrong-wrong-wrong-1!")
    assert cli.main(["unlock", v, "-o", str(tmp_path / "b")]) == 1
    assert cli.main(["verify", v]) == 1


def test_shred_requires_confirmation(tmp_path, monkeypatch):
    f = tmp_path / "gone.txt"; f.write_text("bye")
    monkeypatch.setattr("builtins.input", lambda *_: "no")
    assert cli.main(["shred", str(f)]) == 1 and f.exists()
    assert cli.main(["shred", str(f), "-y", "--passes", "1"]) == 0 and not f.exists()


def test_no_arguments_opens_the_app(monkeypatch):
    """`python run.py` / double-click passes no arguments and must launch the GUI, not print usage."""
    seen = {}
    monkeypatch.setattr("vaultlock.desktop.run", lambda browser=False, port=0: (seen.update(browser=browser), 0)[1])
    monkeypatch.setattr("sys.argv", ["vaultlock"])
    assert cli.main() == 0
    assert seen["browser"] is True            # the tested browser mode is the default
    assert cli.main(["gui", "--native"]) == 0 and seen["browser"] is False


def test_passgen(capsys):
    assert cli.main(["passgen", "--words", "5"]) == 0
    assert len(capsys.readouterr().out.strip().split("-")) == 5


def test_rekey_replace_flow(tmp_path, monkeypatch):
    f = tmp_path / "a.txt"; f.write_text("rekey me")
    cli.main(["lock", str(f), "-o", str(tmp_path / "o")])
    v = tmp_path / "o" / "a.txt.vault"
    monkeypatch.setenv("VAULTLOCK_NEW_PASSWORD", "Another-Strong-Pass-77!")
    assert cli.main(["rekey", str(v), "--replace", "--cipher", "chacha20-poly1305"]) == 0
    assert not (tmp_path / "o" / "a.txt.rekeyed.vault").exists()
    monkeypatch.setenv("VAULTLOCK_PASSWORD", "Another-Strong-Pass-77!")
    assert cli.main(["unlock", str(v), "-o", str(tmp_path / "b")]) == 0
    assert (tmp_path / "b" / "a.txt").read_text() == "rekey me"
    monkeypatch.setenv("VAULTLOCK_PASSWORD", PW)
    assert cli.main(["verify", str(v)]) == 1          # the old password is dead
