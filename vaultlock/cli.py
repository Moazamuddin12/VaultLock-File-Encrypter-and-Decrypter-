"""Command-line interface - the same engine, scriptable.

    vaultlock lock   FILE_OR_DIR... [-o DIR] [--keyfile K] [--shred] [--verify]
    vaultlock unlock VAULT...       [-o DIR] [--keyfile K]
    vaultlock inspect VAULT...
    vaultlock verify  VAULT...
    vaultlock shred   PATH...       [--passes 1|3|7]
    vaultlock keygen  PATH.key
    vaultlock passgen [--words N | --length N]
    vaultlock gui     [--native]

Passwords are read from a hidden prompt (or the ``VAULTLOCK_PASSWORD`` env var
for automation) - never from a command-line argument, which would leak into
shell history and the process list.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

from . import __version__
from .core import engine, kdf as kdfmod
from .core.errors import VaultLockError
from .core.format import CIPHER_BY_NAME
from .core.keyfile import generate_keyfile
from .services import strength
from .services.jobs import JobManager, JobOptions, Source


def _fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def _password(confirm: bool) -> str:
    env = os.environ.get("VAULTLOCK_PASSWORD")
    if env:
        return env
    pw = getpass.getpass("Password: ")
    if confirm and getpass.getpass("Repeat password: ") != pw:
        raise VaultLockError("Passwords do not match.")
    return pw


def _run_job(jm: JobManager, job) -> int:
    jm.start(job)
    last = ""
    try:
        while job.status in ("queued", "running"):
            s = job.snapshot()["overall"]
            eta = f"{s['eta_s']:.0f}s" if s["eta_s"] is not None else "--"
            line = f"\r  {s['percent']:5.1f}%  {_fmt_size(s['speed_bps'])}/s  ETA {eta}   "
            if line != last and sys.stderr.isatty():
                sys.stderr.write(line)
                sys.stderr.flush()
                last = line
            time.sleep(0.1)
    except KeyboardInterrupt:
        job.cancel.set()
        while job.status in ("queued", "running"):
            time.sleep(0.05)
    if sys.stderr.isatty():
        sys.stderr.write("\r" + " " * 50 + "\r")
    snap = job.snapshot()
    rc = 0
    for it in snap["items"]:
        if it["status"] == "done":
            print(f"OK    {it['label']}" + (f" -> {it['output']}" if it["output"] else ""))
            for n in it["notes"]:
                print(f"      {n}")
        else:
            rc = 1
            msg = (it["error"] or {}).get("message", it["status"])
            print(f"FAIL  {it['label']}: {msg}", file=sys.stderr)
    return rc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vaultlock", description="VaultLock - local-first file encryption.")
    p.add_argument("--version", action="version", version=f"VaultLock {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    lock = sub.add_parser("lock", help="encrypt files or folders into .vault containers")
    lock.add_argument("paths", nargs="+")
    lock.add_argument("-o", "--out", help="output directory")
    lock.add_argument("--keyfile")
    lock.add_argument("--profile", choices=list(kdfmod.PRESETS), default="strong")
    lock.add_argument("--cipher", choices=list(CIPHER_BY_NAME), default="aes-256-gcm")
    lock.add_argument("--bundle", metavar="NAME", help="put everything into ONE vault with this name")
    lock.add_argument("--compress", action="store_true")
    lock.add_argument("--obfuscate", action="store_true", help="random vault file names")
    lock.add_argument("--verify", action="store_true")
    lock.add_argument("--shred", action="store_true", help="verify, then securely delete the originals")
    lock.add_argument("--passes", type=int, choices=(1, 3, 7), default=3)
    lock.add_argument("--allow-weak", action="store_true")

    unlock = sub.add_parser("unlock", help="decrypt .vault containers")
    unlock.add_argument("paths", nargs="+")
    unlock.add_argument("-o", "--out")
    unlock.add_argument("--keyfile")
    unlock.add_argument("--overwrite", action="store_true")

    for name, helptext in (("inspect", "show a vault's public header"), ("verify", "authenticate a whole vault")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("paths", nargs="+")
        s.add_argument("--keyfile")

    rk = sub.add_parser("rekey", help="change a vault's password, keyfile or cipher")
    rk.add_argument("vault")
    rk.add_argument("-o", "--out", help="new vault path (default: NAME.rekeyed.vault)")
    rk.add_argument("--keyfile", help="current keyfile")
    rk.add_argument("--new-keyfile", help="keyfile for the new vault (omit to drop the keyfile requirement)")
    rk.add_argument("--profile", choices=list(kdfmod.PRESETS), default="strong")
    rk.add_argument("--cipher", choices=list(CIPHER_BY_NAME))
    rk.add_argument("--replace", action="store_true", help="after verifying the new vault, replace the original with it")

    sh = sub.add_parser("shred", help="overwrite and delete files/folders")
    sh.add_argument("paths", nargs="+")
    sh.add_argument("--passes", type=int, choices=(1, 3, 7), default=3)
    sh.add_argument("-y", "--yes", action="store_true")

    kg = sub.add_parser("keygen", help="create a random keyfile")
    kg.add_argument("path")

    pg = sub.add_parser("passgen", help="generate a strong password / passphrase")
    pg.add_argument("--words", type=int)
    pg.add_argument("--length", type=int, default=24)

    gui = sub.add_parser("gui", help="launch the app (opens in your web browser)")
    gui.add_argument("--native", action="store_true", help="try a native desktop window (needs `pip install pywebview`)")
    gui.add_argument("--browser", action="store_true", help="open in your web browser (the default)")
    gui.add_argument("--port", type=int, default=0)
    return p


def main(argv: list[str] | None = None) -> int:
    # Windows consoles often use a legacy code page: never crash on a non-ASCII file name.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    if argv is None:
        argv = sys.argv[1:]
    if not argv:  # double-click, `python run.py` or `python -m vaultlock` -> open the app
        argv = ["gui"]
    args = build_parser().parse_args(argv)
    try:
        return _dispatch(args)
    except VaultLockError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


def _dispatch(a) -> int:
    if a.cmd == "gui":
        from .desktop import run

        return run(browser=not a.native, port=a.port)
    if a.cmd == "keygen":
        fp = generate_keyfile(a.path)
        print(f"Keyfile written to {a.path}\nFingerprint: {fp}\nKeep an offline backup - without it your vaults cannot be opened.")
        return 0
    if a.cmd == "passgen":
        print(strength.generate_passphrase(a.words) if a.words else strength.generate_password(a.length))
        return 0
    if a.cmd == "inspect":
        for p in a.paths:
            try:
                info = engine.inspect(p)
            except VaultLockError as e:
                print(f"{p}: {e}", file=sys.stderr)
                continue
            print(f"{p}\n  cipher   {info['cipher']}\n  kdf      {info['kdf_description']}\n  keyfile  {'required' if info['uses_keyfile'] else 'no'}"
                  f"\n  chunks   {info['chunks']} x {_fmt_size(info['chunk_size'])}\n  size     {_fmt_size(info['file_size'])}")
        return 0
    if a.cmd == "shred":
        if not a.yes:
            if input(f"Permanently destroy {len(a.paths)} item(s)? Type 'shred' to confirm: ").strip() != "shred":
                print("Aborted.")
                return 1
        jm = JobManager(None, lambda: Path.cwd())
        return _run_job(jm, jm.submit_shred([Source(Path(p)) for p in a.paths], a.passes))

    if a.cmd == "rekey":
        return _rekey(a)

    jm = JobManager(None, lambda: Path.cwd())
    srcs = [Source(Path(p)) for p in a.paths]
    if a.cmd == "lock":
        pw = _password(confirm=True)
        creds = engine.Credentials(pw, a.keyfile)
        opts = JobOptions(
            cipher=CIPHER_BY_NAME[a.cipher], kdf=kdfmod.preset(a.profile), compress=a.compress,
            bundle=bool(a.bundle), bundle_name=a.bundle or "", obfuscate=a.obfuscate, shred=a.shred,
            shred_passes=a.passes, verify=a.verify, output_dir=Path(a.out) if a.out else None,
        )
        return _run_job(jm, jm.submit_encrypt(srcs, creds, opts, allow_weak=a.allow_weak))
    if a.cmd == "unlock":
        creds = engine.Credentials(_password(confirm=False), a.keyfile)
        opts = JobOptions(output_dir=Path(a.out) if a.out else None, overwrite=a.overwrite)
        return _run_job(jm, jm.submit_decrypt(srcs, creds, opts))
    if a.cmd == "verify":
        creds = engine.Credentials(_password(confirm=False), a.keyfile)
        rc = 0
        for p in a.paths:
            try:
                meta = engine.verify(p, creds)
                print(f"OK    {p}  ({meta.get('name')}, every block authenticated)")
            except VaultLockError as e:
                rc = 1
                print(f"FAIL  {p}: {e}", file=sys.stderr)
        return rc
    return 1


def _rekey(a) -> int:
    src = Path(a.vault)
    old = engine.Credentials(os.environ.get("VAULTLOCK_PASSWORD") or getpass.getpass("Current password: "), a.keyfile)
    new_pw = os.environ.get("VAULTLOCK_NEW_PASSWORD")
    if not new_pw:
        new_pw = getpass.getpass("New password: ")
        if getpass.getpass("Repeat new password: ") != new_pw:
            raise VaultLockError("Passwords do not match.")
    if strength.evaluate(new_pw).score < 2:
        raise VaultLockError("The new password is too weak. Run `vaultlock passgen` for a strong one.")
    new = engine.Credentials(new_pw, a.new_keyfile)
    dest = Path(a.out) if a.out else src.with_name(src.stem + ".rekeyed.vault")
    rep = engine.rekey(src, dest, old, new, cipher=CIPHER_BY_NAME[a.cipher] if a.cipher else None, kdf=kdfmod.preset(a.profile))
    engine.verify(dest, new)  # prove the new vault opens before anything is replaced
    if a.replace:
        os.replace(dest, src)
        dest = src
    print(f"OK    re-keyed -> {dest}  ({rep.header.cipher.label}, {rep.header.kdf.describe()})")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
