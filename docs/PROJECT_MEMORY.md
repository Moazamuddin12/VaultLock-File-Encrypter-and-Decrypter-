# VaultLock - project memory / handoff notes

Last updated: 2026-10-25. Update this file whenever a milestone lands.

## Goal
Local-first file encryption app (personal use + GitHub showcase). Python 3.11+ core,
local Flask API, PyWebView desktop shell, glassmorphism vanilla-JS UI.
The user's original brief was cut off at "PROPOSED PROJECT STRUCTURE", so the layout below is my own design.

## Environment facts (cloud sandbox)
- Python 3.13, cryptography 50.x (has native Argon2id), Flask 3.1, argon2-cffi, pycryptodome, pywebview, pytest installed.
- No tkinter. Node 22 available. Project root: /home/claude/VaultLock
- Set `vaultlock.core.kdf.ENFORCE_MINIMUMS = False` in tests/scripts to use cheap KDF params.

## Layout
```
vaultlock/
  core/      errors, memory (SecretBytes, wipe, mlock), kdf, keyfile, format, stream, fsutil, archive, engine
  services/  strength (+data/ wordlists), shredder, staging, fsbrowser, system, jobs
  config.py  validated settings store
  server/    (TODO) Flask API
  web/       (TODO) index.html, css/, js/
  desktop.py / cli.py / __main__.py (TODO)
tests/ docs/ tools/
```

## Crypto design (implemented + smoke-tested)
- Header 100 B: magic `VLCK`, version, cipher id, kdf id, flags(keyfile bit), chunk size,
  KDF params (a,b,c), salt 32, nonce base 12, key-check = HMAC-SHA256(mac_key, first 68 B).
- Key schedule: password (NFKC) [+ keyfile SHA-512 bound via HMAC] -> Argon2id/PBKDF2 -> HKDF-Expand -> enc_key, mac_key.
- Chunk 0 = encrypted fixed 4096 B JSON metadata (name, kind, size, mtime...), then data chunks (default 1 MiB).
- STREAM construction: nonce = base XOR index; AAD = whole header + index + final-flag.
  Detects reorder, drop, truncation, append, header edits. Verified by tests.
- Folder vaults: tar streamed straight into encryptor (no plaintext temp). Symlinks skipped. Extraction validates members.
- Optional zlib compression inside the encryption. Writes go to hidden `.partial` then atomic publish.
- Presets: standard (64 MiB), strong (256 MiB, default), paranoid (1 GiB), pbkdf2 (1M iters).
- Memory hygiene is best-effort only (Python); document honestly in SECURITY.md.

## Status
DONE and smoke-tested: core/*, engine (file/dir/bundle/keyfile/compress/verify/inspect/in-memory/list),
strength meter, shredder (1/3/7 passes, tested via hard link), settings, staging, fsbrowser, jobs.
Jobs fully verified: encrypt+verify+shred, decrypt, wrong password, weak password, cancel mid-flight
(original kept, no leftovers), live speed/ETA (~750 MB/s ChaCha20 on the sandbox).

## LATEST STATUS (2026-10-25 evening) - project is feature-complete
- 104 tests passing: test_crypto, test_engine, test_jobs_and_services, test_server, test_cli_main, test_ui_e2e (Playwright; self-skips).
- Added since last note: engine.rekey() + `vaultlock rekey [--replace]` (streams old->new vault, verifies new before replacing);
  tests/test_ui_e2e.py; CSP tightened to script-src 'self' only (removed leftover unpkg.com) + regression test.
- Run my tests by NAME (the 3 foreign test files still fail to import): 
  python -m pytest tests/test_crypto.py tests/test_engine.py tests/test_jobs_and_services.py tests/test_server.py tests/test_cli_main.py tests/test_ui_e2e.py
- Still untested: native PyWebView window (no GUI in sandbox), Windows/macOS. No rekey button in the UI yet (CLI/engine only).

## WINDOWS / VS CODE PASS (2026-10-25 night)
Trigger: user's `python` created a POSIX-layout .venv (bin/lib/Include, no Scripts/) -> Activate.ps1 missing. Environmental, not a project bug.
Audit result: no undefined names; clean-venv NON-editable install verified on Py 3.11 + 3.12 from a path with spaces (web UI + wordlists packaged, UI served from site-packages); 104 tests pass on 3.11/3.12/3.13.
Fixes: `python run.py`/no-arg now launches the app (was argparse error); `gui` defaults to BROWSER mode, native window opt-in via `--native` (untested path, pywebview traceback noise silenced);
console encoding made non-crashing on Windows; argon2-cffi added as dependency fallback; unused imports removed; build/egg-info debris removed.
Added: start_vaultlock.bat (CRLF, repairs broken .venv, prefers `py -3`, no PowerShell policy issue), start_vaultlock.sh (tested incl. broken-venv repair), .vscode/{settings,launch,tasks}.json, README Windows/VS Code/Troubleshooting section.
NOT testable here: the .bat itself (no Windows) - reviewed by hand only.
PowerShell tips given to user: needs `.\` prefix, quote paths with spaces, `py -3 -m venv .venv`.

## TODO (in order)
1. (done) job cancel + speed/ETA verified.
2. (DONE, API smoke-tested: auth/origin/upload/encrypt/preview/decrypt) server/app.py: 127.0.0.1 only, random port, per-session token, Host/Origin checks, CSP, no-store, upload staging, SSE or polling for jobs, preview endpoint (in-memory, serve with nosniff, never HTML), clear-secrets endpoint.
3. (DONE: launcher.py, desktop.py, cli.py, __main__.py written; CLI not yet tested) desktop.py (PyWebView; native file dialogs), cli.py (encrypt/decrypt/inspect/verify/shred/keygen/passgen), __main__.py.
4. (DONE + verified with Playwright: lock/preview/unlock/wrong-pw/settings/mobile, 0 console errors; screenshots in scratchpad/shots) Frontend: dark glassmorphism, drag-drop, file cards, strength meter, keyfile toggle, progress (%, MB/s, ETA), sounds/haptics toggle, secure viewer, settings, in-app file browser. Lucide via CDN (pin version + SRI) or inline SVG.
5. (DONE: 99 tests passing; README, FORMAT.md, SECURITY.md, pyproject, LICENSE, CI written) tests/ (pytest: format tamper, kdf bounds, archive traversal, shredder, jobs, API), docs/FORMAT.md, SECURITY.md (threat model, limits: SSD shredding, Python memory), README, LICENSE, pyproject.toml, requirements, CI workflow.
6. (DONE) Final: run full tests, launch server and screenshot UI with Playwright, then summarize.

## Frontend facts
- Files: web/index.html, web/css/style.css, web/js/app.js, web/js/icons.js (inline SVG icons; CSP forbids CDNs, so NO Lucide CDN).
- Design: obsidian glass, ambient drifting gradient, signature 'dial' (drop target + progress ring), accent themes via data-accent.
- Browser mode: dropped files are uploaded to staging (shredded after use); folders need 'Add folder' (in-app server-side browser).
- UI test script lives in scratchpad (ui_test.py); port its flow into tests/test_ui_e2e.py (skip if playwright missing).

## Measured (real production params)
Argon2id derive: standard 0.16s, strong 0.79s, paranoid 4.6s, pbkdf2 0.52s. 1 GiB: AES-GCM 355/454 MB/s enc/dec, ChaCha 450/480.
2 GiB file peaks ~97 MiB RSS (incl. 64 MiB Argon2).

## Files NOT written by me (appeared overnight 2026-10-25 01:32-01:44, left untouched)
- web/fonts/* (Bricolage Grotesque, Geist, Lucide licenses), web/favicon.svg, web/js/{api,dialogs,dom,picker,settings,sound,viewer}.js
  (none are loaded by my index.html, which uses app.js + icons.js), run.py, requirements-dev.txt,
  tests/test_api.py, test_cli.py, test_services.py, and a modified services/strength.py (my 99 tests pass against it).
- Looks like a second, parallel frontend/test attempt. Decide: keep, merge, or delete.

## Open items / for the user
- tests/test_api.py, test_cli.py, test_services.py (timestamped 01:44 Oct 25) were NOT written by me; they target a different API (X-VaultLock-Token, create_app(port=), /api/ping, conftest CHEAP/PW). They fail to import. Left untouched; ask user whether to delete or port.
- Not done: tests/test_ui_e2e.py (Playwright flow exists only as a scratch script), native PyWebView window untested (no GUI in sandbox), Windows/macOS untested.
- Nice-to-haves: UI button for rekey, i18n, drag-out of decrypted files, key-file backup QR, PyInstaller/briefcase packaging.

## Gotchas learned
- Playwright wait_for_function with a JS string is blocked by our CSP (no unsafe-eval): use locator.filter(has_text=...).wait_for().
- Test for rekey: new vault with keyfile -> old creds raise MissingCredentialError (keyfile check comes first), not AuthenticationError.
- Tests that hit the API must pass `home=tmp` AND set options.output_dir, else vaults land in ~/VaultLock.
- web/index.html currently a STUB with placeholders __VL_TOKEN__/__VL_VERSION__/__VL_NATIVE__ (server substitutes them). Frontend reads token from page; UI calls /api/* with header X-VL-Token.
- Preview CSP set per-response; global hardening uses setdefault.
- `SecretBytes.take()` is the way to move bytes into a protected buffer (no `take_immutable`).
- Zero-length data: encrypt still writes one empty final chunk.
- Symlinked files must be checked with `is_symlink()` before `lstat` in archive.collect.
