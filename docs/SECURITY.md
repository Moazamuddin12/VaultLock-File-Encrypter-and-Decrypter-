# Security model

## What VaultLock protects against

* **Someone who gets a copy of your vault** (stolen laptop, cloud-storage breach, lost USB stick). Contents and file names are encrypted and authenticated; the attacker's only route is guessing your password (and needs your keyfile, if one was used).
* **Offline password guessing.** Argon2id with 64 MiB to 1 GiB of memory per guess (default 256 MiB, t=4) makes GPU/ASIC attacks expensive. A 6-word passphrase (~75 bits) or a 16+ character random password is out of reach.
* **Tampering and corruption.** Any change, truncation, reordering or extension is detected before plaintext is released. Wrong passwords fail early and cleanly.
* **Other programs and web pages on your machine** probing the local UI server: loopback only, random port, per-launch token, exact `Host` check, `Origin` check, strict CSP, no CORS.

## What it does not protect against

* **Malware or a keylogger on your computer** while you type the password or while a file is decrypted. No file encryptor can.
* **Weak passwords.** The strength meter is a guide, not a guarantee.
* **A forgotten password or lost keyfile.** There is no backdoor and no recovery. This is a feature.
* **Metadata outside the vault**: the vault's size (to within a chunk), its file name on disk (unless you enable random names), timestamps, and the fact that you use VaultLock.
* **Coercion** (rubber-hose attacks). There is no plausible-deniability or hidden-volume mode.

## Design decisions

| Choice | Reason |
|---|---|
| AES-256-GCM or ChaCha20-Poly1305 via `cryptography` (OpenSSL) | audited, constant-time, hardware accelerated |
| Argon2id, 256 MiB default | memory-hard; PBKDF2 (1M iterations) offered for FIPS-style environments |
| Per-vault 32-byte salt and 12-byte nonce base | no key or nonce ever repeats across vaults |
| One AEAD chunk per 1 MiB with index/last-flag binding | streaming with O(chunk) memory and full truncation resistance |
| Key check in the header | instant, exact "wrong password" without trial-decrypting data |
| Key separation with HKDF | the MAC key and encryption key are independent |
| Write to `.partial`, fsync, atomic publish | crashes, cancels and bad passwords never leave half-written files under real names |
| Verify before shred | originals are destroyed only after the new vault is re-read and every block authenticates |
| No plaintext temp files | folders are tar-streamed straight into the encryptor; previews live in RAM |
| Symlinks skipped, extraction validated | a vault can neither pull in files from outside the folder nor write outside the destination |

## Honest limits of "zero-trace" memory

Python cannot guarantee erasure. VaultLock does what is possible:

* key material lives in mutable, `mlock`-ed buffers that are zeroed after use;
* derived keys and decrypted chunks (immutable `bytes`) are zeroed in place with a self-verified CPython routine (`core/memory.py`; disabled automatically on other interpreters);
* plaintext working buffers are scrubbed before being released.

What remains outside our control: the password as a Python `str` typed into the browser engine and sent over loopback, interpreter free-lists, swap files and hibernation images, and copies made by the OS or the web view. Use full-disk encryption and disable hibernation if this matters to you. Auto-clear (Settings) and *Clear now* wipe the UI fields and server-side staged data.

## Shredder limits

Overwriting a file in place destroys it **only** on filesystems that rewrite the same blocks (classic HDD with ext4/NTFS non-journaled data). On **SSD/NVMe** (wear levelling), **copy-on-write or journaled filesystems** (APFS, btrfs, ZFS), **snapshots / shadow copies**, **backups** and **cloud-synced folders**, old copies can survive. For those, rely on full-disk encryption (so deleted data is already ciphertext) and TRIM / ATA Secure Erase. The UI says this wherever shredding is offered.

## Reporting a vulnerability

Please open a private security advisory on the repository rather than a public issue. Include the vault (or a minimal reproduction) and your Python / OS versions.
