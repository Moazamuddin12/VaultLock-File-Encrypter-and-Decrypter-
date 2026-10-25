# The `.vault` container format (version 1)

All integers are big-endian. A vault is a 100-byte plaintext header, one sealed metadata block, then one or more sealed data chunks.

```
offset  size  field
0       4     magic            "VLCK"
4       1     version          1
5       1     cipher id        1 = AES-256-GCM, 2 = ChaCha20-Poly1305
6       1     kdf id           1 = Argon2id,    2 = PBKDF2-HMAC-SHA256
7       1     flags            bit0 = a keyfile is required (other bits must be 0)
8       4     chunk size       plaintext bytes per data chunk (4 KiB .. 16 MiB)
12      4     kdf param a      Argon2id: time cost t      | PBKDF2: iterations
16      4     kdf param b      Argon2id: memory in KiB    | PBKDF2: 0
20      1     kdf param c      Argon2id: parallelism      | PBKDF2: 0
21      3     reserved         must be zero
24      32    salt             random, unique per vault
56      12    nonce base       random, unique per vault
68      32    key check        HMAC-SHA256(mac_key, bytes 0..67)
```

The header is exactly 100 bytes. The normative definition is `vaultlock/core/format.py`.

```
100     4112  metadata chunk   AEAD( 4096 B padded JSON ) || 16 B tag      (chunk index 0)
4212    ...   data chunks      AEAD( <= chunk_size bytes ) || 16 B tag     (indices 1..N)
```

## Key schedule

```
secret  = "P" || NFKC(password)                              password only
        = "K" || HMAC-SHA256(key = SHA-512(keyfile), msg = NFKC(password))   with keyfile

master  = Argon2id(secret, salt, t, m, p) -> 32 B     (or PBKDF2-HMAC-SHA256)
enc_key = HKDF-Expand-SHA256(master, "VaultLock v1 / encryption key", 32)
mac_key = HKDF-Expand-SHA256(master, "VaultLock v1 / header MAC key", 32)
```

The keyfile is bound with an HMAC keyed by the keyfile digest, so a password guess cannot be tested without holding the keyfile.

## Chunk sealing (STREAM construction)

For chunk `i` (0 = metadata):

```
nonce = nonce_base XOR i                          (96-bit big-endian)
aad   = header(100 B) || i (8 B) || is_last (1 B)
chunk = AEAD_Encrypt(enc_key, nonce, aad, plaintext)      -> ciphertext || 16 B tag
```

Consequences, each covered by a test in `tests/test_crypto.py`:

| Attack | Why it fails |
|---|---|
| Edit any header byte | header is in every chunk's AAD, and in the key-check |
| Reorder chunks | the index is in nonce and AAD |
| Drop trailing chunks | the new last chunk was not sealed with `is_last = 1` |
| Append data | the previous last chunk was sealed with `is_last = 1` |
| Swap a header from another vault | different salt gives different keys, so the key check or tags fail |
| Wrong password or keyfile | key check fails *before* any data is touched |

The final chunk is always present and may be empty (an empty file is a header, a metadata block and one 16-byte tag).

## Metadata

A fixed 4096-byte block (length-prefixed JSON, zero padded) so the file name length is not revealed:
`name, kind (file|dir|bundle), size, entries, mtime, mode, compress (none|zlib), created, app`.

Folders and bundles are a `tar` (PAX) stream written directly into the encryptor. With `compress = zlib`, a zlib stream sits *inside* the encryption (never compress after encrypting, and never mix attacker-controlled data with secrets in one compressed stream: here the stream holds only the user's own files).

## Overhead

`100 + 4112 + 16 * ceil(size / chunk_size)` bytes; about 0.0015% at the default 1 MiB chunk size.

## Compatibility

Readers must reject unknown versions, ciphers, KDF ids, non-zero reserved bytes and unknown flag bits rather than guess. KDF parameters read from a file are bounds-checked before use so a hostile vault cannot demand terabytes of RAM.
