# Architecture

This document describes the internal architecture of HB_Zayfer, a full-featured
encryption/decryption suite built with a **Rust core** and **Python bindings**
(via PyO3).

---

## High-Level Overview

```
┌──────────────────── User Interfaces ─────────────────────┐
│                                                          │
│   Rust CLI          Python CLI          Desktop GUI      │
│   (clap)            (Click + Rich)      (PySide6)        │
│                                                          │
│                     Web UI (FastAPI + vanilla JS)         │
│                                                          │
├──────────────── Python Bindings (PyO3) ──────────────────┤
│                                                          │
│   hb_zayfer._native    (crates/python — cdylib)          │
│                                                          │
├──────────────────── Rust Core Library ───────────────────┤
│                                                          │
│   hb_zayfer_core       (crates/core — rlib)              │
│                                                          │
│   ┌─────────┐ ┌───────────┐ ┌───────┐ ┌─────────┐       │
│   │ aes_gcm │ │ chacha20  │ │  rsa  │ │ ed25519 │       │
│   └─────────┘ └───────────┘ └───────┘ └─────────┘       │
│   ┌─────────┐ ┌───────────┐ ┌───────┐ ┌─────────┐       │
│   │ x25519  │ │  openpgp  │ │  kdf  │ │ format  │       │
│   └─────────┘ └───────────┘ └───────┘ └─────────┘       │
│   ┌──────────┐ ┌─────────┐                               │
│   │ keystore │ │  error  │                               │
│   └──────────┘ └─────────┘                               │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Workspace Crates

The Cargo workspace (`Cargo.toml`) contains three crates:

| Crate | Path | Type | Purpose |
|-------|------|------|---------|
| `hb_zayfer_core` | `crates/core` | `rlib` | All cryptographic operations, file format, and key storage |
| `hb_zayfer_cli` | `crates/cli` | `bin` | Rust-native CLI (clap + dialoguer + indicatif) |
| `hb_zayfer_python` | `crates/python` | `cdylib` | PyO3 bindings → `hb_zayfer._native` |

### Dependency Flow

```
hb_zayfer_cli ──────┐
                     ├──► hb_zayfer_core
hb_zayfer_python ───┘
```

Both the CLI and the Python bindings depend exclusively on `hb_zayfer_core`.
The core crate has **no** dependency on the other two.

---

## Core Library Modules

### `aes_gcm` — AES-256-GCM

- Encrypt/decrypt with 256-bit keys, 96-bit nonces, 128-bit tags.
- `encrypt_chunk` / `decrypt_chunk` for streaming with nonce-index XOR.
- Uses the RustCrypto `aes-gcm` crate.

### `chacha20` — ChaCha20-Poly1305

- Mirror API to `aes_gcm`: same key/nonce/tag sizes.
- Streaming chunk support with identical nonce derivation scheme.
- Uses the RustCrypto `chacha20poly1305` crate.

### `rsa` — RSA-OAEP & RSA-PSS

- Key generation at 2048 or 4096 bits.
- Encryption: RSA-OAEP with SHA-256 padding.
- Signing: RSA-PSS with SHA-256, blinded for side-channel resistance.
- Key serialization: PKCS#1 PEM and PKCS#8 PEM (import/export).
- Fingerprint: SHA-256 of DER-encoded public key.

### `ed25519` — Ed25519 Signatures

- Key generation via `ed25519-dalek`.
- Sign/verify with 64-byte signatures.
- Key serialization: PKCS#8 PEM and raw 32-byte formats.
- Signing key bytes are zeroized on drop.

### `x25519` — X25519 ECDH Key Agreement

- Static and ephemeral key pair generation.
- `encrypt_key_agreement`: ephemeral ECDH + HKDF-SHA256 → 32-byte symmetric key.
- `decrypt_key_agreement`: recipient-side derivation.
- Raw 32-byte key import/export.
- Secret key bytes zeroized on drop.

### `openpgp` — OpenPGP (Sequoia)

- Certificate generation with signing, transport-encryption, and storage-encryption subkeys.
- ASCII-armored import/export (public and secret keys).
- Encrypt to multiple recipients.
- Decrypt with secret key (via `DecryptionHelper`).
- Inline signing and signature verification.

### `kdf` — Key Derivation Functions

- **Argon2id**: default (m=64 MiB, t=3, p=1).
- **Scrypt**: alternative (log_n=15, r=8, p=1).
- `generate_salt(len)`: OS CSPRNG salt.
- `derive_key(passphrase, salt, params) → 32 bytes`.
- Derived key material is zeroized on drop (`DerivedKey`).

### `format` — HBZF Streaming AEAD

The custom binary format for file encryption:

```
[4B]  Magic:   "HBZF"
[1B]  Version: 0x01
[1B]  Symmetric algorithm ID:  0x01=AES, 0x02=ChaCha
[1B]  KDF algorithm ID:        0x00=none, 0x01=Argon2id, 0x02=scrypt
[1B]  Key wrapping mode:       0x00=password, 0x01=RSA-OAEP, 0x02=X25519
[var] KDF params (if KDF≠none): salt(16B) + params(12B)
[var] Wrapped key (RSA-OAEP) or ephemeral pubkey (X25519)
[12B] Base nonce
[8B]  Original plaintext length (LE u64)
[var] Stream of chunks: [4B chunk_len_le][chunk_ciphertext]
```

**Chunk encryption**: 64 KiB plaintext → append 16-byte AEAD tag.
Nonce derived by XOR-ing chunk index into the last 8 bytes of the base nonce.
Chunk index is also appended to AAD to prevent chunk reordering.

**Decryption**: malicious chunk sizes capped at `CHUNK_SIZE + 16` to prevent OOM.
Plaintext length verified post-decryption to detect truncation.

### `keystore` — Key & Contact Storage

On-disk layout at `~/.hb_zayfer/` (or `$HB_ZAYFER_HOME`):

```
~/.hb_zayfer/
├── keys/
│   ├── private/<fingerprint>.key  (v2 envelope: KDF params + AES-GCM encrypted)
│   └── public/<fingerprint>.pub   (plaintext key material)
├── keyring.json       (KeyMetadata index)
├── contacts.json      (Contact ↔ key associations)
└── config.toml        (optional app config)
```

**Private key envelope v2** embeds the KDF algorithm and parameters so
decryption works even if the global defaults change later:

```
[1B]  envelope version (0x02)
[1B]  KDF algorithm ID
[12B] KDF params (same layout as HBZF header)
[16B] salt
[12B] nonce
[…]   AES-256-GCM ciphertext
```

Unix file permissions: `0o700` on `keys/private/` dir, `0o600` on `.key` files.

### `error` — Error Types

`HbError` is a `thiserror::Error` enum covering all failure modes:
crypto failures, key not found, invalid passphrase, authentication failure,
I/O, serialization, contacts, and format errors.

`HbResult<T>` is the crate-wide `Result` alias.

---

## Python Layer

### PyO3 Bindings (`crates/python`)

- Every public function in `hb_zayfer._native` maps to one or more core functions.
- Heavy crypto (RSA keygen, KDF, encrypt/decrypt) releases the GIL via `py.detach()`.
- Key interchange formats: RSA/Ed25519 → PEM strings; X25519 → raw `bytes`; PGP → ASCII armor.
- `KeyStore`, `KeyMetadata`, and `Contact` are Python classes wrapping their Rust counterparts.

### Public Python API (`python/hb_zayfer/__init__.py`)

Re-exports all `_native` symbols into the top-level `hb_zayfer` namespace.
Type stubs in `_native.pyi` (PEP 561 compliant with `py.typed` marker).

### Click CLI (`python/hb_zayfer/cli.py`)

Entry point: `hb-zayfer`. Subcommands: `keygen`, `encrypt`, `decrypt`, `sign`,
`verify`, `keys list/import/export/delete`, `contacts list/add/remove`.
Uses `rich` for colored output and status spinners.

### PySide6 GUI (`python/hb_zayfer/gui/`)

Six-view sidebar navigation in a `QMainWindow`:

1. **Encrypt** — file/text encryption with algorithm & recipient selection.
2. **Decrypt** — file/text decryption.
3. **Key Generation** — generate keys of any supported algorithm.
4. **Keyring** — browse, export, and delete stored keys.
5. **Contacts** — manage contact-to-key associations.
6. **Settings** — default algorithm, KDF parameters, keystore path.

Long-running operations dispatched to worker threads (Qt `QThread`).

### FastAPI Web UI (`python/hb_zayfer/web/`)

- `POST /api/encrypt/text`, `POST /api/decrypt/text` — password-based text encrypt/decrypt.
- `POST /api/keygen` — generate and store keys.
- `POST /api/sign`, `POST /api/verify` — sign/verify messages.
- `GET /api/keys`, `DELETE /api/keys/{fp}` — key management.
- `GET /api/contacts`, `POST /api/contacts`, `DELETE /api/contacts/{name}` — contacts.
- `POST /api/contacts/link` — associate key with contact.
- Static SPA served from `web/static/` (HTML + JS + CSS).
- Optional bearer-token auth via `HB_ZAYFER_API_TOKEN`.
- CORS restricted to localhost origins.

---

## Security Design Decisions

| Concern | Approach |
|---------|----------|
| Memory safety | Rust core; no `unsafe` in application code |
| Key material | `zeroize` on drop for signing/secret keys |
| Nonce reuse | Random 96-bit nonce per message; chunk nonce derived from base + index |
| Chunk reordering | Chunk index in AAD prevents reorder/truncation |
| Password hashing | Argon2id default (64 MiB memory, 3 iterations) |
| Side channels | `BlindedSigningKey` for RSA-PSS |
| File permissions | `0o700` / `0o600` on private key storage (Unix) |
| API auth | Optional bearer token for web interface |

---

## Data Flow: File Encryption

```
User provides: plaintext file, wrapping mode, passphrase or recipient

  1. [KDF / ECDH / RSA-OAEP]  →  32-byte symmetric key
  2. Generate random 12-byte base nonce
  3. Write HBZF header (magic, version, params, nonce, …)
  4. Read plaintext in 64 KiB chunks
     For each chunk i:
       a. Derive chunk nonce: base_nonce XOR (i as LE u64) in bytes 4..12
       b. AAD = [algo_id, wrapping_id] ++ chunk_index_LE
       c. AEAD encrypt chunk → ciphertext (64 KiB + 16 B tag)
       d. Write [4B chunk_len_LE][ciphertext]
  5. Flush output
```

---

## Testing Strategy

- **Rust unit tests**: each crypto module has its own `#[cfg(test)]` block.
- **Rust integration tests**: `crates/core/tests/integration.rs` (31 tests).
- **Python binding tests**: `tests/python/test_crypto.py` — exercises every
  `hb_zayfer` API through the PyO3 bridge.
- **Web API tests**: `tests/python/test_web.py` — FastAPI route tests via `httpx`.
- **CI**: GitHub Actions on Linux/macOS/Windows; Rust fmt+clippy+test, Python maturin+pytest.
