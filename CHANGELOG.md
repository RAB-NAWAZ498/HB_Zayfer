# Changelog

All notable changes to HB_Zayfer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-03-06

### Added

- **Rust core library** (`hb_zayfer_core`):
  - AES-256-GCM symmetric encryption with streaming chunk support.
  - ChaCha20-Poly1305 symmetric encryption with streaming chunk support.
  - RSA-2048/4096 key generation, OAEP encryption, PSS signing.
  - Ed25519 key generation, signing, and verification.
  - X25519 ECDH key agreement with HKDF-SHA256 derivation.
  - OpenPGP certificate generation, encrypt/decrypt, sign/verify (via Sequoia).
  - Argon2id and scrypt password-based key derivation.
  - HBZF streaming file encryption format (v1) with 64 KiB chunks.
  - On-disk keystore with encrypted private keys (v2 envelope).
  - Contact management with key association.
  - Unified error types (`HbError`).

- **Rust CLI** (`hb_zayfer_cli`):
  - `keygen`, `encrypt`, `decrypt`, `sign`, `verify` commands.
  - `keys list/export/import/delete` subcommands.
  - `contacts list/add/remove` subcommands.
  - Progress bars and interactive passphrase prompts.

- **Python bindings** (PyO3):
  - Full exposure of all core operations as `hb_zayfer._native`.
  - GIL-releasing for heavy crypto operations.
  - PEP 561 type stubs (`_native.pyi` + `py.typed`).

- **Python CLI** (Click + Rich):
  - `hb-zayfer` entry point with all commands.
  - Colored output, status spinners, table formatting.

- **Desktop GUI** (PySide6):
  - Six-view sidebar: Encrypt, Decrypt, Key Gen, Keyring, Contacts, Settings.
  - Threaded workers for responsive UI.

- **Web interface** (FastAPI + vanilla JS):
  - REST API for text encrypt/decrypt, keygen, sign/verify, keys, contacts.
  - Static SPA frontend.
  - Optional bearer-token authentication.
  - CORS restricted to localhost.

- **Testing**:
  - 31 Rust integration tests.
  - Comprehensive Python binding tests (`test_crypto.py`).
  - FastAPI route tests (`test_web.py`).

- **CI** (GitHub Actions):
  - Multi-platform Rust builds (Linux, macOS, Windows).
  - Python test matrix (3.11 + 3.12).

- **Documentation**:
  - Full documentation suite (architecture, API reference, CLI, web/GUI,
    security model, HBZF format spec, contributing guide).
