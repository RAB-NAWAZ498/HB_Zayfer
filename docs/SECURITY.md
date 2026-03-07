# Security Model

This document describes the security design of HB_Zayfer, the threat model,
algorithm choices, and responsible disclosure policy.

---

## Threat Model

HB_Zayfer is designed to protect data **at rest** and **in transit** against:

- **Unauthorized access** to encrypted files or messages.
- **Tampering** with ciphertext (detected via AEAD authentication).
- **Chunk reordering/truncation** in the HBZF streaming format.
- **Brute-force passphrase attacks** (mitigated by memory-hard KDFs).
- **Key compromise on disk** (private keys encrypted with AES-256-GCM + Argon2id).

### Out of Scope

- Side-channel attacks on the host (e.g., CPU cache timing, EM emissions).
  The RustCrypto implementations aim for constant-time operations where
  possible, but this is not formally verified.
- Compromise of the operating system or hardware root of trust.
- Availability attacks (DoS) on the web interface.

---

## Algorithm Selection

### Symmetric Encryption

| Algorithm | Key Size | Nonce | Tag | Standard |
|-----------|----------|-------|-----|----------|
| AES-256-GCM | 256 bit | 96 bit | 128 bit | NIST SP 800-38D |
| ChaCha20-Poly1305 | 256 bit | 96 bit | 128 bit | RFC 8439 |

Both provide authenticated encryption with associated data (AEAD).
AES-256-GCM is the default; ChaCha20-Poly1305 is offered as an alternative
that performs well on hardware without AES-NI.

### Asymmetric Encryption

| Algorithm | Operation | Standard |
|-----------|-----------|----------|
| RSA-2048 / RSA-4096 (OAEP SHA-256) | Key wrapping | PKCS#1 v2.2 |
| X25519 (ECDH) + HKDF-SHA256 | Key agreement | RFC 7748, RFC 5869 |

RSA-OAEP is used only to encrypt the per-file symmetric key (not bulk data).
X25519 is preferred for new deployments.

### Digital Signatures

| Algorithm | Operation | Standard |
|-----------|-----------|----------|
| RSA-PSS (SHA-256, blinded) | Signing | PKCS#1 v2.2, FIPS 186-5 |
| Ed25519 | Signing | RFC 8032 |
| OpenPGP (Sequoia) | Signing | RFC 4880bis |

RSA-PSS uses `BlindedSigningKey` to resist timing side-channels.

### Key Derivation

| Algorithm | Default Parameters | Standard |
|-----------|-------------------|----------|
| Argon2id | m=64 MiB, t=3, p=1 | RFC 9106 (winner of PHC) |
| scrypt | log_n=15 (32 MiB), r=8, p=1 | RFC 7914 |

Argon2id is the recommended default. It provides resistance against both
GPU/ASIC attacks (memory-hard) and side-channel attacks (data-independent
in the first pass, data-dependent in subsequent passes).

---

## Key Material Handling

### Zeroization

All secret key types implement `Zeroize` and/or `ZeroizeOnDrop`:

- `Ed25519KeyPair.signing_key` → signing key seed bytes zeroed on drop.
- `X25519KeyPair.secret_key` → secret bytes zeroed on drop.
- `DerivedKey.key` → derived key bytes zeroed on drop.
- RSA private keys use the `rsa` crate's internal zeroize support.

### Private Key Encryption at Rest

Private keys are stored in a **versioned envelope** (v2):

```
[1B]  Envelope version: 0x02
[1B]  KDF algorithm ID
[12B] KDF parameters (embedded, immune to config drift)
[16B] Random salt
[12B] Random nonce
[…]   AES-256-GCM ciphertext of the raw private key
```

AAD for the AES-GCM encryption is the key's fingerprint, binding the
ciphertext to its identity.

### File System Permissions

On Unix systems:

- `~/.hb_zayfer/keys/private/` directory: `0o700`
- Individual `.key` files: `0o600`

These are set programmatically. Users should verify their umask settings.

---

## HBZF File Format Security

### Nonce Management

- A random 96-bit **base nonce** is generated per file.
- Per-chunk nonces are derived by XOR-ing the chunk index (64-bit LE) into
  bytes 4..12 of the base nonce.
- This guarantees unique nonces for up to $2^{64}$ chunks per file without
  requiring nonce storage per chunk.

### Chunk Integrity

- Each 64 KiB chunk is independently authenticated with a 128-bit AEAD tag.
- The **chunk index** is appended to the AAD for each chunk, preventing:
  - **Reordering**: swapping chunk positions is detected.
  - **Duplication**: replaying a chunk at a different position fails.
  - **Truncation**: the final plaintext length is recorded in the header and
    verified post-decryption.

### Malicious Input Protection

- Maximum encrypted chunk size is capped at `CHUNK_SIZE + 16` bytes.
  Any larger chunk length in the file header causes an immediate error,
  preventing memory exhaustion from crafted files.

---

## Web Interface Security

### Authentication

- Optional bearer-token authentication via `HB_ZAYFER_API_TOKEN`.
- Static files and docs are explicitly exempt from auth.
- When enabled, all `/api/*` endpoints require the correct token.

### CORS

- Restricted to `http://localhost:8000` and `http://127.0.0.1:8000`.
- The web server binds to `127.0.0.1` by default (not `0.0.0.0`).

### Recommendations

- **Always set `HB_ZAYFER_API_TOKEN`** in any environment where the web
  interface may be reachable by other users on the network.
- **Do not expose** the web interface to the public internet without
  additional hardening (TLS termination, rate limiting, IP allowlisting).
- Passphrases are transmitted in request bodies. Use HTTPS in production.

---

## Cryptographic Library Provenance

All cryptographic primitives are sourced from established, audited libraries:

| Functionality | Rust Crate | Notes |
|---------------|------------|-------|
| AES-256-GCM | `aes-gcm` 0.10 | RustCrypto project |
| ChaCha20-Poly1305 | `chacha20poly1305` 0.10 | RustCrypto project |
| RSA | `rsa` 0.9 | RustCrypto project |
| Ed25519 | `ed25519-dalek` 2.x | Dalek cryptography |
| X25519 | `x25519-dalek` 2.x | Dalek cryptography |
| Argon2 | `argon2` 0.5 | RustCrypto project |
| scrypt | `scrypt` 0.11 | RustCrypto project |
| HKDF | `hkdf` 0.12 | RustCrypto project |
| SHA-256 | `sha2` 0.10 | RustCrypto project |
| OpenPGP | `sequoia-openpgp` 2.x | Sequoia PGP |
| Randomness | `rand` 0.8 / `rand_core` 0.6 | OS CSPRNG (`getrandom`) |
| Zeroization | `zeroize` 1.x | RustCrypto project |

No custom cryptographic implementations are used. All random numbers come
from the operating system's CSPRNG via `getrandom`.

---

## Security Recommendations for Users

1. **Choose strong passphrases.** The Argon2id KDF protects against
   brute-force, but a weak passphrase still compromises security.

2. **Prefer X25519 or Ed25519** for new key pairs. RSA is supported for
   compatibility but offers no advantage for new deployments.

3. **Back up your keystore.** If `~/.hb_zayfer/keys/private/` is lost,
   encrypted data cannot be recovered.

4. **Verify fingerprints** out-of-band when exchanging public keys to
   prevent man-in-the-middle key substitution.

5. **Keep dependencies updated.** Run `cargo update` periodically to pick
   up security patches in cryptographic crates.

6. **Use the web interface locally only** unless you configure TLS and
   bearer-token authentication.

---

## Responsible Disclosure

If you discover a security vulnerability in HB_Zayfer, please report it
responsibly:

1. **Do not** open a public GitHub issue.
2. Email the maintainers with details of the vulnerability, reproduction
   steps, and any suggested fixes.
3. Allow a reasonable period (90 days) for a fix before public disclosure.

We will credit reporters in the release notes (unless anonymity is requested).
