# Python API Reference

Complete reference for the `hb_zayfer` Python package — the public API exposed
via PyO3 bindings to the Rust core.

All heavy cryptographic operations release the GIL and run in native Rust.

---

## Installation

```bash
# Build from source (requires Rust ≥ 1.75 + Maturin)
maturin develop --release

# Install with extras
pip install -e ".[all]"       # CLI + GUI + Web + dev
pip install -e ".[cli]"       # Click CLI only
pip install -e ".[gui]"       # + PySide6 desktop
pip install -e ".[web]"       # + FastAPI web server
pip install -e ".[dev]"       # + pytest, httpx
```

---

## Module: `hb_zayfer`

All symbols are imported from the native extension (`hb_zayfer._native`) into
the top-level namespace. Type stubs are provided in `_native.pyi` (PEP 561).

```python
import hb_zayfer as hbz
```

---

## Version

```python
hbz.version() → str
```

Returns the library version string (e.g. `"0.1.0"`).

---

## Symmetric Encryption

### AES-256-GCM

```python
hbz.aes_encrypt(key: bytes, plaintext: bytes, aad: bytes) → tuple[bytes, bytes]
```

Encrypt with AES-256-GCM. Returns `(nonce, ciphertext_with_tag)`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `bytes` | 32-byte encryption key |
| `plaintext` | `bytes` | Data to encrypt |
| `aad` | `bytes` | Additional authenticated data (can be `b""`) |

```python
hbz.aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) → bytes
```

Decrypt and verify AES-256-GCM ciphertext. Returns plaintext.

**Example:**

```python
key = hbz.derive_key_argon2(b"passphrase", hbz.generate_salt(32))
nonce, ct = hbz.aes_encrypt(key, b"Hello, World!", b"")
pt = hbz.aes_decrypt(key, nonce, ct, b"")
assert pt == b"Hello, World!"
```

### ChaCha20-Poly1305

```python
hbz.chacha_encrypt(key: bytes, plaintext: bytes, aad: bytes) → tuple[bytes, bytes]
hbz.chacha_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) → bytes
```

Identical API to AES-256-GCM. Same key/nonce/tag sizes.

---

## Key Derivation Functions

### `generate_salt`

```python
hbz.generate_salt(length: int) → bytes
```

Generate `length` bytes of cryptographically secure random data.

### `derive_key_argon2`

```python
hbz.derive_key_argon2(
    passphrase: bytes,
    salt: bytes,
    m_cost: int = 65536,     # Memory in KiB (default: 64 MiB)
    t_cost: int = 3,         # Iterations
    p_cost: int = 1,         # Parallelism
) → bytes
```

Derive a 32-byte key using Argon2id.

### `derive_key_scrypt`

```python
hbz.derive_key_scrypt(
    passphrase: bytes,
    salt: bytes,
    log_n: int = 15,    # log₂(N), CPU/memory cost
    r: int = 8,         # Block size
    p: int = 1,         # Parallelism
) → bytes
```

Derive a 32-byte key using scrypt.

**Example:**

```python
salt = hbz.generate_salt(32)
key = hbz.derive_key_argon2(b"my passphrase", salt)
assert len(key) == 32
```

---

## RSA (2048 / 4096)

### Key Generation

```python
hbz.rsa_generate(bits: int) → tuple[str, str]
```

Generate an RSA key pair. `bits` must be `2048` or `4096`.
Returns `(private_pem, public_pem)` as PKCS#8 PEM strings.

### Encrypt & Decrypt (RSA-OAEP SHA-256)

```python
hbz.rsa_encrypt(public_pem: str, plaintext: bytes) → bytes
hbz.rsa_decrypt(private_pem: str, ciphertext: bytes) → bytes
```

Suitable for encrypting small payloads (e.g., symmetric keys up to ~190/446 bytes).

### Sign & Verify (RSA-PSS SHA-256)

```python
hbz.rsa_sign(private_pem: str, message: bytes) → bytes
hbz.rsa_verify(public_pem: str, message: bytes, signature: bytes) → bool
```

### Fingerprint

```python
hbz.rsa_fingerprint(public_pem: str) → str
```

SHA-256 of DER-encoded public key, hex-encoded (64 characters).

**Example:**

```python
priv_pem, pub_pem = hbz.rsa_generate(4096)
ct = hbz.rsa_encrypt(pub_pem, b"secret")
pt = hbz.rsa_decrypt(priv_pem, ct)
assert pt == b"secret"

sig = hbz.rsa_sign(priv_pem, b"document")
assert hbz.rsa_verify(pub_pem, b"document", sig)
```

---

## Ed25519 Signatures

### Key Generation

```python
hbz.ed25519_generate() → tuple[str, str]
```

Returns `(signing_pem, verifying_pem)` as PKCS#8 PEM strings.

### Sign & Verify

```python
hbz.ed25519_sign(signing_pem: str, message: bytes) → bytes
# Returns 64-byte signature

hbz.ed25519_verify(verifying_pem: str, message: bytes, signature: bytes) → bool
```

### Fingerprint

```python
hbz.ed25519_fingerprint(verifying_pem: str) → str
```

**Example:**

```python
sk, vk = hbz.ed25519_generate()
sig = hbz.ed25519_sign(sk, b"Hello Ed25519")
assert hbz.ed25519_verify(vk, b"Hello Ed25519", sig)
```

---

## X25519 ECDH Key Agreement

### Key Generation

```python
hbz.x25519_generate() → tuple[bytes, bytes]
```

Returns `(secret_raw_32, public_raw_32)` as raw 32-byte `bytes` objects.

### Key Agreement (Encrypt Side)

```python
hbz.x25519_encrypt_key_agreement(their_public: bytes) → tuple[bytes, bytes]
```

Performs ephemeral ECDH + HKDF derivation. Returns
`(ephemeral_public_32, symmetric_key_32)`.

### Key Agreement (Decrypt Side)

```python
hbz.x25519_decrypt_key_agreement(secret_raw: bytes, ephemeral_public: bytes) → bytes
```

Returns the same 32-byte symmetric key.

### Fingerprint

```python
hbz.x25519_fingerprint(public_raw: bytes) → str
```

**Example:**

```python
sk_a, pk_a = hbz.x25519_generate()
sk_b, pk_b = hbz.x25519_generate()

eph_pub, sym_a = hbz.x25519_encrypt_key_agreement(pk_b)
sym_b = hbz.x25519_decrypt_key_agreement(sk_b, eph_pub)
assert sym_a == sym_b  # Both derive same symmetric key
```

---

## OpenPGP

### Key Generation

```python
hbz.pgp_generate(user_id: str) → tuple[str, str]
```

Generate a PGP certificate. Returns `(public_armored, secret_armored)`.

### Encrypt & Decrypt

```python
hbz.pgp_encrypt(plaintext: bytes, recipient_public_keys: list[str]) → bytes
# Encrypts to all given recipient public keys (ASCII-armored)

hbz.pgp_decrypt(ciphertext: bytes, secret_key_armored: str) → bytes
```

### Sign & Verify

```python
hbz.pgp_sign(message: bytes, secret_key_armored: str) → bytes
# Returns signed message (inline signature, armored)

hbz.pgp_verify(signed_message: bytes, public_key_armored: str) → tuple[bytes, bool]
# Returns (extracted_message, is_valid)
```

### Metadata

```python
hbz.pgp_fingerprint(armored_key: str) → str
hbz.pgp_user_id(armored_key: str) → Optional[str]
```

**Example:**

```python
pub_arm, sec_arm = hbz.pgp_generate("Alice <alice@example.com>")
ct = hbz.pgp_encrypt(b"PGP message", [pub_arm])
pt = hbz.pgp_decrypt(ct, sec_arm)
assert pt == b"PGP message"
```

---

## HBZF File Format

### In-Memory Encrypt/Decrypt

```python
hbz.encrypt_data(
    plaintext: bytes,
    algorithm: str = "aes",           # "aes" or "chacha"
    wrapping: str = "password",       # "password", "rsa", or "x25519"
    passphrase: Optional[bytes] = None,
    recipient_public_pem: Optional[str] = None,
    recipient_public_raw: Optional[bytes] = None,
) → bytes

hbz.decrypt_data(
    data: bytes,
    passphrase: Optional[bytes] = None,
    private_pem: Optional[str] = None,
    secret_raw: Optional[bytes] = None,
) → bytes
```

### File Encrypt/Decrypt

```python
hbz.encrypt_file(
    input_path: str,
    output_path: str,
    algorithm: str = "aes",
    wrapping: str = "password",
    passphrase: Optional[bytes] = None,
    recipient_public_pem: Optional[str] = None,
    recipient_public_raw: Optional[bytes] = None,
) → int  # bytes written

hbz.decrypt_file(
    input_path: str,
    output_path: str,
    passphrase: Optional[bytes] = None,
    private_pem: Optional[str] = None,
    secret_raw: Optional[bytes] = None,
) → int  # bytes written
```

**Parameters for wrapping modes:**

| `wrapping` | Required parameter |
|------------|-------------------|
| `"password"` | `passphrase` |
| `"rsa"` | `recipient_public_pem` (encrypt) / `private_pem` (decrypt) |
| `"x25519"` | `recipient_public_raw` (encrypt) / `secret_raw` (decrypt) |

**Example:**

```python
# Password-based
hbz.encrypt_file("secret.pdf", "secret.pdf.hbzf",
                  algorithm="aes", wrapping="password",
                  passphrase=b"hunter2")
hbz.decrypt_file("secret.pdf.hbzf", "recovered.pdf",
                  passphrase=b"hunter2")

# RSA public-key encryption
priv_pem, pub_pem = hbz.rsa_generate(4096)
hbz.encrypt_file("data.bin", "data.hbzf",
                  wrapping="rsa", recipient_public_pem=pub_pem)
hbz.decrypt_file("data.hbzf", "data.bin",
                  private_pem=priv_pem)

# X25519 ECDH
sk, pk = hbz.x25519_generate()
hbz.encrypt_file("msg.txt", "msg.hbzf",
                  wrapping="x25519", recipient_public_raw=pk)
hbz.decrypt_file("msg.hbzf", "msg.txt",
                  secret_raw=sk)
```

---

## Utilities

```python
hbz.compute_fingerprint(public_key_bytes: bytes) → str
# SHA-256 of raw bytes, hex-encoded

hbz.detect_key_format(data: bytes) → str
# Returns one of: "pkcs8_pem", "pkcs1_pem", "der", "openpgp_armor", "openssh"
```

---

## KeyStore Class

Manages cryptographic keys and contacts on disk.

### Constructor

```python
ks = hbz.KeyStore(path: Optional[str] = None)
```

If `path` is `None`, uses `$HB_ZAYFER_HOME` or `~/.hb_zayfer/`.

### Properties

```python
ks.base_path → str
```

### Key Operations

```python
ks.store_private_key(
    fingerprint: str,
    key_bytes: bytes,
    passphrase: bytes,
    algorithm: str,          # "rsa2048", "rsa4096", "ed25519", "x25519", "pgp"
    label: str,
) → None

ks.store_public_key(
    fingerprint: str,
    key_bytes: bytes,
    algorithm: str,
    label: str,
) → None

ks.load_private_key(fingerprint: str, passphrase: bytes) → bytes
ks.load_public_key(fingerprint: str) → bytes

ks.list_keys() → list[KeyMetadata]
ks.get_key_metadata(fingerprint: str) → Optional[KeyMetadata]
ks.find_keys_by_label(query: str) → list[KeyMetadata]
ks.delete_key(fingerprint: str) → None
```

### Contact Operations

```python
ks.add_contact(name: str, email: Optional[str] = None, notes: Optional[str] = None) → None
ks.associate_key_with_contact(contact_name: str, fingerprint: str) → None
ks.get_contact(name: str) → Optional[Contact]
ks.list_contacts() → list[Contact]
ks.remove_contact(name: str) → None
ks.resolve_recipient(name_or_fp: str) → list[str]
```

`resolve_recipient` tries to match as a contact name first, then as a
fingerprint prefix. Returns matching fingerprint(s).

### KeyMetadata

| Attribute | Type | Description |
|-----------|------|-------------|
| `fingerprint` | `str` | Hex SHA-256 fingerprint |
| `algorithm` | `str` | Key algorithm name |
| `label` | `str` | Human-readable label |
| `created_at` | `str` | ISO 8601 timestamp |
| `has_private` | `bool` | Private key present |
| `has_public` | `bool` | Public key present |

### Contact

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Contact name |
| `email` | `Optional[str]` | Email address |
| `key_fingerprints` | `list[str]` | Associated key fingerprints |
| `notes` | `Optional[str]` | Free-form notes |
| `created_at` | `str` | ISO 8601 timestamp |

**Example:**

```python
ks = hbz.KeyStore()

# Generate & store a key
sk, vk = hbz.ed25519_generate()
fp = hbz.ed25519_fingerprint(vk)
ks.store_public_key(fp, vk.encode(), "ed25519", "my-key")
ks.store_private_key(fp, sk.encode(), b"passphrase", "ed25519", "my-key")

# Manage contacts
ks.add_contact("Alice", email="alice@example.com")
ks.associate_key_with_contact("Alice", fp)

# Resolve for encryption
fps = ks.resolve_recipient("Alice")
```

---

## Error Handling

All functions raise `ValueError` on failure. The error message contains
details from the Rust `HbError` variant (e.g., "Authentication failed",
"Key not found: abc123", "Invalid passphrase").

```python
try:
    hbz.aes_decrypt(wrong_key, nonce, ct, b"")
except ValueError as e:
    print(f"Decryption failed: {e}")
```
