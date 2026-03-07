# Rust Core API Reference

Complete reference for the `hb_zayfer_core` crate, which provides all
cryptographic primitives, the HBZF file format, and key management.

---

## Table of Contents

- [Error Types (`error`)](#error-types)
- [AES-256-GCM (`aes_gcm`)](#aes-256-gcm)
- [ChaCha20-Poly1305 (`chacha20`)](#chacha20-poly1305)
- [RSA (`rsa`)](#rsa)
- [Ed25519 (`ed25519`)](#ed25519)
- [X25519 ECDH (`x25519`)](#x25519-ecdh)
- [OpenPGP (`openpgp`)](#openpgp)
- [Key Derivation (`kdf`)](#key-derivation)
- [HBZF File Format (`format`)](#hbzf-file-format)
- [Key Store (`keystore`)](#key-store)

---

## Error Types

### `HbError`

Unified error enum for every failure mode in the crate.

| Variant | Description |
|---------|-------------|
| `Rsa(String)` | RSA operation failed |
| `AesGcm(String)` | AES-GCM error |
| `ChaCha20(String)` | ChaCha20-Poly1305 error |
| `Ed25519(String)` | Ed25519 operation error |
| `X25519(String)` | X25519 / HKDF error |
| `OpenPgp(String)` | OpenPGP / Sequoia error |
| `Kdf(String)` | Key derivation error |
| `KeyNotFound(String)` | Key fingerprint not in keystore |
| `KeyAlreadyExists(String)` | Duplicate key fingerprint |
| `InvalidKeyFormat(String)` | Malformed key material |
| `PassphraseRequired` | Operation needs a passphrase |
| `InvalidPassphrase` | Passphrase decryption failed |
| `InvalidFormat(String)` | Malformed HBZF or data format |
| `UnsupportedVersion(u8)` | HBZF version not recognized |
| `UnsupportedAlgorithm(String)` | Unknown algorithm ID |
| `AuthenticationFailed` | AEAD tag verification failed |
| `Io(std::io::Error)` | I/O error (via `From`) |
| `Serialization(String)` | JSON / TOML parse error |
| `ContactNotFound(String)` | Contact name not in store |
| `ContactAlreadyExists(String)` | Duplicate contact name |

### `HbResult<T>`

```rust
pub type HbResult<T> = Result<T, HbError>;
```

---

## AES-256-GCM

**Module**: `hb_zayfer_core::aes_gcm`

### Constants

| Name | Value | Description |
|------|-------|-------------|
| `AES_GCM_NONCE_SIZE` | `12` | 96-bit nonce |
| `AES_256_KEY_SIZE` | `32` | 256-bit key |
| `AES_GCM_TAG_SIZE` | `16` | 128-bit auth tag |

### Functions

#### `encrypt(key, plaintext, aad) → HbResult<(Vec<u8>, Vec<u8>)>`

Encrypt with a randomly-generated nonce. Returns `(nonce, ciphertext_with_tag)`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `&[u8]` | 32-byte key |
| `plaintext` | `&[u8]` | Data to encrypt |
| `aad` | `&[u8]` | Additional authenticated data |

#### `decrypt(key, nonce, ciphertext, aad) → HbResult<Vec<u8>>`

Decrypt and authenticate. Returns plaintext.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `&[u8]` | 32-byte key |
| `nonce` | `&[u8]` | 12-byte nonce |
| `ciphertext` | `&[u8]` | Ciphertext with appended tag |
| `aad` | `&[u8]` | Must match encryption AAD |

#### `encrypt_chunk(key, base_nonce, chunk_index, chunk, aad) → HbResult<Vec<u8>>`

Streaming chunk encryption. Nonce derived by XOR-ing chunk index into
bytes 4..12 of the base nonce. Chunk index appended to AAD.

#### `decrypt_chunk(key, base_nonce, chunk_index, ciphertext, aad) → HbResult<Vec<u8>>`

Inverse of `encrypt_chunk`.

---

## ChaCha20-Poly1305

**Module**: `hb_zayfer_core::chacha20`

API is identical to `aes_gcm`. Same key size (32 B), nonce size (12 B),
and tag size (16 B). Same streaming chunk nonce derivation scheme.

### Constants

| Name | Value |
|------|-------|
| `CHACHA20_NONCE_SIZE` | `12` |
| `CHACHA20_KEY_SIZE` | `32` |
| `CHACHA20_TAG_SIZE` | `16` |

### Functions

- `encrypt(key, plaintext, aad) → HbResult<(Vec<u8>, Vec<u8>)>`
- `decrypt(key, nonce, ciphertext, aad) → HbResult<Vec<u8>>`
- `encrypt_chunk(key, base_nonce, chunk_index, chunk, aad) → HbResult<Vec<u8>>`
- `decrypt_chunk(key, base_nonce, chunk_index, ciphertext, aad) → HbResult<Vec<u8>>`

---

## RSA

**Module**: `hb_zayfer_core::rsa`

### Types

#### `RsaKeySize`

```rust
pub enum RsaKeySize {
    Rsa2048,  // 2048-bit key
    Rsa4096,  // 4096-bit key
}
```

#### `RsaKeyPair`

```rust
pub struct RsaKeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}
```

### Functions

#### Key Generation

```rust
fn generate_keypair(size: RsaKeySize) → HbResult<RsaKeyPair>
```

#### Encryption (RSA-OAEP SHA-256)

```rust
fn encrypt(public_key: &RsaPublicKey, plaintext: &[u8]) → HbResult<Vec<u8>>
fn decrypt(private_key: &RsaPrivateKey, ciphertext: &[u8]) → HbResult<Vec<u8>>
```

#### Signing (RSA-PSS SHA-256, Blinded)

```rust
fn sign(private_key: &RsaPrivateKey, message: &[u8]) → HbResult<Vec<u8>>
fn verify(public_key: &RsaPublicKey, message: &[u8], signature: &[u8]) → HbResult<bool>
```

#### Key Serialization

| Function | Direction | Format |
|----------|-----------|--------|
| `export_private_key_pem` | Export | PKCS#8 PEM |
| `export_public_key_pem` | Export | SPKI PEM |
| `export_private_key_pkcs1_pem` | Export | PKCS#1 PEM |
| `export_public_key_pkcs1_pem` | Export | PKCS#1 PEM |
| `import_private_key_pem` | Import | PKCS#8 PEM |
| `import_public_key_pem` | Import | SPKI PEM |
| `import_private_key_pkcs1_pem` | Import | PKCS#1 PEM |
| `import_public_key_pkcs1_pem` | Import | PKCS#1 PEM |

#### Fingerprint

```rust
fn fingerprint(public_key: &RsaPublicKey) → HbResult<String>
// SHA-256 of DER-encoded public key, hex-encoded (64 chars)
```

---

## Ed25519

**Module**: `hb_zayfer_core::ed25519`

### Types

#### `Ed25519KeyPair`

```rust
pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}
```

Signing key bytes are **zeroized on drop**.

### Functions

#### Key Generation

```rust
fn generate_keypair() → Ed25519KeyPair
```

#### Sign & Verify

```rust
fn sign(signing_key: &SigningKey, message: &[u8]) → Vec<u8>
// Returns 64-byte signature

fn verify(verifying_key: &VerifyingKey, message: &[u8], signature_bytes: &[u8]) → HbResult<bool>
```

#### Serialization

| Function | Direction | Format |
|----------|-----------|--------|
| `export_signing_key_pem` | Export | PKCS#8 PEM |
| `export_verifying_key_pem` | Export | SPKI PEM |
| `import_signing_key_pem` | Import | PKCS#8 PEM |
| `import_verifying_key_pem` | Import | SPKI PEM |
| `export_signing_key_raw` | Export | Raw 32 bytes |
| `export_verifying_key_raw` | Export | Raw 32 bytes |
| `import_signing_key_raw` | Import | Raw 32 bytes |
| `import_verifying_key_raw` | Import | Raw 32 bytes |

#### Fingerprint

```rust
fn fingerprint(verifying_key: &VerifyingKey) → String
// SHA-256 of raw public key bytes, hex-encoded
```

---

## X25519 ECDH

**Module**: `hb_zayfer_core::x25519`

### Types

#### `X25519KeyPair`

```rust
pub struct X25519KeyPair {
    pub secret_key: StaticSecret,
    pub public_key: PublicKey,
}
```

Secret key bytes are **zeroized on drop**.

### Functions

#### Key Generation

```rust
fn generate_keypair() → X25519KeyPair
```

#### Key Agreement

```rust
// Raw static DH
fn key_agreement(our_secret: &StaticSecret, their_public: &PublicKey) → [u8; 32]

// Ephemeral sender side: generates ephemeral secret + DH
fn ephemeral_key_agreement(their_public: &PublicKey) → (PublicKey, [u8; 32])

// Full encrypt side: ephemeral DH + HKDF → 32-byte symmetric key
fn encrypt_key_agreement(their_public: &PublicKey) → HbResult<(PublicKey, [u8; 32])>

// Decrypt side: static DH + HKDF → same 32-byte symmetric key
fn decrypt_key_agreement(our_secret: &StaticSecret, ephemeral_public: &PublicKey) → HbResult<[u8; 32]>

// HKDF-SHA256 key derivation from shared secret
fn derive_symmetric_key(shared_secret: &[u8; 32], info: &[u8], salt: Option<&[u8]>) → HbResult<[u8; 32]>
```

#### Serialization

| Function | Direction | Format |
|----------|-----------|--------|
| `export_public_key_raw` | Export | Raw 32 bytes |
| `import_public_key_raw` | Import | Raw 32 bytes |
| `export_secret_key_raw` | Export | Raw 32 bytes |
| `import_secret_key_raw` | Import | Raw 32 bytes |

#### Fingerprint

```rust
fn fingerprint(public_key: &PublicKey) → String
```

---

## OpenPGP

**Module**: `hb_zayfer_core::openpgp`

Built on [sequoia-openpgp](https://sequoia-pgp.org/) for GPG compatibility.

### Functions

#### Certificate Management

```rust
fn generate_cert(user_id: &str) → HbResult<Cert>
// Generates cert with signing + transport-encryption + storage-encryption subkeys

fn export_public_key(cert: &Cert) → HbResult<String>   // ASCII-armored
fn export_secret_key(cert: &Cert) → HbResult<String>   // ASCII-armored (includes secret material)
fn import_cert(armored: &str) → HbResult<Cert>

fn cert_fingerprint(cert: &Cert) → String
fn cert_user_id(cert: &Cert) → Option<String>
```

#### Encrypt & Decrypt

```rust
fn encrypt_message(plaintext: &[u8], recipients: &[&Cert]) → HbResult<Vec<u8>>
// Encrypts to all valid encryption-capable subkeys of each recipient

fn decrypt_message(ciphertext: &[u8], secret_certs: &[Cert]) → HbResult<Vec<u8>>
```

#### Sign & Verify

```rust
fn sign_message(message: &[u8], signer_cert: &Cert) → HbResult<Vec<u8>>
// Inline signature (armored output)

fn verify_signed_message(signed: &[u8], signer_certs: &[Cert]) → HbResult<(Vec<u8>, bool)>
// Returns (message_content, is_valid)
```

---

## Key Derivation

**Module**: `hb_zayfer_core::kdf`

### Types

#### `KdfAlgorithm`

```rust
pub enum KdfAlgorithm {
    Argon2id,  // ID: 0x01
    Scrypt,    // ID: 0x02
}
```

#### `Argon2Params`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `m_cost` | `u32` | `65536` | Memory in KiB (64 MiB) |
| `t_cost` | `u32` | `3` | Iterations |
| `p_cost` | `u32` | `1` | Parallelism |

#### `ScryptParams`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_n` | `u8` | `15` | log₂(N), CPU/memory cost |
| `r` | `u32` | `8` | Block size |
| `p` | `u32` | `1` | Parallelism |

#### `KdfParams`

```rust
pub enum KdfParams {
    Argon2id(Argon2Params),
    Scrypt(ScryptParams),
}
```

Default: `Argon2id` with default parameters.

#### `DerivedKey`

```rust
pub struct DerivedKey {
    pub salt: Vec<u8>,
    pub key: Vec<u8>,  // Zeroized on drop
}
```

### Functions

```rust
fn generate_salt(len: usize) → Vec<u8>
// OS CSPRNG random bytes

fn derive_key(passphrase: &[u8], salt: &[u8], params: &KdfParams) → HbResult<Vec<u8>>
// Returns 32-byte key

fn derive_key_fresh(passphrase: &[u8], params: &KdfParams) → HbResult<DerivedKey>
// Generates salt + derives key in one call
```

---

## HBZF File Format

**Module**: `hb_zayfer_core::format`

### Constants

| Name | Value | Description |
|------|-------|-------------|
| `MAGIC` | `b"HBZF"` | File magic bytes |
| `VERSION` | `0x01` | Current version |
| `CHUNK_SIZE` | `65536` | 64 KiB chunks |

### Types

#### `SymmetricAlgorithm`

| Variant | ID | Description |
|---------|----|-------------|
| `Aes256Gcm` | `0x01` | AES-256-GCM |
| `ChaCha20Poly1305` | `0x02` | ChaCha20-Poly1305 |

#### `KeyWrapping`

| Variant | ID | Description |
|---------|----|-------------|
| `Password` | `0x00` | Passphrase → KDF → symmetric key |
| `RsaOaep` | `0x01` | Symmetric key encrypted with RSA-OAEP |
| `X25519Ecdh` | `0x02` | Ephemeral ECDH → HKDF → symmetric key |

#### `EncryptParams`

Fields: `algorithm`, `wrapping`, `symmetric_key`, `kdf_params`, `kdf_salt`,
`wrapped_key`, `ephemeral_public`.

#### `FileHeader`

Parsed header from an HBZF file. Fields: `version`, `algorithm`,
`kdf_algorithm`, `wrapping`, `kdf_params`, `kdf_salt`, `wrapped_key`,
`ephemeral_public`, `base_nonce`, `plaintext_len`.

### Functions

```rust
fn read_header<R: Read>(reader: &mut R) → HbResult<FileHeader>

fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    params: &EncryptParams,
    plaintext_len: u64,
    progress_callback: Option<&mut dyn FnMut(u64)>,
) → HbResult<()>

fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    header: &FileHeader,
    symmetric_key: &[u8],
    progress_callback: Option<&mut dyn FnMut(u64)>,
) → HbResult<()>
```

---

## Key Store

**Module**: `hb_zayfer_core::keystore`

### Types

#### `KeyAlgorithm`

```rust
pub enum KeyAlgorithm {
    Rsa2048, Rsa4096, Ed25519, X25519, Pgp,
}
```

#### `KeyMetadata`

| Field | Type | Description |
|-------|------|-------------|
| `fingerprint` | `String` | Hex-encoded SHA-256 |
| `algorithm` | `KeyAlgorithm` | Key type |
| `label` | `String` | Human-readable name |
| `created_at` | `DateTime<Utc>` | Creation time |
| `has_private` | `bool` | Private key stored |
| `has_public` | `bool` | Public key stored |

#### `Contact`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `String` | Contact name |
| `email` | `Option<String>` | Email address |
| `key_fingerprints` | `Vec<String>` | Associated keys |
| `notes` | `Option<String>` | Free-form notes |
| `created_at` | `DateTime<Utc>` | Creation time |

#### `KeyFormat`

```rust
pub enum KeyFormat {
    Pkcs8Pem, Pkcs1Pem, Der, OpenPgpArmor, OpenSsh,
}
```

### `KeyStore` Methods

```rust
// Open
fn open_default() → HbResult<Self>
fn open(base_path: PathBuf) → HbResult<Self>
fn base_path(&self) → &Path

// Key storage
fn store_private_key(&mut self, fp, key_bytes, passphrase, algorithm, label) → HbResult<()>
fn store_public_key(&mut self, fp, key_bytes, algorithm, label) → HbResult<()>
fn load_private_key(&self, fp, passphrase) → HbResult<Vec<u8>>
fn load_public_key(&self, fp) → HbResult<Vec<u8>>

// Key queries
fn list_keys(&self) → Vec<&KeyMetadata>
fn get_key_metadata(&self, fp) → Option<&KeyMetadata>
fn find_keys_by_label(&self, query) → Vec<&KeyMetadata>
fn delete_key(&mut self, fp) → HbResult<()>

// Contact management
fn add_contact(&mut self, name, email, notes) → HbResult<()>
fn associate_key_with_contact(&mut self, contact_name, fingerprint) → HbResult<()>
fn get_contact(&self, name) → Option<&Contact>
fn list_contacts(&self) → Vec<&Contact>
fn remove_contact(&mut self, name) → HbResult<()>
fn resolve_recipient(&self, name_or_fp) → Vec<String>
```

### Utility Functions

```rust
fn compute_fingerprint(public_key_bytes: &[u8]) → String
fn detect_key_format(data: &[u8]) → KeyFormat
```
