# HBZF File Format Specification

**Version**: 1 (`0x01`)
**Status**: Stable

---

## Overview

HBZF (HB Zayfer Format) is a binary file format for authenticated streaming
encryption. It supports multiple symmetric ciphers, key derivation functions,
and key wrapping modes.

Design goals:

- **Streaming**: constant-memory encryption/decryption of arbitrarily large files.
- **Authenticated**: every chunk is independently verified (AEAD).
- **Tamper-resistant**: chunk reordering, duplication, and truncation are detected.
- **Flexible key management**: password-based, RSA-OAEP, and X25519-ECDH wrapping.

---

## Binary Layout

All multi-byte integers are **little-endian**.

### Fixed Header (8 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 B | Magic | ASCII `"HBZF"` (`0x48 0x42 0x5A 0x46`) |
| 4 | 1 B | Version | Format version (`0x01`) |
| 5 | 1 B | Symmetric Algorithm | See [Algorithm IDs](#algorithm-ids) |
| 6 | 1 B | KDF Algorithm | See [KDF IDs](#kdf-ids) |
| 7 | 1 B | Key Wrapping Mode | See [Wrapping IDs](#wrapping-ids) |

### KDF Parameters (conditional)

Present only when KDF Algorithm ≠ `0x00`.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 8 | 16 B | Salt | Random KDF salt |
| 24 | 12 B | KDF Params | Algorithm-specific (see below) |

**Argon2id params** (12 bytes):

| Bytes | Field | Type |
|-------|-------|------|
| 0–3 | `m_cost` | u32 LE (memory in KiB) |
| 4–7 | `t_cost` | u32 LE (iterations) |
| 8–11 | `p_cost` | u32 LE (parallelism) |

**scrypt params** (12 bytes):

| Bytes | Field | Type |
|-------|-------|------|
| 0 | `log_n` | u8 |
| 1–3 | (padding) | zero bytes |
| 4–7 | `r` | u32 LE (block size) |
| 8–11 | `p` | u32 LE (parallelism) |

### Key Wrapping Data (conditional)

Immediately follows the KDF parameters (or offset 8 if no KDF).

**Password mode** (`0x00`): no additional data.

**RSA-OAEP mode** (`0x01`):

| Size | Field | Description |
|------|-------|-------------|
| 2 B | Wrapped key length | u16 LE |
| N B | Wrapped key | RSA-OAEP encrypted symmetric key |

**X25519-ECDH mode** (`0x02`):

| Size | Field | Description |
|------|-------|-------------|
| 32 B | Ephemeral public key | Sender's ephemeral X25519 public key |

### Stream Header

| Size | Field | Description |
|------|-------|-------------|
| 12 B | Base nonce | Random 96-bit nonce |
| 8 B | Plaintext length | u64 LE, original unencrypted size |

### Encrypted Chunks

Repeated until end of file:

| Size | Field | Description |
|------|-------|-------------|
| 4 B | Chunk ciphertext length | u32 LE |
| N B | Chunk ciphertext | AEAD-encrypted chunk + 16-byte tag |

---

## Algorithm IDs

### Symmetric Algorithm (offset 5)

| ID | Algorithm | Key Size | Nonce | Tag |
|----|-----------|----------|-------|-----|
| `0x01` | AES-256-GCM | 32 B | 12 B | 16 B |
| `0x02` | ChaCha20-Poly1305 | 32 B | 12 B | 16 B |

### KDF IDs (offset 6)

| ID | Algorithm |
|----|-----------|
| `0x00` | None (key provided directly) |
| `0x01` | Argon2id |
| `0x02` | scrypt |

### Wrapping IDs (offset 7)

| ID | Mode | Key Source |
|----|------|-----------|
| `0x00` | Password | Passphrase → KDF → 32-byte key |
| `0x01` | RSA-OAEP | Random key wrapped with RSA public key |
| `0x02` | X25519-ECDH | Ephemeral DH + HKDF → 32-byte key |

---

## Chunk Encryption

### Parameters

- **Chunk size**: 65,536 bytes (64 KiB) of plaintext. The last chunk may be
  smaller.
- **Ciphertext size**: plaintext length + 16 bytes (AEAD tag).

### Nonce Derivation

For chunk at index `i` (0-based, as u64 little-endian):

```
chunk_nonce = base_nonce
chunk_nonce[4..12] ^= i.to_le_bytes()
```

This XORs the 8-byte chunk index into bytes 4 through 11 of the 12-byte
base nonce, ensuring a unique nonce for each chunk.

### Additional Authenticated Data (AAD)

```
aad = [symmetric_algorithm_id, wrapping_mode_id] ++ i.to_le_bytes()
```

The chunk index is included in the AAD to bind each ciphertext to its
position in the stream.

---

## Key Derivation Flows

### Password Mode

```
passphrase + salt → KDF(params) → 32-byte symmetric key
```

The KDF algorithm and parameters are embedded in the file header so
decryption does not depend on external configuration.

### RSA-OAEP Mode

```
random 32-byte symmetric key
  → RSA-OAEP encrypt(recipient_public_key, symmetric_key) → wrapped_key
  → stored in header
```

Decryption:

```
wrapped_key → RSA-OAEP decrypt(private_key) → symmetric_key
```

### X25519-ECDH Mode

```
ephemeral_secret ← random()
ephemeral_public = X25519(ephemeral_secret, G)
shared_secret = X25519(ephemeral_secret, recipient_public)
symmetric_key = HKDF-SHA256(shared_secret, info="HB_Zayfer X25519 encryption key")
```

The ephemeral public key is stored in the header. No salt is used for HKDF.

Decryption:

```
shared_secret = X25519(recipient_secret, ephemeral_public)
symmetric_key = HKDF-SHA256(shared_secret, info="HB_Zayfer X25519 encryption key")
```

---

## Integrity Verification

After decrypting all chunks, the total decrypted byte count is compared to
the `plaintext_length` field in the header. A mismatch indicates truncation
or corruption.

Maximum chunk ciphertext length is enforced at `CHUNK_SIZE + 16` (65,552
bytes). Any larger value in the chunk length field causes an immediate
`InvalidFormat` error to prevent memory exhaustion.

---

## Example File (Password Mode, AES-256-GCM)

```
48 42 5A 46     # Magic: "HBZF"
01              # Version: 1
01              # Algorithm: AES-256-GCM
01              # KDF: Argon2id
00              # Wrapping: Password

# KDF salt (16 bytes)
a3 b7 c1 d2 e4 f5 06 17  28 39 4a 5b 6c 7d 8e 9f

# Argon2id params (12 bytes)
00 00 01 00     # m_cost = 65536 (64 MiB)
03 00 00 00     # t_cost = 3
01 00 00 00     # p_cost = 1

# Base nonce (12 bytes)
11 22 33 44 55 66 77 88  99 aa bb cc

# Plaintext length (8 bytes, LE)
0a 00 00 00 00 00 00 00  # 10 bytes

# Chunk 0
1a 00 00 00     # chunk ciphertext length = 26 (10 plaintext + 16 tag)
[26 bytes of encrypted data]
```
