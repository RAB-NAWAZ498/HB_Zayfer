//! HB_Zayfer file encryption format (HBZF).
//!
//! Binary format:
//! ```text
//! [4B] Magic: "HBZF"
//! [1B] Version: 0x01
//! [1B] Symmetric algorithm: 0x01=AES-256-GCM, 0x02=ChaCha20-Poly1305
//! [1B] KDF ID: 0x00=none, 0x01=Argon2id, 0x02=scrypt
//! [1B] Key wrapping mode: 0x00=password, 0x01=RSA-OAEP, 0x02=X25519-ECDH
//! [variable] KDF params (if KDF != none): salt(16B) + params(12B)
//! [variable] Wrapped key / ephemeral pubkey
//! [12B] Base nonce
//! [8B]  Original plaintext length (little-endian u64)
//! [variable] Stream of encrypted chunks, each: [4B chunk_len_le][chunk_data]
//! ```

use std::io::{self, Read, Write};
use rand::RngCore;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{HbError, HbResult};
use crate::kdf::{self, KdfAlgorithm, KdfParams, Argon2Params, ScryptParams};
use crate::{aes_gcm as aes, chacha20 as chacha};

/// Magic bytes identifying an HBZF file.
pub const MAGIC: &[u8; 4] = b"HBZF";
/// Current format version.
pub const VERSION: u8 = 0x01;
/// Default chunk size for streaming encryption (64 KiB).
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Symmetric cipher selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymmetricAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl SymmetricAlgorithm {
    pub fn id(&self) -> u8 {
        match self {
            SymmetricAlgorithm::Aes256Gcm => 0x01,
            SymmetricAlgorithm::ChaCha20Poly1305 => 0x02,
        }
    }

    pub fn from_id(id: u8) -> HbResult<Self> {
        match id {
            0x01 => Ok(SymmetricAlgorithm::Aes256Gcm),
            0x02 => Ok(SymmetricAlgorithm::ChaCha20Poly1305),
            _ => Err(HbError::UnsupportedAlgorithm(format!(
                "Symmetric algorithm ID: 0x{id:02x}"
            ))),
        }
    }
}

/// Key wrapping mode — how the symmetric file-encryption key is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyWrapping {
    /// Password-based: key derived from passphrase via KDF.
    Password,
    /// RSA-OAEP: symmetric key encrypted to recipient's RSA public key.
    RsaOaep,
    /// X25519: ephemeral ECDH → HKDF → symmetric key.
    X25519Ecdh,
}

impl KeyWrapping {
    pub fn id(&self) -> u8 {
        match self {
            KeyWrapping::Password => 0x00,
            KeyWrapping::RsaOaep => 0x01,
            KeyWrapping::X25519Ecdh => 0x02,
        }
    }

    pub fn from_id(id: u8) -> HbResult<Self> {
        match id {
            0x00 => Ok(KeyWrapping::Password),
            0x01 => Ok(KeyWrapping::RsaOaep),
            0x02 => Ok(KeyWrapping::X25519Ecdh),
            _ => Err(HbError::UnsupportedAlgorithm(format!(
                "Key wrapping ID: 0x{id:02x}"
            ))),
        }
    }
}

/// Parameters for file encryption.
pub struct EncryptParams {
    pub algorithm: SymmetricAlgorithm,
    pub wrapping: KeyWrapping,
    /// The 32-byte symmetric key (already derived/unwrapped).
    pub symmetric_key: Vec<u8>,
    /// For password mode: KDF params + salt.
    pub kdf_params: Option<KdfParams>,
    pub kdf_salt: Option<Vec<u8>>,
    /// For RSA-OAEP mode: the RSA-encrypted symmetric key.
    pub wrapped_key: Option<Vec<u8>>,
    /// For X25519 mode: the ephemeral public key (32 bytes).
    pub ephemeral_public: Option<Vec<u8>>,
}

/// File header parsed from an HBZF file.
#[derive(Debug)]
pub struct FileHeader {
    pub version: u8,
    pub algorithm: SymmetricAlgorithm,
    pub kdf_algorithm: Option<KdfAlgorithm>,
    pub wrapping: KeyWrapping,
    pub kdf_params: Option<KdfParams>,
    pub kdf_salt: Option<Vec<u8>>,
    pub wrapped_key: Option<Vec<u8>>,
    pub ephemeral_public: Option<Vec<u8>>,
    pub base_nonce: [u8; 12],
    pub plaintext_len: u64,
}

/// Write the HBZF header to a writer.
fn write_header<W: Write>(writer: &mut W, params: &EncryptParams, base_nonce: &[u8; 12], plaintext_len: u64) -> HbResult<()> {
    // Magic + version
    writer.write_all(MAGIC)?;
    writer.write_all(&[VERSION])?;

    // Algorithm + KDF + wrapping
    writer.write_all(&[params.algorithm.id()])?;

    let kdf_id = match &params.kdf_params {
        Some(p) => p.algorithm().id(),
        None => 0x00,
    };
    writer.write_all(&[kdf_id])?;
    writer.write_all(&[params.wrapping.id()])?;

    // KDF params (if present)
    if let (Some(kdf_p), Some(salt)) = (&params.kdf_params, &params.kdf_salt) {
        // Salt (16 bytes)
        if salt.len() != 16 {
            return Err(HbError::InvalidFormat("KDF salt must be 16 bytes".into()));
        }
        writer.write_all(salt)?;
        // KDF-specific params (12 bytes)
        match kdf_p {
            KdfParams::Argon2id(p) => {
                writer.write_all(&p.m_cost.to_le_bytes())?;
                writer.write_all(&p.t_cost.to_le_bytes())?;
                writer.write_all(&p.p_cost.to_le_bytes())?;
            }
            KdfParams::Scrypt(p) => {
                writer.write_all(&[p.log_n])?;
                writer.write_all(&[0u8; 3])?; // padding
                writer.write_all(&p.r.to_le_bytes())?;
                writer.write_all(&p.p.to_le_bytes())?;
            }
        }
    }

    // Wrapped key / ephemeral public
    match params.wrapping {
        KeyWrapping::Password => {
            // No additional data
        }
        KeyWrapping::RsaOaep => {
            let wk = params.wrapped_key.as_ref()
                .ok_or_else(|| HbError::InvalidFormat("Missing wrapped key for RSA-OAEP".into()))?;
            // Write length (2 bytes) + data
            writer.write_all(&(wk.len() as u16).to_le_bytes())?;
            writer.write_all(wk)?;
        }
        KeyWrapping::X25519Ecdh => {
            let eph = params.ephemeral_public.as_ref()
                .ok_or_else(|| HbError::InvalidFormat("Missing ephemeral public key".into()))?;
            if eph.len() != 32 {
                return Err(HbError::InvalidFormat("Ephemeral public key must be 32 bytes".into()));
            }
            writer.write_all(eph)?;
        }
    }

    // Base nonce (12 bytes)
    writer.write_all(base_nonce)?;

    // Original plaintext length
    writer.write_all(&plaintext_len.to_le_bytes())?;

    Ok(())
}

/// Read and parse an HBZF file header.
pub fn read_header<R: Read>(reader: &mut R) -> HbResult<FileHeader> {
    // Magic
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(HbError::InvalidFormat("Not an HBZF file (wrong magic)".into()));
    }

    // Version
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;
    if version[0] != VERSION {
        return Err(HbError::UnsupportedVersion(version[0]));
    }

    // Algorithm, KDF, wrapping
    let mut algo_kdf_wrap = [0u8; 3];
    reader.read_exact(&mut algo_kdf_wrap)?;
    let algorithm = SymmetricAlgorithm::from_id(algo_kdf_wrap[0])?;
    let kdf_id = algo_kdf_wrap[1];
    let wrapping = KeyWrapping::from_id(algo_kdf_wrap[2])?;

    // KDF params
    let (kdf_algorithm, kdf_params, kdf_salt) = if kdf_id != 0x00 {
        let kdf_alg = kdf::KdfAlgorithm::from_id(kdf_id)?;
        let mut salt = vec![0u8; 16];
        reader.read_exact(&mut salt)?;
        let mut param_bytes = [0u8; 12];
        reader.read_exact(&mut param_bytes)?;

        let params = match kdf_alg {
            KdfAlgorithm::Argon2id => {
                let m = u32::from_le_bytes(param_bytes[0..4].try_into().unwrap());
                let t = u32::from_le_bytes(param_bytes[4..8].try_into().unwrap());
                let p = u32::from_le_bytes(param_bytes[8..12].try_into().unwrap());
                KdfParams::Argon2id(Argon2Params {
                    m_cost: m,
                    t_cost: t,
                    p_cost: p,
                })
            }
            KdfAlgorithm::Scrypt => {
                let log_n = param_bytes[0];
                let r = u32::from_le_bytes(param_bytes[4..8].try_into().unwrap());
                let p = u32::from_le_bytes(param_bytes[8..12].try_into().unwrap());
                KdfParams::Scrypt(ScryptParams { log_n, r, p })
            }
        };
        (Some(kdf_alg), Some(params), Some(salt))
    } else {
        (None, None, None)
    };

    // Wrapped key / ephemeral public
    let (wrapped_key, ephemeral_public) = match wrapping {
        KeyWrapping::Password => (None, None),
        KeyWrapping::RsaOaep => {
            let mut len_bytes = [0u8; 2];
            reader.read_exact(&mut len_bytes)?;
            let len = u16::from_le_bytes(len_bytes) as usize;
            let mut wk = vec![0u8; len];
            reader.read_exact(&mut wk)?;
            (Some(wk), None)
        }
        KeyWrapping::X25519Ecdh => {
            let mut eph = vec![0u8; 32];
            reader.read_exact(&mut eph)?;
            (None, Some(eph))
        }
    };

    // Base nonce
    let mut base_nonce = [0u8; 12];
    reader.read_exact(&mut base_nonce)?;

    // Plaintext length
    let mut len_bytes = [0u8; 8];
    reader.read_exact(&mut len_bytes)?;
    let plaintext_len = u64::from_le_bytes(len_bytes);

    Ok(FileHeader {
        version: VERSION,
        algorithm,
        kdf_algorithm,
        wrapping,
        kdf_params,
        kdf_salt,
        wrapped_key,
        ephemeral_public,
        base_nonce,
        plaintext_len,
    })
}

/// Encrypt from a reader to a writer using streaming AEAD.
///
/// The `params.symmetric_key` must already be a valid 32-byte key.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    params: &EncryptParams,
    plaintext_len: u64,
    mut progress_callback: Option<&mut dyn FnMut(u64)>,
) -> HbResult<()> {
    // Generate base nonce
    let mut base_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut base_nonce);

    // Write header
    write_header(writer, params, &base_nonce, plaintext_len)?;

    // AAD for all chunks: the header fields (algorithm + wrapping mode)
    let aad = [params.algorithm.id(), params.wrapping.id()];

    // Stream encrypt in chunks
    let mut chunk_buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;
    let mut total_read: u64 = 0;

    loop {
        let bytes_read = read_full(reader, &mut chunk_buf)?;
        if bytes_read == 0 {
            break;
        }
        total_read += bytes_read as u64;

        let chunk = &chunk_buf[..bytes_read];
        let encrypted = match params.algorithm {
            SymmetricAlgorithm::Aes256Gcm => {
                aes::encrypt_chunk(&params.symmetric_key, &base_nonce, chunk_index, chunk, &aad)?
            }
            SymmetricAlgorithm::ChaCha20Poly1305 => {
                chacha::encrypt_chunk(&params.symmetric_key, &base_nonce, chunk_index, chunk, &aad)?
            }
        };

        // Write chunk: [4B length][encrypted data]
        writer.write_all(&(encrypted.len() as u32).to_le_bytes())?;
        writer.write_all(&encrypted)?;

        chunk_index += 1;

        if let Some(ref mut cb) = progress_callback {
            cb(total_read);
        }
    }

    writer.flush()?;
    Ok(())
}

/// Decrypt from a reader to a writer using streaming AEAD.
///
/// The header should already have been read. Pass the symmetric key.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    header: &FileHeader,
    symmetric_key: &[u8],
    mut progress_callback: Option<&mut dyn FnMut(u64)>,
) -> HbResult<()> {
    let aad = [header.algorithm.id(), header.wrapping.id()];
    let mut chunk_index: u64 = 0;
    let mut total_written: u64 = 0;

    // Maximum allowed encrypted chunk size = CHUNK_SIZE + 16 (AEAD tag).
    // Reject anything larger to prevent OOM from malicious files.
    const MAX_CHUNK_LEN: usize = CHUNK_SIZE + 16;

    loop {
        // Read chunk length
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let chunk_len = u32::from_le_bytes(len_buf) as usize;

        // Guard against malicious chunk lengths
        if chunk_len > MAX_CHUNK_LEN {
            return Err(HbError::InvalidFormat(format!(
                "Chunk length {chunk_len} exceeds maximum {MAX_CHUNK_LEN}"
            )));
        }

        // Read encrypted chunk
        let mut encrypted = vec![0u8; chunk_len];
        reader.read_exact(&mut encrypted)?;

        let decrypted = match header.algorithm {
            SymmetricAlgorithm::Aes256Gcm => {
                aes::decrypt_chunk(symmetric_key, &header.base_nonce, chunk_index, &encrypted, &aad)?
            }
            SymmetricAlgorithm::ChaCha20Poly1305 => {
                chacha::decrypt_chunk(symmetric_key, &header.base_nonce, chunk_index, &encrypted, &aad)?
            }
        };

        writer.write_all(&decrypted)?;
        total_written += decrypted.len() as u64;
        chunk_index += 1;

        if let Some(ref mut cb) = progress_callback {
            cb(total_written);
        }
    }

    // Verify total decrypted length matches header to detect truncation
    if header.plaintext_len != 0 && total_written != header.plaintext_len {
        return Err(HbError::InvalidFormat(format!(
            "Truncation detected: expected {} bytes, got {total_written}",
            header.plaintext_len
        )));
    }

    writer.flush()?;
    Ok(())
}

/// Helper to read exactly `buf.len()` bytes or fewer at EOF.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut pos = 0;
    while pos < buf.len() {
        match reader.read(&mut buf[pos..]) {
            Ok(0) => break,
            Ok(n) => pos += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(pos)
}

// -- Convenience functions for in-memory encryption --

/// Encrypt bytes in memory (non-streaming, for small data like text).
pub fn encrypt_bytes(
    data: &[u8],
    symmetric_key: &[u8],
    algorithm: SymmetricAlgorithm,
) -> HbResult<(Vec<u8>, Vec<u8>)> {
    match algorithm {
        SymmetricAlgorithm::Aes256Gcm => aes::encrypt(symmetric_key, data, b""),
        SymmetricAlgorithm::ChaCha20Poly1305 => chacha::encrypt(symmetric_key, data, b""),
    }
}

/// Decrypt bytes in memory (non-streaming, for small data like text).
pub fn decrypt_bytes(
    nonce: &[u8],
    ciphertext: &[u8],
    symmetric_key: &[u8],
    algorithm: SymmetricAlgorithm,
) -> HbResult<Vec<u8>> {
    match algorithm {
        SymmetricAlgorithm::Aes256Gcm => aes::decrypt(symmetric_key, nonce, ciphertext, b""),
        SymmetricAlgorithm::ChaCha20Poly1305 => chacha::decrypt(symmetric_key, nonce, ciphertext, b""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_header_roundtrip_password() {
        let mut buf = Vec::new();
        let salt = kdf::generate_salt(16);
        let kdf_params = KdfParams::default();
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);
        let base_nonce = [0u8; 12];

        let params = EncryptParams {
            algorithm: SymmetricAlgorithm::Aes256Gcm,
            wrapping: KeyWrapping::Password,
            symmetric_key: key,
            kdf_params: Some(kdf_params),
            kdf_salt: Some(salt.clone()),
            wrapped_key: None,
            ephemeral_public: None,
        };

        write_header(&mut buf, &params, &base_nonce, 1024).unwrap();

        let mut cursor = Cursor::new(&buf);
        let header = read_header(&mut cursor).unwrap();

        assert_eq!(header.algorithm, SymmetricAlgorithm::Aes256Gcm);
        assert_eq!(header.wrapping, KeyWrapping::Password);
        assert_eq!(header.plaintext_len, 1024);
        assert!(header.kdf_params.is_some());
        assert_eq!(header.kdf_salt.as_ref().unwrap(), &salt);
    }

    #[test]
    fn test_stream_encrypt_decrypt_roundtrip() {
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);

        let plaintext = b"Hello HB_Zayfer! This is a test of streaming encryption.";
        let params = EncryptParams {
            algorithm: SymmetricAlgorithm::ChaCha20Poly1305,
            wrapping: KeyWrapping::Password,
            symmetric_key: key.clone(),
            kdf_params: None,
            kdf_salt: None,
            wrapped_key: None,
            ephemeral_public: None,
        };

        // Encrypt
        let mut encrypted = Vec::new();
        let mut reader = Cursor::new(plaintext);
        encrypt_stream(
            &mut reader,
            &mut encrypted,
            &params,
            plaintext.len() as u64,
            None,
        ).unwrap();

        // Decrypt
        let mut cursor = Cursor::new(&encrypted);
        let header = read_header(&mut cursor).unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(&mut cursor, &mut decrypted, &header, &key, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
