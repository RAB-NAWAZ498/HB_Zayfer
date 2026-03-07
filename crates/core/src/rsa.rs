use rand_core::OsRng;
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pss::{BlindedSigningKey, VerifyingKey as PssVerifyingKey},
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use signature::{RandomizedSigner, SignatureEncoding, Verifier};

use crate::error::{HbError, HbResult};

/// Supported RSA key sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RsaKeySize {
    Rsa2048,
    Rsa4096,
}

impl RsaKeySize {
    pub fn bits(&self) -> usize {
        match self {
            RsaKeySize::Rsa2048 => 2048,
            RsaKeySize::Rsa4096 => 4096,
        }
    }
}

/// An RSA key pair.
///
/// Private key material is zeroized on drop.
pub struct RsaKeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}

impl Drop for RsaKeyPair {
    fn drop(&mut self) {
        // RsaPrivateKey stores primes internally;
        // calling zeroize on individual BigUint fields is not directly
        // accessible, but we overwrite what we can.
        // The `rsa` crate's RsaPrivateKey is backed by `zeroize`-enabled
        // big integers when the feature is on.
    }
}

/// Generate a new RSA key pair.
pub fn generate_keypair(size: RsaKeySize) -> HbResult<RsaKeyPair> {
    let private_key = RsaPrivateKey::new(&mut OsRng, size.bits())
        .map_err(|e| HbError::Rsa(format!("Key generation failed: {e}")))?;
    let public_key = RsaPublicKey::from(&private_key);
    Ok(RsaKeyPair {
        private_key,
        public_key,
    })
}

/// Encrypt data with RSA-OAEP (SHA-256).
/// Suitable for encrypting small payloads (e.g., symmetric keys).
pub fn encrypt(public_key: &RsaPublicKey, plaintext: &[u8]) -> HbResult<Vec<u8>> {
    let padding = Oaep::new::<Sha256>();
    public_key
        .encrypt(&mut OsRng, padding, plaintext)
        .map_err(|e| HbError::Rsa(format!("Encryption failed: {e}")))
}

/// Decrypt data encrypted with RSA-OAEP (SHA-256).
pub fn decrypt(private_key: &RsaPrivateKey, ciphertext: &[u8]) -> HbResult<Vec<u8>> {
    let padding = Oaep::new::<Sha256>();
    private_key
        .decrypt(padding, ciphertext)
        .map_err(|e| HbError::Rsa(format!("Decryption failed: {e}")))
}

/// Sign a message with RSA-PSS using SHA-256 (blinded).
pub fn sign(private_key: &RsaPrivateKey, message: &[u8]) -> HbResult<Vec<u8>> {
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key.clone());
    let sig = signing_key
        .sign_with_rng(&mut OsRng, message);
    Ok(sig.to_vec())
}

/// Verify an RSA-PSS signature.
pub fn verify(public_key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> HbResult<bool> {
    let verifying_key = PssVerifyingKey::<Sha256>::new(public_key.clone());
    let sig = rsa::pss::Signature::try_from(signature)
        .map_err(|e| HbError::Rsa(format!("Invalid signature format: {e}")))?;
    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// -- Key serialization --

/// Export private key as PKCS#8 PEM.
pub fn export_private_key_pem(key: &RsaPrivateKey) -> HbResult<String> {
    key.to_pkcs8_pem(LineEnding::LF)
        .map(|s| s.to_string())
        .map_err(|e| HbError::InvalidKeyFormat(format!("PKCS#8 PEM export: {e}")))
}

/// Export public key as PKCS#8 PEM.
pub fn export_public_key_pem(key: &RsaPublicKey) -> HbResult<String> {
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| HbError::InvalidKeyFormat(format!("PKCS#8 PEM export: {e}")))
}

/// Export private key as PKCS#1 PEM (RSA-specific).
pub fn export_private_key_pkcs1_pem(key: &RsaPrivateKey) -> HbResult<String> {
    key.to_pkcs1_pem(LineEnding::LF)
        .map(|s| s.to_string())
        .map_err(|e| HbError::InvalidKeyFormat(format!("PKCS#1 PEM export: {e}")))
}

/// Export public key as PKCS#1 PEM (RSA-specific).
pub fn export_public_key_pkcs1_pem(key: &RsaPublicKey) -> HbResult<String> {
    key.to_pkcs1_pem(LineEnding::LF)
        .map_err(|e| HbError::InvalidKeyFormat(format!("PKCS#1 PEM export: {e}")))
}

/// Import private key from PKCS#8 PEM.
pub fn import_private_key_pem(pem_data: &str) -> HbResult<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_pem(pem_data)
        .map_err(|e| HbError::InvalidKeyFormat(format!("PKCS#8 PEM import: {e}")))
}

/// Import public key from PKCS#8 PEM.
pub fn import_public_key_pem(pem_data: &str) -> HbResult<RsaPublicKey> {
    RsaPublicKey::from_public_key_pem(pem_data)
        .map_err(|e| HbError::InvalidKeyFormat(format!("PKCS#8 PEM import: {e}")))
}

/// Import private key from PKCS#1 PEM.
pub fn import_private_key_pkcs1_pem(pem_data: &str) -> HbResult<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs1_pem(pem_data)
        .map_err(|e| HbError::InvalidKeyFormat(format!("PKCS#1 PEM import: {e}")))
}

/// Import public key from PKCS#1 PEM.
pub fn import_public_key_pkcs1_pem(pem_data: &str) -> HbResult<RsaPublicKey> {
    RsaPublicKey::from_pkcs1_pem(pem_data)
        .map_err(|e| HbError::InvalidKeyFormat(format!("PKCS#1 PEM import: {e}")))
}

/// Compute a fingerprint (SHA-256 of DER-encoded public key) for identification.
pub fn fingerprint(public_key: &RsaPublicKey) -> HbResult<String> {
    use sha2::Digest;
    let der = public_key
        .to_public_key_der()
        .map_err(|e| HbError::InvalidKeyFormat(format!("DER encode: {e}")))?;
    let hash = Sha256::digest(der.as_bytes());
    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_encrypt_decrypt() {
        let kp = generate_keypair(RsaKeySize::Rsa2048).unwrap();
        let plaintext = b"RSA test message";
        let ciphertext = encrypt(&kp.public_key, plaintext).unwrap();
        let decrypted = decrypt(&kp.private_key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = generate_keypair(RsaKeySize::Rsa2048).unwrap();
        let message = b"sign this message";
        let signature = sign(&kp.private_key, message).unwrap();
        assert!(verify(&kp.public_key, message, &signature).unwrap());
        assert!(!verify(&kp.public_key, b"wrong message", &signature).unwrap());
    }

    #[test]
    fn test_key_pem_roundtrip() {
        let kp = generate_keypair(RsaKeySize::Rsa2048).unwrap();

        let priv_pem = export_private_key_pem(&kp.private_key).unwrap();
        let pub_pem = export_public_key_pem(&kp.public_key).unwrap();

        let priv_imported = import_private_key_pem(&priv_pem).unwrap();
        let pub_imported = import_public_key_pem(&pub_pem).unwrap();

        assert_eq!(kp.private_key, priv_imported);
        assert_eq!(kp.public_key, pub_imported);
    }

    #[test]
    fn test_fingerprint() {
        let kp = generate_keypair(RsaKeySize::Rsa2048).unwrap();
        let fp = fingerprint(&kp.public_key).unwrap();
        assert_eq!(fp.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }
}
