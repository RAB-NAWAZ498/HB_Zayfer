use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{HbError, HbResult};

/// An Ed25519 key pair for digital signatures.
///
/// Signing key bytes are zeroized on drop.
pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        // Overwrite the signing key seed bytes
        let mut seed = self.signing_key.to_bytes();
        seed.zeroize();
    }
}

/// Generate a new Ed25519 key pair.
pub fn generate_keypair() -> Ed25519KeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    Ed25519KeyPair {
        signing_key,
        verifying_key,
    }
}

/// Sign a message with Ed25519.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign(message);
    signature.to_bytes().to_vec()
}

/// Verify an Ed25519 signature.
pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature_bytes: &[u8]) -> HbResult<bool> {
    if signature_bytes.len() != 64 {
        return Err(HbError::Ed25519(format!(
            "Signature must be 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| HbError::Ed25519("Invalid signature length".into()))?;
    let signature = Signature::from_bytes(&sig_array);

    match verifying_key.verify(message, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// -- Key serialization --

/// Export signing key as PKCS#8 PEM.
pub fn export_signing_key_pem(key: &SigningKey) -> HbResult<String> {
    key.to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .map(|s| s.to_string())
        .map_err(|e| HbError::InvalidKeyFormat(format!("Ed25519 PKCS#8 PEM export: {e}")))
}

/// Export verifying key as PEM.
pub fn export_verifying_key_pem(key: &VerifyingKey) -> HbResult<String> {
    key.to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .map_err(|e| HbError::InvalidKeyFormat(format!("Ed25519 public PEM export: {e}")))
}

/// Import signing key from PKCS#8 PEM.
pub fn import_signing_key_pem(pem_data: &str) -> HbResult<SigningKey> {
    SigningKey::from_pkcs8_pem(pem_data)
        .map_err(|e| HbError::InvalidKeyFormat(format!("Ed25519 PKCS#8 PEM import: {e}")))
}

/// Import verifying key from PEM.
pub fn import_verifying_key_pem(pem_data: &str) -> HbResult<VerifyingKey> {
    VerifyingKey::from_public_key_pem(pem_data)
        .map_err(|e| HbError::InvalidKeyFormat(format!("Ed25519 public PEM import: {e}")))
}

/// Export signing key as raw 32-byte seed.
pub fn export_signing_key_raw(key: &SigningKey) -> Vec<u8> {
    key.to_bytes().to_vec()
}

/// Export verifying key as raw 32-byte public key.
pub fn export_verifying_key_raw(key: &VerifyingKey) -> Vec<u8> {
    key.to_bytes().to_vec()
}

/// Import signing key from raw 32-byte seed.
pub fn import_signing_key_raw(bytes: &[u8]) -> HbResult<SigningKey> {
    if bytes.len() != 32 {
        return Err(HbError::Ed25519(format!(
            "Signing key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let array: [u8; 32] = bytes.try_into().unwrap();
    Ok(SigningKey::from_bytes(&array))
}

/// Import verifying key from raw 32 bytes.
pub fn import_verifying_key_raw(bytes: &[u8]) -> HbResult<VerifyingKey> {
    if bytes.len() != 32 {
        return Err(HbError::Ed25519(format!(
            "Verifying key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let array: [u8; 32] = bytes.try_into().unwrap();
    VerifyingKey::from_bytes(&array).map_err(|e| HbError::Ed25519(format!("Invalid public key: {e}")))
}

/// Compute a fingerprint (SHA-256 of raw public key bytes).
pub fn fingerprint(verifying_key: &VerifyingKey) -> String {
    let hash = Sha256::digest(verifying_key.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let kp = generate_keypair();
        let message = b"Hello Ed25519!";
        let sig = sign(&kp.signing_key, message);
        assert!(verify(&kp.verifying_key, message, &sig).unwrap());
        assert!(!verify(&kp.verifying_key, b"wrong", &sig).unwrap());
    }

    #[test]
    fn test_pem_roundtrip() {
        let kp = generate_keypair();
        let priv_pem = export_signing_key_pem(&kp.signing_key).unwrap();
        let pub_pem = export_verifying_key_pem(&kp.verifying_key).unwrap();

        let imported_priv = import_signing_key_pem(&priv_pem).unwrap();
        let imported_pub = import_verifying_key_pem(&pub_pem).unwrap();

        assert_eq!(kp.signing_key.to_bytes(), imported_priv.to_bytes());
        assert_eq!(kp.verifying_key.to_bytes(), imported_pub.to_bytes());
    }

    #[test]
    fn test_raw_roundtrip() {
        let kp = generate_keypair();
        let raw_priv = export_signing_key_raw(&kp.signing_key);
        let raw_pub = export_verifying_key_raw(&kp.verifying_key);

        let imported_priv = import_signing_key_raw(&raw_priv).unwrap();
        let imported_pub = import_verifying_key_raw(&raw_pub).unwrap();

        assert_eq!(kp.signing_key.to_bytes(), imported_priv.to_bytes());
        assert_eq!(kp.verifying_key.to_bytes(), imported_pub.to_bytes());
    }

    #[test]
    fn test_fingerprint_consistent() {
        let kp = generate_keypair();
        let fp1 = fingerprint(&kp.verifying_key);
        let fp2 = fingerprint(&kp.verifying_key);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
    }
}
