use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{HbError, HbResult};

/// An X25519 key pair for key agreement (ECDH).
///
/// Secret key bytes are zeroized on drop.
pub struct X25519KeyPair {
    pub secret_key: StaticSecret,
    pub public_key: PublicKey,
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        // Overwrite the secret key bytes
        let mut bytes = self.secret_key.to_bytes();
        bytes.zeroize();
    }
}

/// Generate a new X25519 static key pair.
pub fn generate_keypair() -> X25519KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    X25519KeyPair {
        secret_key: secret,
        public_key: public,
    }
}

/// Generate an ephemeral X25519 key pair (for one-shot key agreement).
/// Returns (ephemeral_public_key, shared_secret_with_recipient).
pub fn ephemeral_key_agreement(their_public: &PublicKey) -> (PublicKey, [u8; 32]) {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(their_public);
    (ephemeral_public, *shared_secret.as_bytes())
}

/// Perform a static Diffie-Hellman key agreement.
pub fn key_agreement(our_secret: &StaticSecret, their_public: &PublicKey) -> [u8; 32] {
    let shared_secret = our_secret.diffie_hellman(their_public);
    *shared_secret.as_bytes()
}

/// Derive a symmetric key from a DH shared secret using HKDF-SHA256.
///
/// # Arguments
/// * `shared_secret` — the raw DH output
/// * `info` — context/application-specific info string
/// * `salt` — optional salt (if None, HKDF uses a zero-filled salt)
pub fn derive_symmetric_key(
    shared_secret: &[u8; 32],
    info: &[u8],
    salt: Option<&[u8]>,
) -> HbResult<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(salt, shared_secret);
    let mut output = [0u8; 32];
    hk.expand(info, &mut output)
        .map_err(|e| HbError::X25519(format!("HKDF expand failed: {e}")))?;
    Ok(output)
}

/// Full key agreement + derivation helper.
/// Performs ephemeral ECDH and derives a 32-byte symmetric key.
/// Returns (ephemeral_public_key, derived_symmetric_key).
pub fn encrypt_key_agreement(their_public: &PublicKey) -> HbResult<(PublicKey, [u8; 32])> {
    let (eph_pub, shared_secret) = ephemeral_key_agreement(their_public);
    let symmetric_key = derive_symmetric_key(
        &shared_secret,
        b"HB_Zayfer X25519 encryption key",
        None,
    )?;
    Ok((eph_pub, symmetric_key))
}

/// Decrypt-side key agreement.
/// Takes the recipient's static secret and the sender's ephemeral public key.
pub fn decrypt_key_agreement(
    our_secret: &StaticSecret,
    ephemeral_public: &PublicKey,
) -> HbResult<[u8; 32]> {
    let shared_secret = key_agreement(our_secret, ephemeral_public);
    derive_symmetric_key(
        &shared_secret,
        b"HB_Zayfer X25519 encryption key",
        None,
    )
}

// -- Key serialization --

/// Export public key as raw 32 bytes.
pub fn export_public_key_raw(key: &PublicKey) -> Vec<u8> {
    key.as_bytes().to_vec()
}

/// Import public key from raw 32 bytes.
pub fn import_public_key_raw(bytes: &[u8]) -> HbResult<PublicKey> {
    if bytes.len() != 32 {
        return Err(HbError::X25519(format!(
            "Public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let array: [u8; 32] = bytes.try_into().unwrap();
    Ok(PublicKey::from(array))
}

/// Export static secret as raw 32 bytes.
pub fn export_secret_key_raw(key: &StaticSecret) -> Vec<u8> {
    key.to_bytes().to_vec()
}

/// Import static secret from raw 32 bytes.
pub fn import_secret_key_raw(bytes: &[u8]) -> HbResult<StaticSecret> {
    if bytes.len() != 32 {
        return Err(HbError::X25519(format!(
            "Secret key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let array: [u8; 32] = bytes.try_into().unwrap();
    Ok(StaticSecret::from(array))
}

/// Compute a fingerprint (SHA-256 of the public key bytes).
pub fn fingerprint(public_key: &PublicKey) -> String {
    let hash = Sha256::digest(public_key.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_agreement_symmetric() {
        let alice = generate_keypair();
        let bob = generate_keypair();

        let alice_shared = key_agreement(&alice.secret_key, &bob.public_key);
        let bob_shared = key_agreement(&bob.secret_key, &alice.public_key);
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_ephemeral_key_agreement() {
        let recipient = generate_keypair();

        // Sender side: ephemeral agreement
        let (eph_pub, sender_symmetric) =
            encrypt_key_agreement(&recipient.public_key).unwrap();

        // Recipient side: derive same key
        let recipient_symmetric =
            decrypt_key_agreement(&recipient.secret_key, &eph_pub).unwrap();

        assert_eq!(sender_symmetric, recipient_symmetric);
    }

    #[test]
    fn test_key_roundtrip() {
        let kp = generate_keypair();

        let pub_raw = export_public_key_raw(&kp.public_key);
        let sec_raw = export_secret_key_raw(&kp.secret_key);

        let imported_pub = import_public_key_raw(&pub_raw).unwrap();
        let imported_sec = import_secret_key_raw(&sec_raw).unwrap();

        assert_eq!(kp.public_key.as_bytes(), imported_pub.as_bytes());
        // Verify they produce the same public key
        let derived_pub = PublicKey::from(&imported_sec);
        assert_eq!(kp.public_key.as_bytes(), derived_pub.as_bytes());
    }
}
