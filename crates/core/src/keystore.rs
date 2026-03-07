//! Key storage and contact management.
//!
//! Manages keys on disk at `~/.hb_zayfer/` with the structure:
//! ```text
//! ~/.hb_zayfer/
//!   keys/private/<fingerprint>.key  (encrypted)
//!   keys/public/<fingerprint>.pub
//!   keyring.json
//!   contacts.json
//!   config.toml
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{HbError, HbResult};
use crate::kdf::{self, KdfParams};
use crate::aes_gcm;
use crate::format::SymmetricAlgorithm;

/// Algorithm type for a stored key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    Rsa2048,
    Rsa4096,
    Ed25519,
    X25519,
    Pgp,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Rsa2048 => write!(f, "RSA-2048"),
            KeyAlgorithm::Rsa4096 => write!(f, "RSA-4096"),
            KeyAlgorithm::Ed25519 => write!(f, "Ed25519"),
            KeyAlgorithm::X25519 => write!(f, "X25519"),
            KeyAlgorithm::Pgp => write!(f, "PGP"),
        }
    }
}

/// Metadata for a key stored in the keyring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub fingerprint: String,
    pub algorithm: KeyAlgorithm,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub has_private: bool,
    pub has_public: bool,
}

/// A contact in the address book.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub email: Option<String>,
    pub key_fingerprints: Vec<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// The keyring index file.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KeyringIndex {
    pub keys: HashMap<String, KeyMetadata>,
}

/// The contacts file.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ContactsStore {
    pub contacts: HashMap<String, Contact>,
}

/// Application configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub default_symmetric_algorithm: SymmetricAlgorithm,
    pub default_kdf: KdfParams,
    pub keyring_path: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            default_symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            default_kdf: KdfParams::default(),
            keyring_path: None,
        }
    }
}

/// The KeyStore manages all key operations on disk.
pub struct KeyStore {
    base_path: PathBuf,
    index: KeyringIndex,
    contacts: ContactsStore,
}

impl KeyStore {
    /// Open or create a keystore at the default location.
    ///
    /// Checks `HB_ZAYFER_HOME` env-var first, then falls back to `~/.hb_zayfer/`.
    pub fn open_default() -> HbResult<Self> {
        if let Ok(custom) = std::env::var("HB_ZAYFER_HOME") {
            return Self::open(PathBuf::from(custom));
        }
        let home = dirs::home_dir()
            .ok_or_else(|| HbError::Io(io::Error::new(io::ErrorKind::NotFound, "Home directory not found")))?;
        Self::open(home.join(".hb_zayfer"))
    }

    /// Open or create a keystore at the specified path.
    pub fn open(base_path: PathBuf) -> HbResult<Self> {
        // Create directory structure
        fs::create_dir_all(base_path.join("keys/private"))?;
        fs::create_dir_all(base_path.join("keys/public"))?;

        // Set permissions on private key directory (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(base_path.join("keys/private"), perms);
        }

        // Load or create index
        let index_path = base_path.join("keyring.json");
        let index = if index_path.exists() {
            let data = fs::read_to_string(&index_path)?;
            serde_json::from_str(&data)?
        } else {
            KeyringIndex::default()
        };

        // Load or create contacts
        let contacts_path = base_path.join("contacts.json");
        let contacts = if contacts_path.exists() {
            let data = fs::read_to_string(&contacts_path)?;
            serde_json::from_str(&data)?
        } else {
            ContactsStore::default()
        };

        Ok(Self {
            base_path,
            index,
            contacts,
        })
    }

    /// Atomically save data to a file using write-then-rename.
    fn atomic_write(path: &Path, data: &[u8]) -> HbResult<()> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Save the keyring index to disk (atomic).
    fn save_index(&self) -> HbResult<()> {
        let data = serde_json::to_string_pretty(&self.index)?;
        Self::atomic_write(&self.base_path.join("keyring.json"), data.as_bytes())?;
        Ok(())
    }

    /// Save contacts to disk (atomic).
    fn save_contacts(&self) -> HbResult<()> {
        let data = serde_json::to_string_pretty(&self.contacts)?;
        Self::atomic_write(&self.base_path.join("contacts.json"), data.as_bytes())?;
        Ok(())
    }

    /// Get the base path.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    // -- Key storage --

    /// Private key envelope version.
    ///
    /// Version 2 stores KDF metadata so key decryption works even if
    /// global defaults change:
    /// ```text
    /// [1B] envelope version (0x02)
    /// [1B] KDF algorithm ID
    /// [12B] KDF params (same layout as HBZF header)
    /// [16B] salt
    /// [12B] nonce
    /// [...] AES-256-GCM ciphertext
    /// ```
    const KEY_ENVELOPE_VERSION: u8 = 0x02;

    /// Store a private key (encrypted with passphrase).
    pub fn store_private_key(
        &mut self,
        fingerprint: &str,
        key_bytes: &[u8],
        passphrase: &[u8],
        algorithm: KeyAlgorithm,
        label: &str,
    ) -> HbResult<()> {
        // Derive encryption key from passphrase
        let kdf_params = KdfParams::default();
        let salt = kdf::generate_salt(16);
        let enc_key = kdf::derive_key(passphrase, &salt, &kdf_params)?;

        // Encrypt the private key with AES-256-GCM
        let (nonce, ciphertext) = aes_gcm::encrypt(&enc_key, key_bytes, fingerprint.as_bytes())?;

        // Build versioned envelope: version(1) + kdf_id(1) + kdf_params(12) + salt(16) + nonce(12) + ciphertext
        let mut envelope = Vec::new();
        envelope.push(Self::KEY_ENVELOPE_VERSION);
        envelope.push(kdf_params.algorithm().id());
        match &kdf_params {
            KdfParams::Argon2id(p) => {
                envelope.extend_from_slice(&p.m_cost.to_le_bytes());
                envelope.extend_from_slice(&p.t_cost.to_le_bytes());
                envelope.extend_from_slice(&p.p_cost.to_le_bytes());
            }
            KdfParams::Scrypt(p) => {
                envelope.push(p.log_n);
                envelope.extend_from_slice(&[0u8; 3]); // padding
                envelope.extend_from_slice(&p.r.to_le_bytes());
                envelope.extend_from_slice(&p.p.to_le_bytes());
            }
        }
        envelope.extend_from_slice(&salt);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);

        let key_path = self.base_path.join("keys/private").join(format!("{fingerprint}.key"));
        fs::write(&key_path, &envelope)?;

        // Set file permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(&key_path, perms);
        }

        // Update or create index entry
        let entry = self.index.keys.entry(fingerprint.to_string()).or_insert_with(|| KeyMetadata {
            fingerprint: fingerprint.to_string(),
            algorithm: algorithm.clone(),
            label: label.to_string(),
            created_at: Utc::now(),
            has_private: false,
            has_public: false,
        });
        entry.has_private = true;
        entry.algorithm = algorithm;
        if !label.is_empty() {
            entry.label = label.to_string();
        }

        self.save_index()?;
        Ok(())
    }

    /// Store a public key.
    pub fn store_public_key(
        &mut self,
        fingerprint: &str,
        key_bytes: &[u8],
        algorithm: KeyAlgorithm,
        label: &str,
    ) -> HbResult<()> {
        let key_path = self.base_path.join("keys/public").join(format!("{fingerprint}.pub"));
        fs::write(&key_path, key_bytes)?;

        let entry = self.index.keys.entry(fingerprint.to_string()).or_insert_with(|| KeyMetadata {
            fingerprint: fingerprint.to_string(),
            algorithm: algorithm.clone(),
            label: label.to_string(),
            created_at: Utc::now(),
            has_private: false,
            has_public: false,
        });
        entry.has_public = true;
        entry.algorithm = algorithm;
        if !label.is_empty() {
            entry.label = label.to_string();
        }

        self.save_index()?;
        Ok(())
    }

    /// Load an encrypted private key, decrypting with the passphrase.
    ///
    /// Supports both v1 (legacy: no header) and v2 (versioned with embedded KDF params).
    pub fn load_private_key(&self, fingerprint: &str, passphrase: &[u8]) -> HbResult<Vec<u8>> {
        let key_path = self.base_path.join("keys/private").join(format!("{fingerprint}.key"));
        if !key_path.exists() {
            return Err(HbError::KeyNotFound(fingerprint.to_string()));
        }

        let envelope = fs::read(&key_path)?;

        // Detect envelope version
        let (kdf_params, salt, nonce, ciphertext) = if !envelope.is_empty() && envelope[0] == Self::KEY_ENVELOPE_VERSION {
            // V2 envelope: version(1) + kdf_id(1) + kdf_params(12) + salt(16) + nonce(12) + ct
            if envelope.len() < 1 + 1 + 12 + 16 + 12 {
                return Err(HbError::InvalidFormat("V2 key envelope too short".into()));
            }
            let kdf_id = envelope[1];
            let kdf_param_bytes = &envelope[2..14];
            let kdf_p = match kdf::KdfAlgorithm::from_id(kdf_id)? {
                kdf::KdfAlgorithm::Argon2id => {
                    let m = u32::from_le_bytes(kdf_param_bytes[0..4].try_into().unwrap());
                    let t = u32::from_le_bytes(kdf_param_bytes[4..8].try_into().unwrap());
                    let p = u32::from_le_bytes(kdf_param_bytes[8..12].try_into().unwrap());
                    KdfParams::Argon2id(kdf::Argon2Params { m_cost: m, t_cost: t, p_cost: p })
                }
                kdf::KdfAlgorithm::Scrypt => {
                    let log_n = kdf_param_bytes[0];
                    let r = u32::from_le_bytes(kdf_param_bytes[4..8].try_into().unwrap());
                    let p = u32::from_le_bytes(kdf_param_bytes[8..12].try_into().unwrap());
                    KdfParams::Scrypt(kdf::ScryptParams { log_n, r, p })
                }
            };
            let salt = &envelope[14..30];
            let nonce = &envelope[30..42];
            let ciphertext = &envelope[42..];
            (kdf_p, salt, nonce, ciphertext)
        } else {
            // V1 (legacy) envelope: salt(16) + nonce(12) + ciphertext
            if envelope.len() < 28 {
                return Err(HbError::InvalidFormat("Key file too short".into()));
            }
            let salt = &envelope[..16];
            let nonce = &envelope[16..28];
            let ciphertext = &envelope[28..];
            (KdfParams::default(), salt, nonce, ciphertext)
        };

        let enc_key = kdf::derive_key(passphrase, salt, &kdf_params)?;

        aes_gcm::decrypt(&enc_key, nonce, ciphertext, fingerprint.as_bytes())
            .map_err(|_| HbError::InvalidPassphrase)
    }

    /// Load a public key.
    pub fn load_public_key(&self, fingerprint: &str) -> HbResult<Vec<u8>> {
        let key_path = self.base_path.join("keys/public").join(format!("{fingerprint}.pub"));
        if !key_path.exists() {
            return Err(HbError::KeyNotFound(fingerprint.to_string()));
        }
        Ok(fs::read(&key_path)?)
    }

    /// List all keys in the keyring.
    pub fn list_keys(&self) -> Vec<&KeyMetadata> {
        self.index.keys.values().collect()
    }

    /// Get metadata for a specific key.
    pub fn get_key_metadata(&self, fingerprint: &str) -> Option<&KeyMetadata> {
        self.index.keys.get(fingerprint)
    }

    /// Find keys by label (partial match).
    pub fn find_keys_by_label(&self, query: &str) -> Vec<&KeyMetadata> {
        let query_lower = query.to_lowercase();
        self.index
            .keys
            .values()
            .filter(|m| m.label.to_lowercase().contains(&query_lower))
            .collect()
    }

    /// Delete a key (both private and public).
    pub fn delete_key(&mut self, fingerprint: &str) -> HbResult<()> {
        let priv_path = self.base_path.join("keys/private").join(format!("{fingerprint}.key"));
        let pub_path = self.base_path.join("keys/public").join(format!("{fingerprint}.pub"));

        if priv_path.exists() {
            fs::remove_file(&priv_path)?;
        }
        if pub_path.exists() {
            fs::remove_file(&pub_path)?;
        }

        self.index.keys.remove(fingerprint);
        self.save_index()?;

        // Remove from any contacts
        for contact in self.contacts.contacts.values_mut() {
            contact.key_fingerprints.retain(|fp| fp != fingerprint);
        }
        self.save_contacts()?;

        Ok(())
    }

    // -- Contact management --

    /// Add a contact.
    pub fn add_contact(&mut self, name: &str, email: Option<&str>, notes: Option<&str>) -> HbResult<()> {
        if self.contacts.contacts.contains_key(name) {
            return Err(HbError::ContactAlreadyExists(name.to_string()));
        }

        self.contacts.contacts.insert(
            name.to_string(),
            Contact {
                name: name.to_string(),
                email: email.map(String::from),
                key_fingerprints: Vec::new(),
                notes: notes.map(String::from),
                created_at: Utc::now(),
            },
        );
        self.save_contacts()?;
        Ok(())
    }

    /// Associate a key fingerprint with a contact.
    pub fn associate_key_with_contact(
        &mut self,
        contact_name: &str,
        fingerprint: &str,
    ) -> HbResult<()> {
        let contact = self
            .contacts
            .contacts
            .get_mut(contact_name)
            .ok_or_else(|| HbError::ContactNotFound(contact_name.to_string()))?;

        if !contact.key_fingerprints.contains(&fingerprint.to_string()) {
            contact.key_fingerprints.push(fingerprint.to_string());
        }
        self.save_contacts()?;
        Ok(())
    }

    /// Get a contact by name.
    pub fn get_contact(&self, name: &str) -> Option<&Contact> {
        self.contacts.contacts.get(name)
    }

    /// List all contacts.
    pub fn list_contacts(&self) -> Vec<&Contact> {
        self.contacts.contacts.values().collect()
    }

    /// Remove a contact.
    pub fn remove_contact(&mut self, name: &str) -> HbResult<()> {
        if self.contacts.contacts.remove(name).is_none() {
            return Err(HbError::ContactNotFound(name.to_string()));
        }
        self.save_contacts()?;
        Ok(())
    }

    /// Resolve a contact name to their public key fingerprints.
    pub fn resolve_recipient(&self, name_or_fp: &str) -> Vec<String> {
        // Try as a contact name first
        if let Some(contact) = self.contacts.contacts.get(name_or_fp) {
            return contact.key_fingerprints.clone();
        }
        // Try as a fingerprint prefix
        let matches: Vec<String> = self
            .index
            .keys
            .keys()
            .filter(|fp| fp.starts_with(name_or_fp))
            .cloned()
            .collect();
        matches
    }
}

/// Compute a fingerprint from arbitrary public key bytes.
pub fn compute_fingerprint(public_key_bytes: &[u8]) -> String {
    let hash = Sha256::digest(public_key_bytes);
    hex::encode(hash)
}

/// Auto-detect the format of a key file by inspecting its contents.
pub fn detect_key_format(data: &[u8]) -> KeyFormat {
    if let Ok(text) = std::str::from_utf8(data) {
        if text.contains("-----BEGIN PGP") {
            return KeyFormat::OpenPgpArmor;
        }
        if text.starts_with("ssh-") {
            return KeyFormat::OpenSsh;
        }
        if text.contains("-----BEGIN") {
            // Could be PKCS#1 or PKCS#8
            if text.contains("RSA PRIVATE KEY") || text.contains("RSA PUBLIC KEY") {
                return KeyFormat::Pkcs1Pem;
            }
            return KeyFormat::Pkcs8Pem;
        }
    }
    KeyFormat::Der
}

/// Key file format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyFormat {
    Pkcs8Pem,
    Pkcs1Pem,
    Der,
    OpenPgpArmor,
    OpenSsh,
}

use std::io;

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_keystore() -> (tempfile::TempDir, KeyStore) {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(dir.path().to_path_buf()).unwrap();
        (dir, ks)
    }

    #[test]
    fn test_store_and_load_keys() {
        let (_dir, mut ks) = temp_keystore();
        let fake_key = b"this is a fake private key for testing purposes";
        let passphrase = b"secure_passphrase";
        let fp = "abc123def456";

        ks.store_private_key(fp, fake_key, passphrase, KeyAlgorithm::Ed25519, "Test Key")
            .unwrap();
        ks.store_public_key(fp, b"public key data", KeyAlgorithm::Ed25519, "Test Key")
            .unwrap();

        let loaded = ks.load_private_key(fp, passphrase).unwrap();
        assert_eq!(loaded, fake_key);

        let pub_loaded = ks.load_public_key(fp).unwrap();
        assert_eq!(pub_loaded, b"public key data");
    }

    #[test]
    fn test_wrong_passphrase() {
        let (_dir, mut ks) = temp_keystore();
        let fp = "testkey1";
        ks.store_private_key(fp, b"secret", b"correct", KeyAlgorithm::Rsa2048, "Test")
            .unwrap();

        let result = ks.load_private_key(fp, b"wrong");
        assert!(matches!(result, Err(HbError::InvalidPassphrase)));
    }

    #[test]
    fn test_contacts() {
        let (_dir, mut ks) = temp_keystore();
        ks.add_contact("Alice", Some("alice@example.com"), None).unwrap();
        ks.add_contact("Bob", None, Some("Bob's note")).unwrap();

        assert_eq!(ks.list_contacts().len(), 2);
        assert!(ks.get_contact("Alice").is_some());

        ks.associate_key_with_contact("Alice", "fingerprint123").unwrap();
        let alice = ks.get_contact("Alice").unwrap();
        assert_eq!(alice.key_fingerprints, vec!["fingerprint123"]);

        ks.remove_contact("Bob").unwrap();
        assert_eq!(ks.list_contacts().len(), 1);
    }

    #[test]
    fn test_key_format_detection() {
        assert_eq!(
            detect_key_format(b"-----BEGIN PRIVATE KEY-----\n..."),
            KeyFormat::Pkcs8Pem
        );
        assert_eq!(
            detect_key_format(b"-----BEGIN RSA PRIVATE KEY-----\n..."),
            KeyFormat::Pkcs1Pem
        );
        assert_eq!(
            detect_key_format(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."),
            KeyFormat::OpenPgpArmor
        );
        assert_eq!(
            detect_key_format(b"ssh-ed25519 AAAA..."),
            KeyFormat::OpenSsh
        );
        assert_eq!(detect_key_format(&[0x30, 0x82]), KeyFormat::Der);
    }
}
