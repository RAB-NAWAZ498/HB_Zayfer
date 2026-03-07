use std::fs;
use std::io::{self, Read, Write};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::{Parser, Subcommand, ValueEnum};
use dialoguer::{Confirm, Input, Password};
use indicatif::{ProgressBar, ProgressStyle};

use hb_zayfer_core::{
    KeyAlgorithm, KeyStore, KeyWrapping, SymmetricAlgorithm,
    ed25519, format, kdf, rsa, x25519,
    keystore,
};

/// HB_Zayfer — Encryption/Decryption Suite
///
/// A powerful, full-featured cryptographic toolkit supporting
/// RSA, AES-256-GCM, ChaCha20-Poly1305, Ed25519, X25519, and OpenPGP.
#[derive(Parser)]
#[command(name = "hb-zayfer", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Key algorithm
        #[arg(short, long, value_enum)]
        algorithm: AlgorithmChoice,
        /// A human-readable label for the key
        #[arg(short, long)]
        label: String,
        /// Passphrase for protecting the private key (prompted if not given)
        #[arg(short, long)]
        passphrase: Option<String>,
    },

    /// Encrypt a file or text
    Encrypt {
        /// Input file (use '-' for stdin)
        #[arg(short, long)]
        input: String,
        /// Output file (use '-' for stdout)
        #[arg(short, long)]
        output: String,
        /// Recipient key fingerprint or contact name (for public-key encryption)
        #[arg(short, long)]
        recipient: Option<String>,
        /// Symmetric algorithm
        #[arg(long, value_enum, default_value = "aes256gcm")]
        algorithm: SymAlgoChoice,
        /// Use password-based encryption instead of public-key
        #[arg(long)]
        password: bool,
    },

    /// Decrypt a file or text
    Decrypt {
        /// Input file (use '-' for stdin)
        #[arg(short, long)]
        input: String,
        /// Output file (use '-' for stdout)
        #[arg(short, long)]
        output: String,
        /// Key fingerprint for decryption (auto-detected if possible)
        #[arg(short, long)]
        key: Option<String>,
        /// Passphrase for the private key (prompted if not given)
        #[arg(short, long)]
        passphrase: Option<String>,
    },

    /// Sign a file or message
    Sign {
        /// Input file to sign
        #[arg(short, long)]
        input: String,
        /// Key fingerprint for signing
        #[arg(short, long)]
        key: String,
        /// Output file for signature
        #[arg(short, long)]
        output: String,
    },

    /// Verify a signature
    Verify {
        /// Input file that was signed
        #[arg(short, long)]
        input: String,
        /// Signature file
        #[arg(short, long)]
        signature: String,
        /// Public key fingerprint of the signer
        #[arg(short, long)]
        key: String,
    },

    /// Key management commands
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },

    /// Contact management commands
    Contacts {
        #[command(subcommand)]
        action: ContactsAction,
    },
}

#[derive(Subcommand)]
enum KeysAction {
    /// List all keys in the keyring
    List,
    /// Export a key
    Export {
        /// Key fingerprint (or prefix)
        fingerprint: String,
        /// Export format
        #[arg(short, long, default_value = "pem")]
        format: String,
        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Import a key from a file
    Import {
        /// File to import
        file: String,
        /// Label for the imported key
        #[arg(short, long)]
        label: Option<String>,
    },
    /// Delete a key
    Delete {
        /// Key fingerprint
        fingerprint: String,
    },
}

#[derive(Subcommand)]
enum ContactsAction {
    /// List all contacts
    List,
    /// Add a contact
    Add {
        /// Contact name
        name: String,
        /// Associate a key fingerprint
        #[arg(short, long)]
        key: Option<String>,
        /// Email address
        #[arg(short, long)]
        email: Option<String>,
    },
    /// Remove a contact
    Remove {
        /// Contact name
        name: String,
    },
}

#[derive(Clone, ValueEnum)]
enum AlgorithmChoice {
    Rsa2048,
    Rsa4096,
    Ed25519,
    X25519,
    Pgp,
}

#[derive(Clone, ValueEnum)]
enum SymAlgoChoice {
    Aes256gcm,
    Chacha20,
}

impl From<SymAlgoChoice> for SymmetricAlgorithm {
    fn from(c: SymAlgoChoice) -> Self {
        match c {
            SymAlgoChoice::Aes256gcm => SymmetricAlgorithm::Aes256Gcm,
            SymAlgoChoice::Chacha20 => SymmetricAlgorithm::ChaCha20Poly1305,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut keystore = KeyStore::open_default()
        .context("Failed to open keystore")?;

    match cli.command {
        Commands::Keygen {
            algorithm,
            label,
            passphrase,
        } => cmd_keygen(&mut keystore, algorithm, &label, passphrase)?,

        Commands::Encrypt {
            input,
            output,
            recipient,
            algorithm,
            password,
        } => cmd_encrypt(&keystore, &input, &output, recipient, algorithm.into(), password)?,

        Commands::Decrypt {
            input,
            output,
            key,
            passphrase,
        } => cmd_decrypt(&keystore, &input, &output, key, passphrase)?,

        Commands::Sign { input, key, output } => {
            cmd_sign(&keystore, &input, &key, &output)?
        }

        Commands::Verify {
            input,
            signature,
            key,
        } => cmd_verify(&keystore, &input, &signature, &key)?,

        Commands::Keys { action } => match action {
            KeysAction::List => cmd_keys_list(&keystore)?,
            KeysAction::Export {
                fingerprint,
                format,
                output,
            } => cmd_keys_export(&keystore, &fingerprint, &format, output)?,
            KeysAction::Import { file, label } => {
                cmd_keys_import(&mut keystore, &file, label)?
            }
            KeysAction::Delete { fingerprint } => {
                cmd_keys_delete(&mut keystore, &fingerprint)?
            }
        },

        Commands::Contacts { action } => match action {
            ContactsAction::List => cmd_contacts_list(&keystore)?,
            ContactsAction::Add { name, key, email } => {
                cmd_contacts_add(&mut keystore, &name, key, email)?
            }
            ContactsAction::Remove { name } => {
                cmd_contacts_remove(&mut keystore, &name)?
            }
        },
    }

    Ok(())
}

// -- Command implementations --

fn cmd_keygen(
    keystore: &mut KeyStore,
    algorithm: AlgorithmChoice,
    label: &str,
    passphrase: Option<String>,
) -> Result<()> {
    let passphrase = match passphrase {
        Some(p) => p,
        None => Password::new()
            .with_prompt("Enter passphrase for the private key")
            .with_confirmation("Confirm passphrase", "Passphrases don't match")
            .interact()?,
    };

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")?,
    );
    pb.set_message("Generating key pair...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    match algorithm {
        AlgorithmChoice::Rsa2048 => {
            let kp = rsa::generate_keypair(rsa::RsaKeySize::Rsa2048)?;
            let fp = rsa::fingerprint(&kp.public_key)?;

            let priv_pem = rsa::export_private_key_pem(&kp.private_key)?;
            let pub_pem = rsa::export_public_key_pem(&kp.public_key)?;

            keystore.store_private_key(
                &fp,
                priv_pem.as_bytes(),
                passphrase.as_bytes(),
                KeyAlgorithm::Rsa2048,
                label,
            )?;
            keystore.store_public_key(&fp, pub_pem.as_bytes(), KeyAlgorithm::Rsa2048, label)?;

            pb.finish_with_message("RSA-2048 key generated".to_string());
            println!("Fingerprint: {fp}");
            println!("Label: {label}");
        }
        AlgorithmChoice::Rsa4096 => {
            let kp = rsa::generate_keypair(rsa::RsaKeySize::Rsa4096)?;
            let fp = rsa::fingerprint(&kp.public_key)?;

            let priv_pem = rsa::export_private_key_pem(&kp.private_key)?;
            let pub_pem = rsa::export_public_key_pem(&kp.public_key)?;

            keystore.store_private_key(
                &fp,
                priv_pem.as_bytes(),
                passphrase.as_bytes(),
                KeyAlgorithm::Rsa4096,
                label,
            )?;
            keystore.store_public_key(&fp, pub_pem.as_bytes(), KeyAlgorithm::Rsa4096, label)?;

            pb.finish_with_message("RSA-4096 key generated".to_string());
            println!("Fingerprint: {fp}");
            println!("Label: {label}");
        }
        AlgorithmChoice::Ed25519 => {
            let kp = ed25519::generate_keypair();
            let fp = ed25519::fingerprint(&kp.verifying_key);

            let priv_pem = ed25519::export_signing_key_pem(&kp.signing_key)?;
            let pub_pem = ed25519::export_verifying_key_pem(&kp.verifying_key)?;

            keystore.store_private_key(
                &fp,
                priv_pem.as_bytes(),
                passphrase.as_bytes(),
                KeyAlgorithm::Ed25519,
                label,
            )?;
            keystore.store_public_key(&fp, pub_pem.as_bytes(), KeyAlgorithm::Ed25519, label)?;

            pb.finish_with_message("Ed25519 key generated".to_string());
            println!("Fingerprint: {fp}");
            println!("Label: {label}");
        }
        AlgorithmChoice::X25519 => {
            let kp = x25519::generate_keypair();
            let fp = x25519::fingerprint(&kp.public_key);

            let priv_raw = x25519::export_secret_key_raw(&kp.secret_key);
            let pub_raw = x25519::export_public_key_raw(&kp.public_key);

            keystore.store_private_key(
                &fp,
                &priv_raw,
                passphrase.as_bytes(),
                KeyAlgorithm::X25519,
                label,
            )?;
            keystore.store_public_key(&fp, &pub_raw, KeyAlgorithm::X25519, label)?;

            pb.finish_with_message("X25519 key generated".to_string());
            println!("Fingerprint: {fp}");
            println!("Label: {label}");
        }
        AlgorithmChoice::Pgp => {
            let user_id: String = Input::new()
                .with_prompt("User ID (e.g., 'Name <email@example.com>')")
                .interact_text()?;

            let cert = hb_zayfer_core::openpgp::generate_cert(&user_id)?;
            let fp = hb_zayfer_core::openpgp::cert_fingerprint(&cert);
            let pub_armor = hb_zayfer_core::openpgp::export_public_key(&cert)?;
            let sec_armor = hb_zayfer_core::openpgp::export_secret_key(&cert)?;

            keystore.store_private_key(
                &fp,
                sec_armor.as_bytes(),
                passphrase.as_bytes(),
                KeyAlgorithm::Pgp,
                label,
            )?;
            keystore.store_public_key(&fp, pub_armor.as_bytes(), KeyAlgorithm::Pgp, label)?;

            pb.finish_with_message("PGP key generated".to_string());
            println!("Fingerprint: {fp}");
            println!("User ID: {user_id}");
            println!("Label: {label}");
        }
    }

    Ok(())
}

fn cmd_encrypt(
    keystore: &KeyStore,
    input: &str,
    output: &str,
    recipient: Option<String>,
    algorithm: SymmetricAlgorithm,
    use_password: bool,
) -> Result<()> {
    let plaintext = read_input(input)?;

    if use_password {
        // Password-based encryption
        let password = Password::new()
            .with_prompt("Enter encryption password")
            .with_confirmation("Confirm password", "Passwords don't match")
            .interact()?;

        let kdf_params = kdf::KdfParams::default();
        let salt = kdf::generate_salt(16);
        let key = kdf::derive_key(password.as_bytes(), &salt, &kdf_params)?;

        let params = format::EncryptParams {
            algorithm,
            wrapping: KeyWrapping::Password,
            symmetric_key: key,
            kdf_params: Some(kdf_params),
            kdf_salt: Some(salt),
            wrapped_key: None,
            ephemeral_public: None,
        };

        let mut input_cursor = io::Cursor::new(&plaintext);
        let mut output_buf = Vec::new();

        let pb = create_progress_bar(plaintext.len() as u64);
        format::encrypt_stream(
            &mut input_cursor,
            &mut output_buf,
            &params,
            plaintext.len() as u64,
            Some(&mut |bytes| pb.set_position(bytes)),
        )?;
        pb.finish_with_message("Encryption complete");

        write_output(output, &output_buf)?;
    } else if let Some(recipient_name) = recipient {
        // Public-key encryption (X25519 ECDH)
        let fingerprints = keystore.resolve_recipient(&recipient_name);
        if fingerprints.is_empty() {
            bail!("No key found for recipient: {recipient_name}");
        }
        let fp = &fingerprints[0];
        let metadata = keystore
            .get_key_metadata(fp)
            .ok_or_else(|| anyhow::anyhow!("Key metadata not found for {fp}"))?;

        match metadata.algorithm {
            KeyAlgorithm::X25519 => {
                let pub_bytes = keystore.load_public_key(fp)?;
                let their_public = x25519::import_public_key_raw(&pub_bytes)?;
                let (eph_public, symmetric_key) =
                    x25519::encrypt_key_agreement(&their_public)?;

                let params = format::EncryptParams {
                    algorithm,
                    wrapping: KeyWrapping::X25519Ecdh,
                    symmetric_key: symmetric_key.to_vec(),
                    kdf_params: None,
                    kdf_salt: None,
                    wrapped_key: None,
                    ephemeral_public: Some(x25519::export_public_key_raw(&eph_public)),
                };

                let mut input_cursor = io::Cursor::new(&plaintext);
                let mut output_buf = Vec::new();
                format::encrypt_stream(
                    &mut input_cursor,
                    &mut output_buf,
                    &params,
                    plaintext.len() as u64,
                    None,
                )?;
                write_output(output, &output_buf)?;
                println!("Encrypted with X25519 to {}", &fp[..16]);
            }
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
                let pub_bytes = keystore.load_public_key(fp)?;
                let pub_pem = String::from_utf8(pub_bytes)?;
                let rsa_pub = rsa::import_public_key_pem(&pub_pem)?;

                // Generate random symmetric key, encrypt it with RSA
                let mut sym_key = vec![0u8; 32];
                rand::RngCore::fill_bytes(&mut rand_core::OsRng, &mut sym_key);
                let wrapped = rsa::encrypt(&rsa_pub, &sym_key)?;

                let params = format::EncryptParams {
                    algorithm,
                    wrapping: KeyWrapping::RsaOaep,
                    symmetric_key: sym_key,
                    kdf_params: None,
                    kdf_salt: None,
                    wrapped_key: Some(wrapped),
                    ephemeral_public: None,
                };

                let mut input_cursor = io::Cursor::new(&plaintext);
                let mut output_buf = Vec::new();
                format::encrypt_stream(
                    &mut input_cursor,
                    &mut output_buf,
                    &params,
                    plaintext.len() as u64,
                    None,
                )?;
                write_output(output, &output_buf)?;
                println!("Encrypted with RSA to {}", &fp[..16]);
            }
            _ => bail!("Key algorithm {:?} not supported for encryption", metadata.algorithm),
        }
    } else {
        bail!("Specify --recipient for public-key encryption or --password for password-based encryption");
    }

    Ok(())
}

fn cmd_decrypt(
    keystore: &KeyStore,
    input: &str,
    output: &str,
    key_fp: Option<String>,
    passphrase: Option<String>,
) -> Result<()> {
    let ciphertext = read_input(input)?;
    let mut cursor = io::Cursor::new(&ciphertext);
    let header = format::read_header(&mut cursor)?;

    let symmetric_key = match header.wrapping {
        KeyWrapping::Password => {
            let password = match passphrase {
                Some(p) => p,
                None => Password::new()
                    .with_prompt("Enter decryption password")
                    .interact()?,
            };
            let salt = header.kdf_salt.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing KDF salt in file"))?;
            let kdf_params = header.kdf_params.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing KDF params in file"))?;
            kdf::derive_key(password.as_bytes(), salt, kdf_params)?
        }
        KeyWrapping::X25519Ecdh => {
            let fp = key_fp.ok_or_else(|| anyhow::anyhow!("Specify --key for X25519 decryption"))?;
            let passphrase = match passphrase {
                Some(p) => p,
                None => Password::new()
                    .with_prompt("Enter passphrase for private key")
                    .interact()?,
            };
            let priv_bytes = keystore.load_private_key(&fp, passphrase.as_bytes())?;
            let secret = x25519::import_secret_key_raw(&priv_bytes)?;
            let eph_pub_bytes = header.ephemeral_public.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing ephemeral public key"))?;
            let eph_pub = x25519::import_public_key_raw(eph_pub_bytes)?;
            let sym_key = x25519::decrypt_key_agreement(&secret, &eph_pub)?;
            sym_key.to_vec()
        }
        KeyWrapping::RsaOaep => {
            let fp = key_fp.ok_or_else(|| anyhow::anyhow!("Specify --key for RSA decryption"))?;
            let passphrase = match passphrase {
                Some(p) => p,
                None => Password::new()
                    .with_prompt("Enter passphrase for private key")
                    .interact()?,
            };
            let priv_bytes = keystore.load_private_key(&fp, passphrase.as_bytes())?;
            let priv_pem = String::from_utf8(priv_bytes)?;
            let rsa_priv = rsa::import_private_key_pem(&priv_pem)?;
            let wrapped = header.wrapped_key.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing wrapped key"))?;
            rsa::decrypt(&rsa_priv, wrapped)?
        }
    };

    let mut output_buf = Vec::new();
    let pb = create_progress_bar(header.plaintext_len);
    format::decrypt_stream(
        &mut cursor,
        &mut output_buf,
        &header,
        &symmetric_key,
        Some(&mut |bytes| pb.set_position(bytes)),
    )?;
    pb.finish_with_message("Decryption complete");

    write_output(output, &output_buf)?;
    Ok(())
}

fn cmd_sign(keystore: &KeyStore, input: &str, key_fp: &str, output: &str) -> Result<()> {
    let message = read_input(input)?;

    let passphrase = Password::new()
        .with_prompt("Enter passphrase for signing key")
        .interact()?;

    let metadata = keystore
        .get_key_metadata(key_fp)
        .ok_or_else(|| anyhow::anyhow!("Key not found: {key_fp}"))?;

    let priv_bytes = keystore.load_private_key(key_fp, passphrase.as_bytes())?;

    let signature = match metadata.algorithm {
        KeyAlgorithm::Ed25519 => {
            let priv_pem = String::from_utf8(priv_bytes)?;
            let signing_key = ed25519::import_signing_key_pem(&priv_pem)?;
            ed25519::sign(&signing_key, &message)
        }
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
            let priv_pem = String::from_utf8(priv_bytes)?;
            let rsa_priv = rsa::import_private_key_pem(&priv_pem)?;
            rsa::sign(&rsa_priv, &message)?
        }
        _ => bail!("Algorithm {:?} not supported for signing", metadata.algorithm),
    };

    write_output(output, &signature)?;
    println!("Signature written to: {output}");
    Ok(())
}

fn cmd_verify(keystore: &KeyStore, input: &str, sig_file: &str, key_fp: &str) -> Result<()> {
    let message = read_input(input)?;
    let signature = fs::read(sig_file).context("Failed to read signature file")?;

    let metadata = keystore
        .get_key_metadata(key_fp)
        .ok_or_else(|| anyhow::anyhow!("Key not found: {key_fp}"))?;

    let pub_bytes = keystore.load_public_key(key_fp)?;

    let valid = match metadata.algorithm {
        KeyAlgorithm::Ed25519 => {
            let pub_pem = String::from_utf8(pub_bytes)?;
            let vk = ed25519::import_verifying_key_pem(&pub_pem)?;
            ed25519::verify(&vk, &message, &signature)?
        }
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
            let pub_pem = String::from_utf8(pub_bytes)?;
            let rsa_pub = rsa::import_public_key_pem(&pub_pem)?;
            rsa::verify(&rsa_pub, &message, &signature)?
        }
        _ => bail!("Algorithm {:?} not supported for verification", metadata.algorithm),
    };

    if valid {
        println!("✓ Signature is VALID");
    } else {
        println!("✗ Signature is INVALID");
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_keys_list(keystore: &KeyStore) -> Result<()> {
    let keys = keystore.list_keys();
    if keys.is_empty() {
        println!("No keys in keyring. Use 'hb-zayfer keygen' to generate one.");
        return Ok(());
    }

    println!("{:<20} {:<10} {:<8} {:<8} {}", "FINGERPRINT", "ALGORITHM", "PRIVATE", "PUBLIC", "LABEL");
    println!("{}", "-".repeat(70));
    for k in keys {
        let fp_short = if k.fingerprint.len() > 16 {
            &k.fingerprint[..16]
        } else {
            &k.fingerprint
        };
        println!(
            "{:<20} {:<10} {:<8} {:<8} {}",
            format!("{fp_short}..."),
            k.algorithm,
            if k.has_private { "yes" } else { "no" },
            if k.has_public { "yes" } else { "no" },
            k.label,
        );
    }
    Ok(())
}

fn cmd_keys_export(
    keystore: &KeyStore,
    fingerprint: &str,
    _format: &str,
    output: Option<String>,
) -> Result<()> {
    let pub_bytes = keystore.load_public_key(fingerprint)?;
    match output {
        Some(path) => {
            fs::write(&path, &pub_bytes)?;
            println!("Public key exported to: {path}");
        }
        None => {
            if let Ok(text) = String::from_utf8(pub_bytes.clone()) {
                println!("{text}");
            } else {
                println!("{}", BASE64.encode(&pub_bytes));
            }
        }
    }
    Ok(())
}

fn cmd_keys_import(
    keystore: &mut KeyStore,
    file: &str,
    label: Option<String>,
) -> Result<()> {
    let data = fs::read(file).context("Failed to read key file")?;
    let fmt = keystore::detect_key_format(&data);
    let label = label.unwrap_or_else(|| file.to_string());

    // Determine algorithm from detected format
    let algorithm = match &fmt {
        keystore::KeyFormat::OpenPgpArmor => KeyAlgorithm::Pgp,
        keystore::KeyFormat::OpenSsh => {
            // Inspect text prefix for algorithm hint
            if let Ok(text) = std::str::from_utf8(&data) {
                if text.starts_with("ssh-rsa") {
                    KeyAlgorithm::Rsa2048
                } else {
                    KeyAlgorithm::Ed25519
                }
            } else {
                KeyAlgorithm::Ed25519
            }
        }
        _ => {
            // PEM/DER: check for RSA markers
            if let Ok(text) = std::str::from_utf8(&data) {
                if text.contains("RSA") {
                    KeyAlgorithm::Rsa2048
                } else {
                    KeyAlgorithm::Ed25519
                }
            } else {
                KeyAlgorithm::Ed25519
            }
        }
    };

    let fp = keystore::compute_fingerprint(&data);
    keystore.store_public_key(&fp, &data, algorithm, &label)?;

    println!("Key imported:");
    println!("  Fingerprint: {fp}");
    println!("  Format: {fmt:?}");
    println!("  Label: {label}");
    Ok(())
}

fn cmd_keys_delete(keystore: &mut KeyStore, fingerprint: &str) -> Result<()> {
    let confirm = Confirm::new()
        .with_prompt(format!("Delete key {fingerprint}? This cannot be undone"))
        .default(false)
        .interact()?;

    if confirm {
        keystore.delete_key(fingerprint)?;
        println!("Key deleted: {fingerprint}");
    } else {
        println!("Aborted.");
    }
    Ok(())
}

fn cmd_contacts_list(keystore: &KeyStore) -> Result<()> {
    let contacts = keystore.list_contacts();
    if contacts.is_empty() {
        println!("No contacts. Use 'hb-zayfer contacts add' to add one.");
        return Ok(());
    }

    println!("{:<20} {:<30} {}", "NAME", "EMAIL", "KEYS");
    println!("{}", "-".repeat(60));
    for c in contacts {
        println!(
            "{:<20} {:<30} {}",
            c.name,
            c.email.as_deref().unwrap_or("-"),
            c.key_fingerprints.len(),
        );
    }
    Ok(())
}

fn cmd_contacts_add(
    keystore: &mut KeyStore,
    name: &str,
    key: Option<String>,
    email: Option<String>,
) -> Result<()> {
    keystore.add_contact(name, email.as_deref(), None)?;
    if let Some(fp) = key {
        keystore.associate_key_with_contact(name, &fp)?;
        println!("Contact '{name}' added with key {fp}");
    } else {
        println!("Contact '{name}' added");
    }
    Ok(())
}

fn cmd_contacts_remove(keystore: &mut KeyStore, name: &str) -> Result<()> {
    keystore.remove_contact(name)?;
    println!("Contact '{name}' removed");
    Ok(())
}

// -- Utilities --

fn read_input(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        fs::read(path).with_context(|| format!("Failed to read: {path}"))
    }
}

fn write_output(path: &str, data: &[u8]) -> Result<()> {
    if path == "-" {
        io::stdout().write_all(data)?;
        io::stdout().flush()?;
    } else {
        fs::write(path, data).with_context(|| format!("Failed to write: {path}"))?;
    }
    Ok(())
}

fn create_progress_bar(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("█▓░"),
    );
    pb
}
