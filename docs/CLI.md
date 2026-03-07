# CLI Reference

HB_Zayfer provides two command-line interfaces: a **Rust CLI** (compiled
binary) and a **Python CLI** (Click-based, installed via pip).

Both CLIs provide the same core functionality; choose the one that fits your
workflow.

---

## Python CLI (`hb-zayfer`)

Installed automatically with `pip install -e ".[cli]"`. Requires `click` and
`rich`.

### Global Options

```
hb-zayfer --version    Show version and exit
hb-zayfer --help       Show help
```

---

### `keygen` — Generate a Key Pair

```bash
hb-zayfer keygen ALGORITHM --label LABEL [OPTIONS]
```

| Argument | Required | Values |
|----------|----------|--------|
| `ALGORITHM` | Yes | `rsa2048`, `rsa4096`, `ed25519`, `x25519`, `pgp` |

| Option | Description |
|--------|-------------|
| `--label, -l` | Human-readable label (required) |
| `--user-id, -u` | User ID for PGP keys (e.g. `"Name <email>"`) |
| `--export-dir, -o` | Directory to export the public key file |

You will be prompted for a passphrase to protect the private key.

**Examples:**

```bash
# Generate an Ed25519 key
hb-zayfer keygen ed25519 --label "My Signing Key"

# Generate RSA-4096 and export the public key
hb-zayfer keygen rsa4096 --label server-key --export-dir ./keys/

# Generate a PGP certificate
hb-zayfer keygen pgp --label "Work Key" --user-id "Jane <jane@corp.com>"
```

---

### `encrypt` — Encrypt a File

```bash
hb-zayfer encrypt INPUT_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--output, -o` | Output file (default: `<input>.hbzf`) |
| `--algorithm, -a` | `aes` (default) or `chacha` |
| `--password, -p` | Use password-based encryption |
| `--recipient, -r` | Contact name or fingerprint prefix |

If neither `--password` nor `--recipient` is given, defaults to password mode.

**Examples:**

```bash
# Password-based encryption (prompted)
hb-zayfer encrypt secret.pdf --password

# Encrypt to a contact using AES-256-GCM
hb-zayfer encrypt report.xlsx --recipient Alice

# Encrypt with ChaCha20-Poly1305
hb-zayfer encrypt data.bin --password --algorithm chacha --output data.enc
```

---

### `decrypt` — Decrypt an HBZF File

```bash
hb-zayfer decrypt INPUT_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--output, -o` | Output file (default: strip `.hbzf` suffix) |
| `--key, -k` | Fingerprint prefix of decryption key (for public-key mode) |

The CLI auto-detects the wrapping mode from the HBZF header and prompts
accordingly.

**Examples:**

```bash
# Decrypt password-encrypted file
hb-zayfer decrypt secret.pdf.hbzf

# Decrypt with a specific X25519 key
hb-zayfer decrypt message.hbzf --key a1b2c3d4

# Specify output path
hb-zayfer decrypt archive.hbzf --output /tmp/recovered.tar
```

---

### `sign` — Sign a File

```bash
hb-zayfer sign INPUT_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--key, -k` | Fingerprint prefix of the signing key |
| `--output, -o` | Signature output file (default: `<input>.sig`) |
| `--algorithm, -a` | `ed25519` (default), `rsa`, or `pgp` |

**Examples:**

```bash
# Ed25519 signature
hb-zayfer sign document.pdf --key a1b2c3

# RSA-PSS signature with explicit output
hb-zayfer sign firmware.bin --key abc123 --algorithm rsa --output firmware.sig
```

---

### `verify` — Verify a Signature

```bash
hb-zayfer verify INPUT_FILE SIGNATURE_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--key, -k` | Fingerprint prefix or contact name of the verification key (required) |
| `--algorithm, -a` | `ed25519` (default), `rsa`, or `pgp` |

**Examples:**

```bash
hb-zayfer verify document.pdf document.pdf.sig --key Alice
hb-zayfer verify firmware.bin firmware.sig --key abc123 --algorithm rsa
```

Exit code `0` if valid, `1` if invalid.

---

### `keys` — Key Management

#### `keys list`

```bash
hb-zayfer keys list
```

Lists all keys in the keyring with fingerprint, algorithm, label, and
private/public status.

#### `keys export`

```bash
hb-zayfer keys export FINGERPRINT [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--format, -f` | Export format (default: `pem`) |
| `--output, -o` | Output file (stdout if omitted) |

#### `keys import`

```bash
hb-zayfer keys import FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--label, -l` | Label for the imported key |

Supports PEM, DER, ASCII-armored PGP, and OpenSSH formats.

#### `keys delete`

```bash
hb-zayfer keys delete FINGERPRINT
```

Prompts for confirmation before deletion.

---

### `contacts` — Contact Management

#### `contacts list`

```bash
hb-zayfer contacts list
```

#### `contacts add`

```bash
hb-zayfer contacts add NAME [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--key, -k` | Fingerprint to associate (optional) |
| `--email, -e` | Email address (optional) |

#### `contacts remove`

```bash
hb-zayfer contacts remove NAME
```

---

## Rust CLI (`hb_zayfer_cli`)

```bash
cargo run --bin hb_zayfer_cli -- <COMMAND> [OPTIONS]
# Or after `cargo install --path crates/cli`:
hb-zayfer <COMMAND>
```

### Commands

The Rust CLI supports the same commands with slightly different syntax:

```
USAGE: hb-zayfer <COMMAND>

Commands:
  keygen      Generate a new key pair
  encrypt     Encrypt a file or text
  decrypt     Decrypt a file or text
  sign        Sign a file or message
  verify      Verify a signature
  keys        Key management (list, export, import, delete)
  contacts    Contact management (list, add, remove)
```

### `keygen`

```bash
hb-zayfer keygen --algorithm <ALGO> --label <LABEL> [--passphrase <PW>]
```

| `--algorithm` values | Description |
|---------------------|-------------|
| `rsa2048` | RSA 2048-bit |
| `rsa4096` | RSA 4096-bit |
| `ed25519` | Ed25519 |
| `x25519` | X25519 ECDH |
| `pgp` | OpenPGP certificate |

### `encrypt`

```bash
hb-zayfer encrypt --input <FILE> --output <FILE> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--recipient, -r` | Contact name or fingerprint prefix |
| `--algorithm` | `aes256gcm` (default) or `chacha20` |
| `--password` | Use password-based encryption |

### `decrypt`

```bash
hb-zayfer decrypt --input <FILE> --output <FILE> [--key <FP>] [--passphrase <PW>]
```

### `sign`

```bash
hb-zayfer sign --input <FILE> --key <FP> --output <FILE>
```

### `verify`

```bash
hb-zayfer verify --input <FILE> --signature <FILE> --key <FP>
```

### `keys`

```bash
hb-zayfer keys list
hb-zayfer keys export <FP> [--format pem] [--output FILE]
hb-zayfer keys import <FILE> [--label LABEL]
hb-zayfer keys delete <FP>
```

### `contacts`

```bash
hb-zayfer contacts list
hb-zayfer contacts add <NAME> [--key FP] [--email EMAIL]
hb-zayfer contacts remove <NAME>
```

### Input/Output

Both `--input` and `--output` accept `-` for stdin/stdout:

```bash
# Pipe-friendly
cat secret.txt | hb-zayfer encrypt --input - --output - --password > encrypted.hbzf
cat encrypted.hbzf | hb-zayfer decrypt --input - --output - > decrypted.txt
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HB_ZAYFER_HOME` | Override keystore directory (default: `~/.hb_zayfer/`) |
| `HB_ZAYFER_API_TOKEN` | Bearer token for web API authentication |
