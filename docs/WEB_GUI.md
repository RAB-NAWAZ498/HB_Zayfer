# Web & GUI Interfaces

HB_Zayfer includes a **desktop GUI** (PySide6/Qt) and a **browser-based web
UI** (FastAPI + vanilla JS). Both interfaces wrap the same `hb_zayfer` Python
API.

---

## Desktop GUI

### Installation

```bash
pip install -e ".[gui]"
```

Requires PySide6 ≥ 6.5.

### Launch

```bash
hb-zayfer-gui
```

### Overview

The main window features a sidebar with six views:

| View | Icon | Description |
|------|------|-------------|
| **Encrypt** | 🔐 | Select file or enter text, choose algorithm (AES / ChaCha), select wrapping mode (password / recipient), encrypt |
| **Decrypt** | 🔓 | Select encrypted file, auto-detect wrapping mode, enter passphrase or select key, decrypt |
| **Key Generation** | 🔑 | Choose algorithm (RSA-2048/4096, Ed25519, X25519, PGP), set label, generate & store |
| **Keyring** | 📦 | Browse all stored keys, view metadata, export public keys, delete keys |
| **Contacts** | 👥 | Add/remove contacts, associate keys with contacts, search by name |
| **Settings** | ⚙️ | Configure default symmetric algorithm, KDF parameters, keystore path |

### Architecture

- **Main window**: `main_window.py` — `QMainWindow` with `QStackedWidget`.
- **Views**: `encrypt_view.py`, `decrypt_view.py`, `keygen_view.py`,
  `keyring_view.py`, `contacts_view.py`, `settings_view.py`.
- **Workers**: `workers.py` — `QThread`-based workers for long-running
  operations (key generation, encryption, decryption) to keep the UI
  responsive.

### Workflow: Encrypt a File

1. Navigate to the **Encrypt** view.
2. Click "Browse" to select an input file (or type text directly).
3. Choose the symmetric algorithm (AES-256-GCM or ChaCha20-Poly1305).
4. Select wrapping mode:
   - **Password**: enter and confirm a passphrase.
   - **Recipient**: pick a contact or enter a fingerprint prefix.
5. Click "Encrypt". Progress is shown in the status bar.
6. The output file is saved as `<filename>.hbzf`.

### Workflow: Decrypt a File

1. Navigate to the **Decrypt** view.
2. Select the `.hbzf` file.
3. The header is read to determine the wrapping mode.
4. Provide the passphrase or select the appropriate private key.
5. Click "Decrypt". The output file is created.

---

## Web Interface

### Installation

```bash
pip install -e ".[web]"
```

Requires FastAPI ≥ 0.100, uvicorn, and python-multipart.

### Launch

```bash
hb-zayfer-web
```

Opens at **http://127.0.0.1:8000** by default.

### Static Frontend

A single-page application served from `python/hb_zayfer/web/static/`:

- `index.html` — main page with tabs for encrypt, decrypt, keys, contacts
- `style.css` — styling
- `app.js` — vanilla JavaScript calling the REST API

### REST API Endpoints

All API endpoints are prefixed with `/api`.

#### Info

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/version` | Returns `{"version": "0.1.0"}` |

#### Text Encryption / Decryption

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/encrypt/text` | Encrypt text with password |
| `POST` | `/api/decrypt/text` | Decrypt text with password |

**Encrypt request:**

```json
{
  "plaintext": "Hello, World!",
  "passphrase": "my-secret",
  "algorithm": "aes"
}
```

**Encrypt response:**

```json
{
  "ciphertext_b64": "SEJC..."
}
```

**Decrypt request:**

```json
{
  "ciphertext_b64": "SEJC...",
  "passphrase": "my-secret"
}
```

**Decrypt response:**

```json
{
  "plaintext": "Hello, World!"
}
```

#### Key Generation

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/keygen` | Generate and store a key pair |

**Request:**

```json
{
  "algorithm": "ed25519",
  "label": "my-key",
  "passphrase": "secure-pw",
  "user_id": null
}
```

**Response:**

```json
{
  "fingerprint": "a1b2c3d4...",
  "algorithm": "ed25519",
  "label": "my-key"
}
```

Supported `algorithm` values: `rsa2048`, `rsa4096`, `ed25519`, `x25519`, `pgp`.

#### Signing & Verification

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/sign` | Sign a message |
| `POST` | `/api/verify` | Verify a signature |

**Sign request:**

```json
{
  "message_b64": "SGVsbG8=",
  "fingerprint": "a1b2c3d4...",
  "passphrase": "key-pw",
  "algorithm": "ed25519"
}
```

**Sign response:**

```json
{
  "signature_b64": "..."
}
```

**Verify request:**

```json
{
  "message_b64": "SGVsbG8=",
  "signature_b64": "...",
  "fingerprint": "a1b2c3d4...",
  "algorithm": "ed25519"
}
```

**Verify response:**

```json
{
  "valid": true
}
```

#### Key Management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/keys` | List all keys |
| `DELETE` | `/api/keys/{fingerprint}` | Delete a key |
| `GET` | `/api/keys/{fingerprint}/public` | Export public key (base64) |

**List keys response:**

```json
[
  {
    "fingerprint": "a1b2c3d4...",
    "algorithm": "ed25519",
    "label": "my-key",
    "created_at": "2026-03-06T12:00:00Z",
    "has_private": true,
    "has_public": true
  }
]
```

#### Contact Management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/contacts` | List all contacts |
| `POST` | `/api/contacts` | Add a contact |
| `DELETE` | `/api/contacts/{name}` | Remove a contact |
| `POST` | `/api/contacts/link` | Associate a key with a contact |

**Add contact request:**

```json
{
  "name": "Alice",
  "email": "alice@example.com",
  "notes": "Work colleague"
}
```

**Link key request:**

```json
{
  "contact_name": "Alice",
  "fingerprint": "a1b2c3d4..."
}
```

### Authentication

Set the `HB_ZAYFER_API_TOKEN` environment variable to require bearer-token
authentication on all `/api/*` endpoints:

```bash
export HB_ZAYFER_API_TOKEN="my-secret-token"
hb-zayfer-web
```

Clients must include:

```
Authorization: Bearer my-secret-token
```

Static files (`/static/*`), the root page (`/`), and OpenAPI docs
(`/docs`, `/openapi.json`) are always accessible without authentication.

If `HB_ZAYFER_API_TOKEN` is unset, the API is openly accessible (suitable
for local-only use on `127.0.0.1`).

### CORS Policy

Cross-origin requests are allowed from:

- `http://localhost:8000`
- `http://127.0.0.1:8000`

All HTTP methods and headers are permitted for these origins.

### OpenAPI Documentation

FastAPI auto-generates interactive API docs:

- **Swagger UI**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc
- **OpenAPI JSON**: http://127.0.0.1:8000/openapi.json

### Programmatic Usage

```python
import httpx

# Encrypt text
resp = httpx.post("http://127.0.0.1:8000/api/encrypt/text", json={
    "plaintext": "secret data",
    "passphrase": "pw",
    "algorithm": "aes",
})
ct_b64 = resp.json()["ciphertext_b64"]

# Decrypt text
resp = httpx.post("http://127.0.0.1:8000/api/decrypt/text", json={
    "ciphertext_b64": ct_b64,
    "passphrase": "pw",
})
assert resp.json()["plaintext"] == "secret data"
```
