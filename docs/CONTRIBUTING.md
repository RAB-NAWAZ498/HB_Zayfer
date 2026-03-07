# Contributing Guide

Thank you for your interest in contributing to HB_Zayfer! This document covers
the development environment, build process, coding standards, and testing
workflow.

---

## Prerequisites

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| **Rust** | 1.75 (stable) | Core library + CLI |
| **Python** | 3.10 | Bindings, CLI, GUI, Web |
| **Maturin** | 1.0 | Build PyO3 → wheel |
| **pkg-config** | — | Locate system libraries |
| **libssl-dev** | — | OpenSSL headers (Linux) |
| **nettle-dev** | — | Sequoia cryptography backend (Linux) |

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/James-HoneyBadger/HB_Zayfer.git
cd HB_Zayfer

# Install Rust (if not already)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Python dependencies
pip install maturin
pip install -e ".[all]"
```

---

## Repository Structure

```
HB_Zayfer/
├── Cargo.toml              # Workspace root
├── pyproject.toml           # Python / Maturin config
├── crates/
│   ├── core/                # hb_zayfer_core — Rust crypto library
│   ├── cli/                 # hb_zayfer_cli — Rust binary
│   └── python/              # PyO3 cdylib → hb_zayfer._native
├── python/
│   └── hb_zayfer/           # Python package (CLI, GUI, Web)
├── tests/
│   └── python/              # Python integration tests
└── docs/                    # Documentation (this directory)
```

---

## Building

### Rust Only

```bash
# Check everything compiles
cargo build --workspace

# Build in release mode
cargo build --workspace --release
```

### Python Extension Module

```bash
# Development build (editable, debug)
maturin develop

# Development build (release-optimized)
maturin develop --release

# Build a distributable wheel
maturin build --release
# Output: target/wheels/hb_zayfer-*.whl
```

### Full Stack

```bash
# Build Rust + Python in one go
maturin develop --release && pip install -e ".[all]"
```

---

## Development Workflow

### 1. Format Code

**Rust:**

```bash
cargo fmt --all
```

**Python:**

```bash
# If you have ruff or black installed
ruff format python/ tests/
```

### 2. Lint

**Rust:**

```bash
cargo clippy --workspace -- -W warnings
```

**Python:**

```bash
ruff check python/ tests/
```

### 3. Run Tests

**Rust tests** (unit + integration):

```bash
cargo test --workspace
```

This runs:
- Unit tests in each module (`#[cfg(test)]` blocks)
- Integration tests in `crates/core/tests/integration.rs`

**Python tests** (requires `maturin develop` first):

```bash
pytest tests/python/ -v
```

This runs:
- `test_crypto.py` — exercises all `hb_zayfer` API functions
- `test_web.py` — FastAPI route tests via httpx

### 4. Run the Full CI Pipeline Locally

```bash
cargo fmt --all --check
cargo clippy --workspace -- -W warnings
cargo test --workspace
maturin develop --release
pytest tests/python/ -v
```

---

## Adding New Functionality

### Adding a New Crypto Algorithm

1. **Create the Rust module** in `crates/core/src/<algo>.rs`.
2. **Add `pub mod <algo>;`** to `crates/core/src/lib.rs`.
3. **Add unit tests** in the module's `#[cfg(test)]` block.
4. **Add integration tests** to `crates/core/tests/integration.rs`.
5. **Add PyO3 bindings** in `crates/python/src/lib.rs`:
   - Create `#[pyfunction]` wrappers.
   - Register in the `#[pymodule]` function.
6. **Update type stubs** in `python/hb_zayfer/_native.pyi`.
7. **Re-export** from `python/hb_zayfer/__init__.py`.
8. **Add Python tests** in `tests/python/test_crypto.py`.
9. **Update documentation** in `docs/`.

### Adding a New CLI Command

**Python CLI** (`python/hb_zayfer/cli.py`):
- Add a new `@cli.command()` or `@cli.group()`.

**Rust CLI** (`crates/cli/src/main.rs`):
- Add a variant to the `Commands` enum.
- Implement the handler function (`cmd_<name>`).

### Adding a New Web API Endpoint

1. Add request/response models to `python/hb_zayfer/web/routes.py`.
2. Add the route handler to the `router`.
3. Add tests to `tests/python/test_web.py`.

---

## Code Conventions

### Rust

- **Edition**: 2021.
- **Error handling**: return `HbResult<T>` from all fallible functions;
  use `HbError` variants with descriptive messages.
- **Key material security**: wrap secret bytes in types that implement
  `Zeroize` / `ZeroizeOnDrop`. Never log key material.
- **Doc comments**: `///` on all public items.
- **No `unsafe`**: the core library avoids `unsafe` code.

### Python

- **Type hints**: all function signatures should have type annotations.
- **Docstrings**: all public functions and classes.
- **Imports**: `from __future__ import annotations` at the top of every file.
- **`ValueError`**: all errors from the native layer surface as `ValueError`.

---

## Release Process

1. Bump version in `Cargo.toml` (`[workspace.package] version`) and
   `pyproject.toml` (`[project] version`).
2. Update `CHANGELOG.md`.
3. Run the full test suite.
4. Tag the release: `git tag v0.2.0 && git push --tags`.
5. CI builds and publishes wheels.

---

## CI (GitHub Actions)

The CI pipeline runs on every push and pull request to `main`:

### Rust Job

1. `cargo fmt --all --check`
2. `cargo clippy --workspace -- -W warnings`
3. `cargo test --workspace`
4. `cargo build --release`

Matrix: Linux (x86_64), macOS (x86_64 + aarch64), Windows (x86_64).

### Python Job

1. `maturin develop --release`
2. `pytest tests/python/ -v`

Matrix: Linux + macOS, Python 3.11 + 3.12.

---

## Troubleshooting

### `nettle-dev` not found (Linux)

```bash
# Debian/Ubuntu
sudo apt install nettle-dev

# Fedora
sudo dnf install nettle-devel

# Arch
sudo pacman -S nettle
```

### Maturin build fails with "missing Python.h"

Ensure you have Python development headers:

```bash
# Debian/Ubuntu
sudo apt install python3-dev

# Fedora
sudo dnf install python3-devel
```

### `cargo test` hangs on RSA key generation

RSA key generation (especially 4096-bit) can be slow on CI runners. The
test suite uses 2048-bit keys by default for speed.

### Import errors after `maturin develop`

Make sure you're using the same Python environment:

```bash
which python
maturin develop --release
python -c "import hb_zayfer; print(hb_zayfer.version())"
```
