"""Settings view — application preferences with persistence."""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QGroupBox,
    QSpinBox,
    QLineEdit,
    QPushButton,
    QMessageBox,
)

import hb_zayfer as hbz


def _config_path() -> Path:
    """Return path to config.json inside the keystore directory."""
    try:
        ks = hbz.KeyStore()
        return Path(ks.base_path) / "config.json"
    except Exception:
        return Path.home() / ".hb_zayfer" / "config.json"


def _load_config() -> dict:
    """Load persisted settings, returning defaults on any error."""
    p = _config_path()
    defaults = {
        "cipher": "AES-256-GCM",
        "kdf": "Argon2id",
        "argon2_memory_mib": 64,
        "argon2_iterations": 3,
    }
    if p.exists():
        try:
            with open(p) as f:
                saved = json.load(f)
            defaults.update(saved)
        except Exception:
            pass
    return defaults


def _save_config(cfg: dict) -> None:
    """Persist settings to config.json (atomic write)."""
    p = _config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    tmp.rename(p)


class SettingsView(QWidget):
    """Application settings and preferences."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()
        self._load_persisted()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("<h2>Settings</h2>")
        layout.addWidget(title)

        # Default cipher
        crypto_box = QGroupBox("Default Encryption Settings")
        crypto_layout = QVBoxLayout(crypto_box)

        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("Default cipher:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        algo_row.addWidget(self.algo_combo)
        algo_row.addStretch()
        crypto_layout.addLayout(algo_row)

        # KDF settings
        kdf_row = QHBoxLayout()
        kdf_row.addWidget(QLabel("KDF:"))
        self.kdf_combo = QComboBox()
        self.kdf_combo.addItems(["Argon2id", "scrypt"])
        kdf_row.addWidget(self.kdf_combo)
        kdf_row.addStretch()
        crypto_layout.addLayout(kdf_row)

        # Argon2 memory
        mem_row = QHBoxLayout()
        mem_row.addWidget(QLabel("Argon2 memory (MiB):"))
        self.mem_spin = QSpinBox()
        self.mem_spin.setRange(16, 4096)
        self.mem_spin.setValue(64)
        mem_row.addWidget(self.mem_spin)
        mem_row.addStretch()
        crypto_layout.addLayout(mem_row)

        # Argon2 iterations
        iter_row = QHBoxLayout()
        iter_row.addWidget(QLabel("Argon2 iterations:"))
        self.iter_spin = QSpinBox()
        self.iter_spin.setRange(1, 100)
        self.iter_spin.setValue(3)
        iter_row.addWidget(self.iter_spin)
        iter_row.addStretch()
        crypto_layout.addLayout(iter_row)

        layout.addWidget(crypto_box)

        # Keystore path
        store_box = QGroupBox("Key Store")
        store_layout = QVBoxLayout(store_box)

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("Path:"))
        self.path_input = QLineEdit()
        try:
            ks = hbz.KeyStore()
            self.path_input.setText(ks.base_path)
        except Exception:
            self.path_input.setText("~/.hb_zayfer/")
        self.path_input.setReadOnly(True)
        path_row.addWidget(self.path_input, 1)
        store_layout.addLayout(path_row)

        layout.addWidget(store_box)

        # Info
        info_box = QGroupBox("About")
        info_layout = QVBoxLayout(info_box)
        info_layout.addWidget(QLabel(f"HB_Zayfer version: {hbz.version()}"))
        info_layout.addWidget(QLabel("Crypto backend: Rust (RustCrypto + Sequoia-OpenPGP)"))
        info_layout.addWidget(QLabel("GUI toolkit: PySide6 (Qt 6)"))
        info_layout.addWidget(QLabel("License: MIT"))
        layout.addWidget(info_box)

        # Save / Reset buttons
        btn_row = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self._on_save)
        btn_row.addWidget(save_btn)

        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self._on_reset)
        btn_row.addWidget(reset_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        layout.addStretch()

    # ---- Persistence --------------------------------------------------

    def _load_persisted(self) -> None:
        """Load saved settings into the UI widgets."""
        cfg = _load_config()
        idx = self.algo_combo.findText(cfg.get("cipher", "AES-256-GCM"))
        if idx >= 0:
            self.algo_combo.setCurrentIndex(idx)
        idx = self.kdf_combo.findText(cfg.get("kdf", "Argon2id"))
        if idx >= 0:
            self.kdf_combo.setCurrentIndex(idx)
        self.mem_spin.setValue(cfg.get("argon2_memory_mib", 64))
        self.iter_spin.setValue(cfg.get("argon2_iterations", 3))

    def _current_config(self) -> dict:
        """Gather current widget values into a config dict."""
        return {
            "cipher": self.algo_combo.currentText(),
            "kdf": self.kdf_combo.currentText(),
            "argon2_memory_mib": self.mem_spin.value(),
            "argon2_iterations": self.iter_spin.value(),
        }

    def _on_save(self) -> None:
        try:
            _save_config(self._current_config())
            QMessageBox.information(self, "Settings", "Settings saved successfully.")
        except Exception as exc:
            QMessageBox.warning(self, "Error", f"Failed to save settings:\n{exc}")

    def _on_reset(self) -> None:
        self.algo_combo.setCurrentIndex(0)
        self.kdf_combo.setCurrentIndex(0)
        self.mem_spin.setValue(64)
        self.iter_spin.setValue(3)
        try:
            _save_config(self._current_config())
        except Exception:
            pass
        QMessageBox.information(self, "Settings", "Settings reset to defaults.")
