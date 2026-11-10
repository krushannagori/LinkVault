# 🛡️ LinkVault

**LinkVault** is a lightweight, encrypted desktop bookmark and safe link manager built with Python and Tkinter. It keeps personal and work links locally encrypted on disk with **AES-256-GCM** (or an automatic zero-dependency **HMAC-SHA256-CTR Encrypt-then-MAC** fallback), atomic crash-safe writes, and built-in desktop security guards.

---

## ✨ Features

- **Authenticated Encryption**:
  - Uses **AES-256-GCM** (`cryptography`) with **600,000 PBKDF2-HMAC-SHA256** key-derivation iterations and `AAD` domain separation.
  - Zero-dependency fallback to **HMAC-SHA256-CTR** (Encrypt-then-MAC) when `cryptography` is absent, with automatic upgrade to AES-256-GCM once available.
  - Automatic migration of legacy v1 XOR vaults on first unlock (retaining `vault_data.enc.v1.bak`).
- **Crash-Safe Storage & Recovery**:
  - Atomic writes (`.tmp` → `flush` + `os.fsync` → `os.replace`) prevent half-written or corrupted vaults.
  - Automatic `.bak` backup copy on every save, with built-in backup recovery prompt if the primary file is ever damaged.
- **Desktop Security Hardening**:
  - Auto-lock after **5 minutes** of inactivity.
  - Clipboard auto-clear **30 seconds** after copying a URL.
  - Exponential backoff delay after repeated failed unlock attempts.
  - Strict `http://` / `https://` URL validation (blocks `javascript:`, `file:`, `data:`, and malformed URLs).
  - Hardened Windows batch launcher (`Launch_LinkVault.bat`) that resolves `pyw.exe`/`pythonw.exe` from `System32`/`PATH` only.
- **Productivity & Data Portability**:
  - Live search, category filtering, column sorting (`▲` / `▼`), right-click context menu, and keyboard shortcuts.
  - Plain-text **JSON** and **CSV** import/export with duplicate and invalid-URL filtering.
  - Master password rotation (`File → Change master password...`).
  - Rotating error log (`linkvault_error.log`) so `pythonw.exe` failures are never lost silently.

---

## 🏗️ Project Structure

```text
LinkVault/
├── .github/workflows/ci.yml   # Cross-platform CI (Linux & Windows, Python 3.10–3.13)
├── scripts/build_exe.py       # PyInstaller Windows build helper
├── src/linkvault/
│   ├── __init__.py            # Package metadata
│   ├── __main__.py            # `python -m linkvault` entrypoint
│   ├── app.py                 # CLI argument parsing & app bootstrap
│   ├── config.py              # Constants, defaults, and VaultPaths resolution
│   ├── crypto.py              # AES-256-GCM, HMAC-CTR fallback, and v1 migration
│   ├── logging_setup.py       # Rotating file logger & global excepthook
│   ├── storage.py             # Atomic save/load, backup recovery, JSON/CSV I/O
│   ├── ui.py                  # Tkinter desktop GUI
│   └── validation.py          # URL sanitization, duplicate & password validation
├── tests/                     # Unit & GUI smoke tests (unittest / pytest)
├── Launch_LinkVault.bat       # Hardened Windows no-console launcher
├── link_vault.py              # Root launcher script (portable vault next to script)
├── linkvault.spec             # PyInstaller spec for standalone .exe
├── pyproject.toml             # PEP 621 package & tooling configuration
├── requirements.txt           # Runtime dependencies
└── requirements-dev.txt       # Development, lint, and build dependencies
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+** (includes `tkinter` on Windows and macOS; on Debian/Ubuntu install `python3-tk`).
- Optional (recommended for AES-256-GCM): `cryptography>=42.0.0`.

### 1. Run directly from source

```bash
git clone https://github.com/krushannagori/LinkVault.git
cd LinkVault
pip install -r requirements.txt
python link_vault.py
```

On Windows, double-click **`Launch_LinkVault.bat`** to start LinkVault without opening a console window (or send a shortcut of `Launch_LinkVault.bat` to your Desktop for 1-click access).

### 2. Install as a package

```bash
pip install .
linkvault
# or
python -m linkvault
```

### CLI Options & Custom Data Directory

```bash
python link_vault.py --version
python link_vault.py --data-dir "D:\MyEncryptedVault"
```

You can also set `LINKVAULT_HOME` to override where `vault_data.enc` and `linkvault_error.log` are stored. When run via `link_vault.py` (or a standalone `.exe`), the vault defaults to the directory containing the launcher.

---

## 📦 Building a Standalone Windows Executable

```bash
pip install -r requirements-dev.txt
python scripts/build_exe.py
```

This generates `dist/LinkVault.exe` using `linkvault.spec`, which runs without a Python installation on the target Windows machine and stores `vault_data.enc` alongside the executable.

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
| :--- | :--- |
| `Ctrl + N` | Add new link |
| `Ctrl + F` | Focus search bar |
| `Ctrl + L` | Lock vault immediately |
| `Enter` / `Double-click` | Open selected link in default browser |
| `Delete` | Delete selected link |
| `Right-click` | Context menu (Open, Copy URL, Edit, Delete) |

---

## 🔐 Security Model Overview

1. **Key Derivation**: `PBKDF2-HMAC-SHA256` with a random 16-byte salt and `600,000` iterations derives a 64-byte key split into an encryption key and MAC/verification key.
2. **Encryption**:
   - **Primary**: `AES-256-GCM` with a fresh 12-byte nonce and associated data (`b"LinkVault v2"`).
   - **Fallback**: `HMAC-SHA256` counter-mode stream cipher + `HMAC-SHA256` tag over `AAD || salt || nonce || ciphertext` (Encrypt-then-MAC).
3. **Authentication vs. Corruption**: Failed tag checks raise `WrongPassword` (and trigger progressive brute-force lockout), while malformed JSON/metadata raises `CorruptVault` (and offers `.bak` recovery).
4. **Legacy v1 Migration**: Existing v1 vaults (100k PBKDF2 + XOR) are decrypted on unlock, backed up once to `vault_data.enc.v1.bak`, and automatically re-encrypted to v2.

---

## 🧪 Running Tests

Using the built-in test runner (no extra dependencies required):

```bash
python -m unittest discover -s tests -t . -v
```

Using `pytest` and `ruff` (with dev dependencies installed):

```bash
pip install -e ".[dev]"
ruff check src tests link_vault.py
pytest -v
```

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
