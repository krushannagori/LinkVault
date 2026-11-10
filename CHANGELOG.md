# Changelog

All notable changes to LinkVault are documented in this file.

## [2.0.0] - 2026-11-10

### Added
- Modular `linkvault` package under `src/linkvault/` (`config`, `crypto`, `storage`, `validation`, `logging_setup`, `ui`, `app`).
- PEP 621 packaging (`pyproject.toml`), `requirements.txt`, `requirements-dev.txt`, and `linkvault` GUI script entrypoint.
- PyInstaller Windows executable packaging (`linkvault.spec` and `scripts/build_exe.py`).
- Comprehensive `unittest`/`pytest` test suite covering crypto, migration, atomic saves, backup recovery, URL validation, and GUI lifecycle.
- GitHub Actions CI workflow testing Python 3.10–3.13 across Linux and Windows, including zero-dependency fallback testing.
- CLI flags `--data-dir` and `--version`, plus `LINKVAULT_HOME` environment variable support.
- Backup recovery prompt in the unlock screen if the primary vault file fails integrity checks while `.bak` exists.
- Help → About dialog displaying active cipher, KDF iteration count, and vault path.

### Security & Stability
- Authenticated **AES-256-GCM** encryption via `cryptography` with **600,000** PBKDF2-HMAC-SHA256 iterations.
- Zero-dependency **HMAC-SHA256 CTR + Encrypt-then-MAC** fallback when `cryptography` is not installed, with automatic upgrade to AES-256-GCM when available.
- Automatic migration of legacy v1 (XOR) vaults on first unlock, preserving `vault_data.enc.v1.bak`.
- Atomic file writes via `.tmp` + `os.fsync` + `os.replace` and automatic `.bak` snapshots.
- Auto-lock after 5 minutes of inactivity, 30-second clipboard auto-clear, exponential brute-force backoff, and unbinding main vault shortcuts when locked.
- Rotating error log (`linkvault_error.log`) with global `sys.excepthook` for silent `pythonw.exe` launches.

## [1.0.0] - 2026-10-11

### Added
- Initial single-file Tkinter link locker with XOR obfuscation, 100k PBKDF2 key derivation, search bar, and basic CRUD.
