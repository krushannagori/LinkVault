"""Cryptographic primitives and vault packet encoding/decoding."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from typing import Any

from linkvault.config import AAD, KDF_ITERATIONS, V1_KDF_ITERATIONS

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    HAVE_AESGCM = True
except Exception:  # pragma: no cover - covered by fallback tests
    AESGCM = None  # type: ignore[assignment]
    InvalidTag = Exception  # type: ignore[assignment,misc]
    HAVE_AESGCM = False


class VaultError(Exception):
    """Base error for vault encryption, decryption, and file integrity issues."""


class WrongPassword(VaultError):
    """Raised when the master password fails authentication tag verification."""


class CorruptVault(VaultError):
    """Raised when the vault file structure or encoding is invalid or tampered with."""


class MissingCryptoDependency(VaultError):
    """Raised when opening an AES-GCM vault without the 'cryptography' package."""


def active_cipher_label(use_aesgcm: bool | None = None) -> str:
    """Return human-readable name of the active cipher."""
    aes_enabled = HAVE_AESGCM if use_aesgcm is None else use_aesgcm
    if aes_enabled:
        return "AES-256-GCM"
    return "HMAC-CTR (install 'cryptography' for AES-256-GCM)"


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("Expected base64 string")
    return base64.b64decode(text.strip(), validate=True)


def _kdf(password: str, salt: bytes, iterations: int, dklen: int = 64) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=dklen)


def _hmac_ctr(enc_key: bytes, nonce: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 used as a PRF in counter mode (stream cipher). Zero-dependency fallback."""
    out = bytearray(len(data))
    block_count = (len(data) + 31) // 32
    for block in range(block_count):
        stream = hmac.new(enc_key, nonce + block.to_bytes(8, "big"), hashlib.sha256).digest()
        start = block * 32
        chunk = data[start : start + 32]
        for idx, byte in enumerate(chunk):
            out[start + idx] = byte ^ stream[idx]
    return bytes(out)


def _xor_v1(data: bytes, key: bytes) -> bytes:
    """Legacy LinkVault v1 XOR obfuscation helper (kept solely for auto-migration)."""
    key_len = len(key)
    return bytes(byte ^ key[idx % key_len] for idx, byte in enumerate(data))


def encrypt_items(
    items: list[dict[str, Any]],
    password: str,
    *,
    kdf_iterations: int = KDF_ITERATIONS,
    use_aesgcm: bool | None = None,
) -> dict[str, Any]:
    """Encrypt link items into a versioned LinkVault v2 JSON-serializable packet."""
    if kdf_iterations < 1:
        raise ValueError("kdf_iterations must be positive")

    aes_enabled = HAVE_AESGCM if use_aesgcm is None else use_aesgcm
    if aes_enabled and not HAVE_AESGCM:
        raise MissingCryptoDependency(
            "AES-256-GCM requested, but 'cryptography' package is not installed."
        )

    salt = os.urandom(16)
    keys = _kdf(password, salt, kdf_iterations)
    enc_key, mac_key = keys[:32], keys[32:]
    plain = json.dumps(items, ensure_ascii=False).encode("utf-8")

    packet: dict[str, Any] = {
        "version": 2,
        "kdf_iters": kdf_iterations,
        "salt": _b64e(salt),
    }
    if aes_enabled:
        nonce = os.urandom(12)
        ciphertext = AESGCM(enc_key).encrypt(nonce, plain, AAD)
        packet.update(
            cipher="aes-256-gcm",
            nonce=_b64e(nonce),
            ciphertext=_b64e(ciphertext),
        )
    else:
        nonce = os.urandom(16)
        ciphertext = _hmac_ctr(enc_key, nonce, plain)
        tag = hmac.new(mac_key, AAD + salt + nonce + ciphertext, hashlib.sha256).digest()
        packet.update(
            cipher="hmac-ctr",
            nonce=_b64e(nonce),
            ciphertext=_b64e(ciphertext),
            tag=_b64e(tag),
        )
    return packet


def _decrypt_v1(packet: dict[str, Any], salt: bytes, ciphertext: bytes, password: str) -> bytes:
    keys = _kdf(password, salt, V1_KDF_ITERATIONS)
    enc_key, check_key = keys[:32], keys[32:]
    computed = hashlib.sha256(check_key + ciphertext).hexdigest()
    expected_tag = packet["tag"]
    if not isinstance(expected_tag, str) or not hmac.compare_digest(computed, expected_tag):
        raise WrongPassword("Incorrect master password.")
    return _xor_v1(ciphertext, enc_key)


def _decrypt_v2(
    packet: dict[str, Any],
    salt: bytes,
    ciphertext: bytes,
    password: str,
    *,
    target_kdf_iterations: int,
    aes_available: bool,
) -> tuple[bytes, bool]:
    kdf_iters = int(packet["kdf_iters"])
    if kdf_iters < 1:
        raise CorruptVault("Invalid KDF iteration count")

    keys = _kdf(password, salt, kdf_iters)
    enc_key, mac_key = keys[:32], keys[32:]
    nonce = _b64d(packet["nonce"])
    cipher = packet.get("cipher")

    if cipher == "aes-256-gcm":
        if not aes_available or AESGCM is None:
            raise MissingCryptoDependency(
                "This vault uses AES-256-GCM encryption. Install cryptography: pip install cryptography"
            )
        try:
            plain = AESGCM(enc_key).decrypt(nonce, ciphertext, AAD)
        except InvalidTag as exc:
            raise WrongPassword("Incorrect master password.") from exc
    elif cipher == "hmac-ctr":
        expected = hmac.new(mac_key, AAD + salt + nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64d(packet["tag"])):
            raise WrongPassword("Incorrect master password.")
        plain = _hmac_ctr(enc_key, nonce, ciphertext)
    else:
        raise CorruptVault(f"Unknown vault cipher: {cipher!r}")

    needs_upgrade = (aes_available and cipher != "aes-256-gcm") or (
        kdf_iters < target_kdf_iterations
    )
    return plain, needs_upgrade


def decrypt_packet(
    packet: Any,
    password: str,
    *,
    target_kdf_iterations: int = KDF_ITERATIONS,
    use_aesgcm: bool | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Decrypt a parsed vault packet and return (items, needs_upgrade).

    Raises WrongPassword, MissingCryptoDependency, or CorruptVault.
    """
    if not isinstance(packet, dict):
        raise CorruptVault("Vault root must be a JSON object")

    aes_available = HAVE_AESGCM if use_aesgcm is None else (use_aesgcm and HAVE_AESGCM)

    try:
        version = packet.get("version")
        salt = _b64d(packet["salt"])
        ciphertext = _b64d(packet["ciphertext"])

        if version == 1:
            plain = _decrypt_v1(packet, salt, ciphertext, password)
            needs_upgrade = True
        elif version == 2:
            plain, needs_upgrade = _decrypt_v2(
                packet,
                salt,
                ciphertext,
                password,
                target_kdf_iterations=target_kdf_iterations,
                aes_available=aes_available,
            )
        else:
            raise CorruptVault(f"Unsupported vault version: {version!r}")

        items = json.loads(plain.decode("utf-8"))
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise CorruptVault("Unexpected vault payload format")
        return items, needs_upgrade

    except VaultError:
        raise
    except (KeyError, ValueError, TypeError, UnicodeDecodeError, binascii.Error) as exc:
        raise CorruptVault(str(exc)) from exc
