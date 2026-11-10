"""Unit tests for LinkVault cryptographic layer and v1->v2 migration."""

from __future__ import annotations

import hashlib
import json
import os
import unittest

from linkvault.config import KDF_ITERATIONS, V1_KDF_ITERATIONS
from linkvault.crypto import (
    HAVE_AESGCM,
    CorruptVault,
    MissingCryptoDependency,
    WrongPassword,
    _b64d,
    _b64e,
    _kdf,
    _xor_v1,
    decrypt_packet,
    encrypt_items,
)


class CryptoTests(unittest.TestCase):
    SAMPLE_ITEMS = [
        {"id": 1, "title": "Docs", "url": "https://docs.python.org", "category": "Dev", "notes": "Ref"},
        {"id": 2, "title": "Emoji Test 🔐", "url": "https://example.com", "category": "General", "notes": ""},
    ]

    def test_default_kdf_iterations(self) -> None:
        self.assertEqual(KDF_ITERATIONS, 600_000)

    @unittest.skipUnless(HAVE_AESGCM, "cryptography package is required for AES-GCM test")
    def test_aesgcm_roundtrip_and_wrong_password(self) -> None:
        packet = encrypt_items(self.SAMPLE_ITEMS, "StrongPass!1", kdf_iterations=1_000, use_aesgcm=True)
        self.assertEqual(packet["version"], 2)
        self.assertEqual(packet["cipher"], "aes-256-gcm")

        items, needs_upgrade = decrypt_packet(
            packet, "StrongPass!1", target_kdf_iterations=1_000, use_aesgcm=True
        )
        self.assertEqual(items, self.SAMPLE_ITEMS)
        self.assertFalse(needs_upgrade)

        with self.assertRaises(WrongPassword):
            decrypt_packet(packet, "WrongPass!1", target_kdf_iterations=1_000, use_aesgcm=True)

    @unittest.skipUnless(HAVE_AESGCM, "cryptography package is required for AES-GCM test")
    def test_aesgcm_tampered_ciphertext_raises_wrong_password(self) -> None:
        packet = encrypt_items(self.SAMPLE_ITEMS, "StrongPass!1", kdf_iterations=1_000, use_aesgcm=True)
        raw_ct = bytearray(_b64d(packet["ciphertext"]))
        raw_ct[0] ^= 0xFF
        packet["ciphertext"] = _b64e(bytes(raw_ct))

        with self.assertRaises(WrongPassword):
            decrypt_packet(packet, "StrongPass!1", target_kdf_iterations=1_000, use_aesgcm=True)

    def test_hmac_ctr_fallback_roundtrip_and_tampering(self) -> None:
        packet = encrypt_items(self.SAMPLE_ITEMS, "FallbackPass1", kdf_iterations=1_000, use_aesgcm=False)
        self.assertEqual(packet["version"], 2)
        self.assertEqual(packet["cipher"], "hmac-ctr")

        items, needs_upgrade = decrypt_packet(
            packet, "FallbackPass1", target_kdf_iterations=1_000, use_aesgcm=False
        )
        self.assertEqual(items, self.SAMPLE_ITEMS)
        self.assertFalse(needs_upgrade)

        with self.assertRaises(WrongPassword):
            decrypt_packet(packet, "BadPass1", target_kdf_iterations=1_000, use_aesgcm=False)

        tampered = dict(packet)
        raw_ct = bytearray(_b64d(tampered["ciphertext"]))
        raw_ct[-1] ^= 0x01
        tampered["ciphertext"] = _b64e(bytes(raw_ct))
        with self.assertRaises(WrongPassword):
            decrypt_packet(tampered, "FallbackPass1", target_kdf_iterations=1_000, use_aesgcm=False)

    @unittest.skipUnless(HAVE_AESGCM, "cryptography package is required for upgrade flag test")
    def test_upgrade_flags_for_fallback_cipher_and_lower_kdf(self) -> None:
        fallback_packet = encrypt_items(self.SAMPLE_ITEMS, "MySecret123", kdf_iterations=1_000, use_aesgcm=False)
        _, needs_upgrade = decrypt_packet(
            fallback_packet, "MySecret123", target_kdf_iterations=1_000, use_aesgcm=True
        )
        self.assertTrue(needs_upgrade)

        low_kdf_packet = encrypt_items(self.SAMPLE_ITEMS, "MySecret123", kdf_iterations=1_000, use_aesgcm=True)
        _, needs_kdf_upgrade = decrypt_packet(
            low_kdf_packet, "MySecret123", target_kdf_iterations=2_000, use_aesgcm=True
        )
        self.assertTrue(needs_kdf_upgrade)

    @unittest.skipUnless(HAVE_AESGCM, "cryptography package is required to build an AES-GCM packet")
    def test_missing_crypto_dependency_when_aes_unavailable(self) -> None:
        packet = encrypt_items(self.SAMPLE_ITEMS, "MySecret123", kdf_iterations=1_000, use_aesgcm=True)
        with self.assertRaises(MissingCryptoDependency):
            decrypt_packet(packet, "MySecret123", use_aesgcm=False)

    def test_legacy_v1_decryption_and_upgrade_trigger(self) -> None:
        password = "LegacyPassword1"
        salt = os.urandom(16)
        keys = _kdf(password, salt, V1_KDF_ITERATIONS)
        enc_key, check_key = keys[:32], keys[32:]
        plain = json.dumps(self.SAMPLE_ITEMS, ensure_ascii=False).encode("utf-8")
        ciphertext = _xor_v1(plain, enc_key)
        tag = hashlib.sha256(check_key + ciphertext).hexdigest()

        v1_packet = {
            "version": 1,
            "salt": _b64e(salt),
            "tag": tag,
            "ciphertext": _b64e(ciphertext),
        }

        items, needs_upgrade = decrypt_packet(v1_packet, password)
        self.assertEqual(items, self.SAMPLE_ITEMS)
        self.assertTrue(needs_upgrade)

        with self.assertRaises(WrongPassword):
            decrypt_packet(v1_packet, "WrongLegacyPass")

    def test_corrupt_packets_raise_corrupt_vault(self) -> None:
        bad_packets = [
            "not-a-dict",
            {},
            {"version": 99, "salt": "AAAA", "ciphertext": "AAAA"},
            {"version": 2, "kdf_iters": 1000, "salt": "not!base64", "ciphertext": "AAAA", "nonce": "AAAA"},
            {"version": 2, "kdf_iters": 0, "salt": "AAAA", "ciphertext": "AAAA", "nonce": "AAAA", "cipher": "hmac-ctr"},
            {"version": 2, "kdf_iters": 1000, "salt": "AAAA", "ciphertext": "AAAA", "nonce": "AAAA", "cipher": "rot13"},
        ]
        for packet in bad_packets:
            with self.subTest(packet=packet), self.assertRaises(CorruptVault):
                decrypt_packet(packet, "password123")


if __name__ == "__main__":
    unittest.main()
