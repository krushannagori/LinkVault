"""Unit tests for atomic vault storage, backup recovery, and JSON/CSV import-export."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from linkvault.config import V1_KDF_ITERATIONS, VaultPaths, resolve_vault_paths
from linkvault.crypto import CorruptVault, _b64e, _kdf, _xor_v1
from linkvault.storage import VaultStorage, export_links, import_links


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base_dir = Path(self._tmp.name)
        self.paths = VaultPaths(base_dir=self.base_dir)
        self.storage = VaultStorage(self.paths)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_atomic_save_creates_backup_and_recovers(self) -> None:
        first_links = [{"id": 1, "title": "One", "url": "https://one.example", "category": "A", "notes": ""}]
        second_links = [
            {"id": 1, "title": "One", "url": "https://one.example", "category": "A", "notes": ""},
            {"id": 2, "title": "Two", "url": "https://two.example", "category": "B", "notes": "n"},
        ]

        self.assertFalse(self.storage.vault_exists())
        self.storage.save(first_links, "MasterPass1!")
        self.assertTrue(self.storage.vault_exists())
        self.assertFalse(self.storage.backup_exists())
        self.assertFalse(self.paths.temp_file.exists())

        self.storage.save(second_links, "MasterPass1!")
        self.assertTrue(self.storage.backup_exists())

        loaded, needs_upgrade = self.storage.load("MasterPass1!")
        self.assertEqual(loaded, second_links)
        self.assertFalse(needs_upgrade)

        # Simulate primary file corruption and verify backup recovery
        self.paths.data_file.write_text("{corrupt json", encoding="utf-8")
        with self.assertRaises(CorruptVault):
            self.storage.load("MasterPass1!")

        recovered, _ = self.storage.load("MasterPass1!", from_backup=True)
        self.assertEqual(recovered, first_links)

    def test_v1_vault_creates_v1_backup_on_load(self) -> None:
        password = "LegacyUser1!"
        salt = os.urandom(16)
        keys = _kdf(password, salt, V1_KDF_ITERATIONS)
        enc_key, check_key = keys[:32], keys[32:]
        payload = [{"id": 1, "title": "Old", "url": "https://old.example", "category": "Gen", "notes": ""}]
        ciphertext = _xor_v1(json.dumps(payload).encode("utf-8"), enc_key)
        tag = hashlib.sha256(check_key + ciphertext).hexdigest()

        v1_packet = {
            "version": 1,
            "salt": _b64e(salt),
            "tag": tag,
            "ciphertext": _b64e(ciphertext),
        }
        self.paths.data_file.write_text(json.dumps(v1_packet), encoding="utf-8")

        loaded, needs_upgrade = self.storage.load(password)
        self.assertEqual(loaded, payload)
        self.assertTrue(needs_upgrade)
        self.assertTrue(self.paths.v1_backup_file.exists())

    def test_json_and_csv_export_import_roundtrip(self) -> None:
        existing = [
            {"id": 1, "title": "Existing", "url": "https://example.com/", "category": "Tech", "notes": "keep"},
        ]

        json_path = self.base_dir / "export.json"
        csv_path = self.base_dir / "export.csv"

        self.assertEqual(export_links(existing, json_path, "json"), 1)
        self.assertEqual(export_links(existing, csv_path, "csv"), 1)

        # Import mixed valid, duplicate, and invalid records from JSON
        incoming = [
            {"title": "Duplicate", "url": "https://EXAMPLE.com", "category": "Tech", "notes": "dup"},
            {"title": "Bad Scheme", "url": "javascript:alert(1)", "category": "Bad", "notes": ""},
            {"title": "", "url": "https://missing-title.example", "category": "Bad", "notes": ""},
            {"title": "New Link", "url": "docs.python.org", "category": "", "notes": "  Python docs  "},
        ]
        import_json = self.base_dir / "import.json"
        import_json.write_text(json.dumps(incoming), encoding="utf-8")

        merged, added, skipped = import_links(import_json, existing)
        self.assertEqual(added, 1)
        self.assertEqual(skipped, 3)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[1]["id"], 2)
        self.assertEqual(merged[1]["url"], "https://docs.python.org")
        self.assertEqual(merged[1]["category"], "General")
        self.assertEqual(merged[1]["notes"], "Python docs")

        # CSV import roundtrip into empty vault
        merged_csv, added_csv, skipped_csv = import_links(csv_path, [])
        self.assertEqual(added_csv, 1)
        self.assertEqual(skipped_csv, 0)
        self.assertEqual(merged_csv[0]["title"], "Existing")

    def test_resolve_vault_paths_precedence(self) -> None:
        explicit = resolve_vault_paths(self.base_dir)
        self.assertEqual(explicit.base_dir, self.base_dir.resolve())

        old_env = os.environ.get("LINKVAULT_HOME")
        try:
            os.environ["LINKVAULT_HOME"] = str(self.base_dir)
            from_env = resolve_vault_paths()
            self.assertEqual(from_env.base_dir, self.base_dir.resolve())
        finally:
            if old_env is None:
                os.environ.pop("LINKVAULT_HOME", None)
            else:
                os.environ["LINKVAULT_HOME"] = old_env


if __name__ == "__main__":
    unittest.main()
