"""Unit tests for CLI argument parsing, logging setup, and GUI lifecycle."""

from __future__ import annotations

import logging
import sys
import tempfile
import tkinter as tk
import unittest
from pathlib import Path

from linkvault.app import parse_args
from linkvault.config import VaultPaths
from linkvault.logging_setup import configure_logging, log_unhandled_exception
from linkvault.storage import VaultStorage
from linkvault.ui import LinkVaultApp


class AppAndLoggingTests(unittest.TestCase):
    def test_parse_args_data_dir(self) -> None:
        args = parse_args(["--data-dir", "/tmp/my-vault"])
        self.assertEqual(args.data_dir, "/tmp/my-vault")

        default_args = parse_args([])
        self.assertIsNone(default_args.data_dir)

    def test_logging_writes_exception_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "linkvault_error.log"
            logger = configure_logging(log_file)
            try:
                raise RuntimeError("boom")
            except RuntimeError:
                exc_type, exc, tb = sys.exc_info()
                assert exc_type is not None and exc is not None
                log_unhandled_exception(exc_type, exc, tb, logger=logger)

            for handler in list(logger.handlers):
                logger.removeHandler(handler)
                handler.close()

            content = log_file.read_text(encoding="utf-8")
            self.assertIn("RuntimeError: boom", content)
            logging.shutdown()

    def test_gui_first_run_unlock_sort_and_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = VaultStorage(VaultPaths(base_dir=Path(tmp)))
            try:
                app = LinkVaultApp(storage)
            except tk.TclError as exc:
                self.skipTest(f"Tkinter runtime unavailable: {exc}")
            try:
                app.update_idletasks()
                self.assertIsNone(app.current_password)
                # Verify shortcuts from main vault are not bound while locked
                self.assertEqual(app.bind("<Control-n>"), "")

                # Simulate unlocking programmatically with valid items
                app.current_password = "TestPassword1!"
                app.links = [
                    {"id": 1, "title": "Zeta", "url": "https://zeta.example", "category": "CatB", "notes": ""},
                    {"id": 2, "title": "Alpha", "url": "https://alpha.example", "category": "CatA", "notes": ""},
                ]
                storage.save(app.links, app.current_password)
                app.show_main_vault()
                app.update_idletasks()

                self.assertEqual(len(app.tree.get_children()), 2)
                app.sort_by("title")
                children = app.tree.get_children()
                self.assertEqual(children, ("2", "1"))

                app.lock_vault()
                app.update_idletasks()
                self.assertIsNone(app.current_password)
                self.assertEqual(app.links, [])
                self.assertEqual(app.bind("<Control-n>"), "")
            finally:
                app._on_close()


if __name__ == "__main__":
    unittest.main()
