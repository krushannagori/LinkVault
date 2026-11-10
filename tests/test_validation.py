"""Unit tests for URL normalization, duplicate checks, and password rules."""

from __future__ import annotations

import unittest

from linkvault.validation import find_duplicate_link, normalize_url, validate_new_password


class ValidationTests(unittest.TestCase):
    def test_normalize_url_accepts_http_https_and_bare_domains(self) -> None:
        self.assertEqual(normalize_url("https://example.com/a?b=1"), "https://example.com/a?b=1")
        self.assertEqual(normalize_url("http://localhost:8080/health"), "http://localhost:8080/health")
        self.assertEqual(normalize_url("  github.com/krushannagori  "), "https://github.com/krushannagori")
        self.assertEqual(normalize_url("localhost:3000"), "https://localhost:3000")

    def test_normalize_url_rejects_unsafe_or_malformed_inputs(self) -> None:
        unsafe = [
            None,
            "",
            "   ",
            "ftp://files.example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "javascript:123",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
            "mailto:test@example.com",
            "https://",
            "https://example.com/\ninjected",
        ]
        for raw in unsafe:
            with self.subTest(raw=raw):
                self.assertIsNone(normalize_url(raw))

    def test_find_duplicate_link_ignores_trailing_slash_and_case(self) -> None:
        links = [
            {"id": 1, "title": "GitHub", "url": "https://GitHub.com/krushannagori/"},
            {"id": 2, "title": "Python", "url": "https://docs.python.org"},
        ]
        dup = find_duplicate_link(links, "https://github.com/krushannagori")
        self.assertIsNotNone(dup)
        self.assertEqual(dup["id"], 1)  # type: ignore[index]

        # Editing the same record should not treat itself as a duplicate
        self.assertIsNone(
            find_duplicate_link(links, "https://github.com/krushannagori", exclude_item=links[0])
        )

    def test_validate_new_password(self) -> None:
        self.assertIsNotNone(validate_new_password(""))
        self.assertIsNotNone(validate_new_password("short"))
        self.assertIsNotNone(validate_new_password("ValidPass1", "Different1"))
        self.assertIsNone(validate_new_password("ValidPass1", "ValidPass1"))
        self.assertIsNone(validate_new_password(" space pass "))


if __name__ == "__main__":
    unittest.main()
