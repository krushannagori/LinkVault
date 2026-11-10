"""Input validation, URL normalization, and duplicate detection helpers."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from linkvault.config import MIN_PASSWORD_LEN

_BLOCKED_SCHEMES = (
    "javascript:",
    "data:",
    "vbscript:",
    "mailto:",
    "tel:",
    "file:",
    "about:",
)


def normalize_url(raw: str | None) -> str | None:
    """Return a validated http(s) URL string, or None if invalid or unsafe."""
    cleaned = (raw or "").strip()
    if not cleaned:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        return None
    if cleaned.lower().startswith(_BLOCKED_SCHEMES):
        return None

    candidate = cleaned if "://" in cleaned else f"https://{cleaned}"
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in ("http", "https"):
        return None

    try:
        hostname = parsed.hostname
        if not hostname or any(ch.isspace() for ch in hostname):
            return None
        _ = parsed.port  # Validates integer range 1..65535 when a port is present
    except ValueError:
        return None

    return candidate


def canonical_url_key(url: str) -> str:
    """Normalize URL comparison key (case-insensitive, trailing-slash insensitive)."""
    return url.strip().rstrip("/").lower()


def find_duplicate_link(
    links: Iterable[dict[str, Any]],
    url: str,
    *,
    exclude_item: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return the first existing link with the same canonical URL, if any."""
    target_key = canonical_url_key(url)
    for item in links:
        if item is exclude_item:
            continue
        existing_url = str(item.get("url", ""))
        if canonical_url_key(existing_url) == target_key:
            return item
    return None


def validate_new_password(
    password: str,
    confirm: str | None = None,
    *,
    min_length: int = MIN_PASSWORD_LEN,
) -> str | None:
    """Validate a new master password. Returns an error message or None if valid."""
    if not password:
        return "Password cannot be empty."
    if len(password) < min_length:
        return f"Use at least {min_length} characters."
    if confirm is not None and password != confirm:
        return "Passwords do not match."
    return None
