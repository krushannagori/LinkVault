"""Atomic vault persistence, backup recovery, and JSON/CSV import-export."""

from __future__ import annotations

import contextlib
import copy
import csv
import json
import os
import shutil
from pathlib import Path
from typing import Any

from linkvault.config import VaultPaths
from linkvault.crypto import CorruptVault, decrypt_packet, encrypt_items
from linkvault.validation import canonical_url_key, normalize_url

EXPORT_FIELDS: tuple[str, ...] = ("title", "url", "category", "notes")


class VaultStorage:
    """Manages encrypted vault read/write operations with atomic saves and backups."""

    def __init__(self, paths: VaultPaths) -> None:
        self.paths = paths

    def vault_exists(self) -> bool:
        return self.paths.data_file.exists()

    def backup_exists(self) -> bool:
        return self.paths.backup_file.exists()

    def save(self, items: list[dict[str, Any]], password: str) -> None:
        """Atomically persist encrypted vault items and keep a .bak copy of the previous file."""
        self.paths.base_dir.mkdir(parents=True, exist_ok=True)
        packet = encrypt_items(items, password)
        tmp_path = self.paths.temp_file

        try:
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(packet, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())

            if self.paths.data_file.exists():
                with contextlib.suppress(OSError):
                    shutil.copy2(self.paths.data_file, self.paths.backup_file)

            os.replace(tmp_path, self.paths.data_file)
        except Exception:
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)
            raise

    def load(self, password: str, *, from_backup: bool = False) -> tuple[list[dict[str, Any]], bool]:
        """Load and decrypt the vault (or .bak backup). Preserves .v1.bak on v1 vaults."""
        target = self.paths.backup_file if from_backup else self.paths.data_file
        try:
            with open(target, encoding="utf-8") as handle:
                packet = json.load(handle)
        except (OSError, ValueError) as exc:
            raise CorruptVault(str(exc)) from exc

        items, needs_upgrade = decrypt_packet(packet, password)
        if (
            not from_backup
            and isinstance(packet, dict)
            and packet.get("version") == 1
            and not self.paths.v1_backup_file.exists()
        ):
            with contextlib.suppress(OSError):
                shutil.copy2(self.paths.data_file, self.paths.v1_backup_file)
        return items, needs_upgrade


def export_links(items: list[dict[str, Any]], destination: str | Path, fmt: str) -> int:
    """Export links in plain-text JSON or CSV format. Returns number of exported records."""
    dest = Path(destination)
    fmt_lower = fmt.lower()
    records = [{key: str(item.get(key, "")) for key in EXPORT_FIELDS} for item in items]

    if fmt_lower == "json":
        with open(dest, "w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2, ensure_ascii=False)
    elif fmt_lower == "csv":
        with open(dest, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(EXPORT_FIELDS))
            writer.writeheader()
            writer.writerows(records)
    else:
        raise ValueError(f"Unsupported export format: {fmt!r}")

    return len(records)


def import_links(
    source: str | Path,
    existing_links: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int, int]:
    """Read JSON or CSV links, validate and deduplicate against existing_links.

    Returns (merged_links, added_count, skipped_count).
    """
    src = Path(source)
    if src.suffix.lower() == ".json":
        with open(src, encoding="utf-8") as handle:
            rows = json.load(handle)
    else:
        with open(src, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))

    if not isinstance(rows, list):
        raise ValueError("Expected a top-level list of link objects.")

    merged = copy.deepcopy(existing_links)
    known = {canonical_url_key(str(item.get("url", ""))) for item in merged}
    next_id = max((int(item.get("id", 0)) for item in merged if str(item.get("id", "")).isdigit()), default=0) + 1

    added = 0
    skipped = 0

    for row in rows:
        if not isinstance(row, dict):
            skipped += 1
            continue

        url = normalize_url(str(row.get("url", "")))
        title = str(row.get("title", "")).strip()
        if not url or not title:
            skipped += 1
            continue

        key = canonical_url_key(url)
        if key in known:
            skipped += 1
            continue

        known.add(key)
        merged.append(
            {
                "id": next_id,
                "title": title,
                "url": url,
                "category": str(row.get("category", "")).strip() or "General",
                "notes": str(row.get("notes", "")).strip(),
            }
        )
        next_id += 1
        added += 1

    return merged, added, skipped
