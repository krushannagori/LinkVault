"""Application constants, default records, and vault path resolution."""

from __future__ import annotations

import copy
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

APP_NAME: Final[str] = "LinkVault"
APP_VERSION: Final[str] = "2.0.0"

KDF_ITERATIONS: Final[int] = 600_000
V1_KDF_ITERATIONS: Final[int] = 100_000
AAD: Final[bytes] = b"LinkVault v2"

MIN_PASSWORD_LEN: Final[int] = 8
AUTO_LOCK_SECONDS: Final[int] = 5 * 60
CLIPBOARD_CLEAR_MS: Final[int] = 30_000
IDLE_CHECK_INTERVAL_MS: Final[int] = 10_000

VAULT_FILENAME: Final[str] = "vault_data.enc"
LOG_FILENAME: Final[str] = "linkvault_error.log"

DEFAULT_LINKS: Final[list[dict[str, object]]] = [
    {
        "id": 1,
        "title": "GraphQL vs REST: API Design Landscape",
        "url": "https://blog.levelupcoding.com/luc-69-graphql-vs-rest-navigating-the-evolving-landscape-of-api-design",
        "category": "Tech & Reading",
        "notes": "Guide on GraphQL vs REST architecture comparison",
    },
    {
        "id": 2,
        "title": "LinkedIn Saved Posts",
        "url": "https://www.linkedin.com/my-items/saved-posts/",
        "category": "Career & Networking",
        "notes": "Bookmarked career posts and updates",
    },
    {
        "id": 3,
        "title": "HackerRank Java Domain",
        "url": "https://www.hackerrank.com/domains/java",
        "category": "Coding & Practice",
        "notes": "Java challenges and practice problems",
    },
    {
        "id": 4,
        "title": "Devpost Hackathons",
        "url": "https://devpost.com/hackathons",
        "category": "Competitions & Hackathons",
        "notes": "Global and virtual hackathon listings",
    },
    {
        "id": 5,
        "title": "Vahan Parivahan Mobile Update",
        "url": "https://vahan.parivahan.gov.in/mobileupdate/vahan/ui/session/sessionTimeout.xhtml",
        "category": "Government & Services",
        "notes": "Vehicle registration / Parivahan mobile update service portal",
    },
    {
        "id": 6,
        "title": "Naukri Job Portal",
        "url": "https://www.naukri.com",
        "category": "Career & Jobs",
        "notes": "Job search & opportunities",
    },
]


def default_links_copy() -> list[dict[str, object]]:
    """Return a fresh deep copy of starter links."""
    return copy.deepcopy(DEFAULT_LINKS)


@dataclass(frozen=True)
class VaultPaths:
    """Resolved filesystem locations for a LinkVault workspace."""

    base_dir: Path

    @property
    def data_file(self) -> Path:
        return self.base_dir / VAULT_FILENAME

    @property
    def backup_file(self) -> Path:
        return self.base_dir / f"{VAULT_FILENAME}.bak"

    @property
    def v1_backup_file(self) -> Path:
        return self.base_dir / f"{VAULT_FILENAME}.v1.bak"

    @property
    def temp_file(self) -> Path:
        return self.base_dir / f"{VAULT_FILENAME}.tmp"

    @property
    def log_file(self) -> Path:
        return self.base_dir / LOG_FILENAME


def _platform_user_data_dir() -> Path:
    """Return standard per-user application data directory when installed globally."""
    if sys.platform == "win32":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if root:
            return Path(root) / APP_NAME
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        return Path(xdg_data) / "linkvault"
    return Path.home() / ".local" / "share" / "linkvault"


def resolve_vault_paths(data_dir: str | os.PathLike[str] | None = None) -> VaultPaths:
    """Resolve the storage directory using CLI arg, env var, frozen exe, or user data dir."""
    if data_dir is not None:
        base = Path(data_dir).expanduser().resolve()
        return VaultPaths(base_dir=base)

    env_home = os.environ.get("LINKVAULT_HOME", "").strip()
    if env_home:
        return VaultPaths(base_dir=Path(env_home).expanduser().resolve())

    if getattr(sys, "frozen", False):
        return VaultPaths(base_dir=Path(sys.executable).resolve().parent)

    cwd = Path.cwd().resolve()
    if (cwd / VAULT_FILENAME).exists():
        return VaultPaths(base_dir=cwd)

    return VaultPaths(base_dir=_platform_user_data_dir())
