"""Application bootstrapper and CLI entrypoint for LinkVault."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from pathlib import Path

from linkvault.config import APP_NAME, APP_VERSION, resolve_vault_paths
from linkvault.logging_setup import configure_logging, install_excepthook
from linkvault.storage import VaultStorage


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="linkvault",
        description=f"{APP_NAME} - Encrypted desktop link manager",
    )
    parser.add_argument(
        "--data-dir",
        help="Directory where vault_data.enc and logs are stored (overrides LINKVAULT_HOME).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {APP_VERSION}",
    )
    return parser.parse_args(argv)


def main(
    argv: Sequence[str] | None = None,
    *,
    default_data_dir: str | os.PathLike[str] | None = None,
) -> int:
    """Configure logging, resolve vault storage, and launch the Tkinter desktop GUI."""
    args = parse_args(argv)
    target_dir: str | os.PathLike[str] | None = args.data_dir or default_data_dir
    paths = resolve_vault_paths(target_dir)

    logger = configure_logging(paths.log_file)
    install_excepthook(logger)

    # Import Tkinter UI lazily so CLI flags like --version work without a display server.
    from linkvault.ui import LinkVaultApp

    storage = VaultStorage(paths)
    app = LinkVaultApp(storage)
    app.mainloop()
    return 0


def run_from_repo_root(root_file: str | os.PathLike[str]) -> int:
    """Launch LinkVault keeping vault_data.enc adjacent to the root script."""
    return main(default_data_dir=Path(root_file).resolve().parent)
