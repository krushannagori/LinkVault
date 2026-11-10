"""LinkVault desktop launcher entrypoint.

Supports running directly via `python link_vault.py`, `pythonw link_vault.py`,
`Launch_LinkVault.bat`, or as a PyInstaller frozen Windows executable.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _bootstrap_src_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    root_dir = Path(__file__).resolve().parent
    src_dir = root_dir / "src"
    if src_dir.is_dir() and str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    return root_dir


if __name__ == "__main__":
    data_dir = _bootstrap_src_path()
    from linkvault.app import main

    raise SystemExit(main(default_data_dir=data_dir))
