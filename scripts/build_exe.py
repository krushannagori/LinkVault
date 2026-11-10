"""Build a standalone Windows executable using PyInstaller."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    spec = root / "linkvault.spec"
    cmd = [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", str(spec)]
    print("Running:", " ".join(cmd))
    return subprocess.call(cmd, cwd=root)


if __name__ == "__main__":
    raise SystemExit(main())
