"""Module entrypoint for `python -m linkvault`."""

from __future__ import annotations

import sys

from linkvault.app import main

if __name__ == "__main__":
    raise SystemExit(main())
