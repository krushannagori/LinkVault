"""Structured rotating logging and global exception hook for GUI runs."""

from __future__ import annotations

import logging
import sys
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import TracebackType


def configure_logging(log_file: Path) -> logging.Logger:
    """Configure a rotating file logger for LinkVault without console noise."""
    logger = logging.getLogger("linkvault")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Avoid duplicate handlers if re-initialized in tests or multiple app starts
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_file,
            maxBytes=1_048_576,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
        )
        logger.addHandler(handler)
    except OSError:
        logger.addHandler(logging.NullHandler())

    return logger


def log_unhandled_exception(
    exc_type: type[BaseException],
    exc: BaseException,
    tb: TracebackType | None,
    logger: logging.Logger | None = None,
) -> None:
    """Record an unhandled exception to the application log file."""
    target = logger or logging.getLogger("linkvault")
    formatted = "".join(traceback.format_exception(exc_type, exc, tb))
    target.error("Unhandled exception:\n%s", formatted.rstrip())


def install_excepthook(logger: logging.Logger) -> None:
    """Install sys.excepthook so pythonw.exe failures are never silently lost."""

    def _hook(
        exc_type: type[BaseException],
        exc: BaseException,
        tb: TracebackType | None,
    ) -> None:
        log_unhandled_exception(exc_type, exc, tb, logger=logger)

    sys.excepthook = _hook
