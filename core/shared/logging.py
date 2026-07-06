"""Shared logging helpers for THRAGG engines."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager

__all__ = ["get_logger", "logged_operation"]


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced framework logger."""
    return logging.getLogger(f"thragg.{name}")


@contextmanager
def logged_operation(logger: logging.Logger, operation: str) -> Iterator[None]:
    """Log start, completion duration, and exceptions for one operation."""
    start = time.perf_counter()
    logger.info("%s started", operation)
    try:
        yield
    except Exception:
        logger.exception("%s failed", operation)
        raise
    logger.info("%s completed in %.4fs", operation, time.perf_counter() - start)
