"""
core.stable_id
==============

Shared deterministic SHA-256 id helper.
"""

from __future__ import annotations

import hashlib

__all__ = ["stable_sha_id"]


def stable_sha_id(prefix: str, *parts: str, length: int = 16) -> str:
    """Return prefix plus a truncated SHA-256 hash of pipe-joined parts."""
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:length]
    return f"{prefix}-{digest}"
