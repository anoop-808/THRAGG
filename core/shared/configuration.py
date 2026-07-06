"""Shared runtime configuration constants."""

from __future__ import annotations

DEFAULT_REPORT_OUTPUT_DIR = "thragg_results"
MODULE_CONTRACT_KEYS = {
    "metadata": dict,
    "summary": dict,
    "details": dict,
    "artifacts": dict,
    "errors": list,
}

__all__ = ["DEFAULT_REPORT_OUTPUT_DIR", "MODULE_CONTRACT_KEYS"]
