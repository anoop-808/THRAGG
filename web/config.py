"""
web.config
==========

All web-layer configuration constants.

This is the single source of truth for every limit, path, and timeout
used by the THRAGG web adapter. Nothing is hardcoded elsewhere.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

#: Absolute path to the repository root (parent of the web/ package).
PROJECT_ROOT: Path = Path(__file__).parent.parent

#: Where all session subdirectories are created at runtime.
WEB_SESSIONS_DIR: Path = PROJECT_ROOT / "web_sessions"

#: Where the existing dashboard SPA and upload UI live.
FRONTEND_DIR: Path = PROJECT_ROOT / "frontend"

#: Absolute path to the upload page HTML file.
UPLOAD_PAGE: Path = FRONTEND_DIR / "upload" / "index.html"

#: Absolute path to the dashboard SPA HTML file.
DASHBOARD_PAGE: Path = FRONTEND_DIR / "index.html"

# ---------------------------------------------------------------------------
# Upload limits
# ---------------------------------------------------------------------------

#: Maximum size of a single uploaded file (10 MB).
MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024

#: Maximum total upload size per session (50 MB).
MAX_TOTAL_SIZE_BYTES: int = 50 * 1024 * 1024

#: Accepted file extensions (lowercase, with leading dot).
ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
    {".log", ".xml", ".json", ".html", ".txt"}
)

# ---------------------------------------------------------------------------
# Session retention
# ---------------------------------------------------------------------------

#: Sessions older than this many hours are deleted on server startup.
SESSION_RETENTION_HOURS: int = 24

# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------

#: Maximum number of concurrent analysis jobs.
#: Each job runs in its own isolated THRAGGOrchestrator instance.
MAX_ANALYSIS_WORKERS: int = 2

# ---------------------------------------------------------------------------
# Flask runtime
# ---------------------------------------------------------------------------

#: Host binding — always localhost for offline security.
SERVER_HOST: str = "127.0.0.1"

#: Port the development server listens on.
SERVER_PORT: int = 5000

#: Flask debug mode — should always be False in any non-dev context.
DEBUG: bool = False

#: Maximum Flask request content length.
#: Set equal to total session limit to prevent Flask from accepting
#: oversized uploads before UploadManager can inspect them.
MAX_CONTENT_LENGTH: int = MAX_TOTAL_SIZE_BYTES

__all__ = [
    "PROJECT_ROOT",
    "WEB_SESSIONS_DIR",
    "FRONTEND_DIR",
    "UPLOAD_PAGE",
    "DASHBOARD_PAGE",
    "MAX_FILE_SIZE_BYTES",
    "MAX_TOTAL_SIZE_BYTES",
    "ALLOWED_EXTENSIONS",
    "SESSION_RETENTION_HOURS",
    "MAX_ANALYSIS_WORKERS",
    "SERVER_HOST",
    "SERVER_PORT",
    "DEBUG",
    "MAX_CONTENT_LENGTH",
]
