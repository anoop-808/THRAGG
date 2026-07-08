"""
web.errors
==========

Web-layer error codes and HTTP response builders.

Frozen error contract from Session 1 Architecture:
  - Every error HTTP response uses the same JSON envelope.
  - Error codes are symbolic constants, not bare strings.
  - The ORCHESTRATOR_EXCEPTION code is stored in session state,
    not returned as an HTTP error code — analysis is async.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from flask import jsonify, Response


# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

class WebErrorCode(str, Enum):
    """Symbolic error codes used throughout the web adapter."""

    # Upload errors
    NO_FILES = "NO_FILES"
    UNSUPPORTED_FILE_TYPE = "UNSUPPORTED_FILE_TYPE"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    TOTAL_SIZE_EXCEEDED = "TOTAL_SIZE_EXCEEDED"
    UPLOAD_STORAGE_FAILURE = "UPLOAD_STORAGE_FAILURE"

    # Session errors
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    ANALYSIS_ALREADY_RUNNING = "ANALYSIS_ALREADY_RUNNING"
    QUEUE_FAILURE = "QUEUE_FAILURE"
    SESSION_NOT_COMPLETE = "SESSION_NOT_COMPLETE"
    RESULT_READ_FAILURE = "RESULT_READ_FAILURE"

    # Download errors
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    PATH_TRAVERSAL_BLOCKED = "PATH_TRAVERSAL_BLOCKED"

    # Engine errors (stored in session state, not as HTTP codes)
    ORCHESTRATOR_EXCEPTION = "ORCHESTRATOR_EXCEPTION"


# ---------------------------------------------------------------------------
# Human-readable descriptions (kept in one place)
# ---------------------------------------------------------------------------

_DESCRIPTIONS: dict[WebErrorCode, str] = {
    WebErrorCode.NO_FILES: "No files were included in the upload request.",
    WebErrorCode.UNSUPPORTED_FILE_TYPE: (
        "One or more files have an unsupported extension. "
        "Accepted: .log, .xml, .json, .html, .txt"
    ),
    WebErrorCode.FILE_TOO_LARGE: "A file exceeds the 10 MB per-file limit.",
    WebErrorCode.TOTAL_SIZE_EXCEEDED: "Total upload exceeds the 50 MB per-session limit.",
    WebErrorCode.UPLOAD_STORAGE_FAILURE: "Failed to write uploaded files to disk.",
    WebErrorCode.SESSION_NOT_FOUND: "The requested session does not exist.",
    WebErrorCode.INVALID_STATE_TRANSITION: (
        "The requested action is not valid in the current session state."
    ),
    WebErrorCode.ANALYSIS_ALREADY_RUNNING: "An analysis is already running. Please wait.",
    WebErrorCode.QUEUE_FAILURE: "The analysis runner could not accept this job.",
    WebErrorCode.SESSION_NOT_COMPLETE: (
        "Results are not yet available. The analysis is still in progress."
    ),
    WebErrorCode.RESULT_READ_FAILURE: "The analysis report could not be read from disk.",
    WebErrorCode.FILE_NOT_FOUND: "The requested file was not found in this session.",
    WebErrorCode.PATH_TRAVERSAL_BLOCKED: "The requested filename is not permitted.",
    WebErrorCode.ORCHESTRATOR_EXCEPTION: (
        "The intelligence engine raised an exception during analysis."
    ),
}


# ---------------------------------------------------------------------------
# HTTP status codes
# ---------------------------------------------------------------------------

_HTTP_STATUS: dict[WebErrorCode, int] = {
    WebErrorCode.NO_FILES: 400,
    WebErrorCode.UNSUPPORTED_FILE_TYPE: 400,
    WebErrorCode.FILE_TOO_LARGE: 400,
    WebErrorCode.TOTAL_SIZE_EXCEEDED: 400,
    WebErrorCode.UPLOAD_STORAGE_FAILURE: 500,
    WebErrorCode.SESSION_NOT_FOUND: 404,
    WebErrorCode.INVALID_STATE_TRANSITION: 409,
    WebErrorCode.ANALYSIS_ALREADY_RUNNING: 409,
    WebErrorCode.QUEUE_FAILURE: 500,
    WebErrorCode.SESSION_NOT_COMPLETE: 409,
    WebErrorCode.RESULT_READ_FAILURE: 500,
    WebErrorCode.FILE_NOT_FOUND: 404,
    WebErrorCode.PATH_TRAVERSAL_BLOCKED: 403,
}


# ---------------------------------------------------------------------------
# Exception classes
# ---------------------------------------------------------------------------

class WebError(Exception):
    """Base exception for all web-layer errors.

    Raised by UploadManager, SessionManager, and AnalysisRunner.
    Caught by Flask error handlers and converted to a JSON response.
    """

    def __init__(
        self,
        code: WebErrorCode,
        session_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(code.value)
        self.code = code
        self.session_id = session_id
        self.detail = detail

    @property
    def http_status(self) -> int:
        return _HTTP_STATUS.get(self.code, 500)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": self.code.value,
            "message": _DESCRIPTIONS.get(self.code, self.code.value),
            "session_id": self.session_id,
        }
        if self.detail:
            payload["detail"] = self.detail
        return payload


# ---------------------------------------------------------------------------
# Response builder
# ---------------------------------------------------------------------------

def error_response(
    code: WebErrorCode,
    session_id: str | None = None,
    detail: str | None = None,
) -> tuple[Response, int]:
    """Build a standard JSON error response tuple for Flask routes."""
    err = WebError(code, session_id=session_id, detail=detail)
    return jsonify(err.to_dict()), err.http_status


__all__ = [
    "WebErrorCode",
    "WebError",
    "error_response",
]
