"""
web.session
===========

Session state machine, ID generation, and session.json persistence.

Every analysis session moves through deterministic states defined by
SessionState. Only valid transitions (per VALID_TRANSITIONS) are allowed.
Invalid transitions raise WebError(INVALID_STATE_TRANSITION).

Session records are kept in memory (Python dict) during server runtime
and persisted to session.json on every state change for durability.
On startup, existing sessions are reconstructed from their JSON files.

Thread safety: a single threading.RLock guards all in-memory state.
The lock is per-SessionManager instance, not global.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .config import SESSION_RETENTION_HOURS, WEB_SESSIONS_DIR
from .errors import WebError, WebErrorCode


# ---------------------------------------------------------------------------
# State machine definition
# ---------------------------------------------------------------------------

class SessionState(str, Enum):
    """All valid states for an analysis session."""

    CREATED = "CREATED"
    UPLOADING = "UPLOADING"
    UPLOADED = "UPLOADED"
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    GENERATING_REPORTS = "GENERATING_REPORTS"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    DELETED = "DELETED"


#: Terminal states — no further transitions are valid (except DELETED).
TERMINAL_STATES: frozenset[SessionState] = frozenset(
    {SessionState.COMPLETE, SessionState.FAILED, SessionState.CANCELLED, SessionState.DELETED}
)

#: Valid transitions from each state.
#: Every non-terminal state can also transition to DELETED.
VALID_TRANSITIONS: dict[SessionState, frozenset[SessionState]] = {
    SessionState.CREATED: frozenset(
        {SessionState.UPLOADING, SessionState.DELETED}
    ),
    SessionState.UPLOADING: frozenset(
        {SessionState.UPLOADED, SessionState.CANCELLED, SessionState.DELETED}
    ),
    SessionState.UPLOADED: frozenset(
        {SessionState.QUEUED, SessionState.CANCELLED, SessionState.DELETED}
    ),
    SessionState.QUEUED: frozenset(
        {SessionState.ANALYZING, SessionState.CANCELLED, SessionState.DELETED}
    ),
    SessionState.ANALYZING: frozenset(
        {SessionState.GENERATING_REPORTS, SessionState.FAILED, SessionState.DELETED}
    ),
    SessionState.GENERATING_REPORTS: frozenset(
        {SessionState.COMPLETE, SessionState.FAILED, SessionState.DELETED}
    ),
    SessionState.COMPLETE: frozenset({SessionState.DELETED}),
    # FAILED allows retry: transition back to QUEUED
    SessionState.FAILED: frozenset({SessionState.QUEUED, SessionState.DELETED}),
    SessionState.CANCELLED: frozenset({SessionState.DELETED}),
    SessionState.DELETED: frozenset(),
}


# ---------------------------------------------------------------------------
# Session record
# ---------------------------------------------------------------------------

@dataclass
class SessionRecord:
    """In-memory representation of one analysis session."""

    session_id: str
    state: SessionState
    created_at: str
    updated_at: str
    upload_dir: Path
    reports_dir: Path
    files: list[dict[str, Any]] = field(default_factory=list)
    dashboard_path: str | None = None
    report_json_path: str | None = None
    error: str | None = None
    error_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict (for session.json and API)."""
        return {
            "session_id": self.session_id,
            "state": self.state.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "upload_dir": str(self.upload_dir),
            "reports_dir": str(self.reports_dir),
            "files": self.files,
            "dashboard_path": self.dashboard_path,
            "report_json_path": self.report_json_path,
            "error": self.error,
            "error_detail": self.error_detail,
        }

    def to_status_dict(self) -> dict[str, Any]:
        """Minimal dict for /api/status responses."""
        return {
            "session_id": self.session_id,
            "status": self.state.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "files": [f["name"] for f in self.files],
            "error": self.error,
            "error_detail": self.error_detail,
        }


# ---------------------------------------------------------------------------
# Session Manager
# ---------------------------------------------------------------------------

class SessionManager:
    """Creates, transitions, and persists analysis session records.

    Usage::

        manager = SessionManager()
        session = manager.create()
        manager.transition(session.session_id, SessionState.UPLOADING)
    """

    def __init__(self, sessions_dir: Path | None = None) -> None:
        self._dir: Path = sessions_dir or WEB_SESSIONS_DIR
        self._sessions: dict[str, SessionRecord] = {}
        self._lock: threading.RLock = threading.RLock()
        self._load_existing_sessions()

    # -- Public API ----------------------------------------------------------

    def create(self) -> SessionRecord:
        """Create a new session in CREATED state.

        Returns:
            The newly created SessionRecord.
        """
        session_id = str(uuid.uuid4())
        now = _utc_now()
        upload_dir = self._dir / session_id / "uploads"
        reports_dir = self._dir / session_id / "reports"
        upload_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        record = SessionRecord(
            session_id=session_id,
            state=SessionState.CREATED,
            created_at=now,
            updated_at=now,
            upload_dir=upload_dir,
            reports_dir=reports_dir,
        )

        with self._lock:
            self._sessions[session_id] = record
            self._persist(record)

        return record

    def get(self, session_id: str) -> SessionRecord:
        """Return the session record for *session_id*.

        Raises:
            WebError(SESSION_NOT_FOUND): if no such session exists.
        """
        with self._lock:
            record = self._sessions.get(session_id)
        if record is None:
            raise WebError(WebErrorCode.SESSION_NOT_FOUND, session_id=session_id)
        return record

    def transition(
        self,
        session_id: str,
        new_state: SessionState,
        *,
        files: list[dict[str, Any]] | None = None,
        dashboard_path: str | None = None,
        report_json_path: str | None = None,
        error: str | None = None,
        error_detail: str | None = None,
    ) -> SessionRecord:
        """Transition *session_id* to *new_state*.

        Args:
            session_id:       The session to update.
            new_state:        The target state.
            files:            Optional list of file metadata to store.
            dashboard_path:   Optional path to the generated dashboard HTML.
            report_json_path: Optional path to the generated report JSON.
            error:            Optional WebErrorCode string on failure.
            error_detail:     Optional human-readable detail for FAILED state.

        Returns:
            The updated SessionRecord.

        Raises:
            WebError(SESSION_NOT_FOUND):        If the session does not exist.
            WebError(INVALID_STATE_TRANSITION): If the transition is not allowed.
        """
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                raise WebError(WebErrorCode.SESSION_NOT_FOUND, session_id=session_id)

            allowed = VALID_TRANSITIONS.get(record.state, frozenset())
            if new_state not in allowed:
                raise WebError(
                    WebErrorCode.INVALID_STATE_TRANSITION,
                    session_id=session_id,
                    detail=(
                        f"Cannot transition from {record.state.value} "
                        f"to {new_state.value}."
                    ),
                )

            # Apply updates
            record.state = new_state
            record.updated_at = _utc_now()

            if files is not None:
                record.files = files
            if dashboard_path is not None:
                record.dashboard_path = dashboard_path
            if report_json_path is not None:
                record.report_json_path = report_json_path
            if error is not None:
                record.error = error
            if error_detail is not None:
                record.error_detail = error_detail

            # Clear errors when retrying from FAILED
            if new_state == SessionState.QUEUED and record.error:
                record.error = None
                record.error_detail = None

            self._persist(record)

        return record

    def delete(self, session_id: str) -> None:
        """Remove a session record and delete its directory from disk.

        Raises:
            WebError(SESSION_NOT_FOUND): if no such session exists.
        """
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                raise WebError(WebErrorCode.SESSION_NOT_FOUND, session_id=session_id)

            session_dir = self._dir / session_id
            _rmtree(session_dir)
            del self._sessions[session_id]

    def cleanup_expired(self) -> list[str]:
        """Delete sessions older than SESSION_RETENTION_HOURS.

        Called once at server startup. Returns a list of deleted session IDs.
        """
        import time

        cutoff = time.time() - SESSION_RETENTION_HOURS * 3600
        deleted: list[str] = []

        with self._lock:
            for sid, record in list(self._sessions.items()):
                try:
                    ts = datetime.fromisoformat(record.created_at).timestamp()
                except (ValueError, AttributeError):
                    continue
                if ts < cutoff:
                    session_dir = self._dir / sid
                    _rmtree(session_dir)
                    del self._sessions[sid]
                    deleted.append(sid)

        return deleted

    # -- Private helpers -----------------------------------------------------

    def _persist(self, record: SessionRecord) -> None:
        """Write session.json atomically inside the session directory."""
        session_dir = self._dir / record.session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        json_path = session_dir / "session.json"
        tmp_path = json_path.with_suffix(".tmp")
        try:
            tmp_path.write_text(
                json.dumps(record.to_dict(), indent=2),
                encoding="utf-8",
            )
            tmp_path.replace(json_path)
        except OSError:
            # Persistence failure is non-fatal: in-memory state remains valid.
            pass

    def _load_existing_sessions(self) -> None:
        """Reconstruct in-memory sessions from existing session.json files."""
        if not self._dir.exists():
            return
        for json_path in self._dir.glob("*/session.json"):
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
                record = SessionRecord(
                    session_id=data["session_id"],
                    state=SessionState(data["state"]),
                    created_at=data["created_at"],
                    updated_at=data["updated_at"],
                    upload_dir=Path(data["upload_dir"]),
                    reports_dir=Path(data["reports_dir"]),
                    files=data.get("files", []),
                    dashboard_path=data.get("dashboard_path"),
                    report_json_path=data.get("report_json_path"),
                    error=data.get("error"),
                    error_detail=data.get("error_detail"),
                )
                # Sessions that were ANALYZING/QUEUED/GENERATING on restart
                # are considered FAILED — they were interrupted.
                if record.state in (
                    SessionState.QUEUED,
                    SessionState.ANALYZING,
                    SessionState.GENERATING_REPORTS,
                ):
                    record.state = SessionState.FAILED
                    record.error = WebErrorCode.ORCHESTRATOR_EXCEPTION.value
                    record.error_detail = "Session was interrupted by a server restart."
                    self._persist(record)

                self._sessions[record.session_id] = record
            except (KeyError, ValueError, OSError):
                # Corrupted session.json — skip it.
                continue


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _rmtree(path: Path) -> None:
    """Recursively remove *path* if it exists, silently ignoring errors."""
    import shutil
    try:
        if path.exists():
            shutil.rmtree(path)
    except OSError:
        pass


__all__ = [
    "SessionState",
    "SessionRecord",
    "SessionManager",
    "TERMINAL_STATES",
    "VALID_TRANSITIONS",
]
