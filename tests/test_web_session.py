"""
tests/test_web_session.py
=========================

Unit tests for the web.session module.

Tests cover:
  - Session creation
  - State transitions (valid and invalid)
  - Persistence to session.json
  - Session expiry / cleanup
  - Server-restart recovery (ANALYZING → FAILED)
  - WebError code correctness
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

# Ensure project root is importable
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from web.session import SessionManager, SessionState, VALID_TRANSITIONS
from web.errors import WebErrorCode, WebError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_sessions(tmp_path: Path) -> Path:
    """Temporary directory for web_sessions."""
    sessions_dir = tmp_path / "web_sessions"
    sessions_dir.mkdir()
    return sessions_dir


@pytest.fixture
def manager(tmp_sessions: Path) -> SessionManager:
    return SessionManager(sessions_dir=tmp_sessions)


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------

class TestSessionCreation:
    def test_creates_session_in_created_state(self, manager: SessionManager):
        record = manager.create()
        assert record.state == SessionState.CREATED

    def test_creates_unique_session_ids(self, manager: SessionManager):
        ids = {manager.create().session_id for _ in range(5)}
        assert len(ids) == 5

    def test_upload_dir_exists_after_create(self, manager: SessionManager):
        record = manager.create()
        assert record.upload_dir.exists()

    def test_reports_dir_exists_after_create(self, manager: SessionManager):
        record = manager.create()
        assert record.reports_dir.exists()

    def test_session_json_written_on_create(
        self, manager: SessionManager, tmp_sessions: Path
    ):
        record = manager.create()
        json_path = tmp_sessions / record.session_id / "session.json"
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert data["session_id"] == record.session_id
        assert data["state"] == "CREATED"


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------

class TestSessionRetrieval:
    def test_get_returns_record(self, manager: SessionManager):
        record = manager.create()
        retrieved = manager.get(record.session_id)
        assert retrieved.session_id == record.session_id

    def test_get_missing_raises_session_not_found(self, manager: SessionManager):
        with pytest.raises(WebError) as exc_info:
            manager.get("does-not-exist")
        assert exc_info.value.code == WebErrorCode.SESSION_NOT_FOUND


# ---------------------------------------------------------------------------
# Transitions
# ---------------------------------------------------------------------------

class TestStateTransitions:
    def test_valid_transition_created_to_uploading(self, manager: SessionManager):
        record = manager.create()
        updated = manager.transition(record.session_id, SessionState.UPLOADING)
        assert updated.state == SessionState.UPLOADING

    def test_valid_full_happy_path(self, manager: SessionManager):
        """Walk through the full happy-path state machine."""
        s = manager.create()
        sid = s.session_id
        states = [
            SessionState.UPLOADING,
            SessionState.UPLOADED,
            SessionState.QUEUED,
            SessionState.ANALYZING,
            SessionState.GENERATING_REPORTS,
            SessionState.COMPLETE,
        ]
        for state in states:
            manager.transition(sid, state)
        assert manager.get(sid).state == SessionState.COMPLETE

    def test_invalid_transition_raises_error(self, manager: SessionManager):
        record = manager.create()
        # Cannot go directly from CREATED to COMPLETE.
        with pytest.raises(WebError) as exc_info:
            manager.transition(record.session_id, SessionState.COMPLETE)
        assert exc_info.value.code == WebErrorCode.INVALID_STATE_TRANSITION

    def test_transition_persists_new_state(
        self, manager: SessionManager, tmp_sessions: Path
    ):
        record = manager.create()
        manager.transition(record.session_id, SessionState.UPLOADING)
        json_path = tmp_sessions / record.session_id / "session.json"
        data = json.loads(json_path.read_text())
        assert data["state"] == "UPLOADING"

    def test_transition_stores_file_metadata(self, manager: SessionManager):
        record = manager.create()
        manager.transition(record.session_id, SessionState.UPLOADING)
        files = [{"name": "auth.log", "size": 1024, "extension": ".log"}]
        updated = manager.transition(
            record.session_id, SessionState.UPLOADED, files=files
        )
        assert updated.files == files

    def test_failed_to_queued_clears_error(self, manager: SessionManager):
        """FAILED → QUEUED should clear the error fields (retry)."""
        record = manager.create()
        sid = record.session_id
        # Advance to ANALYZING so we can transition to FAILED.
        for state in [SessionState.UPLOADING, SessionState.UPLOADED,
                      SessionState.QUEUED, SessionState.ANALYZING]:
            manager.transition(sid, state)
        manager.transition(sid, SessionState.FAILED,
                           error="ORCHESTRATOR_EXCEPTION", error_detail="boom")
        assert manager.get(sid).error == "ORCHESTRATOR_EXCEPTION"

        # Retry: transition back to QUEUED
        manager.transition(sid, SessionState.QUEUED)
        assert manager.get(sid).error is None
        assert manager.get(sid).error_detail is None

    def test_deleted_state_is_terminal(self, manager: SessionManager):
        """After deletion, no further transitions should be possible."""
        record = manager.create()
        sid = record.session_id
        manager.delete(sid)
        with pytest.raises(WebError) as exc_info:
            manager.get(sid)
        assert exc_info.value.code == WebErrorCode.SESSION_NOT_FOUND


# ---------------------------------------------------------------------------
# Valid transitions completeness
# ---------------------------------------------------------------------------

class TestValidTransitionsDefinition:
    def test_all_states_have_transition_entries(self):
        for state in SessionState:
            assert state in VALID_TRANSITIONS, (
                f"{state} missing from VALID_TRANSITIONS"
            )

    def test_deleted_has_no_transitions(self):
        assert len(VALID_TRANSITIONS[SessionState.DELETED]) == 0


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

class TestSessionCleanup:
    def test_cleanup_removes_expired_sessions(
        self, manager: SessionManager, tmp_sessions: Path
    ):
        """Sessions with created_at in the past should be deleted."""
        from web.session import SessionRecord
        import uuid
        from datetime import datetime, timezone, timedelta

        # Manually inject an old session.
        old_id = str(uuid.uuid4())
        old_ts = (
            datetime.now(timezone.utc) - timedelta(hours=25)
        ).replace(microsecond=0).isoformat()

        old_dir = tmp_sessions / old_id
        (old_dir / "uploads").mkdir(parents=True)
        (old_dir / "reports").mkdir(parents=True)

        record = SessionRecord(
            session_id=old_id,
            state=SessionState.COMPLETE,
            created_at=old_ts,
            updated_at=old_ts,
            upload_dir=old_dir / "uploads",
            reports_dir=old_dir / "reports",
        )
        # Manually register in the manager's internal dict (simulate restart).
        manager._sessions[old_id] = record

        deleted = manager.cleanup_expired()
        assert old_id in deleted
        assert old_id not in manager._sessions

    def test_cleanup_keeps_recent_sessions(self, manager: SessionManager):
        record = manager.create()
        deleted = manager.cleanup_expired()
        assert record.session_id not in deleted
        assert manager.get(record.session_id).session_id == record.session_id


# ---------------------------------------------------------------------------
# Server-restart recovery
# ---------------------------------------------------------------------------

class TestServerRestartRecovery:
    def test_interrupted_analyzing_session_becomes_failed(
        self, tmp_sessions: Path
    ):
        """A session persisted as ANALYZING before restart should become FAILED."""
        from web.session import SessionRecord
        import uuid
        from datetime import datetime, timezone

        session_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        session_dir = tmp_sessions / session_id
        upload_dir = session_dir / "uploads"
        reports_dir = session_dir / "reports"
        upload_dir.mkdir(parents=True)
        reports_dir.mkdir(parents=True)

        # Write a session.json that simulates a crash mid-analysis.
        data = {
            "session_id": session_id,
            "state": "ANALYZING",
            "created_at": now,
            "updated_at": now,
            "upload_dir": str(upload_dir),
            "reports_dir": str(reports_dir),
            "files": [],
            "dashboard_path": None,
            "report_json_path": None,
            "error": None,
            "error_detail": None,
        }
        (session_dir / "session.json").write_text(
            json.dumps(data), encoding="utf-8"
        )

        # Simulate server restart by creating a new SessionManager.
        manager = SessionManager(sessions_dir=tmp_sessions)
        record = manager.get(session_id)
        assert record.state == SessionState.FAILED
        assert record.error == WebErrorCode.ORCHESTRATOR_EXCEPTION.value
