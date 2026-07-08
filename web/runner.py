"""
web.runner
==========

Background analysis runner.

AnalysisRunner is a thin wrapper around ThreadPoolExecutor that:
  1. Accepts one analysis job per session.
  2. Runs each job in its own isolated THRAGGOrchestrator instance.
  3. Writes session state transitions throughout the job lifecycle.
  4. Captures the orchestrator's return dict and persists it to disk.

Thread safety:
  - The ExecutionPool (max_workers=2) handles concurrency.
  - Session state transitions are protected by SessionManager's RLock.
  - Each job uses a completely isolated THRAGGOrchestrator instance;
    no engine state is shared between jobs (verified in concurrency audit).

Architecture constraint:
  - This module is the ONLY place that imports THRAGGOrchestrator.
  - The intelligence engine is treated as a pure black-box callable.
"""

from __future__ import annotations

import json
import sys
import threading
import traceback
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .config import MAX_ANALYSIS_WORKERS
from .errors import WebErrorCode
from .session import SessionManager, SessionState


# ---------------------------------------------------------------------------
# Analysis Runner
# ---------------------------------------------------------------------------

class AnalysisRunner:
    """Background worker pool for THRAGG analysis jobs.

    Usage::

        runner = AnalysisRunner(session_manager)
        runner.submit(session_id)
        # Status is polled via SessionManager; runner updates state internally.

    The runner holds a reference to the SessionManager so that background
    threads can update state without any callbacks.
    """

    def __init__(self, session_manager: SessionManager) -> None:
        self._sessions = session_manager
        self._executor: ThreadPoolExecutor = ThreadPoolExecutor(
            max_workers=MAX_ANALYSIS_WORKERS,
            thread_name_prefix="thragg-worker",
        )
        # Track active futures per session_id to avoid double-submission.
        self._active: dict[str, Future[None]] = {}
        self._active_lock = threading.Lock()

    # -- Public API ----------------------------------------------------------

    def submit(self, session_id: str) -> None:
        """Queue *session_id* for background analysis.

        Transitions the session to QUEUED and submits to the thread pool.

        Args:
            session_id: The session to analyze. Must be in UPLOADED state.

        Raises:
            WebError(ANALYSIS_ALREADY_RUNNING): If a job for this session is
                                                already in the executor queue.
            WebError(INVALID_STATE_TRANSITION): If session is not in UPLOADED.
            WebError(SESSION_NOT_FOUND):        If the session does not exist.
        """
        from .errors import WebError

        with self._active_lock:
            if session_id in self._active and not self._active[session_id].done():
                raise WebError(
                    WebErrorCode.ANALYSIS_ALREADY_RUNNING,
                    session_id=session_id,
                )

        # Transition to QUEUED — validates session exists and is in UPLOADED.
        self._sessions.transition(session_id, SessionState.QUEUED)

        # Submit background job.
        future = self._executor.submit(self._execute, session_id)
        with self._active_lock:
            self._active[session_id] = future

    def shutdown(self, wait: bool = True) -> None:
        """Shut down the thread pool.

        Called during application teardown. Waits for running jobs by default.
        """
        self._executor.shutdown(wait=wait, cancel_futures=not wait)

    # -- Private: background job ---------------------------------------------

    def _execute(self, session_id: str) -> None:
        """The analysis job that runs in a background thread.

        This method:
          1. Reads the session record to get upload and output dirs.
          2. Creates a fresh THRAGGOrchestrator instance with the session's
             output directory.
          3. Calls orchestrator.run(upload_dir).
          4. Persists the returned report dict to session_data.json.
          5. Transitions the session to COMPLETE or FAILED.

        All exceptions are caught and stored in the session record.
        """
        try:
            record = self._sessions.get(session_id)
            upload_dir = str(record.upload_dir)
            reports_dir = record.reports_dir

            # ---- ANALYZING ------------------------------------------------
            self._sessions.transition(session_id, SessionState.ANALYZING)

            # Import here to isolate engine coupling to this single location.
            # Each call creates a completely independent orchestrator instance.
            import sys
            import os
            # Ensure project root is on sys.path for thragg module resolution.
            project_root = str(Path(__file__).parent.parent)
            if project_root not in sys.path:
                sys.path.insert(0, project_root)

            from thragg import THRAGGOrchestrator

            orchestrator = THRAGGOrchestrator(output_dir=str(reports_dir))

            # ---- Run intelligence pipeline --------------------------------
            report = orchestrator.run(upload_dir)

            # ---- GENERATING_REPORTS ----------------------------------------
            self._sessions.transition(
                session_id, SessionState.GENERATING_REPORTS
            )

            # Persist the full orchestrator result so the API can serve it.
            _persist_session_data(reports_dir, report)

            # Extract key artifact paths from the report dict.
            artifacts = report.get("artifacts", {})
            dashboard_info = artifacts.get("dashboard", {})
            dashboard_path = dashboard_info.get("html_file") if isinstance(
                dashboard_info, dict
            ) else None
            report_json_path = artifacts.get("thragg_report")

            # ---- COMPLETE --------------------------------------------------
            self._sessions.transition(
                session_id,
                SessionState.COMPLETE,
                dashboard_path=dashboard_path,
                report_json_path=report_json_path,
            )

        except Exception as exc:  # noqa: BLE001
            # Capture full traceback for operator debugging.
            detail = "".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            )
            _safe_fail(self._sessions, session_id, str(exc), detail)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _persist_session_data(reports_dir: Path, report: Any) -> None:
    """Write the orchestrator return dict to session_data.json.

    This is the source of truth for /api/results. Saved alongside the
    other report artifacts in the session's reports/ directory.
    """
    reports_dir.mkdir(parents=True, exist_ok=True)
    out = reports_dir / "session_data.json"
    tmp = out.with_suffix(".tmp")
    try:
        tmp.write_text(
            json.dumps(report, indent=2, default=str),
            encoding="utf-8",
        )
        tmp.replace(out)
    except (OSError, TypeError):
        # Non-fatal — session will still transition to COMPLETE.
        pass


def _safe_fail(
    sessions: SessionManager,
    session_id: str,
    error: str,
    detail: str,
) -> None:
    """Attempt to transition *session_id* to FAILED without raising."""
    try:
        sessions.transition(
            session_id,
            SessionState.FAILED,
            error=WebErrorCode.ORCHESTRATOR_EXCEPTION.value,
            error_detail=detail[:2000],  # cap for session.json readability
        )
    except Exception:  # noqa: BLE001
        # If even the FAILED transition fails, there is nothing we can do.
        pass


__all__ = ["AnalysisRunner"]
