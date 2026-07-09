"""
web.app
=======

Flask application factory and route definitions.

Routes
------

Static / Frontend
    GET  /                         → Upload page (frontend/upload/index.html)
    GET  /dashboard/<session_id>   → Dashboard SPA (frontend/index.html)
    GET  /frontend/<path:filename> → Static frontend assets

Upload & Analysis
    POST /api/upload               → Validate, save files, create session
    POST /api/analyze/<session_id> → Queue background analysis job
    GET  /api/status/<session_id>  → Poll session state

Results
    GET  /api/results/<session_id>    → Intelligence data JSON for dashboard
    GET  /api/download/<session_id>/<filename> → Download report file

Lifecycle
    DELETE /api/session/<session_id> → Delete session and all files

Architecture constraint:
    This module is the ONLY web-aware code that builds Flask responses.
    It imports only: session, upload, runner, config, errors from the
    web package. It never imports from core/ or modules/ directly.
"""

from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, jsonify, request, send_file, Response

from .config import (
    DASHBOARD_PAGE,
    FRONTEND_DIR,
    MAX_CONTENT_LENGTH,
    UPLOAD_PAGE,
)
from .errors import WebError, WebErrorCode, error_response
from .runner import AnalysisRunner
from .session import SessionManager, SessionState, TERMINAL_STATES
from .upload import UploadManager


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Create and configure the THRAGG Flask application.

    Returns:
        A configured Flask app instance. This function is the single
        construction point; no global state lives outside it.
    """
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    # No secret key needed — we use no Flask sessions, only explicit state.

    # -- Shared singletons ---------------------------------------------------
    session_manager = SessionManager()
    upload_manager = UploadManager()
    analysis_runner = AnalysisRunner(session_manager)

    # Startup: remove sessions older than 24 hours.
    expired = session_manager.cleanup_expired()
    if expired:
        print(f"[THRAGG] Cleaned up {len(expired)} expired session(s) on startup.")

    # -- Error handlers -------------------------------------------------------

    @app.errorhandler(WebError)
    def handle_web_error(exc: WebError):
        return jsonify(exc.to_dict()), exc.http_status

    @app.errorhandler(413)
    def handle_too_large(exc):
        return error_response(WebErrorCode.TOTAL_SIZE_EXCEEDED)

    @app.errorhandler(404)
    def handle_not_found(exc):
        return jsonify({"error": "NOT_FOUND", "message": "Resource not found."}), 404

    # -- Static / Frontend routes --------------------------------------------

    @app.route("/")
    def upload_page():
        """Serve the upload UI."""
        if not UPLOAD_PAGE.exists():
            return jsonify({"error": "SETUP_INCOMPLETE", "message": "Upload page not found."}), 503
        return send_file(str(UPLOAD_PAGE))

    @app.route("/dashboard/<session_id>")
    def dashboard_page(session_id: str):
        """Serve the dashboard SPA for a completed session."""
        try:
            record = session_manager.get(session_id)
        except WebError as exc:
            return jsonify(exc.to_dict()), exc.http_status

        if record.state != SessionState.COMPLETE:
            return jsonify({
                "error": "SESSION_NOT_COMPLETE",
                "message": "Dashboard is only available after analysis completes.",
                "status": record.state.value,
            }), 409

        if not DASHBOARD_PAGE.exists():
            return jsonify({"error": "SETUP_INCOMPLETE", "message": "Dashboard not found."}), 503

        return send_file(str(DASHBOARD_PAGE))

    @app.route("/frontend/<path:filename>")
    def frontend_static(filename: str):
        """Serve static frontend assets (CSS, JS, fonts, etc.)."""
        # Resolve and validate to prevent path traversal.
        requested = (FRONTEND_DIR / filename).resolve()
        if not str(requested).startswith(str(FRONTEND_DIR.resolve())):
            return error_response(WebErrorCode.PATH_TRAVERSAL_BLOCKED)
        if not requested.is_file():
            return error_response(WebErrorCode.FILE_NOT_FOUND)
        return send_file(str(requested))

    # -- Upload & Analysis routes --------------------------------------------

    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        """Accept evidence files, validate, save, and return a session ID.

        Request: multipart/form-data with one or more files under 'files'.

        Response 201::

            {
              "session_id": "uuid",
              "status": "UPLOADED",
              "files": [{"name": "auth.log", "size": 75631, "extension": ".log"}]
            }
        """
        raw_files = request.files.getlist("files")

        # Validate (raises WebError on failure)
        upload_manager.validate(raw_files)

        # Create session and persist files
        record = session_manager.create()

        # Transition to UPLOADING
        session_manager.transition(record.session_id, SessionState.UPLOADING)

        # Save files to disk
        file_metadata = upload_manager.save(raw_files, record.upload_dir)

        # Transition to UPLOADED with file list
        session_manager.transition(
            record.session_id,
            SessionState.UPLOADED,
            files=file_metadata,
        )

        return jsonify({
            "session_id": record.session_id,
            "status": SessionState.UPLOADED.value,
            "files": file_metadata,
        }), 201

    @app.route("/api/analyze/<session_id>", methods=["POST"])
    def api_analyze(session_id: str):
        """Queue an uploaded session for background analysis.

        Response 202::

            {
              "session_id": "uuid",
              "status": "QUEUED",
              "message": "Analysis queued. Poll /api/status/<session_id>."
            }
        """
        analysis_runner.submit(session_id)
        return jsonify({
            "session_id": session_id,
            "status": SessionState.QUEUED.value,
            "message": f"Analysis queued. Poll /api/status/{session_id} for updates.",
        }), 202

    # -- Status polling route ------------------------------------------------

    @app.route("/api/status/<session_id>", methods=["GET"])
    def api_status(session_id: str):
        """Return the current state of a session.

        Response 200::

            {
              "session_id": "uuid",
              "status": "ANALYZING",
              "created_at": "...",
              "updated_at": "...",
              "files": ["auth.log"],
              "error": null,
              "error_detail": null
            }
        """
        record = session_manager.get(session_id)
        return jsonify(record.to_status_dict()), 200

    # -- Results route -------------------------------------------------------

    @app.route("/api/results/<session_id>", methods=["GET"])
    def api_results(session_id: str):
        """Return intelligence data for a completed session.

        This is the data contract for the dashboard SPA. The response
        contains all keys needed by window.THRAGG_DATA (Session 3 will
        inject this into the dashboard using this endpoint).

        Response 200::

            {
              "session_id": "uuid",
              "executive_assessment": {...},
              "framework_snapshot": {...},
              "risk_assessments": [...],
              "attack_chains": [...],
              "correlations": [...],
              "relationships": [...],
              "resolved_entities": [...],
              "findings": [...],
              "generated_at": "..."
            }
        """
        record = session_manager.get(session_id)

        if record.state != SessionState.COMPLETE:
            return error_response(
                WebErrorCode.SESSION_NOT_COMPLETE,
                session_id=session_id,
                detail=f"Current state: {record.state.value}",
            )

        # Read from session_data.json written by the runner.
        data_path = record.reports_dir / "session_data.json"
        if not data_path.exists():
            return error_response(
                WebErrorCode.RESULT_READ_FAILURE,
                session_id=session_id,
                detail="session_data.json not found in reports directory.",
            )

        try:
            raw = json.loads(data_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return error_response(
                WebErrorCode.RESULT_READ_FAILURE,
                session_id=session_id,
                detail=str(exc),
            )

        # Extract the intelligence layer from the report.
        details = raw.get("details", {})
        intelligence = details.get("intelligence", {})

        executive = intelligence.get("executive_assessment", {})
        snapshot = intelligence.get("framework_snapshot", {})

        response_payload = {
            "session_id": session_id,
            "generated_at": details.get(
                "generated_at", snapshot.get("generated_at", "")
            ),
            "views": [
                "EXECUTIVE_SUMMARY",
                "RISK_PRIORITY",
                "ATTACK_CHAINS",
                "CORRELATIONS",
                "KNOWLEDGE_GRAPH",
                "MITRE_MATRIX",
                "EVIDENCE_EXPLORER",
            ],
            "executive_assessment": executive,
            "framework_snapshot": snapshot,
            "risk_assessments": details.get(
                "risk_assessments", snapshot.get("risk_assessments", [])
            ),
            "attack_chains": details.get(
                "attack_chains", snapshot.get("attack_chains", [])
            ),
            "correlations": details.get(
                "correlations", snapshot.get("correlations", [])
            ),
            "relationships": details.get("relationships", []),
            "resolved_entities": details.get("resolved_entities", []),
            "entities": details.get("entities", []),
            "findings": details.get("findings", []),
            "explain_order": [
                "ExecutiveAssessment",
                "RiskAssessment",
                "AttackChain",
                "Correlation",
                "Relationship",
                "ResolvedEntity",
                "Entity",
                "Finding",
            ],
        }

        return jsonify(response_payload), 200

    # -- Download route ------------------------------------------------------

    @app.route("/api/download/<session_id>/<filename>", methods=["GET"])
    def api_download(session_id: str, filename: str):
        """Download a report artifact for a completed session.

        Args:
            session_id: UUID of the completed session.
            filename:   Basename of the file to download (e.g. the report JSON).

        Returns 200 with the file as an attachment, or an error response.
        """
        record = session_manager.get(session_id)

        if record.state != SessionState.COMPLETE:
            return error_response(
                WebErrorCode.SESSION_NOT_COMPLETE,
                session_id=session_id,
            )

        # Validate filename to prevent path traversal.
        safe_name = Path(filename).name
        if safe_name != filename or ".." in filename or "/" in filename:
            return error_response(WebErrorCode.PATH_TRAVERSAL_BLOCKED)

        requested = record.reports_dir / safe_name
        # Confirm the resolved path is still inside the session's reports dir.
        try:
            requested.resolve().relative_to(record.reports_dir.resolve())
        except ValueError:
            return error_response(WebErrorCode.PATH_TRAVERSAL_BLOCKED)

        if not requested.is_file():
            return error_response(
                WebErrorCode.FILE_NOT_FOUND,
                detail=f"'{safe_name}' not found in session reports.",
            )

        return send_file(str(requested), as_attachment=True, download_name=safe_name)

    # -- Session lifecycle ---------------------------------------------------

    @app.route("/api/session/<session_id>", methods=["DELETE"])
    def api_delete_session(session_id: str):
        """Delete a session and all its files from disk.

        Response 200::

            {"session_id": "uuid", "message": "Session deleted."}
        """
        session_manager.delete(session_id)
        return jsonify({"session_id": session_id, "message": "Session deleted."}), 200

    # -- Register teardown ---------------------------------------------------

    @app.teardown_appcontext
    def _teardown(exc: BaseException | None) -> None:
        # Nothing to teardown per-request; runner shuts down with the process.
        pass

    return app


__all__ = ["create_app"]
