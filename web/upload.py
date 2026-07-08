"""
web.upload
==========

Upload validation and file storage.

UploadManager is the single authority for everything that happens between
the browser sending files and those files being placed on disk.

Two-pass validation:
  1. validate(files)  — inspect file list before any I/O
  2. save(session_id, files, upload_dir) — write to disk after validation

Both methods raise WebError on any violation. The Flask route calls them
in sequence and never reaches THRAGGOrchestrator if validation fails.

This ensures that unsupported or oversized files are rejected before the
engine ever sees them, satisfying the Q3 upload limits decision.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from werkzeug.datastructures import FileStorage

from .config import ALLOWED_EXTENSIONS, MAX_FILE_SIZE_BYTES, MAX_TOTAL_SIZE_BYTES
from .errors import WebError, WebErrorCode

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Upload Manager
# ---------------------------------------------------------------------------

class UploadManager:
    """Validate and persist uploaded evidence files.

    All public methods are stateless — the manager holds no mutable state.
    It can be safely used from multiple threads simultaneously.
    """

    # -- Public API ----------------------------------------------------------

    def validate(self, files: list[FileStorage]) -> None:
        """Validate *files* before any disk I/O.

        Args:
            files: List of werkzeug FileStorage objects from the request.

        Raises:
            WebError(NO_FILES):              If *files* is empty.
            WebError(UNSUPPORTED_FILE_TYPE): If any file has a banned extension.
            WebError(FILE_TOO_LARGE):        If any file exceeds MAX_FILE_SIZE_BYTES.
            WebError(TOTAL_SIZE_EXCEEDED):   If the combined size exceeds
                                             MAX_TOTAL_SIZE_BYTES.
        """
        if not files:
            raise WebError(WebErrorCode.NO_FILES)

        total_bytes = 0

        for fs in files:
            # --- Extension check ---
            name = (fs.filename or "").strip()
            ext = Path(name).suffix.lower()
            if ext not in ALLOWED_EXTENSIONS:
                raise WebError(
                    WebErrorCode.UNSUPPORTED_FILE_TYPE,
                    detail=(
                        f"'{name}' has extension '{ext}' which is not in the "
                        f"allowed set: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
                    ),
                )

            # --- Per-file size check ---
            # Seek to end to measure without loading the whole file into RAM.
            fs.stream.seek(0, 2)
            file_size = fs.stream.tell()
            fs.stream.seek(0)

            if file_size > MAX_FILE_SIZE_BYTES:
                raise WebError(
                    WebErrorCode.FILE_TOO_LARGE,
                    detail=(
                        f"'{name}' is {file_size:,} bytes, "
                        f"exceeding the {MAX_FILE_SIZE_BYTES:,} byte limit."
                    ),
                )

            total_bytes += file_size

        # --- Total size check ---
        if total_bytes > MAX_TOTAL_SIZE_BYTES:
            raise WebError(
                WebErrorCode.TOTAL_SIZE_EXCEEDED,
                detail=(
                    f"Combined upload is {total_bytes:,} bytes, "
                    f"exceeding the {MAX_TOTAL_SIZE_BYTES:,} byte session limit."
                ),
            )

    def save(
        self,
        files: list[FileStorage],
        upload_dir: Path,
    ) -> list[dict[str, object]]:
        """Write *files* to *upload_dir* and return file metadata.

        Args:
            files:      Validated FileStorage list from validate().
            upload_dir: Absolute path to this session's upload subdirectory.

        Returns:
            List of dicts with keys: name, size, extension — one per file.

        Raises:
            WebError(UPLOAD_STORAGE_FAILURE): If any file cannot be written.
        """
        upload_dir.mkdir(parents=True, exist_ok=True)
        metadata: list[dict[str, object]] = []

        for fs in files:
            name = _safe_filename(fs.filename or "unnamed")
            dest = upload_dir / name

            # Disambiguate duplicates by appending a counter.
            if dest.exists():
                stem = dest.stem
                suffix = dest.suffix
                counter = 1
                while dest.exists():
                    dest = upload_dir / f"{stem}_{counter}{suffix}"
                    counter += 1

            try:
                fs.stream.seek(0)
                dest.write_bytes(fs.stream.read())
            except OSError as exc:
                raise WebError(
                    WebErrorCode.UPLOAD_STORAGE_FAILURE,
                    detail=f"Could not write '{dest.name}': {exc}",
                ) from exc

            metadata.append(
                {
                    "name": dest.name,
                    "size": dest.stat().st_size,
                    "extension": dest.suffix.lower(),
                }
            )

        return metadata


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_filename(filename: str) -> str:
    """Sanitize *filename* for safe filesystem storage.

    Strips path components and replaces whitespace/unsafe characters.
    Werkzeug's secure_filename is used as the underlying primitive.
    """
    from werkzeug.utils import secure_filename

    safe = secure_filename(filename)
    # secure_filename returns '' for names that are all unsafe chars
    if not safe:
        safe = "evidence_file"
    return safe


__all__ = ["UploadManager"]
