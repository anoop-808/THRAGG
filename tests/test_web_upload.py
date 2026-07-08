"""
tests/test_web_upload.py
========================

Unit tests for the web.upload module.

Tests cover:
  - Extension validation (allowed / rejected)
  - Per-file size limit enforcement
  - Total session size limit enforcement
  - Safe filename sanitization
  - Duplicate filename disambiguation
  - Successful save with correct metadata
  - Empty file list rejection
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from werkzeug.datastructures import FileStorage

from web.upload import UploadManager
from web.errors import WebErrorCode, WebError
from web.config import MAX_FILE_SIZE_BYTES, MAX_TOTAL_SIZE_BYTES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_file(name: str, content: bytes | None = None) -> FileStorage:
    """Create a minimal FileStorage for testing."""
    data = content if content is not None else b"test content"
    return FileStorage(stream=io.BytesIO(data), filename=name)


def make_file_of_size(name: str, size: int) -> FileStorage:
    """Create a FileStorage with exactly *size* bytes of content."""
    return make_file(name, b"x" * size)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def manager() -> UploadManager:
    return UploadManager()


# ---------------------------------------------------------------------------
# Extension validation
# ---------------------------------------------------------------------------

class TestExtensionValidation:
    @pytest.mark.parametrize("filename", [
        "auth.log", "scan.xml", "export.json", "report.html", "notes.txt",
        "AUTH.LOG", "SCAN.XML",  # case-insensitive
    ])
    def test_allowed_extensions_pass(self, manager: UploadManager, filename: str):
        files = [make_file(filename)]
        # Should not raise
        manager.validate(files)

    @pytest.mark.parametrize("filename", [
        "malware.exe", "script.py", "archive.zip", "config.yaml",
        "spreadsheet.csv", "image.png", "binary.bin",
    ])
    def test_rejected_extensions_raise(self, manager: UploadManager, filename: str):
        files = [make_file(filename)]
        with pytest.raises(WebError) as exc_info:
            manager.validate(files)
        assert exc_info.value.code == WebErrorCode.UNSUPPORTED_FILE_TYPE

    def test_no_extension_is_rejected(self, manager: UploadManager):
        files = [make_file("no_extension")]
        with pytest.raises(WebError) as exc_info:
            manager.validate(files)
        assert exc_info.value.code == WebErrorCode.UNSUPPORTED_FILE_TYPE


# ---------------------------------------------------------------------------
# Empty file list
# ---------------------------------------------------------------------------

class TestEmptyFileList:
    def test_empty_list_raises_no_files(self, manager: UploadManager):
        with pytest.raises(WebError) as exc_info:
            manager.validate([])
        assert exc_info.value.code == WebErrorCode.NO_FILES


# ---------------------------------------------------------------------------
# Per-file size limit
# ---------------------------------------------------------------------------

class TestPerFileSizeLimit:
    def test_file_at_limit_passes(self, manager: UploadManager):
        files = [make_file_of_size("scan.xml", MAX_FILE_SIZE_BYTES)]
        manager.validate(files)  # Should not raise

    def test_file_one_byte_over_limit_raises(self, manager: UploadManager):
        files = [make_file_of_size("scan.xml", MAX_FILE_SIZE_BYTES + 1)]
        with pytest.raises(WebError) as exc_info:
            manager.validate(files)
        assert exc_info.value.code == WebErrorCode.FILE_TOO_LARGE

    def test_detail_contains_filename(self, manager: UploadManager):
        files = [make_file_of_size("giant.log", MAX_FILE_SIZE_BYTES + 1)]
        with pytest.raises(WebError) as exc_info:
            manager.validate(files)
        assert "giant.log" in (exc_info.value.detail or "")


# ---------------------------------------------------------------------------
# Total size limit
# ---------------------------------------------------------------------------

class TestTotalSizeLimit:
    def test_total_at_limit_passes(self, manager: UploadManager):
        # Five files of exactly 10 MB each = 50 MB total (at the limit).
        files = [
            make_file_of_size(f"file{i}.log", MAX_FILE_SIZE_BYTES)
            for i in range(5)
        ]
        manager.validate(files)  # Should not raise

    def test_total_over_limit_raises(self, manager: UploadManager):
        # Six files of 9 MB each = 54 MB total — each within the per-file limit
        # but combined they exceed the 50 MB session limit.
        chunk = 9 * 1024 * 1024  # 9 MB — within per-file limit
        files = [make_file_of_size(f"file{i}.log", chunk) for i in range(6)]
        with pytest.raises(WebError) as exc_info:
            manager.validate(files)
        assert exc_info.value.code == WebErrorCode.TOTAL_SIZE_EXCEEDED


# ---------------------------------------------------------------------------
# Save to disk
# ---------------------------------------------------------------------------

class TestSaveToDisk:
    def test_save_creates_files_on_disk(
        self, manager: UploadManager, tmp_path: Path
    ):
        files = [make_file("auth.log", b"hello world")]
        metadata = manager.save(files, tmp_path)
        assert (tmp_path / "auth.log").exists()
        assert metadata[0]["name"] == "auth.log"

    def test_save_returns_correct_metadata(
        self, manager: UploadManager, tmp_path: Path
    ):
        content = b"test content here"
        files = [make_file("scan.xml", content)]
        metadata = manager.save(files, tmp_path)
        assert len(metadata) == 1
        assert metadata[0]["size"] == len(content)
        assert metadata[0]["extension"] == ".xml"

    def test_save_multiple_files(
        self, manager: UploadManager, tmp_path: Path
    ):
        files = [
            make_file("auth.log", b"log data"),
            make_file("export.json", b'{"key":"value"}'),
        ]
        metadata = manager.save(files, tmp_path)
        assert len(metadata) == 2
        assert (tmp_path / "auth.log").exists()
        assert (tmp_path / "export.json").exists()

    def test_saves_exact_content(
        self, manager: UploadManager, tmp_path: Path
    ):
        content = b"specific binary content 12345"
        files = [make_file("evidence.txt", content)]
        manager.save(files, tmp_path)
        assert (tmp_path / "evidence.txt").read_bytes() == content

    def test_duplicate_filename_is_disambiguated(
        self, manager: UploadManager, tmp_path: Path
    ):
        # Pre-create the target file to force disambiguation.
        (tmp_path / "auth.log").write_bytes(b"existing")
        files = [make_file("auth.log", b"new content")]
        metadata = manager.save(files, tmp_path)
        # The saved file should have a different name.
        assert metadata[0]["name"] != "auth.log"
        saved_path = tmp_path / metadata[0]["name"]
        assert saved_path.exists()
        assert saved_path.read_bytes() == b"new content"

    def test_upload_dir_created_if_missing(
        self, manager: UploadManager, tmp_path: Path
    ):
        target = tmp_path / "new_session" / "uploads"
        files = [make_file("auth.log", b"data")]
        manager.save(files, target)
        assert target.exists()


# ---------------------------------------------------------------------------
# Filename sanitization
# ---------------------------------------------------------------------------

class TestFilenameSanitization:
    def test_path_traversal_in_name_is_sanitized(
        self, manager: UploadManager, tmp_path: Path
    ):
        # werkzeug's secure_filename should strip the path component.
        fs = FileStorage(
            stream=io.BytesIO(b"data"),
            filename="../../etc/passwd.txt",
        )
        metadata = manager.save([fs], tmp_path)
        saved = tmp_path / metadata[0]["name"]
        assert saved.exists()
        # Should NOT be outside tmp_path.
        assert saved.resolve().parent == tmp_path.resolve()
