"""
core.reporting.exporters.markdown_exporter
==========================================
Writes Markdown renderer output to a .md file.
Never accesses ExecutiveAssessment or Report directly.
Consumes only the rendered string from MarkdownRenderer.
"""

from __future__ import annotations

import os

from ...shared.errors import ExportError


class MarkdownExporter:

    def export(self, rendered_content: str, output_path: str) -> str:
        """Write rendered string to file. Returns the resolved path."""
        try:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(rendered_content)
            return os.path.abspath(output_path)
        except OSError as exc:
            raise ExportError(str(exc)) from exc
