"""
core.reporting.exporters.json_exporter
=======================================
Writes JSON renderer output to a .json file.
"""

from __future__ import annotations

import os

from ...shared.errors import ExportError


class JSONExporter:

    def export(self, rendered_content: str, output_path: str) -> str:
        try:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(rendered_content)
            return os.path.abspath(output_path)
        except OSError as exc:
            raise ExportError(str(exc)) from exc
