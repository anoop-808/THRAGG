#!/usr/bin/env python3
"""
run_web.py
==========

THRAGG Local Web Interface — entry point.

Usage::

    python run_web.py

The server binds to 127.0.0.1:5000 (localhost only) and is accessible at:

    http://localhost:5000

Workflow:
  1. Open http://localhost:5000 in your browser.
  2. Upload evidence files (.log, .xml, .json, .html, .txt).
  3. Click "Start Analysis".
  4. Watch live progress via the status panel.
  5. The dashboard opens automatically when analysis completes.

Constraints:
  - This server is for local offline use only.
  - Do NOT expose this port to a network.
  - All data remains on your local filesystem.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on sys.path so that `thragg` is importable.
_PROJECT_ROOT = Path(__file__).parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from web.app import create_app
from web.config import DEBUG, SERVER_HOST, SERVER_PORT


def main() -> None:
    app = create_app()

    print("=" * 60)
    print("  THRAGG Local Web Interface")
    print("=" * 60)
    print(f"  URL:     http://{SERVER_HOST}:{SERVER_PORT}")
    print(f"  Workers: 2 concurrent analyses")
    print(f"  Offline: Yes — no internet required")
    print("=" * 60)
    print("  Press Ctrl+C to stop the server.")
    print()

    app.run(
        host=SERVER_HOST,
        port=SERVER_PORT,
        debug=DEBUG,
        use_reloader=False,   # Reloader would duplicate the ThreadPoolExecutor.
        threaded=True,        # Handle multiple browser requests in parallel.
    )


if __name__ == "__main__":
    main()
