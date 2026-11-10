"""Konfigurasi pytest global.

Qt berjalan headless (offscreen) sebelum PySide6 diimpor — wajib untuk
CI tanpa display.
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
