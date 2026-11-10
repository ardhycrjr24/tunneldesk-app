"""Worker thread untuk operasi blocking (PRD-01 §11 — UI tetap responsif).

Start/stop/restart/probe origin dijalankan di thread; hasil dikirim ke
UI thread via Qt signal (queued connection otomatis lintas thread).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, Signal

__all__ = ["FunctionWorker"]


class FunctionWorker(QObject):
    """Jalankan fungsi di thread worker; hasil/kegagalan via signal.

    Satu worker = satu operasi. Sinyal ``failed`` membawa pesan yang
    sudah disanitasi oleh controller (D-18).
    """

    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, function: Callable[[], Any], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._function = function
        self._thread: threading.Thread | None = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running():
            return  # anti eksekusi ganda
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="tunneldesk-ui-worker"
        )
        self._thread.start()

    def _run(self) -> None:
        try:
            result = self._function()
        except Exception as exc:  # noqa: BLE001 — pesan sudah disanitasi controller
            self.failed.emit(str(exc))
            return
        self.finished.emit(result)
