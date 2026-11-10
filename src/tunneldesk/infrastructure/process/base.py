"""Fondasi bersama session proses (E-2) — dipakai adapter POSIX & Windows.

Menangani: idempotensi stop (anti double termination), cache exit code,
thread pembaca keluaran (anti deadlock pipe) dengan buffer terbatas.
Logika platform (sinyal graceful, force kill) dititipkan ke subclass.
"""

from __future__ import annotations

import subprocess
import threading
from collections import deque

from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.domain.tunnel.process_contracts import LaunchedProcess

_OUTPUT_BUFFER_LINES = 1000


class BaseProcessSession(LaunchedProcess):
    """Session proses yang dilahirkan TunnelDesk — milik aplikasi.

    Subclass wajib mengimplementasikan ``_send_graceful_signal`` dan
    ``_force_kill``. Kelas ini tidak pernah menyentuh proses yang bukan
    hasil launch-nya sendiri (D-18, K-07).
    """

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self._lock = threading.Lock()
        self._stop_requested = False
        self._forced = False
        self._exit_code: int | None = process.poll()
        self._output: deque[str] = deque(maxlen=_OUTPUT_BUFFER_LINES)
        self._redaction = RedactionEngine()
        self._reader: threading.Thread | None = None
        if self._exit_code is None and process.stdout is not None:
            self._reader = threading.Thread(
                target=self._drain_output, daemon=True, name="tunneldesk-log-reader"
            )
            self._reader.start()

    # ------------------------------------------------------------------
    # Kontrak LaunchedProcess
    # ------------------------------------------------------------------
    def pid(self) -> int:
        return self._process.pid

    def poll(self) -> int | None:
        with self._lock:
            if self._exit_code is not None:
                return self._exit_code
            code = self._process.poll()
            if code is not None:
                self._exit_code = code
            return code

    def graceful_stop(self) -> None:
        with self._lock:
            if self._stop_requested:
                return  # anti double termination
            self._stop_requested = True
        try:
            self._send_graceful_signal()
        except (ProcessLookupError, OSError):
            # proses sudah mati di antara cek dan sinyal
            pass

    def force_kill(self) -> None:
        with self._lock:
            self._forced = True
        try:
            self._force_kill()
        except (ProcessLookupError, OSError):
            pass

    def wait(self, timeout_seconds: float) -> int | None:
        try:
            code = self._process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            return None
        with self._lock:
            self._exit_code = code
        return code

    def output_lines(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._output)

    # ------------------------------------------------------------------
    # Hook platform
    # ------------------------------------------------------------------
    def _send_graceful_signal(self) -> None:
        raise NotImplementedError

    def _force_kill(self) -> None:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _drain_output(self) -> None:
        """Baca pipe keluaran agar tidak penuh (anti deadlock), simpan
        salinan teredaksi terbatas untuk diagnostik (A-12)."""
        stream = self._process.stdout
        if stream is None:  # pragma: no cover
            return
        for raw_line in iter(stream.readline, b""):
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            with self._lock:
                self._output.append(self._redaction.redact(line))
