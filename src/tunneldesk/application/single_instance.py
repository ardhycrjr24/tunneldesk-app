"""Single-instance lock (A-13) — satu instance aplikasi aktif.

Mekanisme: file lock di direktori data aplikasi berisi JSON
(pid, hostname, token akuisisi, timestamp). Aturan:

- Lock aktif: file ada, payload valid, hostname sama, **dan** proses
  pemilik masih hidup → :class:`InstanceAlreadyRunningError`.
- Stale lock (recovery): file korup, hostname berbeda, atau pemilik
  **terverifikasi mati** → dihapus dan diakuisisi ulang.
- **Tidak pernah** menganggap lock basi hanya karena file ditemukan;
  identitas & status proses pemilik selalu divalidasi.
- Lock milik instance lain yang masih hidup tidak pernah dihapus.
- Token acak per akuisisi menjamin hanya pemegang token yang dapat
  me-release.

Keterbatasan yang diakui (tercatat di laporan E-3): pemakaian-ulang PID
oleh proses lain setelah pemilik mati tidak dapat dibedakan tanpa
API platform tambahan — risikonya dimitigasi oleh penempatan file di
direktori data privat aplikasi + validasi alive per akses.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
import uuid
from pathlib import Path

__all__ = [
    "InstanceLock",
    "InstanceAlreadyRunningError",
    "LOCK_FORMAT_VERSION",
]

LOCK_FORMAT_VERSION = 1
_LOCK_APP_MARKER = "tunneldesk-instance-lock"


class InstanceAlreadyRunningError(RuntimeError):
    """Dilempar saat akuisisi ditolak karena instance lain masih hidup."""

    def __init__(self, pid: int, lock_path: Path) -> None:
        self.pid = pid
        self.lock_path = lock_path
        super().__init__(
            f"TunnelDesk sudah berjalan (pid {pid}) — lock: {lock_path.name}"
        )


class InstanceLock:
    """Lock file single-instance dengan validasi & stale recovery (A-13)."""

    def __init__(
        self,
        lock_path: Path,
        hostname: str | None = None,
        alive_checker: object = None,
    ) -> None:
        self._path = Path(lock_path)
        self._hostname = hostname or socket.gethostname()
        self._token: str | None = None
        self._acquired = False
        # alive_checker: callable(pid)->bool untuk injeksi pada uji;
        # default = pemeriksa platform nyata.
        self._alive_checker = alive_checker or _default_process_alive

    # ------------------------------------------------------------------
    # Akuisisi / pelepasan
    # ------------------------------------------------------------------
    def acquire(self) -> None:
        """Akuisisi lock; naikkan :class:`InstanceAlreadyRunningError`
        bila instance lain masih hidup (dengan validasi identitas)."""
        if self._acquired:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = self._read_payload()
        if payload is not None:
            if self._is_actively_held(payload):
                pid_value = payload.get("pid", -1)
                pid = pid_value if isinstance(pid_value, int) else -1
                raise InstanceAlreadyRunningError(pid, self._path)
            # stale: korup / mesin berbeda / pemilik terverifikasi mati
            self._remove_stale()
        token = uuid.uuid4().hex
        record = {
            "version": LOCK_FORMAT_VERSION,
            "app": _LOCK_APP_MARKER,
            "pid": os.getpid(),
            "hostname": self._hostname,
            "token": token,
            "created_at_epoch": round(time.time(), 3),
        }
        self._path.write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        self._token = token
        self._acquired = True

    def release(self) -> None:
        """Lepaskan lock — hanya bila kita pemegang token aktif.
        Lock milik instance lain yang hidup tidak pernah dihapus (A-13)."""
        if not self._acquired or self._token is None:
            return
        payload = self._read_payload()
        if payload is not None and payload.get("token") == self._token:
            self._path.unlink(missing_ok=True)
        self._token = None
        self._acquired = False

    def is_acquired(self) -> bool:
        return self._acquired

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _read_payload(self) -> dict[str, object] | None:
        """Baca payload lock; None bila tidak ada / korup / bukan milik app."""
        if not self._path.exists():
            return None
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None  # korup → kandidat stale
        if not isinstance(payload, dict):
            return None
        if payload.get("app") != _LOCK_APP_MARKER:
            return None
        if payload.get("version") != LOCK_FORMAT_VERSION:
            return None
        if not isinstance(payload.get("pid"), int):
            return None
        return payload

    def _is_actively_held(self, payload: dict[str, object]) -> bool:
        """Validasi identitas & status pemilik lock (A-13):
        hostname harus sama dan proses pemilik harus masih hidup."""
        if payload.get("hostname") != self._hostname:
            # lock dari mesin berbeda (mis. direktori bersama) — tidak bisa
            # divalidasi hidup/matinya; perlakukan sebagai kandidat stale.
            return False
        pid = payload.get("pid")
        if not isinstance(pid, int):
            return False
        return bool(self._alive_checker(pid))  # type: ignore[operator]

    def _remove_stale(self) -> None:
        self._path.unlink(missing_ok=True)


def _default_process_alive(pid: int) -> bool:
    """Cek hidup/matinya pid lintas platform tanpa dependensi baru."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        return _windows_process_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # proses ada, milik pengguna lain
    return True


def _windows_process_alive(pid: int) -> bool:
    """Cek hidup/matinya pid di Windows via pywin32 (lazy import)."""
    import win32api  # type: ignore[import-untyped]
    import win32con  # type: ignore[import-untyped]
    import win32event  # type: ignore[import-untyped]

    handle = win32api.OpenProcess(
        win32con.SYNCHRONIZE | win32con.PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid,
    )
    if handle == 0:
        return False
    try:
        # WAIT_TIMEOUT berarti proses masih hidup (belum signaled).
        return win32event.WaitForSingleObject(handle, 0) == win32event.WAIT_TIMEOUT
    finally:
        win32api.CloseHandle(handle)
