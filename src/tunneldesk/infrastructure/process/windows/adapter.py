"""Adapter Windows (E-2, keputusan A-07).

- Launch: ``subprocess.Popen`` tanpa shell, ``CREATE_NEW_PROCESS_GROUP``
  agar sinyal ``CTRL_BREAK`` dapat dikirim ke grup.
- **Job Object (A-07)**: setiap proses hasil launch di-assign ke Job Object
  dengan flag ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` — bila aplikasi mati/
  crash, handle job tertutup oleh OS dan proses (beserta child) ikut
  dihentikan (anti orphan). Hanya proses hasil launch milik TunnelDesk
  yang di-assign; tidak ada adopsi proses eksternal (D-18, K-07).
- Graceful: ``CTRL_BREAK_EVENT``; force: ``TerminateProcess``.
- Impor pywin32 dilakukan secara lazy — modul ini hanya dieksekusi di
  Windows (dependensi bermarker ``sys_platform == 'win32'``).

**Tidak ada** dukungan Windows Service di modul ini (K-07).
"""

from __future__ import annotations

import signal
import subprocess
import sys

from tunneldesk.domain.tunnel.process_contracts import (
    LaunchedProcess,
    ProcessLauncher,
    ProcessSpec,
)
from tunneldesk.infrastructure.process.base import BaseProcessSession

__all__ = ["WindowsProcessSession", "WindowsProcessLauncher"]


class WindowsProcessSession(BaseProcessSession):
    """Session proses Windows milik TunnelDesk, terkurung Job Object."""

    def __init__(self, process: subprocess.Popen[bytes], job_handle: object) -> None:
        super().__init__(process)
        # Handle Job Object sengaja disimpan terbuka: KILL_ON_JOB_CLOSE
        # menghentikan proses bila aplikasi mati tanpa cleanup (A-07).
        self._job_handle = job_handle

    def _send_graceful_signal(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("adapter Windows hanya berjalan di Windows")
        # CTRL_BREAK dikirim ke process group (cloudflared menangani
        # graceful shutdown pada sinyal ini).
        self._process.send_signal(signal.CTRL_BREAK_EVENT)

    def _force_kill(self) -> None:
        self._process.kill()


class WindowsProcessLauncher(ProcessLauncher):
    """Launcher Windows — menghasilkan session terkurung Job Object."""

    def launch(self, spec: ProcessSpec) -> LaunchedProcess:
        if sys.platform != "win32":
            raise RuntimeError("adapter Windows hanya berjalan di Windows")
        process = subprocess.Popen(  # noqa: S603 — argumen list, tanpa shell
            list(spec.argv),
            cwd=spec.cwd,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        job_handle = _assign_to_job_object(process)
        return WindowsProcessSession(process, job_handle)


def _assign_to_job_object(process: subprocess.Popen[bytes]) -> object:
    """Assign proses ke Job Object kill-on-close (A-07).

    Gagal assign dianggap fatal untuk launch: menjalankan cloudflared
    tanpa containment melanggar batas kepemilikan proses.
    """
    # Impor lazy: modul hanya dieksekusi di Windows.
    import win32api  # type: ignore[import-untyped]
    import win32con  # type: ignore[import-untyped]
    import win32job  # type: ignore[import-untyped]

    job = win32job.CreateJobObject(None, "")
    extended = win32job.QueryInformationJobObject(
        job, win32job.JobObjectExtendedLimitInformation
    )
    extended["BasicLimitInformation"]["LimitFlags"] |= (
        win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    win32job.SetInformationJobObject(
        job, win32job.JobObjectExtendedLimitInformation, extended
    )
    process_handle = win32api.OpenProcess(
        win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE,
        False,
        process.pid,
    )
    try:
        win32job.AssignProcessToJobObject(job, process_handle)
    finally:
        win32api.CloseHandle(process_handle)
    return job
