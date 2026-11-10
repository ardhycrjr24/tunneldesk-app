"""Uji adapter Windows nyata (E-2, A-07) — berjalan otomatis di CI
windows-latest dan saat uji Windows fisik. Skip di non-Windows.

Menggunakan proses python kecil sebagai stand-in (bukan cloudflared).
"""

from __future__ import annotations

import sys

import pytest

from tunneldesk.domain.tunnel.process_contracts import ProcessSpec
from tunneldesk.infrastructure.process.windows.adapter import (
    WindowsProcessLauncher,
    _assign_to_job_object,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="adapter Windows — jalankan di Windows"
)

SLEEP_SCRIPT = "import time; print('siap', flush=True); time.sleep(30)"
EXIT_SCRIPT = "import sys; sys.exit(int(sys.argv[1]))"


def test_launch_dan_pid() -> None:
    launcher = WindowsProcessLauncher()
    process = launcher.launch(
        ProcessSpec.from_sequence([sys.executable, "-c", SLEEP_SCRIPT])
    )
    try:
        assert process.pid() > 0
        assert process.poll() is None
    finally:
        process.force_kill()


def test_job_object_terpasang_dan_kill_on_close_aktif() -> None:
    """A-07: proses hasil launch wajib ter-assign ke Job Object."""
    launcher = WindowsProcessLauncher()
    process = launcher.launch(
        ProcessSpec.from_sequence([sys.executable, "-c", SLEEP_SCRIPT])
    )
    try:
        # assign ulang tidak dibutuhkan; verifikasi via QueryInformation
        # bahwa session menyimpan handle job yang bisa di-query.
        job = process._job_handle  # noqa: SLF001 — akses uji terkendali
        assert job is not None
        import win32job  # type: ignore[import-untyped]

        extended = win32job.QueryInformationJobObject(
            job, win32job.JobObjectExtendedLimitInformation
        )
        limit_flags = extended["BasicLimitInformation"]["LimitFlags"]
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        assert limit_flags & 0x00002000
    finally:
        process.force_kill()


def test_graceful_ctrl_break_dan_force() -> None:
    launcher = WindowsProcessLauncher()
    process = launcher.launch(
        ProcessSpec.from_sequence([sys.executable, "-c", SLEEP_SCRIPT])
    )
    try:
        process.graceful_stop()
        code = process.wait(5.0)
        if code is None:  # beberapa skenario mengabaikan CTRL_BREAK
            process.force_kill()
            code = process.wait(5.0)
        assert code is not None
    finally:
        process.force_kill()


def test_exit_code_ditangkap() -> None:
    launcher = WindowsProcessLauncher()
    process = launcher.launch(
        ProcessSpec.from_sequence([sys.executable, "-c", EXIT_SCRIPT, "9"])
    )
    assert process.wait(5.0) == 9


def test_assign_menolak_pid_tidak_valid() -> None:
    """pid tak valid → OpenProcess gagal → error (bukan dibungkam)."""
    with pytest.raises(OSError):
        _assign_to_job_object(type("FakePopen", (), {"pid": 4294967295})())
