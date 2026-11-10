"""Uji adapter POSIX nyata (E-2) — bukan cloudflared, melainkan proses
python kecil sebagai stand-in lifecycle (A-14: uji otomatis tanpa
cloudflared sungguhan). Skip di platform non-POSIX.
"""

from __future__ import annotations

import sys

import pytest

from tunneldesk.domain.tunnel.process_contracts import ProcessSpec
from tunneldesk.infrastructure.process.posix.adapter import PosixProcessLauncher

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="adapter POSIX — jalankan di macOS/Linux"
)

SLEEP_SCRIPT = "import time; print('siap', flush=True); time.sleep(30)"
EXIT_SCRIPT = "import sys; sys.exit(int(sys.argv[1]))"


def test_launch_dan_pid_terdaftar() -> None:
    launcher = PosixProcessLauncher()
    process = launcher.launch(ProcessSpec.from_sequence([sys.executable, "-c", SLEEP_SCRIPT]))
    try:
        assert process.pid() > 0
        assert process.poll() is None
    finally:
        process.force_kill()


def test_graceful_stop_menghentikan_proses() -> None:
    launcher = PosixProcessLauncher()
    process = launcher.launch(
        ProcessSpec.from_sequence([sys.executable, "-c", SLEEP_SCRIPT])
    )
    try:
        process.graceful_stop()
        code = process.wait(5.0)
        assert code is not None
    finally:
        process.force_kill()


def test_force_kill_menghentikan_proses_hung() -> None:
    launcher = PosixProcessLauncher()
    process = launcher.launch(
        ProcessSpec.from_sequence(
            [
                sys.executable,
                "-c",
                "import signal, time;\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN);\n"
                "print('siap', flush=True);\n"
                "time.sleep(60)",
            ]
        )
    )
    try:
        assert process.wait(2.0) is None  # tetap hidup walau diberi waktu
        process.graceful_stop()
        assert process.wait(1.0) is None  # SIGTERM diabaikan
        process.force_kill()
        assert process.wait(5.0) is not None  # SIGKILL efektif
    finally:
        process.force_kill()


def test_exit_code_ditangkap() -> None:
    launcher = PosixProcessLauncher()
    process = launcher.launch(
        ProcessSpec.from_sequence([sys.executable, "-c", EXIT_SCRIPT, "7"])
    )
    code = process.wait(5.0)
    assert code == 7


def test_output_teredaksi_dan_tersedia() -> None:
    launcher = PosixProcessLauncher()
    process = launcher.launch(
        ProcessSpec.from_sequence(
            [
                sys.executable,
                "-c",
                "print('Authorization: Bearer dummy123.dummy456.dummy789', flush=True)",
            ]
        )
    )
    process.wait(5.0)
    lines = process.output_lines()
    assert any("Authorization:" in line for line in lines)
    assert all("dummy123" not in line for line in lines)  # nilai tersaring


def test_redacted_repr_menyembunyikan_token() -> None:
    spec = ProcessSpec.from_sequence(
        ["cloudflared", "tunnel", "run", "--token", "RAHASIA_TOKEN_000000000"]
    )
    teks = spec.redacted_repr()
    assert "RAHASIA_TOKEN_000000000" not in teks
    assert "--token" in teks
