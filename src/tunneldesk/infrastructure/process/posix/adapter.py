"""Adapter POSIX (macOS/Linux) — E-2.

- Launch: ``subprocess.Popen`` tanpa shell (argumen list terstruktur,
  D-18), ``start_new_session=True`` → proses punya session/group sendiri
  sehingga force kill menyasar seluruh grup (anti orphan child).
- Graceful: ``SIGTERM``; force: ``SIGKILL`` ke grup proses.
- Hanya proses hasil launch milik TunnelDesk yang disentuh (D-18, K-07).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys

from tunneldesk.domain.tunnel.process_contracts import (
    LaunchedProcess,
    ProcessLauncher,
    ProcessSpec,
)
from tunneldesk.infrastructure.process.base import BaseProcessSession

__all__ = ["PosixProcessSession", "PosixProcessLauncher"]


class PosixProcessSession(BaseProcessSession):
    """Session proses POSIX milik TunnelDesk."""

    def _send_graceful_signal(self) -> None:
        # SIGTERM ke proses; cloudflared menangani graceful shutdown.
        self._process.send_signal(signal.SIGTERM)

    def _force_kill(self) -> None:
        if sys.platform == "win32":
            raise RuntimeError("adapter POSIX hanya berjalan di POSIX")
        # SIGKILL ke seluruh process group agar child ikut mati (anti orphan).
        try:
            group_id = os.getpgid(self._process.pid)
        except ProcessLookupError:
            return
        if group_id == os.getpgrp():
            # pengaman: jangan pernah membunuh group milik shell aplikasi
            self._process.kill()
            return
        try:
            os.killpg(group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass


class PosixProcessLauncher(ProcessLauncher):
    """Launcher POSIX — menghasilkan session yang dimiliki aplikasi."""

    def launch(self, spec: ProcessSpec) -> LaunchedProcess:
        process = subprocess.Popen(  # noqa: S603 — argumen list, tanpa shell
            list(spec.argv),
            cwd=spec.cwd,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        return PosixProcessSession(process)
