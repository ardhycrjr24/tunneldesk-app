"""Probe status service cloudflared (E-5) — hanya-baca (K-07).

- Windows: ``sc query cloudflared`` melalui **port ProcessLauncher E-2**
  (argumen list, tanpa shell); output diparse untuk status RUNNING.
- POSIX: systemd bukan target MVP Windows — dikembalikan None (tidak
  diketahui) dengan jujur.

Kontrak: tidak melempar exception; hasil None berarti "tidak dapat
dipastikan". Output melewati redaksi sebelum disimpan.
"""

from __future__ import annotations

import sys

from tunneldesk.domain.tunnel.detection import (
    InstallMode,
    ModeIndicator,
)
from tunneldesk.domain.tunnel.process_contracts import (
    ProcessLauncher,
    ProcessSpec,
)

__all__ = ["ServiceStatusProbe", "SERVICE_NAME"]

SERVICE_NAME = "cloudflared"
_QUERY_TIMEOUT_SECONDS = 5.0


class ServiceStatusProbe:
    """Probe keberadaan service cloudflared — status hanya-baca (K-07)."""

    def __init__(self, launcher: ProcessLauncher) -> None:
        self._launcher = launcher

    def probe(self) -> ModeIndicator | None:
        """ModeIndicator(SERVICE) bila terdaftar; None bila tidak/ragu."""
        if sys.platform != "win32":
            # systemd/launchd bukan target MVP Windows — jujur: tidak
            # diketahui, tanpa indikator palsu.
            return None
        try:
            process = self._launcher.launch(
                ProcessSpec.from_sequence(["sc", "query", SERVICE_NAME])
            )
        except OSError:
            return None
        try:
            exit_code = process.wait(_QUERY_TIMEOUT_SECONDS)
        except Exception:  # noqa: BLE001 — fail-safe kontrak probe
            return None
        if exit_code is None:
            process.force_kill()
            return None
        lines = process.output_lines()
        output = "\n".join(lines)
        # sc query mengembalikan 1060 (service tidak ada) tanpa RUNNING;
        # "RUNNING" / "STOPPED" sama-sama berarti service TERDAFTAR.
        if "RUNNING" in output or "STOPPED" in output or exit_code == 0:
            return ModeIndicator(
                mode=InstallMode.SERVICE,
                evidence=f"layanan Windows '{SERVICE_NAME}' terdaftar "
                "(status hanya-baca)",
                definitive=True,
            )
        return None

