"""Definisi state kanonis proses tunnel (PRD-01 §8) dan tabel transisi.

Sumber kebenaran: PRD-01 §8 — STOPPED / STARTING / RUNNING / STOPPING / ERROR.
Modul ini murni domain: tanpa Qt, subprocess, atau API platform (A-08).
"""

from __future__ import annotations

import enum


class TunnelState(enum.Enum):
    """Status kanonis proses tunnel (PRD-01 §8)."""

    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


class TunnelEvent(enum.Enum):
    """Event yang memicu transisi state (dipancarkan application/adapter).

    Semantik:
    - ``START``         : pengguna meminta start.
    - ``STARTED``       : adapter mengonfirmasi proses berjalan (terdeteksi).
    - ``START_FAILED``  : start gagal (exit code / error saat STARTING atau STOPPING).
    - ``STOP``          : pengguna meminta stop (idempoten saat STOPPING).
    - ``EXITED``        : proses berakhir dengan exit code (STARTING/STOPPING/RUNNING).
    - ``RESET``         : pengakuan error — kembali ke STOPPED tanpa start ulang.
    """

    START = "START"
    STARTED = "STARTED"
    START_FAILED = "START_FAILED"
    STOP = "STOP"
    EXITED = "EXITED"
    RESET = "RESET"


#: Tabel transisi kanonis. Kunci = (state, event); nilai = state berikutnya.
#: Self-transition STARTING+START dan STOPPING+STOP bersifat idempoten —
#: permintaan berulang tidak mengubah state (PRD-02 §3.1: tanpa proses ganda).
TRANSITIONS: dict[tuple[TunnelState, TunnelEvent], TunnelState] = {
    (TunnelState.STOPPED, TunnelEvent.START): TunnelState.STARTING,
    (TunnelState.STARTING, TunnelEvent.START): TunnelState.STARTING,
    (TunnelState.STARTING, TunnelEvent.STARTED): TunnelState.RUNNING,
    (TunnelState.STARTING, TunnelEvent.START_FAILED): TunnelState.ERROR,
    (TunnelState.STARTING, TunnelEvent.EXITED): TunnelState.ERROR,
    (TunnelState.RUNNING, TunnelEvent.STOP): TunnelState.STOPPING,
    (TunnelState.RUNNING, TunnelEvent.EXITED): TunnelState.ERROR,
    (TunnelState.STOPPING, TunnelEvent.STOP): TunnelState.STOPPING,
    (TunnelState.STOPPING, TunnelEvent.EXITED): TunnelState.STOPPED,
    (TunnelState.STOPPING, TunnelEvent.START_FAILED): TunnelState.ERROR,
    (TunnelState.ERROR, TunnelEvent.START): TunnelState.STARTING,
    (TunnelState.ERROR, TunnelEvent.RESET): TunnelState.STOPPED,
}


class InvalidTransitionError(RuntimeError):
    """Dilempar saat event tidak valid untuk state saat ini.

    Aman ditangkap oleh application: state TIDAK berubah ketika transisi
    ditolak (deterministik).
    """

    def __init__(self, current: TunnelState, event: TunnelEvent) -> None:
        self.current = current
        self.event = event
        super().__init__(
            f"Transisi tidak valid: {current.value} + {event.value}"
        )
