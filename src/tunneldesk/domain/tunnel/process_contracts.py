"""Kontrak proses untuk E-2 — port yang diimplementasi adapter (A-08).

Aturan kepemilikan (D-18, K-07, A-07):
- Hanya proses yang dilahirkan oleh :class:`ProcessLauncher` milik
  TunnelDesk yang boleh dihentikan.
- Tidak ada adopsi proses berdasarkan nama executable.
- Windows Service bukan bagian dari kontrak ini (K-07).

Modul murni domain: tanpa subprocess/Qt/platform API.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from tunneldesk.domain.redaction.engine import RedactionEngine


class NotOwnedProcessError(RuntimeError):
    """Dilempar bila mencoba mengelola proses yang bukan milik aplikasi."""


@dataclass(frozen=True)
class ProcessSpec:
    """Spesifikasi proses — argument list terstruktur, tanpa shell.

    ``argv[0]`` adalah path executable. Kontrak logging: gunakan
    :meth:`redacted_repr` agar token pada argv tidak pernah masuk log.
    """

    argv: tuple[str, ...]
    cwd: str | None = None

    def __post_init__(self) -> None:
        if not self.argv:
            raise ValueError("argv tidak boleh kosong")

    @staticmethod
    def from_sequence(argv: Sequence[str], cwd: str | None = None) -> ProcessSpec:
        return ProcessSpec(argv=tuple(argv), cwd=cwd)

    def redacted_repr(self) -> str:
        """Representasi argv aman untuk log: nilai setelah ``--token``
        diganti placeholder (D-18: token tidak pernah dicatat)."""
        engine = RedactionEngine()
        parts: list[str] = []
        mask_next = False
        for element in self.argv:
            if mask_next:
                parts.append("[REDACTED:TOKEN_FLAG]")
                mask_next = False
                continue
            if element == "--token":
                mask_next = True
                parts.append(element)
                continue
            parts.append(element)
        redacted = " ".join(parts)
        return engine.redact(redacted)


@dataclass(frozen=True)
class ProcessResult:
    """Hasil akhir sebuah proses yang dikelola."""

    pid: int
    exit_code: int
    #: True bila proses dihentikan paksa setelah graceful timeout.
    forced: bool = False


class LaunchedProcess:
    """Port: proses hidup yang dilahirkan oleh launcher milik aplikasi.

    Implementasi: adapter POSIX, adapter Windows, dan fake-cloudflared.
    Semua metode blocking dan aman dipanggil dua kali (idempoten).
    """

    def pid(self) -> int:
        raise NotImplementedError

    def poll(self) -> int | None:
        """Kembalikan exit code bila proses sudah berakhir, selain itu None."""
        raise NotImplementedError

    def graceful_stop(self) -> None:
        """Kirim sinyal penghentian terkendali (SIGTERM / CTRL_BREAK)."""
        raise NotImplementedError

    def force_kill(self) -> None:
        """Hentikan paksa proses (dan grup/Job Object miliknya)."""
        raise NotImplementedError

    def wait(self, timeout_seconds: float) -> int | None:
        """Tunggu sampai berakhir; None bila timeout tercapai."""
        raise NotImplementedError

    def output_lines(self) -> tuple[str, ...]:
        """Baris keluaran terbaru (terdedyupasi, terbatas buffer)."""
        raise NotImplementedError


class ProcessLauncher:
    """Port: melahirkan proses baru dari :class:`ProcessSpec`.

    Implementasi wajib memastikan proses yang dilahirkan tercatat sebagai
    milik aplikasi (Job Object di Windows — A-07; process group di POSIX).
    """

    def launch(self, spec: ProcessSpec) -> LaunchedProcess:
        raise NotImplementedError
