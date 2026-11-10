"""Binding lifecycle proses ke state machine E-1 (fondasi E-2).

Kelas ini adalah jembatan domain antara :class:`TunnelStateMachine` (E-1)
dan port proses (adapter E-2). **Bukan** TunnelController (E-3) — tidak
ada konfigurasi YAML, origin check, atau orkestrasi UI di sini.

Kepemilikan: hanya handle hasil ``launch()`` milik instance ini yang
boleh dihentikan; pid diverifikasi terhadap :class:`OwnershipRegistry`.

Kontrak idempoten (PRD-02 §3.1):
- ``start()`` saat STARTING → menunggu hasil start (tidak spawn ganda).
- ``stop()`` saat STOPPING → menunggu stop yang sedang berjalan.
- ``stop()`` saat sudah STOPPED → mengembalikan hasil terakhir.
- ``start()`` saat RUNNING → ditolak (InvalidTransitionError dari E-1).
"""

from __future__ import annotations

import threading

from .ownership import OwnershipRegistry
from .process_contracts import (
    LaunchedProcess,
    NotOwnedProcessError,
    ProcessLauncher,
    ProcessResult,
    ProcessSpec,
)
from .state_machine import TunnelStateMachine
from .states import InvalidTransitionError, TunnelEvent, TunnelState

__all__ = [
    "ProcessLifecycle",
    "ProcessStartError",
    "DEFAULT_GRACEFUL_TIMEOUT_SECONDS",
]

DEFAULT_GRACEFUL_TIMEOUT_SECONDS = 5.0


class ProcessStartError(RuntimeError):
    """Proses gagal dimulai (exit saat STARTING) — memuat exit code."""

    def __init__(self, exit_code: int) -> None:
        self.exit_code = exit_code
        super().__init__(f"proses gagal dimulai (exit code {exit_code})")


class ProcessLifecycle:
    """Mengikat launcher + ownership + state machine untuk satu proses.

    Thread-safe: guard internal melindungi transisi start/stop dari race
    condition dan double termination.
    """

    def __init__(
        self,
        launcher: ProcessLauncher,
        ownership: OwnershipRegistry | None = None,
    ) -> None:
        self._launcher = launcher
        self._ownership = ownership or OwnershipRegistry()
        self._machine = TunnelStateMachine()
        self._lock = threading.RLock()
        self._process: LaunchedProcess | None = None
        self._last_result: ProcessResult | None = None

    # ------------------------------------------------------------------
    # Properti status
    # ------------------------------------------------------------------
    @property
    def state(self) -> TunnelState:
        with self._lock:
            return self._machine.state

    @property
    def last_result(self) -> ProcessResult | None:
        """Hasil terakhir proses yang berakhir (None bila belum pernah)."""
        with self._lock:
            return self._last_result

    def current_pid(self) -> int | None:
        """Pid proses yang sedang dikelola; None bila tidak ada."""
        with self._lock:
            return self._process.pid() if self._process is not None else None

    def owned_pids(self) -> frozenset[int]:
        with self._lock:
            return self._ownership.owned_pids()

    # ------------------------------------------------------------------
    # Start
    # ------------------------------------------------------------------
    def start(self, spec: ProcessSpec) -> LaunchedProcess:
        """Lahirkan proses milik aplikasi; state → STARTING → RUNNING.

        - Saat STARTING: menunggu start sebelumnya selesai (idempoten,
          tanpa spawn ganda) lalu mengembalikan handle yang sama.
        - Saat RUNNING: ditolak oleh state machine (start ganda).
        - Proses mati segera setelah dilahirkan → START_FAILED → state
          ERROR, :class:`ProcessStartError` dinaikkan.
        """
        with self._lock:
            if self._machine.state is TunnelState.STARTING:
                assert self._process is not None
                return self._process
            self._machine.transition(TunnelEvent.START)
            try:
                process = self._launcher.launch(spec)
            except Exception:
                self._machine.transition(TunnelEvent.START_FAILED)
                raise
            self._process = process
            self._ownership.register(process.pid())
            # Proses bisa mati seketika setelah dilahirkan.
            exit_code = process.poll()
            if exit_code is not None:
                self._ownership.release(process.pid())
                self._process = None
                self._machine.transition(TunnelEvent.START_FAILED)
                self._last_result = ProcessResult(
                    pid=0 if exit_code is None else process.pid(),
                    exit_code=exit_code,
                )
                raise ProcessStartError(exit_code)
            self._machine.transition(TunnelEvent.STARTED)
            return process

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------
    def stop(
        self,
        graceful_timeout_seconds: float = DEFAULT_GRACEFUL_TIMEOUT_SECONDS,
    ) -> ProcessResult:
        """Hentikan proses milik aplikasi secara graceful → paksa bila perlu.

        - Saat RUNNING: state → STOPPING; graceful → tunggu → paksa bila
          timeout; state → STOPPED.
        - Saat STOPPING: menunggu stop yang sedang berjalan (idempoten).
        - Saat STOPPED: mengembalikan hasil terakhir (idempoten).
        - Pid diverifikasi terhadap registri kepemilikan sebelum disentuh.
        """
        with self._lock:
            state = self._machine.state
            if state is TunnelState.STOPPED:
                assert self._last_result is not None
                return self._last_result
            if state is TunnelState.STOPPING:
                return self._wait_out_stop(graceful_timeout_seconds)
            if state is not TunnelState.RUNNING:
                raise InvalidTransitionError(state, TunnelEvent.STOP)

            process = self._require_owned_process()
            self._machine.transition(TunnelEvent.STOP)
            result = self._terminate_and_collect(process, graceful_timeout_seconds)
            self._finish_exit(process, result)
            self._machine.transition(TunnelEvent.EXITED)  # STOPPING → STOPPED
            return result

    # ------------------------------------------------------------------
    # Exit tak terduga (crash detection)
    # ------------------------------------------------------------------
    def poll_exit(self) -> ProcessResult | None:
        """Deteksi proses yang berakhir sendiri saat RUNNING.

        Mengembalikan :class:`ProcessResult` dan memindahkan state ke
        ERROR (crash) bila proses terdeteksi berakhir; ``None`` bila
        masih berjalan.
        """
        with self._lock:
            process = self._process
            if process is None or self._machine.state is not TunnelState.RUNNING:
                return None
            exit_code = process.poll()
            if exit_code is None:
                return None
            result = ProcessResult(pid=process.pid(), exit_code=exit_code)
            self._finish_exit(process, result)
            self._machine.transition(TunnelEvent.EXITED)  # RUNNING → ERROR
            return result

    def cleanup_after_parent_shutdown(self) -> None:
        """Bersihkan proses saat aplikasi ditutup (idempoten, aman dipanggil
        kapan saja): stop bila masih hidup, lepas registrasi kepemilikan."""
        with self._lock:
            if self._process is not None and self._machine.state in (
                TunnelState.RUNNING,
                TunnelState.STARTING,
            ):
                try:
                    self.stop()
                except Exception:
                    # cleanup terakhir: pastikan tidak ada yang tertinggal
                    process = self._process
                    if process is not None:
                        self._force_release(process)
                return
            if self._process is not None and self._machine.state in (
                TunnelState.STOPPED,
                TunnelState.ERROR,
            ):
                self._force_release(self._process)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _require_owned_process(self) -> LaunchedProcess:
        process = self._process
        if process is None:
            raise NotOwnedProcessError("tidak ada proses yang dikelola")
        self._ownership.require_owned(process.pid())
        return process

    def _terminate_and_collect(
        self,
        process: LaunchedProcess,
        graceful_timeout_seconds: float,
    ) -> ProcessResult:
        forced = False
        process.graceful_stop()
        exit_code = process.wait(graceful_timeout_seconds)
        if exit_code is None:
            forced = True
            process.force_kill()
            exit_code = process.wait(graceful_timeout_seconds)
        if exit_code is None:
            # bahkan force gagal (proses hung tanpa kill) — catat apa adanya
            exit_code = -1
        return ProcessResult(pid=process.pid(), exit_code=exit_code, forced=forced)

    def _finish_exit(self, process: LaunchedProcess, result: ProcessResult) -> None:
        self._last_result = result
        self._ownership.release(process.pid())
        self._process = None

    def _wait_out_stop(self, graceful_timeout_seconds: float) -> ProcessResult:
        """Idempoten: ada stop yang sedang berjalan — tunggu hasilnya."""
        process = self._require_owned_process()
        exit_code = process.wait(graceful_timeout_seconds)
        if exit_code is None:
            process.force_kill()
            exit_code = process.wait(graceful_timeout_seconds) or -1
        result = ProcessResult(pid=process.pid(), exit_code=exit_code, forced=True)
        self._finish_exit(process, result)
        self._machine.transition(TunnelEvent.EXITED)  # STOPPING → STOPPED
        return result

    def _force_release(self, process: LaunchedProcess) -> None:
        try:
            process.force_kill()
        except Exception:
            pass
        self._ownership.release(process.pid())
        self._process = None
