"""TunnelController (E-3) — penghubung domain & application service.

Mengintegrasikan:
- state machine E-1 (sumber tunggal status tunnel — PRD-01 §8),
- ProcessLifecycle E-2 (kepemilikan & lifecycle proses),
- deteksi origin (status origin **terpisah** dari status tunnel),
- referensi konfigurasi run (:class:`TunnelRunConfig`).

Bukan bagian epic ini: UI (E-4), parsing YAML lengkap (E-6), backup,
Windows Service (K-07). Restart = komposisi stop→start (tanpa state baru).

Kontrak rahasia (D-18): exception dan pesan status disanitasi via
RedactionEngine E-1; token pada argv tidak pernah dicatat (gunakan
``ProcessSpec.redacted_repr()``).
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from tunneldesk.domain.diagnostics.origin import (
    OriginCheckResult,
    OriginProbe,
    OriginStatus,
    OriginTarget,
    classify_probe_error,
    classify_probe_outcome,
    validate_origin_target,
)
from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.domain.tunnel.lifecycle import ProcessLifecycle, ProcessStartError
from tunneldesk.domain.tunnel.process_contracts import (
    LaunchedProcess,
    ProcessResult,
    ProcessSpec,
)
from tunneldesk.infrastructure.network.origin_probe import SocketOriginProbe

__all__ = [
    "TunnelRunConfig",
    "TunnelStatusSnapshot",
    "TunnelController",
]

DEFAULT_ORIGIN_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class TunnelRunConfig:
    """Referensi konfigurasi run yang dibutuhkan controller.

    Parsing YAML lengkap adalah E-6; pada E-3 konfigurasi diberikan
    jadi oleh pemanggil (spec + target origin) tanpa asumsi port/host.
    """

    spec: ProcessSpec
    origin_host: str
    origin_port: int
    graceful_timeout_seconds: float = 5.0
    origin_timeout_seconds: float = DEFAULT_ORIGIN_TIMEOUT_SECONDS

    def origin_target(self) -> OriginTarget:
        return OriginTarget(host=self.origin_host, port=self.origin_port)


@dataclass(frozen=True)
class TunnelStatusSnapshot:
    """Snapshot status: tunnel dan origin **terpisah** (PRD-01 §8)."""

    tunnel_state: str
    pid: int | None
    last_result: ProcessResult | None
    origin: OriginCheckResult | None
    crashed: ProcessResult | None


class TunnelController:
    """Kontroler tingkat aplikasi untuk satu tunnel (mode config-file, A-09).

    Operasi berulang aman dan deterministik; race condition dilindungi
    lock internal :class:`ProcessLifecycle` (E-2) + guard controller.
    """

    def __init__(
        self,
        config: TunnelRunConfig,
        lifecycle: ProcessLifecycle,
        probe: OriginProbe | None = None,
        redaction: RedactionEngine | None = None,
    ) -> None:
        self._config = config
        self._lifecycle = lifecycle
        if probe is not None:
            self._probe: OriginProbe = probe
        else:
            self._probe = SocketOriginProbe()
        self._redaction = redaction or RedactionEngine()
        self._last_origin: OriginCheckResult | None = None
        # Validasi konfigurasi origin sedini mungkin (MISCONFIGURED tanpa jaringan).
        self._origin_config_error = validate_origin_target(config.origin_target())

    # ------------------------------------------------------------------
    # Secret handling (D-18)
    # ------------------------------------------------------------------
    def register_secret(self, value: str, label: str = "SECRET") -> bool:
        """Daftarkan nilai rahasia yang diketahui ke engine redaksi.

        Dipanggil saat credential/config input tersedia; nilai terdaftar
        tidak pernah muncul di pesan exception maupun log controller.
        """
        return self._redaction.register_secret(value, label)

    def _sanitize(self, text: str) -> str:
        return self._redaction.redact(text)

    # ------------------------------------------------------------------
    # Operasi utama
    # ------------------------------------------------------------------
    def start(self) -> LaunchedProcess:
        """Start tunnel; gagal start menghasilkan state ERROR + pesan aman."""
        try:
            return self._lifecycle.start(self._config.spec)
        except ProcessStartError as exc:
            # exit code bukan rahasia; pesan disanitasi untuk konsistensi
            raise ProcessStartError(exc.exit_code) from None
        except Exception as exc:
            raise RuntimeError(
                f"start tunnel gagal: {self._sanitize(str(exc))}"
            ) from exc

    def stop(self) -> ProcessResult:
        """Stop tunnel milik aplikasi; idempoten (kontrak E-2)."""
        try:
            return self._lifecycle.stop(self._config.graceful_timeout_seconds)
        except RuntimeError as exc:
            # termasuk NotOwnedProcessError / InvalidTransitionError (RuntimeError)
            # — pesan disanitasi, tipe dipertahankan.
            raise type(exc)(self._sanitize(str(exc))) from exc

    def restart(self) -> LaunchedProcess:
        """Restart = komposisi stop → start (tanpa state baru)."""
        self.stop()
        return self.start()

    def poll_process_exit(self) -> ProcessResult | None:
        """Deteksi exit tak terduga; state → ERROR bila crash (lazy)."""
        return self._lifecycle.poll_exit()

    def recent_output(self) -> tuple[str, ...]:
        """Baris keluaran proses terakhir (teredaksi) — untuk tampilan log."""
        return self._lifecycle.recent_output()

    def started_at(self) -> float | None:
        """Epoch detik saat proses terakhir terkonfirmasi berjalan."""
        return self._lifecycle.started_at

    def shutdown(self) -> None:
        """Cleanup saat aplikasi ditutup (idempoten — kontrak E-2)."""
        self._lifecycle.cleanup_after_parent_shutdown()

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def check_origin(
        self, timeout_seconds: float | None = None
    ) -> OriginCheckResult:
        """Periksa origin **independen** dari status tunnel."""
        if self._origin_config_error is not None:
            result = OriginCheckResult(
                status=OriginStatus.MISCONFIGURED,
                detail=self._origin_config_error,
            )
            self._last_origin = result
            return result
        target = self._config.origin_target()
        timeout = (
            self._config.origin_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        try:
            outcome = self._probe.probe(target, timeout)
            result = classify_probe_outcome(target, outcome)
        except Exception as exc:  # noqa: BLE001 — probe port kontraknya tak melempar
            result = classify_probe_error(target, self._sanitize(str(exc)))
        # Pertahanan kedua: detail apapun dari jalur probe disanitasi
        # (D-18) sebelum disimpan/ditampilkan.
        result = replace(result, detail=self._sanitize(result.detail))
        self._last_origin = result
        return result

    def status(self, probe_origin: bool = False) -> TunnelStatusSnapshot:
        """Snapshot status terkini (origin hanya bila diminta — tanpa I/O bila tidak)."""
        crashed = self._lifecycle.poll_exit()
        origin = self.check_origin() if probe_origin else self._last_origin
        return TunnelStatusSnapshot(
            tunnel_state=self._lifecycle.state.value,
            pid=self._lifecycle.current_pid(),
            last_result=self._lifecycle.last_result,
            origin=origin,
            crashed=crashed,
        )
