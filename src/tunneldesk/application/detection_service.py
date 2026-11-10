"""DetectionService (E-5) — orkestrasi deteksi instalasi & mode.

Menggabungkan:
- locator executable (port ProcessLauncher E-2 untuk probe versi),
- locator kandidat file konfigurasi,
- probe service (hanya-baca, K-07),
- klasifikasi mode dari domain (deterministik).

Fail-safe: kegagalan tiap komponen dikumpulkan sebagai penjelasan —
deteksi tidak pernah melempar exception ke pemanggil. Read-only: tidak
ada file yang dibuat/diubah (D-17).

Kontrak rahasia (D-18): teks apa pun dari proses/probe disanitasi
RedactionEngine E-1 sebelum masuk report.
"""

from __future__ import annotations

from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.domain.tunnel.detection import (
    ConfigCandidate,
    DetectionConfidence,
    DetectionReport,
    DetectionSource,
    ExecutableFinding,
    InstallMode,
    ModeIndicator,
    classify_mode,
    dedupe_executables,
)
from tunneldesk.domain.tunnel.process_contracts import ProcessLauncher
from tunneldesk.infrastructure.detection.cloudflared_locator import (
    CloudflaredLocator,
)
from tunneldesk.infrastructure.detection.config_locator import ConfigLocator
from tunneldesk.infrastructure.detection.service_probe import ServiceStatusProbe

__all__ = ["DetectionService"]


class DetectionService:
    """Orkestrasi deteksi read-only (tugas 2.1)."""

    def __init__(
        self,
        launcher: ProcessLauncher,
        cloudflared_locator: CloudflaredLocator | None = None,
        config_locator: ConfigLocator | None = None,
        service_probe: ServiceStatusProbe | None = None,
        redaction: RedactionEngine | None = None,
    ) -> None:
        self._launcher = launcher
        self._cloudflared_locator = cloudflared_locator or CloudflaredLocator(
            launcher
        )
        self._config_locator = config_locator or ConfigLocator()
        self._service_probe = service_probe or ServiceStatusProbe(launcher)
        self._redaction = redaction or RedactionEngine()

    def detect(self) -> DetectionReport:
        """Jalankan deteksi penuh — read-only, tanpa exception."""
        explanations: list[str] = []

        executables = self._locate_executables(explanations)
        candidates = self._locate_config_candidates(explanations)
        service_indicator = self._probe_service(explanations)
        indicators = self._build_indicators(
            executables, candidates, service_indicator
        )
        mode, mode_certain, mode_explanation = classify_mode(indicators)
        explanations.extend(self._contextual_explanations(executables, mode))

        sources = self._collect_sources(executables, candidates, service_indicator)
        confidence = self._confidence(executables, candidates, mode_certain)
        return DetectionReport(
            executables=executables,
            config_candidates=candidates,
            mode_indicators=indicators,
            sources=sources,
            mode=mode,
            mode_certain=mode_certain,
            mode_explanation=self._sanitize(mode_explanation),
            explanations=tuple(self._sanitize(text) for text in explanations),
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Komponen (masing-masing fail-safe)
    # ------------------------------------------------------------------
    def _locate_executables(
        self, explanations: list[str]
    ) -> tuple[ExecutableFinding, ...]:
        try:
            return dedupe_executables(self._cloudflared_locator.locate())
        except Exception as exc:  # noqa: BLE001 — fail-safe kontrak deteksi
            explanations.append(
                self._sanitize(f"pencarian executable gagal: {exc}")
            )
            return ()

    def _locate_config_candidates(
        self, explanations: list[str]
    ) -> tuple[ConfigCandidate, ...]:
        try:
            return self._config_locator.locate()
        except Exception as exc:  # noqa: BLE001
            explanations.append(
                self._sanitize(f"pencarian konfigurasi gagal: {exc}")
            )
            return ()

    def _probe_service(
        self, explanations: list[str]
    ) -> ModeIndicator | None:
        try:
            return self._service_probe.probe()
        except Exception as exc:  # noqa: BLE001
            explanations.append(self._sanitize(f"probe service gagal: {exc}"))
            return None

    # ------------------------------------------------------------------
    # Indikator & penjelasan
    # ------------------------------------------------------------------
    def _build_indicators(
        self,
        executables: tuple[ExecutableFinding, ...],
        candidates: tuple[ConfigCandidate, ...],
        service_indicator: ModeIndicator | None,
    ) -> tuple[ModeIndicator, ...]:
        indicators: list[ModeIndicator] = []
        if candidates:
            names = ", ".join(str(candidate.path) for candidate in candidates)
            indicators.append(
                ModeIndicator(
                    mode=InstallMode.CONFIG_FILE,
                    evidence=self._sanitize(names),
                    definitive=True,
                )
            )
        if service_indicator is not None:
            indicators.append(service_indicator)
        if executables and not candidates and service_indicator is None:
            indicators.append(
                ModeIndicator(
                    mode=InstallMode.TOKEN,
                    evidence="cloudflared terpasang tanpa file konfigurasi "
                    "yang ditemukan",
                    definitive=False,
                )
            )
        return tuple(indicators)

    def _contextual_explanations(
        self,
        executables: tuple[ExecutableFinding, ...],
        mode: InstallMode,
    ) -> list[str]:
        notes: list[str] = []
        if not executables:
            notes.append(
                "cloudflared tidak ditemukan — panduan instalasi manual "
                "tersedia pada dokumentasi"
            )
        if mode is InstallMode.CONFIG_FILE:
            notes.append(
                "instalasi siap diverifikasi lebih lanjut (validasi isi "
                "konfigurasi tersedia pada tahap berikutnya)"
            )
        if mode is InstallMode.TOKEN:
            notes.append(
                "mode token dan Windows Service berada di luar kendali "
                "TunnelDesk (hanya-baca)"
            )
        return notes

    # ------------------------------------------------------------------
    # Util
    # ------------------------------------------------------------------
    @staticmethod
    def _collect_sources(
        executables: tuple[ExecutableFinding, ...],
        candidates: tuple[ConfigCandidate, ...],
        service_indicator: ModeIndicator | None,
    ) -> tuple[DetectionSource, ...]:
        sources: list[DetectionSource] = []
        for finding in executables:
            if finding.source not in sources:
                sources.append(finding.source)
        for candidate in candidates:
            if candidate.source not in sources:
                sources.append(candidate.source)
        if service_indicator is not None and (
            DetectionSource.SERVICE_QUERY not in sources
        ):
            sources.append(DetectionSource.SERVICE_QUERY)
        return tuple(sources)

    @staticmethod
    def _confidence(
        executables: tuple[ExecutableFinding, ...],
        candidates: tuple[ConfigCandidate, ...],
        mode_certain: bool,
    ) -> DetectionConfidence:
        if executables and mode_certain:
            return DetectionConfidence.CONFIRMED
        if executables or candidates:
            return DetectionConfidence.PARTIAL
        return DetectionConfidence.UNKNOWN

    def register_secret(self, value: str, label: str = "SECRET") -> bool:
        """Daftarkan nilai rahasia (mis. dari credential config) ke engine
        redaksi — tidak pernah muncul di report/exception (D-18)."""
        return self._redaction.register_secret(value, label)

    def _sanitize(self, text: str) -> str:
        return self._redaction.redact(text)
