"""DiagnosticsService (Task 2.7) — orkestrasi diagnostik menyeluruh.

Komponen resmi (IMPLEMENTATION_PLAN 2.7, PRD-01 §7.5): lima kelompok
pemeriksaan — proses, origin, file config, DNS/HTTPS, verifikasi akses
publik dengan tingkat kepastian — lalu laporan terstruktur yang
**direview pengguna sebelum ekspor**.

Ketegasan arsitektur:
- FR-1/2/3 memakai kontrak yang sudah ada (TunnelController snapshot +
  check_origin; ConfigValidator) — tanpa duplikasi mekanisme.
- FR-4/5/6 memakai probe infrastructure baru (DnsProbe, HttpsTlsProbe,
  PublicAccessProbe) yang seluruhnya never-raises dan lolos SSRF guard.
- **Isolasi kegagalan (AC-07)**: kegagalan satu pemeriksaan menjadi
  hasil TIDAK_DIPASTIKAN miliknya — tidak membatalkan pemeriksaan lain;
  tidak ada false success (certainty TERVERIFIKASI hanya dari hasil
  faktual).
- **Read-only total**: diagnostik tidak mengubah file/konfigurasi/proses.
- Semua teks hasil disanitasi RedactionEngine (D-18) SEBELUM report
  dibentuk — renderer/ekspor tidak bisa membocorkan apa pun.
- Hostname publik diekstrak dari dokumen konfigurasi (semua hostname
  ingress unik — multi-hostname dilaporkan per hostname, tanpa asumsi
  baris pertama; selaras keputusan PC-2 Task 2.6).
- Versi aplikasi dari metadata paket dengan fallback konstanta.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from tunneldesk.application.config_validator import ConfigValidator
from tunneldesk.domain.config.model import (
    ValidationClassification,
)
from tunneldesk.domain.diagnostics.checks import (
    Certainty,
    CheckKind,
    CheckResult,
    DiagnosticReport,
)
from tunneldesk.domain.diagnostics.origin import OriginStatus
from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.infrastructure.config_io.yaml_parser import RoundTripYamlParser
from tunneldesk.infrastructure.network.dns_probe import (
    DnsProbe,
    filter_public_addresses,
)
from tunneldesk.infrastructure.network.https_tls_probe import (
    DEFAULT_TIMEOUT_SECONDS,
    HttpsTlsProbe,
    TlsKind,
)
from tunneldesk.infrastructure.network.public_probe import (
    PublicAccessProbe,
    PublicKind,
)

if TYPE_CHECKING:
    from tunneldesk.application.tunnel_controller import TunnelController

__all__ = ["DiagnosticsService", "render_report_text"]

_FALLBACK_VERSION = "0.0.1"


def _app_version() -> str:
    """Versi aplikasi dari metadata paket; fallback konstanta pyproject."""
    try:
        from importlib.metadata import version

        return str(version("tunneldesk"))
    except Exception:  # noqa: BLE001 — fail-safe: laporan tetap dibuat
        return _FALLBACK_VERSION


class DiagnosticsService:
    """Orkestrator diagnostik menyeluruh (read-only; on-demand)."""

    def __init__(
        self,
        controller: TunnelController,
        validator: ConfigValidator,
        dns_probe: DnsProbe,
        tls_probe: HttpsTlsProbe,
        public_probe: PublicAccessProbe,
        redaction: RedactionEngine | None = None,
        parser: RoundTripYamlParser | None = None,
        version_provider: Callable[[], str] | None = None,
        clock: Callable[[], float] = time.time,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        #: TunnelController (proses + origin — kontrak E-2/E-3).
        self._controller = controller
        self._validator = validator
        self._dns = dns_probe
        self._tls = tls_probe
        self._public = public_probe
        self._redaction = redaction or RedactionEngine()
        self._parser = parser or RoundTripYamlParser()
        self._version_provider = version_provider or _app_version
        self._clock = clock
        self._timeout = timeout_seconds

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------
    def run_report(self, config_path: str | None) -> DiagnosticReport:
        """Jalankan seluruh pemeriksaan (read-only) → laporan utuh.

        Kegagalan satu pemeriksaan tidak membatalkan yang lain (AC-07).
        ``config_path`` = lokasi konfigurasi aktif dari pengaturan.
        """
        dibuat = self._clock()
        dibuat_iso = datetime.fromtimestamp(dibuat, tz=UTC).isoformat()
        results: list[CheckResult] = []

        results.append(self._check_proses())
        results.append(self._check_origin())

        config_text = self._read_config(config_path)
        results.append(self._check_config(config_path, config_text))

        hostnames = self._extract_hostnames(config_text)
        for hostname in hostnames:
            results.append(self._check_dns(hostname))
            results.append(self._check_tls(hostname))
            results.append(self._check_publik(hostname))
        if not hostnames:
            alasan = (
                "hostname tidak tersedia — konfigurasi tidak dapat dibaca "
                "atau tidak memuat hostname ingress"
            )
            for kind in (CheckKind.DNS, CheckKind.HTTPS, CheckKind.PUBLIK):
                results.append(
                    CheckResult(
                        kind=kind,
                        certainty=Certainty.TIDAK_DIPASTIKAN,
                        status="TIDAK_DIPASTIKAN",
                        ringkasan=alasan,
                        kategori="lingkungan/konfigurasi",
                        langkah="pastikan file konfigurasi valid dan memuat "
                        "hostname ingress, lalu ulangi diagnostik",
                    )
                )

        return DiagnosticReport(
            dibuat_epoch=dibuat,
            dibuat_iso=dibuat_iso,
            versi_aplikasi=self._safe_version(),
            results=tuple(results),
        )

    # ------------------------------------------------------------------
    # Pemeriksaan
    # ------------------------------------------------------------------
    def _check_proses(self) -> CheckResult:
        """FR-1 — status proses milik aplikasi (D-18); PID ≠ klaim sehat."""
        try:
            snapshot = self._controller.status(probe_origin=False)
        except Exception as exc:  # noqa: BLE001 — isolasi kegagalan (AC-07)
            return self._gagal(
                CheckKind.PROSES,
                self._redaction.redact(str(exc)),
            )
        state = str(snapshot.tunnel_state)
        pid = snapshot.pid
        ringkasan = (
            f"proses tunnel berjalan (PID {pid})"
            if pid is not None
            else f"proses tunnel tidak berjalan (status: {state})"
        )
        kategori = "proses"
        langkah = ""
        if snapshot.crashed is not None:
            ringkasan = (
                f"proses tunnel berakhir tak terduga "
                f"(exit code {snapshot.crashed.exit_code})"
            )
            kategori = "proses berakhir tak terduga"
            langkah = (
                "lihat log teredaksi pada dashboard; periksa pesan kesalahan "
                "konfigurasi, lalu jalankan Start kembali"
            )
        elif pid is None:
            kategori = "proses tidak berjalan"
            langkah = "jalankan tunnel melalui tombol Start pada dashboard"
        return CheckResult(
            kind=CheckKind.PROSES,
            certainty=Certainty.TERVERIFIKASI,  # state lifecycle = fakta lokal
            status=state,
            ringkasan=ringkasan,
            kategori=kategori,
            langkah=langkah,
        )

    def _check_origin(self) -> CheckResult:
        """FR-2 — kontrak origin E-3 apa adanya (tanpa duplikasi)."""
        try:
            result = self._controller.check_origin()
        except Exception as exc:  # noqa: BLE001 — isolasi kegagalan
            return self._gagal(
                CheckKind.ORIGIN, self._redaction.redact(str(exc))
            )
        pemetaan = {
            OriginStatus.HEALTHY: Certainty.TERVERIFIKASI,
            OriginStatus.UNREACHABLE: Certainty.TERVERIFIKASI,
            OriginStatus.MISCONFIGURED: Certainty.TERVERIFIKASI,
            OriginStatus.UNKNOWN: Certainty.TIDAK_DIPASTIKAN,
        }
        langkah = ""
        if result.status is OriginStatus.UNREACHABLE:
            langkah = (
                "pastikan aplikasi e-Rapor berjalan dan menerima koneksi "
                "pada alamat/port yang dikonfigurasi"
            )
        elif result.status is OriginStatus.MISCONFIGURED:
            langkah = (
                "periksa alamat/port origin pada pengaturan dan file "
                "konfigurasi"
            )
        return CheckResult(
            kind=CheckKind.ORIGIN,
            certainty=pemetaan[result.status],
            status=result.status.value,
            ringkasan=result.detail,
            kategori="origin lokal",
            langkah=langkah,
        )

    def _check_config(
        self, config_path: str | None, text: str | None
    ) -> CheckResult:
        """FR-3 — file dapat dibaca + lolos validasi E-6 (isi credential
        tidak pernah dibaca — callback keberadaan saja)."""
        if not config_path:
            return CheckResult(
                kind=CheckKind.CONFIG,
                certainty=Certainty.TERVERIFIKASI,
                status="TIDAK_TERSEDIA",
                ringkasan="belum ada file konfigurasi yang dikonfigurasi",
                kategori="konfigurasi",
                langkah="atur lokasi file konfigurasi pada Pengaturan atau "
                "jalankan Setup Wizard",
            )
        if text is None:
            return CheckResult(
                kind=CheckKind.CONFIG,
                certainty=Certainty.TERVERIFIKASI,
                status="GAGAL_BACA",
                ringkasan="file konfigurasi tidak dapat dibaca",
                kategori="konfigurasi tidak dapat dibaca",
                langkah="periksa lokasi dan izin berkas pada Pengaturan",
            )
        outcome = self._validator.validate_text(
            text, credentials_file_exists=self._credentials_exists(config_path)
        )
        certainty = Certainty.TERVERIFIKASI  # hasil validasi = fakta dokumen
        if outcome.classification is ValidationClassification.UNKNOWN:
            certainty = Certainty.KEMUNGKINAN
        kategori = f"konfigurasi {outcome.classification.value}"
        langkah = ""
        if outcome.classification is not ValidationClassification.VALID:
            langkah = (
                "perbaiki item yang tercantum melalui Setup Wizard atau "
                "edit manual, lalu ulangi diagnostik"
            )
        ringkasan = (
            f"konfigurasi {outcome.classification.value} "
            f"({len(outcome.errors)} kesalahan, {len(outcome.warnings)} peringatan)"
        )
        return CheckResult(
            kind=CheckKind.CONFIG,
            certainty=certainty,
            status=outcome.classification.value,
            ringkasan=ringkasan,
            kategori=kategori,
            langkah=langkah,
            detail="\n".join(f"{item!r}" for item in outcome.errors),
        )

    def _check_dns(self, hostname: str) -> CheckResult:
        """FR-4 — resolusi DNS hostname publik konfigurasi."""
        try:
            outcome = self._dns.resolve(hostname)
        except Exception as exc:  # noqa: BLE001 — isolasi kegagalan
            return self._gagal(
                CheckKind.DNS, self._redaction.redact(str(exc)), hostname
            )
        certainty = {
            "DNS_RESOLVED": Certainty.TERVERIFIKASI,
            "DNS_UNRESOLVED": Certainty.TERVERIFIKASI,
            "DNS_UNCONFIRMED": Certainty.TIDAK_DIPASTIKAN,
        }[outcome.status.value]
        langkah = ""
        if outcome.status.value == "DNS_UNRESOLVED":
            langkah = (
                "periksa ejaan hostname pada konfigurasi; hostname baru "
                "mungkin belum terdaftar atau masih dalam propagasi DNS"
            )
        elif outcome.status.value == "DNS_UNCONFIRMED":
            langkah = "periksa koneksi jaringan dan pengaturan DNS, lalu ulangi"
        ringkasan = (
            f"DNS {hostname}: {len(outcome.addresses)} alamat ditemukan"
            if outcome.status.value == "DNS_RESOLVED"
            else f"DNS {hostname}: {outcome.reason}"
        )
        return CheckResult(
            kind=CheckKind.DNS,
            certainty=certainty,
            status=outcome.status.value,
            ringkasan=ringkasan,
            kategori="DNS",
            langkah=langkah,
            hostname=hostname,
            addresses=filter_public_addresses(outcome.addresses),
        )

    def _check_tls(self, hostname: str) -> CheckResult:
        """FR-5 — koneksi TLS + field sertifikat publik (P-4)."""
        try:
            outcome = self._tls.check(hostname)
        except Exception as exc:  # noqa: BLE001 — isolasi kegagalan
            return self._gagal(
                CheckKind.HTTPS, self._redaction.redact(str(exc)), hostname
            )
        certainty = {
            TlsKind.VERIFIED: Certainty.TERVERIFIKASI,
            TlsKind.INVALID: Certainty.TERVERIFIKASI,
            TlsKind.UNCONFIRMED: Certainty.TIDAK_DIPASTIKAN,
        }[outcome.kind]
        langkah = ""
        if outcome.kind is TlsKind.INVALID:
            langkah = (
                "periksa masa berlaku dan kecocokan hostname sertifikat — "
                "dielola melalui Cloudflare"
            )
        elif outcome.kind is TlsKind.UNCONFIRMED:
            langkah = "periksa koneksi jaringan sekolah, lalu ulangi"
        return CheckResult(
            kind=CheckKind.HTTPS,
            certainty=certainty,
            status=outcome.kind.value,
            ringkasan=f"TLS {hostname}: {outcome.reason}",
            kategori="HTTPS/TLS",
            langkah=langkah,
            hostname=hostname,
            cert_subject=outcome.cert_subject,
            cert_issuer=outcome.cert_issuer,
            cert_not_after=outcome.cert_not_after,
        )

    def _check_publik(self, hostname: str) -> CheckResult:
        """FR-6 — akses publik via edge dengan tingkat kepastian (P-2)."""
        try:
            outcome = self._public.check(hostname)
        except Exception as exc:  # noqa: BLE001 — isolasi kegagalan
            return self._gagal(
                CheckKind.PUBLIK, self._redaction.redact(str(exc)), hostname
            )
        pemetaan = {
            PublicKind.RESPONDING: Certainty.TERVERIFIKASI,
            PublicKind.REDIRECTING: Certainty.TERVERIFIKASI,
            PublicKind.REJECTING: Certainty.KEMUNGKINAN,
            PublicKind.ERROR: Certainty.KEMUNGKINAN,
            PublicKind.UNCONFIRMED: Certainty.TIDAK_DIPASTIKAN,
        }
        certainty = pemetaan[outcome.kind]
        langkah = ""
        if outcome.kind in (PublicKind.REJECTING, PublicKind.ERROR):
            langkah = (
                "Cloudflare edge merespons dengan error — periksa status "
                "tunnel dan origin lokal; penyebab tidak dapat dipastikan "
                "dari luar"
            )
        elif outcome.kind is PublicKind.UNCONFIRMED:
            langkah = "periksa koneksi internet jaringan sekolah, lalu ulangi"
        elif outcome.kind is PublicKind.RESPONDING:
            langkah = (
                "akses publik merespons — uji membuka hostname di peramban; "
                "respons edge bukan bukti origin lokal sehat"
            )
        return CheckResult(
            kind=CheckKind.PUBLIK,
            certainty=certainty,
            status=outcome.kind.value,
            ringkasan=(
                f"akses publik {hostname}: {outcome.reason}"
                if outcome.reason
                else f"akses publik {hostname}"
            ),
            kategori="akses publik",
            langkah=langkah,
            hostname=hostname,
            http_status=outcome.http_status,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _gagal(
        self, kind: CheckKind, detail: str, hostname: str = ""
    ) -> CheckResult:
        """Isolasi kegagalan (AC-07): satu pemeriksaan gagal → hasil
        TIDAK_DIPASTIKAN miliknya; tanpa false success; tanpa crash."""
        return CheckResult(
            kind=kind,
            certainty=Certainty.TIDAK_DIPASTIKAN,
            status="TIDAK_DIPASTIKAN",
            ringkasan="pemeriksaan gagal dijalankan",
            kategori="kesalahan internal (tersanitasi)",
            langkah="ulangi diagnostik; bila berulang, gunakan laporan "
            "sebagai bahan dukungan",
            detail=detail,
            hostname=hostname,
        )

    def _read_config(self, config_path: str | None) -> str | None:
        """Baca teks konfigurasi (read-only, utf-8); gagal → None."""
        if not config_path:
            return None
        try:
            return Path(config_path).read_text(encoding="utf-8")
        except OSError:
            return None

    def _credentials_exists(self, config_path: str) -> Callable[[str], bool]:
        """Callback keberadaan credential (isi TIDAK pernah dibaca)."""
        direktori = Path(config_path).parent

        def cek(reference: str) -> bool:
            candidate = Path(reference)
            if not candidate.is_absolute():
                candidate = direktori / candidate
            return candidate.is_file()

        return cek

    def _extract_hostnames(self, text: str | None) -> tuple[str, ...]:
        """Hostname ingress unik + terurut dari dokumen konfigurasi."""
        if not text:
            return ()
        parsed = self._parser.parse(text)
        document = parsed.document
        if document is None or not hasattr(document, "get"):
            return ()
        ingress = document.get("ingress")
        if not isinstance(ingress, list):
            return ()
        hostnames: list[str] = []
        for item in ingress:
            if not hasattr(item, "get"):
                continue
            hostname = item.get("hostname", "")
            if isinstance(hostname, str) and hostname.strip():
                bersih = hostname.strip()
                if bersih not in hostnames:
                    hostnames.append(bersih)
        return tuple(hostnames)

    def _safe_version(self) -> str:
        try:
            return self._redaction.redact(self._version_provider())
        except Exception:  # noqa: BLE001 — fail-safe
            return _FALLBACK_VERSION


def render_report_text(report: DiagnosticReport) -> str:
    """Render laporan → teks kanonik untuk preview, TXT, dan clipboard
    (representasi SAMA untuk ketiganya — AC-08). Hanya memakai field
    yang sudah disanitasi di service."""
    baris: list[str] = [
        "LAPORAN DIAGNOSTIK TUNNELDESK",
        f"Waktu: {report.dibuat_iso}",
        f"Versi aplikasi: {report.versi_aplikasi}",
        "",
    ]
    for hasil in report.results:
        baris.append(f"[{hasil.kind.value}] {hasil.ringkasan}")
        baris.append(f"  Status: {hasil.status} | Kepastian: {hasil.certainty.value}")
        if hasil.hostname:
            baris.append(f"  Hostname: {hasil.hostname}")
        if hasil.kategori:
            baris.append(f"  Kategori: {hasil.kategori}")
        if hasil.langkah:
            baris.append(f"  Langkah: {hasil.langkah}")
        if hasil.addresses:
            baris.append(f"  Alamat IP: {', '.join(hasil.addresses)}")
        if hasil.http_status is not None:
            baris.append(f"  HTTP status: {hasil.http_status}")
        if hasil.cert_subject:
            baris.append(f"  Sertifikat subjek: {hasil.cert_subject}")
        if hasil.cert_issuer:
            baris.append(f"  Sertifikat issuer: {hasil.cert_issuer}")
        if hasil.cert_not_after:
            baris.append(f"  Sertifikat berlaku hingga: {hasil.cert_not_after}")
        if hasil.detail:
            baris.append("  Detail:")
            for sub in hasil.detail.splitlines():
                baris.append(f"    {sub}")
        baris.append("")
    return "\n".join(baris).rstrip() + "\n"
