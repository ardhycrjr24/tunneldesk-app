"""Kontrak deteksi origin (E-3) — klasifikasi murni sesuai PRD-01 §8.

Status origin **terpisah** dari status tunnel (PRD-01 §8): tunnel RUNNING
tidak berarti origin sehat. Kategori status tidak boleh diperluas tanpa
dasar PRD: UNKNOWN / HEALTHY / UNREACHABLE / MISCONFIGURED.

Modul murni domain: tanpa socket/Qt/platform. Pemeriksaan jaringan nyata
diimplementasikan adapter via port :class:`OriginProbe` (A-08).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Protocol

__all__ = [
    "OriginStatus",
    "OriginProbeKind",
    "OriginTarget",
    "OriginProbeOutcome",
    "OriginCheckResult",
    "OriginProbe",
    "validate_origin_target",
    "origin_target_from_service",
    "classify_probe_outcome",
    "classify_probe_error",
]


class OriginStatus(enum.Enum):
    """Status kesehatan origin (PRD-01 §8) — kategori tertutup."""

    UNKNOWN = "UNKNOWN"
    HEALTHY = "HEALTHY"
    UNREACHABLE = "UNREACHABLE"
    MISCONFIGURED = "MISCONFIGURED"


class OriginProbeKind(enum.Enum):
    """Hasil mentah percobaan probe jaringan (diinterpretasi domain)."""

    REACHABLE = "REACHABLE"      # terhubung & mendapat respons HTTP
    REFUSED = "REFUSED"          # koneksi ditolak (port tertutup / layanan mati)
    TIMEOUT = "TIMEOUT"          # tidak ada respons dalam batas waktu
    ERROR = "ERROR"              # kegagalan lain (DNS, jaringan, tak terduga)


@dataclass(frozen=True)
class OriginTarget:
    """Alamat origin lokal yang diperiksa — tidak pernah diasumsikan.

    Host/port berasal dari konfigurasi pengguna atau konfirmasi eksplisit
    (PRD-01 §14: jangan hardcode tanpa verifikasi).
    """

    host: str
    port: int
    scheme: str = "http"

    def validation_error(self) -> str | None:
        """Kembalikan pesan kesalahan konfigurasi, atau None bila valid."""
        if not isinstance(self.host, str) or not self.host.strip():
            return "host origin kosong"
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            return "port origin bukan bilangan bulat"
        if not 1 <= self.port <= 65535:
            return f"port origin di luar rentang 1-65535: {self.port}"
        if self.scheme not in ("http", "https"):
            return f"scheme origin tidak didukung: {self.scheme}"
        return None


@dataclass(frozen=True)
class OriginProbeOutcome:
    """Hasil mentah probe dari adapter."""

    kind: OriginProbeKind
    http_status: int | None = None
    detail: str = ""


@dataclass(frozen=True)
class OriginCheckResult:
    """Hasil terklasifikasi yang ditampilkan ke pengguna.

    ``detail`` aman untuk ditampilkan: tidak memuat kredensial.
    """

    status: OriginStatus
    detail: str
    http_status: int | None = None
    checked_at_state: str = ""  # status tunnel saat pemeriksaan (informasional)


class OriginProbe(Protocol):
    """Port: pemeriksa origin nyata (diimplementasi adapter jaringan).

    Implementasi **tidak boleh melempar exception** — semua kegagalan
    dipetakan menjadi :class:`OriginProbeOutcome` (REFUSED/TIMEOUT/ERROR).
    """

    def probe(
        self, target: OriginTarget, timeout_seconds: float
    ) -> OriginProbeOutcome:
        ...


def validate_origin_target(target: OriginTarget) -> str | None:
    """Validasi konfigurasi origin (PRD-01 §7.4). None berarti valid."""
    return target.validation_error()


def origin_target_from_service(
    service: str,
) -> tuple[OriginTarget | None, str | None]:
    """Petakan nilai ``service`` ingress → :class:`OriginTarget`.

    Komponen baru Task 2.6 (keputusan PC-2, disetujui 2026-11-13) — fungsi
    murni atas teks, tanpa I/O. Kontrak hasil (tuple):

    - ``(target, None)``  — service dapat diprobe (http/https).
    - ``(None, None)``    — service catch-all (``http_status:``) — **bukan**
      error; pemanggil melewatinya dengan catatan.
    - ``(None, pesan)``   — tidak dapat dipetakan (scheme tidak didukung /
      URL rusak / port tidak valid); pesan aman untuk ditampilkan.

    Port tanpa nilai eksplisit mengikuti semantik URL standar
    (http=80, https=443) — konstanta protokol, bukan asumsi deployment.
    Pemanggil TIDAK boleh mengasumsikan baris ingress pertama adalah
    target aktif (keputusan PC-2): baris mana pun yang dapat dipetakan
    diperiksa masing-masing, dan keambiguanan multi-origin ditangani
    eksplisit oleh pemanggil.
    """
    import urllib.parse

    normalized = service.strip() if isinstance(service, str) else ""
    if not normalized:
        return None, "nilai service kosong"
    if normalized.startswith("http_status:"):
        return None, None  # catch-all — bukan origin lokal, dilewati

    try:
        parsed = urllib.parse.urlparse(normalized)
    except ValueError as exc:
        return None, f"service tidak dapat dibaca: {exc}"

    if parsed.scheme not in ("http", "https"):
        ringkas = normalized if len(normalized) <= 40 else normalized[:37] + "..."
        return None, f"service tidak didukung untuk pemeriksaan origin: {ringkas}"
    if not parsed.hostname:
        return None, "host origin tidak ditemukan dalam service"

    try:
        port = parsed.port
    except ValueError:
        return None, "port origin tidak valid (di luar rentang 1-65535 atau bukan angka)"
    if port is None:
        port = 80 if parsed.scheme == "http" else 443

    target = OriginTarget(
        host=parsed.hostname, port=port, scheme=parsed.scheme
    )
    error = target.validation_error()
    if error is not None:
        return None, error
    return target, None


def classify_probe_outcome(
    target: OriginTarget, outcome: OriginProbeOutcome
) -> OriginCheckResult:
    """Klasifikasikan hasil probe menjadi status origin PRD (deterministik)."""
    config_error = validate_origin_target(target)
    if config_error is not None:
        return OriginCheckResult(
            status=OriginStatus.MISCONFIGURED, detail=config_error
        )
    if outcome.kind is OriginProbeKind.REACHABLE:
        detail = "origin merespons"
        if outcome.http_status is not None:
            detail += f" (HTTP {outcome.http_status})"
        return OriginCheckResult(
            status=OriginStatus.HEALTHY,
            detail=detail,
            http_status=outcome.http_status,
        )
    if outcome.kind is OriginProbeKind.REFUSED:
        return OriginCheckResult(
            status=OriginStatus.UNREACHABLE,
            detail="koneksi ditolak — layanan origin tidak merespons pada "
            f"{target.host}:{target.port}",
        )
    if outcome.kind is OriginProbeKind.TIMEOUT:
        return OriginCheckResult(
            status=OriginStatus.UNREACHABLE,
            detail="tidak ada respons dalam batas waktu — kemungkinan origin "
            "mati, lambat, atau jaringan memblokir; hasil belum dapat "
            "dipastikan sepenuhnya",
        )
    return OriginCheckResult(
        status=OriginStatus.UNKNOWN,
        detail="pemeriksaan gagal — hasil belum dapat dipastikan"
        + (f": {outcome.detail}" if outcome.detail else ""),
    )


def classify_probe_error(target: OriginTarget, error_text: str) -> OriginCheckResult:
    """Klasifikasi untuk jalur error tak terduga pada pemeriksa."""
    del target  # validasi tetap dilakukan pemanggil sebelum probe
    return OriginCheckResult(
        status=OriginStatus.UNKNOWN,
        detail="pemeriksaan origin gagal — hasil belum dapat dipastikan"
        + (f": {error_text}" if error_text else ""),
    )
