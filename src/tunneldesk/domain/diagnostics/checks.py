"""Model pemeriksaan diagnostik (Task 2.7, PRD-01 §7.5) — murni domain.

Semantik hasil (keputusan PO P-2, ratifikasi 2026-11-13 — klasifikasi
berlapis per pemeriksaan):

- DNS: DNS_RESOLVED / DNS_UNRESOLVED / DNS_UNCONFIRMED
- TLS: TLS_VERIFIED / TLS_INVALID / TLS_UNCONFIRMED
- HTTP publik: PUBLIC_ENDPOINT_RESPONDING (2xx) / REDIRECTING (3xx) /
  REJECTING (4xx) / ERROR (5xx) / UNCONFIRMED (timeout/koneksi gagal)
- Proses/origin/konfigurasi: mempertahankan klasifikasi kontrak E-2/E-3/E-6.

``Certainty`` = tingkat kepastian (PRD-01 §7.5: "jika tidak, jelaskan
bahwa hasil belum dapat dipastikan") — hasil jaringan TIDAK pernah
diklaim mutlak. Hasil DNS/TLS/HTTP **tidak** digabung menjadi satu
status sukses/gagal (keputusan P-2).

Modul murni: tanpa socket/Qt/jaringan — probe nyata di infrastructure.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

__all__ = [
    "CheckKind",
    "Certainty",
    "DnsStatus",
    "TlsStatus",
    "PublicHttpStatus",
    "CheckResult",
    "DiagnosticReport",
]


class CheckKind(enum.Enum):
    """Kelompok pemeriksaan (PRD-01 §7.5) — kategori tertutup."""

    PROSES = "PROSES"
    ORIGIN = "ORIGIN"
    CONFIG = "CONFIG"
    DNS = "DNS"
    HTTPS = "HTTPS"
    PUBLIK = "PUBLIK"


class Certainty(enum.Enum):
    """Tingkat kepastian hasil (PRD-01 §7.5) — kategori tertutup."""

    TERVERIFIKASI = "TERVERIFIKASI"
    KEMUNGKINAN = "KEMUNGKINAN"
    TIDAK_DIPASTIKAN = "TIDAK_DIPASTIKAN"


class DnsStatus(enum.Enum):
    """Status resolusi DNS — kategori tertutup (keputusan P-2)."""

    DNS_RESOLVED = "DNS_RESOLVED"
    DNS_UNRESOLVED = "DNS_UNRESOLVED"
    DNS_UNCONFIRMED = "DNS_UNCONFIRMED"


class TlsStatus(enum.Enum):
    """Status koneksi TLS + sertifikat — kategori tertutup (P-2)."""

    TLS_VERIFIED = "TLS_VERIFIED"
    TLS_INVALID = "TLS_INVALID"
    TLS_UNCONFIRMED = "TLS_UNCONFIRMED"


class PublicHttpStatus(enum.Enum):
    """Status respons endpoint publik — kategori tertutup (P-2)."""

    PUBLIC_ENDPOINT_RESPONDING = "PUBLIC_ENDPOINT_RESPONDING"   # 2xx
    PUBLIC_ENDPOINT_REDIRECTING = "PUBLIC_ENDPOINT_REDIRECTING"  # 3xx (tidak diikuti)
    PUBLIC_ENDPOINT_REJECTING = "PUBLIC_ENDPOINT_REJECTING"      # 4xx
    PUBLIC_ENDPOINT_ERROR = "PUBLIC_ENDPOINT_ERROR"              # 5xx
    PUBLIC_ENDPOINT_UNCONFIRMED = "PUBLIC_ENDPOINT_UNCONFIRMED"  # timeout/gagal


@dataclass(frozen=True)
class CheckResult:
    """Hasil satu pemeriksaan — semua teks sudah disanitasi (D-18).

    ``status`` = nilai enum status kelompok terkait (Proses/Origin/Config
    memakai klasifikasi kontrak masing-masing; DNS/TLS/Publik memakai
    enum di modul ini) sebagai string untuk render — kesesuaian dijaga
    uji mapping.
    """

    kind: CheckKind
    certainty: Certainty
    status: str
    ringkasan: str
    kategori: str = ""
    langkah: str = ""
    detail: str = ""
    hostname: str = ""  # DNS/HTTPS/Publik (per hostname — multi-ingress jujur)
    addresses: tuple[str, ...] = ()  # hasil resolusi DNS (IP Edge — P-4)
    http_status: int | None = None
    cert_subject: str = ""  # P-4: field sertifikat publik (HTTPS)
    cert_issuer: str = ""
    cert_not_after: str = ""


@dataclass(frozen=True)
class DiagnosticReport:
    """Laporan diagnostik utuh (PRD-01 §7.5 paragraf 2)."""

    dibuat_epoch: float
    dibuat_iso: str
    versi_aplikasi: str
    results: tuple[CheckResult, ...]

    def by_kind(self, kind: CheckKind) -> tuple[CheckResult, ...]:
        """Hasil per kelompok (bisa lebih dari satu untuk DNS/HTTPS/Publik
        bila konfigurasi memuat beberapa hostname)."""
        return tuple(r for r in self.results if r.kind is kind)
