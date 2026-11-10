"""Model & klasifikasi deteksi (E-5, tugas 2.1) — murni domain.

Sumber: PRD-01 §7.3 (deteksi konfigurasi), A-09/K-06/K-07 (mode token &
Windows Service = status hanya-baca + penjelasan), D-18 (tanpa shell,
hanya proses milik sendiri). Kategori mode & status tertutup — jangan
diperluas tanpa dasar dokumen.

Modul murni: tanpa subprocess/Qt/platform/ I/O.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "InstallMode",
    "DetectionConfidence",
    "DetectionSource",
    "ExecutableFinding",
    "ConfigCandidate",
    "ModeIndicator",
    "DetectionReport",
    "parse_version_output",
    "classify_mode",
    "dedupe_executables",
]


class InstallMode(enum.Enum):
    """Mode operasi terdeteksi (A-09/K-06/K-07) — hanya-baca."""

    CONFIG_FILE = "CONFIG_FILE"
    TOKEN = "TOKEN"
    SERVICE = "SERVICE"
    UNKNOWN = "UNKNOWN"


class DetectionConfidence(enum.Enum):
    """Tingkat kepastian hasil deteksi (PRD-01 §7.5: jangan overclaim)."""

    CONFIRMED = "CONFIRMED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class DetectionSource(enum.Enum):
    """Sumber penemuan — wajib dilaporkan bersama temuan (E-5 kontrak)."""

    PATH = "PATH"
    COMMON_LOCATION = "COMMON_LOCATION"
    USER_SPECIFIED = "USER_SPECIFIED"
    SERVICE_QUERY = "SERVICE_QUERY"


@dataclass(frozen=True)
class ExecutableFinding:
    """Eksekusi cloudflared yang ditemukan di satu lokasi."""

    path: Path
    source: DetectionSource
    version: str | None = None
    #: Alasan versi tidak diketahui (kosong bila versi diketahui).
    version_detail: str = ""

    def version_display(self) -> str:
        return self.version if self.version is not None else "tidak diketahui"


@dataclass(frozen=True)
class ConfigCandidate:
    """Kandidat file konfigurasi — ditemukan, **belum** tervalidasi
    (validasi isi adalah E-6)."""

    path: Path
    source: DetectionSource


@dataclass(frozen=True)
class ModeIndicator:
    """Indikator mode operasi — selalu hanya-baca (A-09)."""

    mode: InstallMode
    evidence: str
    #: True bila bukti struktural definitif (mis. service terdaftar).
    definitive: bool = False


@dataclass(frozen=True)
class DetectionReport:
    """Hasil deteksi terstruktur — read-only, tanpa isi file konfigurasi.

    ``sources`` merangkum sumber pemeriksaan (kontrak E-5: sumber wajib
    dilaporkan); rincian per-temuan tetap ada di masing-masing finding.
    """

    executables: tuple[ExecutableFinding, ...] = ()
    config_candidates: tuple[ConfigCandidate, ...] = ()
    mode_indicators: tuple[ModeIndicator, ...] = ()
    sources: tuple[DetectionSource, ...] = ()
    mode: InstallMode = InstallMode.UNKNOWN
    mode_certain: bool = False
    mode_explanation: str = ""
    explanations: tuple[str, ...] = field(default_factory=tuple)
    confidence: DetectionConfidence = DetectionConfidence.UNKNOWN

    @property
    def has_executable(self) -> bool:
        return bool(self.executables)

    @property
    def best_executable(self) -> ExecutableFinding | None:
        """Executable pertama (PATH diutamakan atas lokasi umum)."""
        return self.executables[0] if self.executables else None

    @property
    def has_config_candidates(self) -> bool:
        return bool(self.config_candidates)


_VERSION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"cloudflared\s+version\s+(\S+)", re.IGNORECASE),
    re.compile(r"\b(\d{4}\.\d+\.\d+)\b"),
)


def parse_version_output(output: str) -> str | None:
    """Parsir versi dari output ``cloudflared --version`` — toleran format.

    Mengembalikan None bila tidak ada pola versi yang dikenali (R-07).
    Output dipercaya berasal dari proses yang sudah melewati jalur aman;
    pemanggil wajib mensanitasi sebelum menyimpan (kontrak E-5).
    """
    for pattern in _VERSION_PATTERNS:
        match = pattern.search(output)
        if match:
            return match.group(1)
    return None


def dedupe_executables(
    findings: tuple[ExecutableFinding, ...]
) -> tuple[ExecutableFinding, ...]:
    """Hilangkan duplikasi path (PATH dan lokasi umum bisa bertumpuk),
    mempertahankan kemunculan pertama."""
    seen: set[Path] = set()
    unique: list[ExecutableFinding] = []
    for finding in findings:
        key = finding.path
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return tuple(unique)


def classify_mode(
    indicators: tuple[ModeIndicator, ...],
) -> tuple[InstallMode, bool, str]:
    """Klasifikasi mode operasi dari indikator — deterministik.

    Aturan (urutan keputusan):
    1. Service terdaftar (bukti definitif) → SERVICE, pasti.
    2. File konfigurasi ditemukan → CONFIG_FILE, pasti.
    3. Hanya indikasi token (config tidak ada, cloudflared ada) → TOKEN,
       **tidak pasti** (ketiadaan config bukti lemah).
    4. Tanpa indikator → UNKNOWN.
    """
    service = next((i for i in indicators if i.mode is InstallMode.SERVICE), None)
    if service is not None and service.definitive:
        return (
            InstallMode.SERVICE,
            True,
            f"layanan 'cloudflared' terdaftar — dikelola di luar TunnelDesk: {service.evidence}",
        )
    config = next(
        (i for i in indicators if i.mode is InstallMode.CONFIG_FILE), None
    )
    if config is not None:
        return (
            InstallMode.CONFIG_FILE,
            True,
            f"file konfigurasi ditemukan: {config.evidence}",
        )
    token = next((i for i in indicators if i.mode is InstallMode.TOKEN), None)
    if token is not None:
        return (
            InstallMode.TOKEN,
            False,
            "tidak ditemukan file konfigurasi — kemungkinan mode token; "
            "hasil tidak pasti dan mode ini di luar kendali TunnelDesk",
        )
    return InstallMode.UNKNOWN, False, "mode operasi tidak dapat dipastikan"
