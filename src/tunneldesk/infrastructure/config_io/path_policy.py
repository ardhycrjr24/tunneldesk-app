"""Kebijakan validasi path tulis konfigurasi (Task 2.5, keputusan PO Q3b).

Sumber normatif: PRD-01 §10 ("Validasi path file untuk mencegah penulisan
ke lokasi yang tidak diinginkan") + PRD-02 §3.3 ("Uji path yang tidak
valid dan input berbahaya") + keputusan PO Q3b (2026-11-12):
path absolut ternormalisasi, tanpa traversal, tanpa symlink/reparse,
regular file, parent ada & tervalidasi, direktori sistem ditolak,
tanpa pembuatan parent otomatis, tanpa penulisan acak semata karena
pemanggil mengirim ``Path``.

Desain:
- Status tertutup + result object (tanpa exception) — konsisten dengan
  gaya backup_io/backup_service; pesan detail disanitasi oleh pemanggil.
- Pemeriksaan filesystem memakai ``os.path`` atas representasi string
  sehingga logika kebijakan (termasuk daftar direktori sistem Windows)
  dapat diuji PORTABEL dengan injeksi platform, tanpa OS target dan
  tanpa akses filesystem nyata untuk kasus tolak-logika.
- Pemeriksaan berlapis: struktural (absolut/traversal) → daftar tolak
  (direktori sistem + deny-prefix milik aplikasi) → filesystem (parent,
  symlink, regular file). Urutan ini memastikan kegagalan kebijakan
  terdeteksi sebelum I/O mana pun.

Limitasi jujur (didokumentasikan, TIDAK diklaim tertutup):
- Symlink/junction pada leluhur DI ATAS parent langsung tidak diperiksa
  per-komponen; OS me-resolve-nya. Yang diperiksa: target (islink +
  junction) + parent langsung (islink + junction) + regular-file.
- Windows: junction (reparse point IO_REPARSE_TAG_MOUNT_POINT) diperiksa
  via ``Path.is_junction`` bila tersedia (Python ≥3.12, OS Windows);
  bentuk reparse lain (mis. OneDrive placeholder) tidak dibedakan dari
  file biasa.
- Kebijakan ini mendeteksi, bukan mengunci — jendela TOCTOU kecil antara
  validasi dan replace tetap ada (diperkecil: writer mem-validasi ulang
  tepat sebelum menulis; service memverifikasi ulang hash sumber).
"""

from __future__ import annotations

import enum
import ntpath
import os
import posixpath
import stat as stat_module
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath

__all__ = [
    "PathValidationResult",
    "PathValidationStatus",
    "normalize_platform",
    "validate_config_write_path",
]


class PathValidationStatus(enum.Enum):
    """Status validasi path tulis — kategori tertutup."""

    OK = "OK"
    NOT_ABSOLUTE = "NOT_ABSOLUTE"
    TRAVERSAL = "TRAVERSAL"
    SYSTEM_DIRECTORY = "SYSTEM_DIRECTORY"
    DENIED_PREFIX = "DENIED_PREFIX"
    PARENT_MISSING = "PARENT_MISSING"
    PARENT_NOT_DIRECTORY = "PARENT_NOT_DIRECTORY"
    PARENT_SYMLINK = "PARENT_SYMLINK"
    SYMLINK = "SYMLINK"
    NOT_REGULAR_FILE = "NOT_REGULAR_FILE"


@dataclass(frozen=True)
class PathValidationResult:
    """Hasil validasi path — status + alasan (tanpa isi file)."""

    status: PathValidationStatus
    ok: bool
    detail: str = ""


def normalize_platform(platform: str | None) -> str:
    """Normalisasi nama platform ke ``"posix"``/``"windows"``.

    ``sys.platform`` (win32/darwin/linux) dipetakan; injeksi uji memakai
    dua nilai kanonis langsung.
    """
    raw = platform if platform is not None else sys.platform
    return "windows" if raw in ("win32", "windows") else "posix"


_WINDOWS_SYSTEM_PREFIXES: tuple[str, ...] = (
    "c:\\windows",
    "c:\\program files",
    "c:\\program files (x86)",
    "c:\\programdata",
)

_POSIX_SYSTEM_PREFIXES: tuple[str, ...] = (
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib32",
    "/lib64",
    "/proc",
    "/sbin",
    "/sys",
    "/system",
    "/library",
    "/tmp",
    "/usr",
    "/var",
)

# Alias kanonis macOS (fakta OS stabil: /etc, /var, /tmp adalah symlink ke
# /private/*) — koreksi audit T-3: tanpa ini, bentuk kanonis /private/etc
# melewati daftar padahal /etc ditolak. Dihardcode agar deterministik dan
# portabel (realpath saat import berperilaku beda antar OS); bentuk kanonis
# lain ditangkap saat pemeriksaan via realpath atas path target.
_POSIX_CANONICAL_ALIASES: tuple[str, ...] = (
    "/private/etc",
    "/private/var",
    "/private/tmp",
)

_POSIX_SYSTEM_PREFIXES_ALL: tuple[str, ...] = _POSIX_SYSTEM_PREFIXES + _POSIX_CANONICAL_ALIASES

_WINDOWS_SYSTEM_PREFIXES_CANONICAL: tuple[str, ...] | None = None


def _windows_canonical_prefixes() -> tuple[str, ...]:
    """Prefiks sistem Windows dalam bentuk kanonis (lazy, hanya di Windows
    nyata — realpath lintas-OS menghasilkan bentuk tidak bermakna; koreksi T-3).

    ``ntpath.realpath`` di Windows menyelesaikan komponen yang ADA melalui
    filesystem (termasuk ekspansi nama-pendek 8.3 oleh GetFinalPathNameByHandle)
    sehingga alias seperti ``C:\\PROGRA~1`` tercocokkan ke ``c:\\program files``.
    Perilaku 8.3 pada volume tertentu TIDAK diverifikasi fisik (lihat laporan).
    """
    global _WINDOWS_SYSTEM_PREFIXES_CANONICAL
    if _WINDOWS_SYSTEM_PREFIXES_CANONICAL is None:
        import ntpath

        canonical: set[str] = set()
        for prefix in _WINDOWS_SYSTEM_PREFIXES:
            canonical.add(_normalized_windows_string(Path(prefix)))
            resolved = ntpath.realpath(prefix)
            canonical.add(_normalized_windows_string(Path(resolved)))
        _WINDOWS_SYSTEM_PREFIXES_CANONICAL = tuple(sorted(canonical))
    return _WINDOWS_SYSTEM_PREFIXES_CANONICAL


def _normalized_windows_string(path: Path) -> str:
    """Bentuk kanonis pembanding Windows: backslash + huruf kecil,
    berakhiran pemisah agar cocok berbatas komponen."""
    return str(path).replace("/", "\\").rstrip("\\").lower() + "\\"


def _reject_system_directory(target: Path, platform: str) -> bool:
    """True bila target berada di bawah direktori sistem platform.

    Koreksi audit T-3: pencocokan KANONIS — bentuk literal DAN bentuk
    ter-resolve (realpath atas komponen yang ada) dibandingkan terhadap
    daftar yang memuat alias kanonis (macOS: /private/{etc,var,tmp};
    Windows nyata: resolusi ntpath.realpath termasuk nama-pendek 8.3).
    Kedua sisi diberi akhiran pemisah sehingga cocoknya berbatas
    komponen (``/etc/foo`` ditolak, ``/etcfoo`` tidak; ``C:\\WindowsX``
    tidak dianggap di bawah ``C:\\Windows``). Pembandingan tidak
    sensitif huruf (filesystem Windows dan macOS umumnya
    case-insensitive; pada Linux case-sensitive, menolak lebih banyak
    variasi huruf = konservatif-aman).
    """
    if platform == "windows":
        literal = _normalized_windows_string(target)
        if any(
            literal.startswith(prefix + "\\")
            for prefix in _WINDOWS_SYSTEM_PREFIXES
        ):
            return True
        # Kanonis hanya di OS Windows nyata (realpath lintas-OS tidak
        # bermakna); di luar itu pencocokan literal portabel saja.
        if sys.platform == "win32":
            canonical = _normalized_windows_string(Path(ntpath.realpath(str(target))))
            return any(
                canonical.startswith(prefix + "\\")
                for prefix in _windows_canonical_prefixes()
            )
        return False
    literal = str(target).rstrip("/").lower() + "/"
    if any(
        literal.startswith(prefix + "/")
        for prefix in _POSIX_SYSTEM_PREFIXES_ALL
    ):
        return True
    # Bentuk ter-resolve: symlink/alias yang mengarah ke direktori sistem
    # ditolak meski path literalnya di luar daftar (koreksi T-3).
    resolved = posixpath.realpath(str(target)).rstrip("/").lower() + "/"
    if resolved == literal:
        return False
    return any(
        resolved.startswith(prefix + "/")
        for prefix in _POSIX_SYSTEM_PREFIXES_ALL
    )


def _is_reparse_point(raw: str, platform: str) -> bool:
    """True bila path (string) adalah symlink atau junction Windows."""
    if os.path.islink(raw):
        return True
    if platform != "windows":
        return False
    # Path.is_junction tersedia sejak 3.12 dan hanya relevan di OS
    # Windows; di luar itu pemeriksaan dilewati (limitasi terdokumentasi).
    try:
        junction_check = getattr(Path(raw), "is_junction", None)
    except (OSError, ValueError):  # path tak valid → perlakukan curiga
        return True
    if callable(junction_check):
        try:
            return bool(junction_check())
        except OSError:
            return True  # tidak dapat diperiksa → perlakukan curiga
    return False


def validate_config_write_path(
    target: Path,
    *,
    platform: str | None = None,
    deny_prefixes: Sequence[Path] = (),
) -> PathValidationResult:
    """Validasi ``target`` sebagai path tulis konfigurasi (kebijakan Q3b).

    Urutan pemeriksaan (berhenti pada kegagalan pertama):
    1. absolut + tanpa traversal (``..``),
    2. bukan direktori sistem (daftar per platform — logika string),
    3. bukan di bawah ``deny_prefixes`` milik aplikasi,
    4. parent ada, berupa direktori, bukan symlink/junction,
    5. target bukan symlink/junction, dan bila sudah ada wajib regular
       file.

    ``deny_prefixes`` dipakai lapisan application untuk menolak direktori
    data TunnelDesk sendiri (settings/log/backup) — infrastruktur tidak
    mengenal lokasi tersebut (arah dependensi A-08).

    ``target`` menerima ``PurePosixPath``/``PureWindowsPath`` untuk
    pengujian portabel logika platform (tanpa OS target); objek
    PurePath dipertahankan apa adanya agar rasa path tidak dipaksa
    mengikuti OS proses.
    """
    if not isinstance(target, PurePath):
        target = Path(target)
    resolved_platform = normalize_platform(platform)

    if not target.is_absolute():
        return PathValidationResult(
            PathValidationStatus.NOT_ABSOLUTE,
            ok=False,
            detail="path target wajib absolut",
        )
    if ".." in target.parts:
        return PathValidationResult(
            PathValidationStatus.TRAVERSAL,
            ok=False,
            detail="path target memuat traversal '..' — ditolak",
        )
    if _reject_system_directory(target, resolved_platform):
        return PathValidationResult(
            PathValidationStatus.SYSTEM_DIRECTORY,
            ok=False,
            detail="target berada di dalam direktori sistem — ditolak",
        )
    raw_target = str(target)
    for prefix in deny_prefixes:
        # Pembandingan leksikal (abspath, tanpa akses FS) — pelarian
        # via symlink sudah tertutup pemeriksaan PARENT_SYMLINK/SYMLINK.
        prefix_raw = os.path.abspath(str(prefix))
        target_raw = os.path.abspath(raw_target)
        if target_raw == prefix_raw or target_raw.startswith(
            prefix_raw.rstrip(os.sep) + os.sep
        ):
            return PathValidationResult(
                PathValidationStatus.DENIED_PREFIX,
                ok=False,
                detail="target berada di dalam direktori data aplikasi "
                "— ditolak",
            )

    parent = target.parent
    raw_parent = str(parent)
    if not os.path.exists(raw_parent):
        return PathValidationResult(
            PathValidationStatus.PARENT_MISSING,
            ok=False,
            detail="direktori induk tidak ada — tidak dibuat otomatis",
        )
    if not os.path.isdir(raw_parent):
        return PathValidationResult(
            PathValidationStatus.PARENT_NOT_DIRECTORY,
            ok=False,
            detail="induk target bukan direktori",
        )
    if _is_reparse_point(raw_parent, resolved_platform):
        return PathValidationResult(
            PathValidationStatus.PARENT_SYMLINK,
            ok=False,
            detail="induk target adalah symlink/reparse point — ditolak",
        )
    if _is_reparse_point(raw_target, resolved_platform):
        return PathValidationResult(
            PathValidationStatus.SYMLINK,
            ok=False,
            detail="target adalah symlink/reparse point — ditolak",
        )
    if os.path.exists(raw_target):
        try:
            mode = os.stat(raw_target).st_mode
        except OSError as exc:
            return PathValidationResult(
                PathValidationStatus.NOT_REGULAR_FILE,
                ok=False,
                detail=f"target tidak dapat diperiksa: {exc}",
            )
        if not stat_module.S_ISREG(mode):
            return PathValidationResult(
                PathValidationStatus.NOT_REGULAR_FILE,
                ok=False,
                detail="target sudah ada dan bukan file reguler",
            )
    return PathValidationResult(PathValidationStatus.OK, ok=True)
