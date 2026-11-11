"""Penulis konfigurasi atomik (Task 2.5) — implementasi port ``ConfigFileWriter``.

Komponen resmi (IMPLEMENTATION_PLAN 2.5, PRD-01 §10): penulisan atomik +
pembatasan izin file. Kontrak port (domain/config/backup.py:117): tulis
atomik (temp + replace) sehingga target tidak pernah setengah tertulis;
verifikasi akhir oleh pemanggil.

Jaminan (jujur — TIDAK identik antar OS):
- **Target tidak pernah setengah tertulis**: bytes ditulis ke file sementara
  di direktori yang SAMA (filesystem sama — syarat rename atomik), isi temp
  diverifikasi SHA-256, lalu replace atomik. POSIX: ``rename(2)`` atomik.
  Windows: ``MoveFileEx(MOVEFILE_REPLACE_EXISTING)`` — atomik untuk file
  biasa pada volume yang sama.
- **TOCTOU parent-swap (koreksi audit T-1)** — dua strategi:
  * POSIX (kapabilitas ``dir_fd`` tersedia): direktori induk DIBUKA sekali
    (``os.open(O_NOFOLLOW)``) SEBELUM penulisan; seluruh operasi — probe
    target (lstat), pembuatan temp (O_EXCL), tulis/fsync, verifikasi,
    chmod, dan ``os.replace`` — dilakukan **relatif terhadap fd
    direktori yang ter-pin** (``*at`` semantics). Menukar path induk
    setelah validasi TIDAK lagi mengarahkan tulisan ke direktori lain:
    fd tetap merujuk inode yang tervalidasi (teruji adversarial).
    Jendela sisa: menukar isi direktori ter-pin itu sendiri (attacker
    dengan hak tulis ke direktori tsb) — tereduksi ke minimum praktis,
    TIDAK diklaim tereliminasi.
  * Windows / platform tanpa ``dir_fd``: path-based + **penjaga identitas
    direktori** — ``(st_dev, st_ino)`` induk direkam sebelum menulis dan
    diverifikasi ulang (a) setelah pembuatan temp dan (b) TEPAT sebelum
    ``os.replace``; ketidakcocokan → batal, target utuh, temp bersih.
    Jendela mikro antara cek terakhir dan replace TETAP ADA — limitasi
    platform diakui jujur (tidak dapat dihilangkan di stdlib Python).
- **Durabilitas ≠ atomisitas**: flush + ``os.fsync`` pada temp sebelum
  replace (file fsync); POSIX menambah fsync direktori induk *best-effort*
  (kegagalan non-fatal — entri rename mungkin belum persist saat crash,
  didokumentasikan). Windows tidak memiliki padanan fsync-direktori.
- **Target terkunci (Windows)**: bila target dibuka proses lain tanpa
  ``FILE_SHARE_DELETE``, replace dapat gagal (``PermissionError``/
  WinError 32) — dilaporkan terstruktur, **tanpa retry otomatis** (pola
  proyek: kegagalan = status jelas, bukan sihir). Interferensi antivirus
  pada file baru termasuk kategori ini (best-effort, tidak dapat
  dihilangkan).
- **Izin (keputusan PO Q3a)**: file lama → ``st_mode`` dipertahankan apa
  adanya (tanpa memperlebar, tanpa mengubah kepemilikan); file baru →
  0o600 (POSIX). Windows: file mengikuti ACL profil pengguna; temp yang
  baru dibuat mewarisi ACL induk — **preservasi ACL eksplisit file lama
  TIDAK dijamin** pada replace (koreksi dokumentasi L-1); ``os.chmod``
  Windows hanya mengatur bit read-only — **bukan** padanan keamanan POSIX
  (jujur, tidak diklaim setara). Kegagalan chmod dilaporkan eksplisit
  (OSError) — target tidak tersentuh.
- **Error model**: hanya ``OSError`` (dan subclass) — kontrak konsumen
  aktual ``BackupService.restore`` yang menangkap ``OSError`` saja.
- Temp file dibersihkan di semua jalur gagal (``finally``); nama temp
  berkarakter acak (O_EXCL) sehingga tidak mungkin menabrak file pengguna.

Validasi path kebijakan Q3b dijalankan ulang di sini TEPAT sebelum
menulis (lapisan pertahanan terakhir; kebijakan penuh = tanggung jawab
pemanggil via ``path_policy``). Tanpa pembuatan direktori otomatis.
"""

from __future__ import annotations

import errno
import os
import stat
import tempfile
from pathlib import Path
from uuid import uuid4

from tunneldesk.domain.config.backup import sha256_hex
from tunneldesk.infrastructure.config_io.path_policy import (
    normalize_platform,
    validate_config_write_path,
)

__all__ = ["AtomicConfigFileWriter", "file_sha256_hex"]

_TEMP_SUFFIX = ".tmp-"


def file_sha256_hex(path: Path) -> str:
    """SHA-256 hex isi file (pembantu internal; OSError melempar apa adanya)."""
    return sha256_hex(Path(path).read_bytes())


def _dir_fd_supported() -> bool:
    """True bila platform mendukung seluruh operasi ``*at`` yang dipakai.

    Diperiksa saat panggilan (bukan saat import) agar dapat diinjeksikan
    untuk menguji jalur fallback secara deterministik. Catatan jujur:
    ``os.supports_dir_fd`` pada sebagian build CPython tidak mencantumkan
    ``os.replace`` padahal kwargs-nya didukung (terverifikasi empiris di
    macOS/CPython 3.11) — karena itu jangkar = ``os.rename`` (semantik
    replace pada POSIX identik), dengan fallback ``TypeError → rename``
    di titik replace.
    """
    if os.name != "posix":
        return False
    required = (os.open, os.stat, os.chmod, os.unlink)
    if not all(op in os.supports_dir_fd for op in required):
        return False
    return os.rename in os.supports_dir_fd


def _sha256_of_handle(handle: object) -> str:
    """SHA-256 isi file temp dari handle (titik injeksi uji verifikasi)."""
    handle.seek(0)  # type: ignore[attr-defined]
    return sha256_hex(handle.read())  # type: ignore[attr-defined]


class AtomicConfigFileWriter:
    """Adapter penulis konfigurasi produksi (memenuhi port Task 2.4).

    Melempar **hanya** ``OSError`` untuk semua kegagalan (termasuk
    pelanggaran kebijakan path — dipetakan ke ``OSError`` agar konsumen
    port tidak perlu menangkap jenis lain).
    """

    def __init__(self, *, platform: str | None = None) -> None:
        #: Injeksi uji ("posix"/"windows"); default dari sys.platform.
        self._platform = normalize_platform(platform)

    # ------------------------------------------------------------------
    # Port ConfigFileWriter
    # ------------------------------------------------------------------
    def write_config_bytes(self, target: Path, data: bytes) -> None:
        """Tulis ``data`` ke ``target`` secara atomik (kontrak port).

        Urutan: validasi kebijakan path → pilih strategi platform:
        POSIX ``dir_fd`` ter-pin (T-1) atau penjaga identitas induk
        (fallback). Kegagalan di langkah mana pun sebelum replace →
        target **terjamin utuh**; setelah replace → target berisi
        ``data`` utuh (verifikasi akhir oleh pemanggil).
        """
        target = Path(target)
        # Identitas induk direkam SEBELUM validasi (T-1): penukaran induk
        # setelah titik ini terdeteksi oleh penjaga identitas pada jalur
        # fallback; jalur dir_fd meminnya sepenuhnya via fd.
        identity = self._dir_identity(target.parent)
        policy = validate_config_write_path(target, platform=self._platform)
        if not policy.ok:
            raise OSError(
                errno.EINVAL,
                f"target tidak memenuhi kebijakan path "
                f"({policy.status.value}): {policy.detail}",
            )
        if _dir_fd_supported():
            self._write_dir_fd_pinned(target, data)
        else:
            self._write_identity_guarded(target, data, identity)

    # ------------------------------------------------------------------
    # Strategi POSIX — direktori induk ter-pin via fd (T-1)
    # ------------------------------------------------------------------
    def _write_dir_fd_pinned(self, target: Path, data: bytes) -> None:
        """Tulis dalam direktori induk yang DIBUKA dan ter-pin.

        Semua operasi ber-relative terhadap ``dir_fd``: pertukaran path
        induk setelah validasi tidak dapat mengarahkan tulisan ke
        direktori lain (fd merujuk inode tervalidasi). Tanpa operasi
        berbasis path setelah titik ini.
        """
        dir_fd = os.open(
            target.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        tmp_name = f".{target.name}{_TEMP_SUFFIX}{uuid4().hex}"
        try:
            target_mode = self._probe_target_in_dir(target.name, dir_fd)
            # Temp eksklusif DI DALAM direktori ter-pin (bukan via path).
            fd: int | None = None
            try:
                fd = self._create_temp_in_dir(dir_fd, tmp_name)
                with os.fdopen(fd, "wb+") as handle:
                    fd = None  # kepemilikan fd beralih ke handle
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                    if _sha256_of_handle(handle) != sha256_hex(data):
                        raise OSError(
                            errno.EIO,
                            "verifikasi isi file sementara gagal — target "
                            "tidak disentuh",
                        )
                if target_mode is not None:
                    # Mode file lama dipertahankan (Q3a) — operasi *at,
                    # gagal → OSError eksplisit.
                    os.chmod(tmp_name, target_mode, dir_fd=dir_fd)
                # Replace di DALAM direktori ter-pin; bila build Python
                # tidak menandai replace dir_fd (set tidak lengkap),
                # rename(2) POSIX memiliki semantik replace yang sama.
                try:
                    os.replace(
                        tmp_name,
                        target.name,
                        src_dir_fd=dir_fd,
                        dst_dir_fd=dir_fd,
                    )
                except TypeError:  # pragma: no cover — build tanpa kwargs
                    os.rename(
                        tmp_name,
                        target.name,
                        src_dir_fd=dir_fd,
                        dst_dir_fd=dir_fd,
                    )
            finally:
                if fd is not None:
                    os.close(fd)
                try:
                    os.unlink(tmp_name, dir_fd=dir_fd)
                except FileNotFoundError:
                    pass  # sudah berganti nama → tidak ada temp tersisa
            # fsync direktori ter-pin (best-effort, non-fatal).
            try:
                os.fsync(dir_fd)
            except OSError:
                pass
        finally:
            os.close(dir_fd)

    @staticmethod
    def _probe_target_in_dir(name: str, dir_fd: int) -> int | None:
        """Lstat target DI DALAM direktori ter-pin (tanpa follow).

        Mengembalikan mode file lama (dipertahankan, Q3a) atau ``None``
        bila target belum ada. Symlink/bukan-regular → ditolak (pemeriksaan
        ulang keadaan terkini di dalam direktori tervalidasi).
        """
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise OSError(
                errno.EINVAL,
                "target bukan file reguler di direktori tervalidasi "
                "(lstat ulang) — batal",
            )
        return stat.S_IMODE(st.st_mode)

    @staticmethod
    def _create_temp_in_dir(dir_fd: int, tmp_name: str) -> int:
        """Buat file temp O_EXCL 0o600 di dalam direktori ter-pin.

        Kolisi nama (praktis mustahil, uuid4) dicoba ulang terbatas.
        """
        name = tmp_name
        for _ in range(5):
            try:
                return os.open(
                    name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=dir_fd,
                )
            except FileExistsError:
                name = f"{tmp_name.rsplit(_TEMP_SUFFIX, 1)[0]}{_TEMP_SUFFIX}{uuid4().hex}"
        raise OSError(errno.EEXIST, "tidak dapat membuat nama file sementara unik")

    # ------------------------------------------------------------------
    # Strategi fallback (Windows / platform tanpa dir_fd) — T-1
    # ------------------------------------------------------------------
    def _write_identity_guarded(
        self,
        target: Path,
        data: bytes,
        identity: tuple[int, int] | None,
    ) -> None:
        """Tulis path-based dengan penjaga identitas direktori induk.

        ``identity`` direkam SEBELUM validasi (oleh pemanggil) dan
        diverifikasi ulang setelah mkstemp dan TEPAT sebelum replace —
        menukar induk di antara titik-titik terdeteksi dan membatalkan
        tulisan (target utuh, temp bersih). Jendela mikro setelah cek
        terakhir: limitasi platform yang diakui (tidak dapat
        dihilangkan di stdlib).
        """
        parent = target.parent

        expected_sha = sha256_hex(data)
        # mkstemp: pembuatan aman (O_EXCL), dir SAMA dengan target
        # (rename atomik); parent tidak ada → OSError.
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{target.name}{_TEMP_SUFFIX}", dir=parent
        )
        temp_path = Path(temp_name)
        fd_terbuka = True
        try:
            self._ensure_parent_stable(target, parent, identity)
            try:
                handle = os.fdopen(fd, "wb")
            except OSError:
                os.close(fd)
                fd_terbuka = False
                raise
            fd_terbuka = False  # kepemilikan fd beralih ke handle
            with handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            if file_sha256_hex(temp_path) != expected_sha:
                raise OSError(
                    errno.EIO,
                    "verifikasi isi file sementara gagal — target tidak "
                    "disentuh",
                )
            self._apply_permissions(temp_path, target)
            self._ensure_parent_stable(target, parent, identity)
            os.replace(temp_path, target)
        finally:
            # Pelajaran CI Windows (WinError 32): file dengan handle
            # terbuka TIDAK dapat dihapus — fd ditutup SEBELUM unlink
            # pada semua jalur (kegagalan di tengah menutup fd dulu).
            if fd_terbuka:
                try:
                    os.close(fd)
                except OSError:
                    pass
            temp_path.unlink(missing_ok=True)

    def _dir_identity(self, parent: Path) -> tuple[int, int] | None:
        """Identitas direktori (dev, ino); None bila tidak ter-stat."""
        try:
            st = os.stat(parent)
        except OSError:
            return None
        return (st.st_dev, st.st_ino)

    def _ensure_parent_stable(
        self,
        target: Path,
        parent: Path,
        identity: tuple[int, int] | None,
    ) -> None:
        """Penjaga T-1 jalur fallback: identitas induk + kebijakan ulang.

        Deteksi (a) induk tertukar (dev/ino berubah atau tidak ter-stat)
        dan (b) perubahan keadaan yang melanggar kebijakan (symlink target
        dsb.) — semuanya SEBELUM byte berikutnya ditulis/direplace.
        """
        if self._dir_identity(parent) != identity:
            raise OSError(
                errno.EINVAL,
                "direktori induk berubah selama penulisan (TOCTOU guard) "
                "— batal, target tidak disentuh",
            )
        recheck = validate_config_write_path(target, platform=self._platform)
        if not recheck.ok:
            raise OSError(
                errno.EINVAL,
                f"kebijakan path berubah selama penulisan "
                f"({recheck.status.value}) — batal, target tidak disentuh",
            )

    # ------------------------------------------------------------------
    # Internal bersama
    # ------------------------------------------------------------------
    def _apply_permissions(self, temp_path: Path, target: Path) -> None:
        """Izin temp sesuai keputusan Q3a sebelum replace (jalur fallback).

        POSIX: mode file lama dipertahankan; file baru tetap 0o600
        (warisan mkstemp). Windows: tidak ada chmod — ACL mengikuti
        profil pengguna (dokumentasi limitasi di docstring modul).
        """
        if self._platform == "windows":
            return
        try:
            mode = stat.S_IMODE(target.stat().st_mode)
        except FileNotFoundError:
            return  # file baru — izin ketat mkstemp (0o600) dipakai
        os.chmod(temp_path, mode)  # gagal → OSError eksplisit (Q3a)
