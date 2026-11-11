"""Penulis konfigurasi atomik (Task 2.5) — implementasi port ``ConfigFileWriter``.

Komponen resmi (IMPLEMENTATION_PLAN 2.5, PRD-01 §10): penulisan atomik +
pembatasan izin file. Kontrak port (domain/config/backup.py:117): tulis
atomik (temp + replace) sehingga target tidak pernah setengah tertulis;
verifikasi akhir oleh pemanggil.

Jaminan (jujur — TIDAK identik antar OS):
- **Target tidak pernah setengah tertulis**: bytes ditulis ke file sementara
  di direktori yang SAMA (filesystem sama — syarat rename atomik), isi temp
  diverifikasi SHA-256, lalu ``os.replace``. POSIX: ``rename(2)`` atomik.
  Windows: ``MoveFileEx(MOVEFILE_REPLACE_EXISTING)`` — atomik untuk file
  biasa pada volume yang sama.
- **Durabilitas ≠ atomisitas**: flush + ``os.fsync`` pada temp sebelum
  replace (file fsync); POSIX menambah fsync direktori induk *best-effort*
  (kegagalan non-fatal — entri rename mungkin belum persist saat crash,
  didokumentasikan). Windows tidak memiliki padanan fsync-direktori.
- **Target terkunci (Windows)**: bila target dibuka proses lain tanpa
  ``FILE_SHARE_DELETE``, ``os.replace`` dapat gagal (``PermissionError``/
  WinError 32) — dilaporkan terstruktur, **tanpa retry otomatis** (pola
  proyek: kegagalan = status jelas, bukan sihir). Interferensi antivirus
  pada file baru termasuk kategori ini (best-effort, tidak dapat
  dihilangkan).
- **Izin (keputusan PO Q3a)**: file lama → ``st_mode`` dipertahankan apa
  adanya (tanpa memperlebar, tanpa mengubah kepemilikan); file baru →
  ``mkstemp`` = 0o600 (POSIX). Windows: file mengikuti ACL profil
  pengguna; ``os.chmod`` Windows hanya mengatur bit read-only — **bukan**
  padanan keamanan POSIX (jujur, tidak diklaim setara). Kegagalan chmod
  dilaporkan eksplisit (OSError) — target tidak tersentuh.
- **Error model**: hanya ``OSError`` (dan subclass) — kontrak konsumen
  aktual ``BackupService.restore`` yang menangkap ``OSError`` saja.
- Temp file dibersihkan di semua jalur gagal (``finally``); nama temp
  berkarakter acak (``mkstemp`` O_EXCL) sehingga tidak mungkin menabrak
  file pengguna.

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

from tunneldesk.domain.config.backup import sha256_hex
from tunneldesk.infrastructure.config_io.path_policy import (
    normalize_platform,
    validate_config_write_path,
)

__all__ = ["AtomicConfigFileWriter", "file_sha256_hex"]


def file_sha256_hex(path: Path) -> str:
    """SHA-256 hex isi file (pembantu internal; OSError melempar apa adanya)."""
    return sha256_hex(Path(path).read_bytes())


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

        Urutan: validasi kebijakan path → temp (dir sama) → tulis + flush
        + fsync → verifikasi hash temp → izin → ``os.replace`` → fsync
        direktori (POSIX, best-effort). Kegagalan di langkah mana pun
        sebelum replace → target **terjamin utuh**; setelah replace →
        target berisi ``data`` utuh (verifikasi akhir oleh pemanggil).
        """
        target = Path(target)
        policy = validate_config_write_path(target, platform=self._platform)
        if not policy.ok:
            raise OSError(
                errno.EINVAL,
                f"target tidak memenuhi kebijakan path "
                f"({policy.status.value}): {policy.detail}",
            )

        expected_sha = sha256_hex(data)
        # mkstemp: pembuatan aman (O_EXCL), 0o600 di POSIX, dir SAMA
        # dengan target (rename atomik); parent tidak ada → OSError.
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{target.name}.tmp-", dir=target.parent
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
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
            os.replace(temp_path, target)
        finally:
            temp_path.unlink(missing_ok=True)
        self._fsync_parent_best_effort(target.parent)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _apply_permissions(self, temp_path: Path, target: Path) -> None:
        """Izin temp sesuai keputusan Q3a sebelum replace.

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

    def _fsync_parent_best_effort(self, parent: Path) -> None:
        """fsync direktori induk (POSIX saja, best-effort, non-fatal).

        Kegagalan TIDAK menggugurkan penulisan yang sudah atomik di
        memori; konsekuensi durabilitas crash terdokumentasi jujur.
        """
        if self._platform == "windows":
            return
        try:
            dir_fd = os.open(parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            os.close(dir_fd)
