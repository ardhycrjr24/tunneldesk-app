"""Model backup & restore konfigurasi (Task 2.4, PRD-01 §7.6, D-03, D-17).

Status tertutup dan terstruktur — semua jalur gagal dilaporkan tanpa
exception mentah ke pemanggil (kontrak E-5/E-6). Modul murni domain:
tanpa sqlite/subprocess/Qt.

Kebijakan tetap (disetujui Project Control, Task 2.4):
- Credential-file **tidak** di-backup dan isinya tidak pernah dibaca.
- Tanpa penghapusan/retensi otomatis (Q-09 masih MENUNGGU).
- Restore wajib konfirmasi eksplisit; penulisan produksi membutuhkan
  port :class:`ConfigFileWriter` (implementasi = Task 2.5, atomic write).
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from .model import ValidationOutcome

__all__ = [
    "BackupStatus",
    "RestoreStatus",
    "BackupRecord",
    "BackupResult",
    "RestoreOutcome",
    "ConfigFileWriter",
    "backup_filename_for",
    "sha256_hex",
]


class BackupStatus(enum.Enum):
    """Status pembuatan backup — kategori tertutup."""

    OK = "OK"
    SOURCE_NOT_FOUND = "SOURCE_NOT_FOUND"
    SOURCE_UNREADABLE = "SOURCE_UNREADABLE"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    WRITE_ERROR = "WRITE_ERROR"
    #: File backup berhasil dibuat; metadata gagal — file dipertahankan
    #: (recovery: retry register_backup, terdokumentasi).
    REGISTER_ERROR = "REGISTER_ERROR"


class RestoreStatus(enum.Enum):
    """Status restore — kategori tertutup."""

    RESTORED = "RESTORED"
    #: Kontrak terpenuhi; penulisan produksi menunggu Task 2.5 (atomic write).
    PENDING_ATOMIC_WRITE = "PENDING_ATOMIC_WRITE"
    RESTORE_NOT_CONFIRMED = "RESTORE_NOT_CONFIRMED"
    BACKUP_NOT_REGISTERED = "BACKUP_NOT_REGISTERED"
    BACKUP_FILE_MISSING = "BACKUP_FILE_MISSING"
    BACKUP_HASH_MISMATCH = "BACKUP_HASH_MISMATCH"
    BACKUP_VALIDATION_FAILED = "BACKUP_VALIDATION_FAILED"
    #: Backup target saat ini (pra-restore, keputusan PO Q4 Task 2.5)
    #: gagal dibuat/diverifikasi — restore dibatalkan tanpa menulis.
    PRE_RESTORE_BACKUP_FAILED = "PRE_RESTORE_BACKUP_FAILED"
    #: Target melanggar kebijakan path Q3b (deny-prefix direktori data
    #: aplikasi / struktural) — koreksi audit T-2: kebijakan yang sama
    #: dengan jalur apply, ditegakkan SEBELUM backup dan SEBELUM tulis.
    TARGET_POLICY_REJECTED = "TARGET_POLICY_REJECTED"
    TARGET_UNWRITABLE = "TARGET_UNWRITABLE"
    RESTORE_HASH_MISMATCH = "RESTORE_HASH_MISMATCH"
    REGISTER_ERROR = "REGISTER_ERROR"


@dataclass(frozen=True)
class BackupRecord:
    """Satu baris register metadata (D-03) — tanpa isi konfigurasi."""

    backup_id: str
    backup_filename: str
    created_at_epoch: float
    created_at_iso: str
    source_path: str
    backup_path: str
    size_bytes: int
    sha256: str
    trigger: str
    restored_at_epoch: float | None = None


@dataclass(frozen=True)
class BackupResult:
    """Hasil :meth:`BackupService.create_backup` — status + jejak."""

    status: BackupStatus
    ok: bool
    detail: str = ""
    backup_id: str | None = None
    backup_path: Path | None = None
    backup_filename: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    created_at_epoch: float | None = None
    #: Record siap-register bila REGISTER_ERROR (recovery manual/retry).
    pending_record: BackupRecord | None = None


@dataclass(frozen=True)
class RestoreOutcome:
    """Hasil restore — hasil **penyalinan** dan hasil **validasi ulang**
    dilaporkan terpisah (instruksi Task 2.4 §5.9)."""

    status: RestoreStatus
    ok: bool
    detail: str = ""
    backup_id: str | None = None
    backup_path: Path | None = None
    target_path: Path | None = None
    #: True bila byte benar-benar ditulis ke target.
    copied: bool = False
    restored_sha256: str | None = None
    #: Validasi ulang pasca-restore (E-6) — terpisah dari hasil salinan.
    post_restore_validation: ValidationOutcome | None = None
    #: Backup target saat ini SEBELUM ditimpa (keputusan PO Q4, Task
    #: 2.5) — terpisah dari backup sumber (``backup_id``/``backup_path``
    #: = backup sumber yang direstore).
    pre_restore_backup_id: str | None = None
    pre_restore_backup_path: Path | None = None


class ConfigFileWriter(Protocol):
    """Port penulis konfigurasi produksi — diimplementasi Task 2.5
    (``AtomicConfigFileWriter``).

    Kontrak implementasi wajib: tulis atomik (temp + replace) sehingga
    target tidak pernah setengah tertulis; verifikasi oleh pemanggil.
    Task 2.4 hanya mendefinisikan port ini (tanpa implementasi kedua —
    instruksi §3.D).

    Model error (dikontrakkan Task 2.5): implementasi melempar **hanya**
    ``OSError`` (dan subclass) — konsumen aktual
    (``BackupService.restore``) menangkap ``OSError`` saja.
    """

    def write_config_bytes(self, target: Path, data: bytes) -> None:
        """Tulis ``data`` ke ``target`` secara atomik."""
        ...


def sha256_hex(data: bytes) -> str:
    """SHA-256 hex dari bytes (helper dipakai service & register)."""
    return hashlib.sha256(data).hexdigest()


def backup_filename_for(
    source_filename: str, epoch: float, existing_names: set[str] | frozenset[str]
) -> str:
    """Nama file backup bertimestamp tanpa overwrite (PRD-01 §7.6).

    Format: ``<nama-sumber>.backup-YYYYMMDD-HHMMSS`` (waktu lokal);
    kolisi (detik sama) → akhiran ``-1``, ``-2``, … — backup lama tidak
    pernah tertimpa.
    """
    stamp = datetime.fromtimestamp(epoch, tz=UTC).astimezone().strftime(
        "%Y%m%d-%H%M%S"
    )
    base = f"{source_filename}.backup-{stamp}"
    if base not in existing_names:
        return base
    index = 1
    while f"{base}-{index}" in existing_names:
        index += 1
    return f"{base}-{index}"
