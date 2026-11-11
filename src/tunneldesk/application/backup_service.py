"""BackupService (Task 2.4) — backup, register, restore berkonfirmasi.

Komponen resmi (IMPLEMENTATION_PLAN 2.4, PRD-01 §7.6):
1. Backup bertimestamp (snapshot bytes sekali, SHA-256, tanpa overwrite,
   tanpa backup setengah jadi — SOURCE_CHANGED gagal terstruktur).
2. Register metadata SQLite (D-03) — kegagalan register tidak menghapus
   file backup (recovery: retry ``register_backup``, terdokumentasi).
3. Restore dengan konfirmasi eksplisit (``confirm=True`` wajib).
4. Validasi ulang pasca-restore via ConfigValidator E-6 — hasil
   **dilaporkan terpisah** dari hasil penyalinan.

Kebijakan (disetujui Project Control, Task 2.4):
- Credential-file tidak di-backup, tidak dibaca, tidak dipulihkan;
  referensi ``credentials-file`` di YAML dipertahankan apa adanya.
- Q-09 MENUNGGU → tanpa penghapusan/retensi otomatis.
- Penulisan produksi restore membutuhkan port :class:`ConfigFileWriter`
  (Task 2.5, atomic write). Tanpa writer → ``PENDING_ATOMIC_WRITE`` dan
  **tidak ada byte yang ditulis** (instruksi §3.D.4).
- Backup pra-restore target (keputusan PO Q4, Task 2.5): sebelum
  menimpa target yang ada, kondisi terkininya dibackup via
  ``create_backup(trigger="pre-restore")`` — gagal → restore dibatalkan
  tanpa menulis (``PRE_RESTORE_BACKUP_FAILED``). Backup sumber dan
  backup target dilaporkan di field terpisah.

Perbedaan kondisi yang tidak boleh disamakan (instruksi §5):
backup hash valid ≠ file berhasil dipulihkan ≠ konfigurasi valid skema ≠
tunnel siap dijalankan — masing-masing ada di field terpisah.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from tunneldesk.domain.config.backup import (
    BackupRecord,
    BackupResult,
    BackupStatus,
    ConfigFileWriter,
    RestoreOutcome,
    RestoreStatus,
    backup_filename_for,
    sha256_hex,
)
from tunneldesk.domain.config.model import (
    ValidationClassification,
)
from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.infrastructure.config_io.backup_io import (
    BackupCopyResult,
    BackupCopyStatus,
    create_backup_copy,
    read_backup_bytes,
)
from tunneldesk.infrastructure.persistence.backup_register import (
    BackupRegisterError,
    SqliteBackupRegister,
)

if TYPE_CHECKING:
    from tunneldesk.application.config_validator import ConfigValidator

__all__ = ["BackupService"]


class BackupService:
    """Backup + register + restore berkonfirmasi (Task 2.4)."""

    def __init__(
        self,
        backup_dir: Path,
        register: SqliteBackupRegister | None = None,
        register_db_path: Path | None = None,
        validator: ConfigValidator | None = None,
        writer: ConfigFileWriter | None = None,
        redaction: RedactionEngine | None = None,
    ) -> None:
        self._backup_dir = Path(backup_dir)
        self._register = register or SqliteBackupRegister(
            register_db_path
            or (Path(backup_dir).parent / "backup-register.sqlite")
        )
        # ConfigValidator E-6 untuk validasi ulang pasca-restore.
        from tunneldesk.application.config_validator import ConfigValidator

        self._validator = validator or ConfigValidator()
        #: Port penulis produksi — None sampai Task 2.5 menyediakan
        #: implementasi atomic write (instruksi §3.D).
        self._writer = writer
        self._redaction = redaction or RedactionEngine()

    # ------------------------------------------------------------------
    # Create backup
    # ------------------------------------------------------------------
    def create_backup(
        self, config_path: Path, trigger: str = "manual"
    ) -> BackupResult:
        """Backup file konfigurasi (snapshot bytes sekali + verifikasi)."""
        config_path = Path(config_path)
        epoch = time.time()
        self._backup_dir.mkdir(parents=True, exist_ok=True)

        existing = {
            item.name for item in self._backup_dir.iterdir() if item.is_file()
        } if self._backup_dir.is_dir() else set()
        filename = backup_filename_for(config_path.name, epoch, existing)
        backup_path = self._backup_dir / filename

        # Snapshot sekali + verifikasi + anti setengah jadi (backup_io).
        copy_result = create_backup_copy(config_path, backup_path)
        if not copy_result.ok:
            return self._failed_result(copy_result)

        assert copy_result.data is not None and copy_result.sha256 is not None
        snapshot_sha = copy_result.sha256

        record = BackupRecord(
            backup_id=uuid.uuid4().hex,
            backup_filename=filename,
            created_at_epoch=epoch,
            created_at_iso=_iso(epoch),
            source_path=str(config_path),
            backup_path=str(backup_path),
            size_bytes=backup_path.stat().st_size,
            sha256=snapshot_sha,
            trigger=trigger,
        )
        try:
            self._register.add(record)
        except BackupRegisterError as exc:
            # File backup yang sudah jadi DIPERTAHANKAN; metadata dipulihkan
            # dengan retry register_backup(record) (terdokumentasi, Q-09
            # tidak terpengaruh — tidak ada penghapusan).
            return BackupResult(
                status=BackupStatus.REGISTER_ERROR,
                ok=False,
                detail=(
                    "backup file tersimpan, register metadata gagal: "
                    f"{exc.reason}; pemulihan: panggil register_backup(record)"
                ),
                backup_path=backup_path,
                backup_filename=filename,
                sha256=snapshot_sha,
                size_bytes=record.size_bytes,
                created_at_epoch=epoch,
                pending_record=record,
            )

        return BackupResult(
            status=BackupStatus.OK,
            ok=True,
            backup_id=record.backup_id,
            backup_path=backup_path,
            backup_filename=filename,
            sha256=snapshot_sha,
            size_bytes=record.size_bytes,
            created_at_epoch=epoch,
        )

    def register_backup(self, record: BackupRecord) -> None:
        """Recovery metadata: daftarkan record tertunda (REGISTER_ERROR)."""
        self._register.add(record)

    def list_backups(self) -> tuple[BackupRecord, ...]:
        """Riwayat register (terbaru dulu) — tanpa penghapusan (Q-09)."""
        return self._register.list_all()

    # ------------------------------------------------------------------
    # Restore
    # ------------------------------------------------------------------
    def restore(
        self,
        backup_id: str,
        target_path: Path,
        confirm: bool = False,
    ) -> RestoreOutcome:
        """Restore backup terdaftar ke target — wajib ``confirm=True``.

        Penulisan produksi membutuhkan ``ConfigFileWriter`` (Task 2.5).
        Tanpa writer → ``PENDING_ATOMIC_WRITE`` dan tidak ada byte yang
        ditulis (kontrak aman, instruksi §3.D). Target yang sudah ada
        dibackup dulu (Q4) — gagal backup → restore dibatalkan.
        """
        target_path = Path(target_path)
        if not confirm:
            return RestoreOutcome(
                status=RestoreStatus.RESTORE_NOT_CONFIRMED,
                ok=False,
                detail="restore membutuhkan konfirmasi eksplisit (confirm=True)",
                backup_id=backup_id,
                target_path=target_path,
            )
        try:
            record = self._register.get(backup_id)
        except BackupRegisterError as exc:
            return RestoreOutcome(
                status=RestoreStatus.REGISTER_ERROR,
                ok=False,
                detail=exc.reason,
                backup_id=backup_id,
                target_path=target_path,
            )
        if record is None:
            return RestoreOutcome(
                status=RestoreStatus.BACKUP_NOT_REGISTERED,
                ok=False,
                detail=f"backup {backup_id} tidak terdaftar",
                backup_id=backup_id,
                target_path=target_path,
            )
        backup_path = Path(record.backup_path)
        try:
            data = read_backup_bytes(backup_path)
        except FileNotFoundError:
            return RestoreOutcome(
                status=RestoreStatus.BACKUP_FILE_MISSING,
                ok=False,
                detail="file backup tidak ditemukan",
                backup_id=backup_id,
                backup_path=backup_path,
                target_path=target_path,
            )
        except OSError as exc:
            return RestoreOutcome(
                status=RestoreStatus.BACKUP_FILE_MISSING,
                ok=False,
                detail=f"file backup tidak dapat dibaca: {exc}",
                backup_id=backup_id,
                backup_path=backup_path,
                target_path=target_path,
            )

        backup_sha = sha256_hex(data)
        if backup_sha != record.sha256:
            return RestoreOutcome(
                status=RestoreStatus.BACKUP_HASH_MISMATCH,
                ok=False,
                detail="hash backup tidak cocok dengan register — restore "
                "ditolak (tidak ada yang ditulis)",
                backup_id=backup_id,
                backup_path=backup_path,
                target_path=target_path,
            )

        # Validasi file backup (E-6) SEBELUM menulis ke target. UNKNOWN
        # juga menahan restore (PRD-02 §3.2: tidak dikenal tidak diubah).
        post_validation = self._validator.validate_text(
            data.decode("utf-8", errors="replace"),
            credentials_file_exists=None,
        )
        if post_validation.classification is not ValidationClassification.VALID:
            return RestoreOutcome(
                status=RestoreStatus.BACKUP_VALIDATION_FAILED,
                ok=False,
                detail="isi backup gagal/tidak pasti validasi — tidak ada "
                "yang ditulis ke target",
                backup_id=backup_id,
                backup_path=backup_path,
                target_path=target_path,
                post_restore_validation=post_validation,
            )

        if self._writer is None:
            return RestoreOutcome(
                status=RestoreStatus.PENDING_ATOMIC_WRITE,
                ok=False,
                detail="penulisan produksi menunggu Task 2.5 (atomic write) — "
                "tidak ada byte yang ditulis",
                backup_id=backup_id,
                backup_path=backup_path,
                target_path=target_path,
                post_restore_validation=post_validation,
            )

        # Backup target saat ini SEBELUM ditimpa (keputusan PO Q4,
        # Task 2.5) — memakai mekanisme Task 2.4 sendiri (tanpa
        # duplikasi). Tidak ada loop: create_backup hanya MEMBACA
        # sumber dan menulis ke direktori backup. Target tidak ada →
        # restore membuat ulang file (tidak ada yang perlu dibackup).
        # Backup sumber (direstore) tetap tercatat di backup_id/
        # backup_path — dua backup ini TIDAK disamakan.
        pre_restore: BackupResult | None = None
        if target_path.exists():
            pre_restore = self.create_backup(target_path, "pre-restore")
            if not pre_restore.ok:
                return RestoreOutcome(
                    status=RestoreStatus.PRE_RESTORE_BACKUP_FAILED,
                    ok=False,
                    detail=(
                        "backup pra-restore gagal "
                        f"({pre_restore.status.value}) — restore "
                        "dibatalkan, target tidak disentuh"
                    ),
                    backup_id=backup_id,
                    backup_path=backup_path,
                    target_path=target_path,
                    post_restore_validation=post_validation,
                )
        pre_id = pre_restore.backup_id if pre_restore else None
        pre_path = pre_restore.backup_path if pre_restore else None

        try:
            self._writer.write_config_bytes(target_path, data)
        except OSError as exc:
            return RestoreOutcome(
                status=RestoreStatus.TARGET_UNWRITABLE,
                ok=False,
                detail=f"target tidak dapat ditulis: {self._sanitize(str(exc))}",
                backup_id=backup_id,
                backup_path=backup_path,
                target_path=target_path,
                post_restore_validation=post_validation,
                pre_restore_backup_id=pre_id,
                pre_restore_backup_path=pre_path,
            )

        verify_sha = self._verify_target(target_path, backup_sha)
        if verify_sha is None:
            return RestoreOutcome(
                status=RestoreStatus.RESTORE_HASH_MISMATCH,
                ok=False,
                detail="hash target setelah restore tidak cocok",
                backup_id=backup_id,
                backup_path=backup_path,
                target_path=target_path,
                pre_restore_backup_id=pre_id,
                pre_restore_backup_path=pre_path,
            )
        try:
            self._register.mark_restored(backup_id, time.time())
        except BackupRegisterError as exc:
            # Restore sudah terjadi; kegagalan penanda hanya catatan.
            return RestoreOutcome(
                status=RestoreStatus.RESTORED,
                ok=True,
                detail=f"restore berhasil; penanda register gagal: {exc.reason}",
                backup_id=backup_id,
                backup_path=backup_path,
                target_path=target_path,
                copied=True,
                restored_sha256=verify_sha,
                post_restore_validation=self._validator.validate_path(target_path),
                pre_restore_backup_id=pre_id,
                pre_restore_backup_path=pre_path,
            )

        return RestoreOutcome(
            status=RestoreStatus.RESTORED,
            ok=True,
            copied=True,
            restored_sha256=verify_sha,
            backup_id=backup_id,
            backup_path=backup_path,
            target_path=target_path,
            post_restore_validation=self._validator.validate_path(target_path),
            pre_restore_backup_id=pre_id,
            pre_restore_backup_path=pre_path,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    @staticmethod
    def _failed_result(copy_result: BackupCopyResult) -> BackupResult:
        mapping = {
            BackupCopyStatus.SOURCE_NOT_FOUND: BackupStatus.SOURCE_NOT_FOUND,
            BackupCopyStatus.SOURCE_UNREADABLE: BackupStatus.SOURCE_UNREADABLE,
            BackupCopyStatus.SOURCE_CHANGED: BackupStatus.SOURCE_CHANGED,
            BackupCopyStatus.WRITE_ERROR: BackupStatus.WRITE_ERROR,
        }
        status = mapping[copy_result.status]
        return BackupResult(status=status, ok=False, detail=copy_result.detail)

    def _verify_target(self, target_path: Path, expected: str) -> str | None:
        try:
            data = target_path.read_bytes()
        except OSError:
            return None
        computed = sha256_hex(data)
        return computed if computed == expected else None

    def _sanitize(self, text: str) -> str:
        return self._redaction.redact(text)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat()
