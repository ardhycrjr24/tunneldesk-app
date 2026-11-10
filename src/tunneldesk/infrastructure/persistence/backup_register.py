"""Register metadata backup (Task 2.4, D-03) — SQLite.

- Skema: tabel ``config_backups`` — tanpa isi konfigurasi, tanpa token,
  tanpa credential, tanpa hostname, tanpa data sekolah (kontrak Task 2.4).
- Transaksi: INSERT/UPDATE dalam satu koneksi; kegagalan dinaikkan
  sebagai :class:`BackupRegisterError` agar service memutuskan
  (file backup yang sudah jadi **dipertahankan** — strategi recovery:
  retry ``register_backup`` / rebuild dari direktori, terdokumentasi).
- Tanpa penghapusan baris (Q-09; riwayat utuh).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from tunneldesk.domain.config.backup import BackupRecord

__all__ = ["BackupRegisterError", "SqliteBackupRegister"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS config_backups (
    backup_id          TEXT PRIMARY KEY,
    created_at_epoch   REAL    NOT NULL,
    created_at_iso     TEXT    NOT NULL,
    source_path        TEXT    NOT NULL,
    backup_filename    TEXT    NOT NULL,
    backup_path        TEXT    NOT NULL,
    size_bytes         INTEGER NOT NULL,
    sha256             TEXT    NOT NULL,
    trigger            TEXT    NOT NULL,
    restored_at_epoch  REAL
);
"""

_INSERT = """
INSERT INTO config_backups (
    backup_id, created_at_epoch, created_at_iso, source_path,
    backup_filename, backup_path, size_bytes, sha256, trigger,
    restored_at_epoch
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_BY_ID = """
SELECT backup_id, created_at_epoch, created_at_iso, source_path,
       backup_filename, backup_path, size_bytes, sha256, trigger,
       restored_at_epoch
FROM config_backups WHERE backup_id = ?
"""

_SELECT_ALL = """
SELECT backup_id, created_at_epoch, created_at_iso, source_path,
       backup_filename, backup_path, size_bytes, sha256, trigger,
       restored_at_epoch
FROM config_backups ORDER BY created_at_epoch DESC, backup_id
"""

_MARK_RESTORED = "UPDATE config_backups SET restored_at_epoch = ? WHERE backup_id = ?"

_COLUMNS = (
    "backup_id",
    "created_at_epoch",
    "created_at_iso",
    "source_path",
    "backup_filename",
    "backup_path",
    "size_bytes",
    "sha256",
    "trigger",
    "restored_at_epoch",
)


class BackupRegisterError(RuntimeError):
    """Kegagalan register metadata — membawa alasan untuk service."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class SqliteBackupRegister:
    """Register SQLite — transaksional, tanpa penghapusan (Q-09)."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)

    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._db_path)
        connection.execute(_SCHEMA)
        connection.commit()
        return connection

    @staticmethod
    def _record_from_row(row: tuple) -> BackupRecord:
        return BackupRecord(**dict(zip(_COLUMNS, row, strict=True)))

    # ------------------------------------------------------------------
    def add(self, record: BackupRecord) -> None:
        """Sisipkan satu record (transaksi). Gagal → BackupRegisterError."""
        try:
            with self._connect() as connection:
                connection.execute(
                    _INSERT,
                    (
                        record.backup_id,
                        record.created_at_epoch,
                        record.created_at_iso,
                        record.source_path,
                        record.backup_filename,
                        record.backup_path,
                        record.size_bytes,
                        record.sha256,
                        record.trigger,
                        record.restored_at_epoch,
                    ),
                )
        except sqlite3.Error as exc:
            raise BackupRegisterError(f"register gagal: {exc}") from exc

    def get(self, backup_id: str) -> BackupRecord | None:
        """Ambil record per id; None bila tidak terdaftar."""
        try:
            with self._connect() as connection:
                row = connection.execute(_SELECT_BY_ID, (backup_id,)).fetchone()
        except sqlite3.Error as exc:
            raise BackupRegisterError(f"baca register gagal: {exc}") from exc
        return self._record_from_row(row) if row is not None else None

    def list_all(self) -> tuple[BackupRecord, ...]:
        """Seluruh record (terbaru dulu) — riwayat utuh (Q-09)."""
        try:
            with self._connect() as connection:
                rows = connection.execute(_SELECT_ALL).fetchall()
        except sqlite3.Error as exc:
            raise BackupRegisterError(f"baca register gagal: {exc}") from exc
        return tuple(self._record_from_row(row) for row in rows)

    def mark_restored(self, backup_id: str, restored_at_epoch: float) -> None:
        """Tandai waktu restore (riwayat — bukan penghapusan)."""
        try:
            with self._connect() as connection:
                cursor = connection.execute(_MARK_RESTORED, (restored_at_epoch, backup_id))
                if cursor.rowcount == 0:
                    raise BackupRegisterError(
                        f"backup {backup_id} tidak terdaftar — tidak bisa ditandai"
                    )
        except sqlite3.Error as exc:
            raise BackupRegisterError(f"tandai restore gagal: {exc}") from exc
