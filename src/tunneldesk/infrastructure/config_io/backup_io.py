"""Operasi file backup (Task 2.4) — salinan snapshot + verifikasi SHA-256.

- Snapshot bytes sumber dibaca **sekali** di awal; salinan ditulis via
  temp + ``os.replace`` di direktori backup (backup tidak pernah setengah
  jadi).
- ``SOURCE_CHANGED``: setelah salinan terverifikasi, sumber dibaca ulang;
  bila hash berubah → salinan dihapus dan kegagalan dilaporkan (pemanggil
  dapat mengulang — snapshot baru akan konsisten).
- Read-only terhadap sumber: hanya dibaca, tidak pernah ditulis.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from tunneldesk.domain.config.backup import sha256_hex

__all__ = ["BackupCopyStatus", "BackupCopyResult", "create_backup_copy"]


class BackupCopyStatus(Enum):
    """Status penyalinan backup — kategori tertutup."""

    OK = "OK"
    SOURCE_NOT_FOUND = "SOURCE_NOT_FOUND"
    SOURCE_UNREADABLE = "SOURCE_UNREADABLE"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    WRITE_ERROR = "WRITE_ERROR"


@dataclass(frozen=True)
class BackupCopyResult:
    """Hasil penyalinan — snapshot + hash, atau alasan kegagalan."""

    status: BackupCopyStatus
    ok: bool
    detail: str = ""
    data: bytes | None = None
    sha256: str | None = None
    size_bytes: int | None = None


def create_backup_copy(
    source_path: Path,
    backup_path: Path,
    source_reader: Callable[[], bytes] | None = None,
    change_checker: Callable[[bytes], bool] | None = None,
) -> BackupCopyResult:
    """Salin ``source_path`` → ``backup_path`` dengan verifikasi hash.

    ``source_reader``: injeksi untuk uji (pemanggilan pertama = snapshot).
    ``change_checker``: injeksi uji SOURCE_CHANGED deterministik —
    menerima snapshot bytes, kembalikan True bila sumber berubah.
    Default: baca ulang file nyata dan bandingkan hash.

    Jaminan: gagal → tidak ada file backup setengah jadi.
    """
    reader: Callable[[], bytes] = (
        source_reader if source_reader is not None else (lambda: Path(source_path).read_bytes())
    )

    try:
        snapshot = reader()
    except FileNotFoundError:
        return BackupCopyResult(
            BackupCopyStatus.SOURCE_NOT_FOUND,
            ok=False,
            detail=f"file konfigurasi tidak ditemukan: {source_path.name}",
        )
    except PermissionError as exc:
        return BackupCopyResult(
            BackupCopyStatus.SOURCE_UNREADABLE,
            ok=False,
            detail=f"file konfigurasi tidak dapat dibaca (izin): {exc.strerror or ''}".strip(),
        )
    except OSError as exc:
        return BackupCopyResult(
            BackupCopyStatus.SOURCE_UNREADABLE,
            ok=False,
            detail=f"file konfigurasi tidak dapat dibaca: {exc}",
        )

    snapshot_sha = sha256_hex(snapshot)

    backup_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = backup_path.with_name(backup_path.name + ".part")
    try:
        temp_path.write_bytes(snapshot)
        written = temp_path.read_bytes()
        if sha256_hex(written) != snapshot_sha:
            temp_path.unlink(missing_ok=True)
            return BackupCopyResult(
                BackupCopyStatus.WRITE_ERROR,
                ok=False,
                detail="salinan backup tidak identik — dihapus, tidak ada "
                "backup setengah jadi",
            )
        temp_path.replace(backup_path)
    except OSError as exc:
        temp_path.unlink(missing_ok=True)
        return BackupCopyResult(
            BackupCopyStatus.WRITE_ERROR,
            ok=False,
            detail=f"penulisan backup gagal: {exc}",
        )

    # SOURCE_CHANGED: baca ulang sumber (hanya mode file nyata —
    # injeksi reader untuk uji bersifat deterministik).
    changed = (
        change_checker(snapshot)
        if change_checker is not None
        else _source_changed_now(source_path, snapshot_sha)
    )
    if changed:
        backup_path.unlink(missing_ok=True)
        return BackupCopyResult(
            BackupCopyStatus.SOURCE_CHANGED,
            ok=False,
            detail="file konfigurasi berubah selama proses backup — "
            "salinan dihapus, silakan ulangi",
        )

    return BackupCopyResult(
        BackupCopyStatus.OK,
        ok=True,
        data=snapshot,
        sha256=snapshot_sha,
        size_bytes=len(snapshot),
    )


def _source_changed_now(source_path: Path, snapshot_sha: str) -> bool:
    """Baca ulang sumber; True bila hash kini ≠ snapshot."""
    try:
        current = Path(source_path).read_bytes()
    except OSError:
        return False  # sumber tak terbaca lagi; snapshot tetap valid
    return sha256_hex(current) != snapshot_sha


def read_backup_bytes(backup_path: Path) -> bytes:
    """Baca bytes backup — OSError melempar apa adanya (service memetakan)."""
    return Path(backup_path).read_bytes()
