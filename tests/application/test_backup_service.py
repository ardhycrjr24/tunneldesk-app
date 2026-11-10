"""Uji BackupService (Task 2.4): backup, register SQLite, restore, hash,
keamanan, fail-safe. Fixture sintetis — tanpa data produksi."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tunneldesk.application.backup_service import BackupService
from tunneldesk.domain.config.backup import (
    BackupStatus,
    RestoreStatus,
    backup_filename_for,
    sha256_hex,
)
from tunneldesk.infrastructure.config_io.backup_io import (
    BackupCopyStatus,
    create_backup_copy,
)
from tunneldesk.infrastructure.persistence.backup_register import (
    BackupRegisterError,
    SqliteBackupRegister,
)

VALID_CONFIG = (
    "tunnel: 11111111-2222-3333-4444-555555555555\n"
    "credentials-file: credentials-dummy.json\n"
    "ingress:\n"
    "  - service: http_status:404\n"
)


class StubWriter:
    """Stub ConfigFileWriter — mencatat penulisan (kontrak 2.5 nanti)."""

    def __init__(self, fail: bool = False) -> None:
        self.writes: list[tuple[str, bytes]] = []
        self.fail = fail

    def write_config_bytes(self, target: Path, data: bytes) -> None:
        if self.fail:
            raise OSError(13, "simulasi target tidak dapat ditulis")
        target.write_bytes(data)
        self.writes.append((str(target), data))


def make_service(tmp_path: Path, writer: StubWriter | None = None) -> BackupService:
    return BackupService(
        backup_dir=tmp_path / "backups",
        register_db_path=tmp_path / "register.sqlite",
        writer=writer,
    )


def make_config(tmp_path: Path, content: str = VALID_CONFIG) -> Path:
    config = tmp_path / "config.yml"
    config.write_text(content, encoding="utf-8")
    return config


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------


def test_backup_berhasil_byte_identik(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    service = make_service(tmp_path)
    result = service.create_backup(config)
    assert result.status is BackupStatus.OK and result.ok is True
    assert result.backup_path is not None
    assert result.backup_path.read_bytes() == config.read_bytes()  # byte-per-byte
    assert result.sha256 == sha256_hex(config.read_bytes())
    assert result.size_bytes == len(config.read_bytes())


def test_metadata_tercatat_di_register(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    service = make_service(tmp_path)
    result = service.create_backup(config, trigger="uji")
    assert result.backup_id is not None
    records = service.list_backups()
    assert len(records) == 1
    record = records[0]
    assert record.backup_id == result.backup_id
    assert record.source_path == str(config)
    assert record.sha256 == result.sha256
    assert record.trigger == "uji"
    assert record.size_bytes == len(config.read_bytes())
    assert record.backup_filename == result.backup_filename


def test_timestamp_dan_lokasi_tampil(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    service = make_service(tmp_path)
    result = service.create_backup(config)
    assert result.created_at_epoch is not None
    assert result.backup_path is not None
    assert result.backup_path.parent.name == "backups"  # A-11 default dir


def test_backup_lama_tidak_tertimpa(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    service = make_service(tmp_path)
    pertama = service.create_backup(config)
    kedua = service.create_backup(config)  # detik sama → kolisi
    assert pertama.backup_path != kedua.backup_path
    assert pertama.backup_path is not None and pertama.backup_path.exists()
    assert kedua.backup_path is not None and kedua.backup_path.exists()
    assert len(service.list_backups()) == 2


def test_sumber_tidak_ditemukan(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    result = service.create_backup(tmp_path / "tidak-ada.yml")
    assert result.status is BackupStatus.SOURCE_NOT_FOUND
    assert result.ok is False


def test_permission_ditolak_posix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    service = make_service(tmp_path)

    def tolak() -> bytes:
        raise PermissionError(13, "izin ditolak")

    monkeypatch.setattr(
        "tunneldesk.infrastructure.config_io.backup_io.Path.read_bytes",
        lambda self: (_ for _ in ()).throw(PermissionError(13, "izin ditolak")),
    )
    result = service.create_backup(config)
    assert result.status is BackupStatus.SOURCE_UNREADABLE
    assert result.ok is False
    del tolak  # helper dipakai via monkeypatch di atas (dokumentasi)


def test_sumber_berubah_saats_backup_source_changed(tmp_path: Path) -> None:
    """Snapshot ≠ pembacaan ulang → SOURCE_CHANGED, salinan dihapus
    (tanpa backup setengah jadi) — change_checker diinjeksikan agar
    deterministik."""
    config = make_config(tmp_path, "versi awal\n")
    backup_dir = tmp_path / "backups"

    def change_checker(snapshot: bytes) -> bool:
        return snapshot == b"versi awal\n"  # simulasi sumber berubah

    result = create_backup_copy(
        config,
        backup_dir / "config.yml.backup-x",
        change_checker=change_checker,
    )
    assert result.status is BackupCopyStatus.SOURCE_CHANGED
    assert result.ok is False
    assert not (backup_dir / "config.yml.backup-x").exists()
    # tidak ada backup tersisa dari percobaan gagal
    backups = list(backup_dir.glob("*")) if backup_dir.exists() else []
    assert backups == []


def test_tidak_ada_backup_setengah_jadi_saats_write_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    service = make_service(tmp_path)

    def write_rusak(self: object, data: bytes) -> None:
        raise OSError(28, "simulasi disk penuh")

    monkeypatch.setattr(
        "tunneldesk.infrastructure.config_io.backup_io.Path.write_bytes",
        write_rusak,
    )
    result = service.create_backup(config)
    assert result.status is BackupStatus.WRITE_ERROR
    assert result.ok is False
    backups = list((tmp_path / "backups").glob("*")) if (tmp_path / "backups").exists() else []
    assert backups == []


def test_register_gagal_file_dipertahankan_dengan_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = make_config(tmp_path)
    service = make_service(tmp_path)

    asli = SqliteBackupRegister.add
    panggilan = {"n": 0}

    def add_gagal(self: object, record: object) -> None:
        panggilan["n"] += 1
        if panggilan["n"] == 1:
            raise BackupRegisterError("simulasi sqlite gagal")
        return asli(self, record)

    monkeypatch.setattr(
        "tunneldesk.infrastructure.persistence.backup_register.SqliteBackupRegister.add",
        add_gagal,
    )
    result = service.create_backup(config)
    assert result.status is BackupStatus.REGISTER_ERROR
    assert result.ok is False
    assert result.pending_record is not None  # recovery tersedia
    assert result.backup_path is not None
    assert result.backup_path.exists()  # file backup DIPERTAHANKAN
    # retry register_backup berhasil (recovery terdokumentasi)
    service.register_backup(result.pending_record)
    assert len(service.list_backups()) == 1


def test_sha256_salinan_identik_dengan_sumber(tmp_path: Path) -> None:
    config = make_config(tmp_path, "isi tetap\n" * 50)
    service = make_service(tmp_path)
    result = service.create_backup(config)
    salinan = result.backup_path.read_bytes()
    assert hashlib.sha256(salinan).hexdigest() == result.sha256
    assert salinan == config.read_bytes()


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


def test_restore_tanpa_konfirmasi_ditolak(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    service = make_service(tmp_path)
    result = service.create_backup(config)
    target = tmp_path / "restore-target.yml"
    outcome = service.restore(result.backup_id, target, confirm=False)
    assert outcome.status is RestoreStatus.RESTORE_NOT_CONFIRMED
    assert outcome.copied is False
    assert not target.exists()


def test_restore_dengan_konfirmasi_dan_verifikasi_hash(
    tmp_path: Path,
) -> None:
    config = make_config(tmp_path)
    writer = StubWriter()
    service = make_service(tmp_path, writer=writer)
    result = service.create_backup(config)
    target = tmp_path / "restored.yml"
    target.write_text("lama\n", encoding="utf-8")

    outcome = service.restore(result.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.RESTORED and outcome.ok is True
    assert outcome.copied is True
    assert outcome.restored_sha256 == result.sha256
    assert target.read_bytes() == config.read_bytes()  # byte-per-byte


def test_restore_tanpa_writer_pending_atomic_write(tmp_path: Path) -> None:
    """BackupService tanpa writer (default) → PENDING_ATOMIC_WRITE,
    tidak ada byte yang ditulis (dependency Task 2.5 eksplisit)."""
    config = make_config(tmp_path)
    service = make_service(tmp_path)  # writer None (default produksi)
    result = service.create_backup(config)
    target = tmp_path / "restored.yml"
    outcome = service.restore(result.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.PENDING_ATOMIC_WRITE
    assert outcome.copied is False
    assert not target.exists()
    assert outcome.post_restore_validation is not None  # validasi backup tetap dilaporkan


def test_restore_dengan_writer_stub_tertulis_dan_validasi_pisah(
    tmp_path: Path,
) -> None:
    config = make_config(tmp_path)
    # credentials-file dirujuk relatif terhadap lokasi config/restore
    (tmp_path / "credentials-dummy.json").write_text(
        '{"AccountTag": "DUMMY"}', encoding="utf-8"
    )
    writer = StubWriter()
    service = make_service(tmp_path, writer=writer)
    result = service.create_backup(config)
    target = tmp_path / "restored.yml"
    outcome = service.restore(result.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.RESTORED
    assert outcome.copied is True
    assert outcome.restored_sha256 == result.sha256
    # hasil penyalinan vs hasil validasi = field terpisah (instruksi §5.9)
    assert outcome.post_restore_validation is not None
    assert (
        outcome.post_restore_validation.classification.value
        == "VALID"
    )


def test_restore_hash_backup_tidak_cocok_ditolak(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    service = make_service(tmp_path)
    result = service.create_backup(config)
    # tamper file backup setelah register
    assert result.backup_path is not None
    result.backup_path.write_bytes(b"dirusak\n")
    target = tmp_path / "restored.yml"
    outcome = service.restore(result.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.BACKUP_HASH_MISMATCH
    assert outcome.copied is False
    assert not target.exists()


def test_restore_file_backup_hilang(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    service = make_service(tmp_path)
    result = service.create_backup(config)
    assert result.backup_path is not None
    result.backup_path.unlink()
    outcome = service.restore(result.backup_id, tmp_path / "r.yml", confirm=True)
    assert outcome.status is RestoreStatus.BACKUP_FILE_MISSING


def test_restore_backup_tidak_terdaftar(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    outcome = service.restore("id-ngawur", tmp_path / "r.yml", confirm=True)
    assert outcome.status is RestoreStatus.BACKUP_NOT_REGISTERED


def test_target_tidak_dapat_ditulis(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    writer = StubWriter(fail=True)
    service = make_service(tmp_path, writer=writer)
    result = service.create_backup(config)
    outcome = service.restore(result.backup_id, tmp_path / "r.yml", confirm=True)
    assert outcome.status is RestoreStatus.TARGET_UNWRITABLE
    assert outcome.copied is False


def test_validasi_ulang_gagal_mencegah_restore(tmp_path: Path) -> None:
    """Backup yang isinya tidak valid (mis. YAML rusak terdaftar manual)
    → restore ditolak (BACKUP_VALIDATION_FAILED), tidak ada penulisan."""
    service = make_service(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_file = backup_dir / "config.yml.backup-rusak"
    backup_file.write_bytes(b"tunnel: [rusak\n")
    sha = sha256_hex(backup_file.read_bytes())
    # daftarkan manual melalui jalur recovery yang tersedia
    from tunneldesk.domain.config.backup import BackupRecord

    record = BackupRecord(
        backup_id="rusak-001",
        backup_filename=backup_file.name,
        created_at_epoch=0.0,
        created_at_iso="1970-01-01T00:00:00+00:00",
        source_path=str(tmp_path / "config.yml"),
        backup_path=str(backup_file),
        size_bytes=backup_file.stat().st_size,
        sha256=sha,
        trigger="uji",
    )
    service.register_backup(record)

    target = tmp_path / "target.yml"
    outcome = service.restore("rusak-001", target, confirm=True)
    assert outcome.status is RestoreStatus.BACKUP_VALIDATION_FAILED
    assert outcome.copied is False
    assert not target.exists()
    assert outcome.post_restore_validation is not None
    assert outcome.post_restore_validation.classification.value == "INVALID"


# ---------------------------------------------------------------------------
# Keamanan credential (keputusan PO Task 2.4)
# ---------------------------------------------------------------------------


def test_credential_file_tidak_disalin_dan_tidak_dibaca(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    credential = tmp_path / "credentials-dummy.json"
    credential.write_text('{"AccountTag": "DUMMY"}', encoding="utf-8")
    isi_credential = credential.read_text(encoding="utf-8")

    service = make_service(tmp_path)
    result = service.create_backup(config)
    assert result.backup_path is not None

    # backup hanya berisi konfigurasi — bukan credential
    assert result.backup_path.read_text(encoding="utf-8") == VALID_CONFIG
    assert "DUMMY" not in result.backup_path.read_text(encoding="utf-8")
    # credential tetap di tempatnya, tidak tersalin ke backup dir
    backups = sorted(item.name for item in (tmp_path / "backups").iterdir())
    assert all("credential" not in name for name in backups)

    # restore menulis hanya konfigurasi — isi credential tidak muncul
    target = tmp_path / "restored.yml"
    writer = StubWriter()
    service2 = BackupService(
        backup_dir=tmp_path / "backups",
        register_db_path=tmp_path / "register.sqlite",
        writer=writer,
    )
    outcome = service2.restore(result.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.RESTORED
    for _target, data in writer.writes:
        assert isi_credential not in data.decode("utf-8")


# ---------------------------------------------------------------------------
# Regresi helper penamaan
# ---------------------------------------------------------------------------


def test_backup_filename_format_dan_kolisi() -> None:
    nama = backup_filename_for("config.yml", 0.0, frozenset())
    assert nama.startswith("config.yml.backup-")
    nama2 = backup_filename_for("config.yml", 0.0, {nama})
    assert nama2.startswith(f"{nama}-1")
    assert nama2 != nama
    assert sha256_hex(b"x")  # helper hash tersedia


def test_backup_copy_status_enum_lengkap() -> None:
    assert BackupCopyStatus.SOURCE_CHANGED is not None
    assert BackupCopyStatus.WRITE_ERROR is not None
