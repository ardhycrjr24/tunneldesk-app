"""Uji ConfigApplyService (Task 2.5) — artefak preview→apply (Q2),
kebijakan path (Q3b), backup pra-apply (Q4), konfirmasi eksplisit (Q5),
rollback otomatis (Q1), keamanan, konkurensi hash-based.

Validator E-6 dan BackupService Task 2.4 ASLI (bukan stub) untuk
kebenaran integrasi; kegagalan tulis/validasi disimulasikan via stub
deterministik. Fixture sintetis; tanpa operasi destruktif ke file sistem.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from tunneldesk.application.backup_service import BackupService
from tunneldesk.application.config_apply_service import (
    ApplyArtifact,
    ApplyStatus,
    ArtifactRejectedError,
    ConfigApplyService,
)
from tunneldesk.application.config_preview import (
    ConfigPreview,
    ConfigPreviewService,
)
from tunneldesk.application.config_validator import ConfigValidator
from tunneldesk.domain.config.backup import BackupResult, BackupStatus, RestoreStatus, sha256_hex
from tunneldesk.domain.config.model import (
    ValidationClassification,
    ValidationOutcome,
)
from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.infrastructure.config_io.backup_io import (
    BackupCopyResult,
    BackupCopyStatus,
)
from tunneldesk.infrastructure.config_io.config_writer import (
    AtomicConfigFileWriter,
)

IS_WINDOWS = sys.platform == "win32"

ORIGINAL = (
    "tunnel: 11111111-2222-3333-4444-555555555555\n"
    "credentials-file: credentials-dummy.json\n"
    "ingress:\n"
    "  - service: http_status:404\n"
)
# Usulan: ubah origin + tambah hostname (tetap VALID, tanpa kunci asing).
PROPOSED = (
    "tunnel: 11111111-2222-3333-4444-555555555555\n"
    "credentials-file: credentials-dummy.json\n"
    "ingress:\n"
    "  - hostname: rapor.sekolah.sch.id\n"
    "    service: http://localhost:8080\n"
    "  - service: http_status:404\n"
)
DUMMY_TOKEN = "rahasia-dummy-tunnel-1234567890"


def make_service(
    tmp_path: Path,
    writer: object | None = None,
    validator: ConfigValidator | None = None,
    redaction: RedactionEngine | None = None,
) -> ConfigApplyService:
    backup = BackupService(
        backup_dir=tmp_path / "backups",
        register_db_path=tmp_path / "register.sqlite",
        validator=validator,
    )
    return ConfigApplyService(
        writer=writer or AtomicConfigFileWriter(),
        backup_service=backup,
        validator=validator,
        redaction=redaction,
        deny_prefixes=(tmp_path / "dilarang",),
    )


def make_config(
    tmp_path: Path, content: str = ORIGINAL, with_credentials: bool = True
) -> Path:
    """Config + credential dummy (validator E-6 memeriksa keberadaan
    credentials-file secara sadar-credential — isi tidak pernah dibaca)."""
    target = tmp_path / "config.yml"
    target.write_text(content, encoding="utf-8")
    if with_credentials:
        (tmp_path / "credentials-dummy.json").write_text(
            '{"TunnelSecret": "' + DUMMY_TOKEN + '"}', encoding="utf-8"
        )
    return target


def make_preview(original: str = ORIGINAL, proposed: str = PROPOSED) -> ConfigPreview:
    return ConfigPreviewService().preview(original, proposed)


def make_artifact(
    tmp_path: Path,
    target: Path | None = None,
    original: str = ORIGINAL,
    proposed: str = PROPOSED,
) -> ApplyArtifact:
    target = target or make_config(tmp_path, original)
    service = make_service(tmp_path)
    return service.prepare(target, make_preview(original, proposed), original)


class StubWriter:
    """Stub ConfigFileWriter deterministik — simulasi gagal/korupsi per
    nomor panggilan (1-based)."""

    def __init__(
        self,
        fail_calls: tuple[int, ...] = (),
        corrupt_calls: tuple[int, ...] = (),
        error_message: str = "simulasi tulis gagal",
    ) -> None:
        self.writes: list[tuple[str, bytes]] = []
        self._fail = set(fail_calls)
        self._corrupt = set(corrupt_calls)
        self._message = error_message
        self._calls = 0

    def write_config_bytes(self, target: Path, data: bytes) -> None:
        self._calls += 1
        if self._calls in self._fail:
            raise OSError(13, self._message)
        payload = data + b"# korup\n" if self._calls in self._corrupt else data
        target.write_bytes(payload)
        self.writes.append((str(target), payload))


class FailingPostWriteValidator(ConfigValidator):
    """Validator ASLI untuk pra-tulis, tetapi valid_path (pasca-tulis)
    selalu INVALID — simulasi deterministik validasi ulang gagal."""

    def validate_path(self, config_path: Path) -> ValidationOutcome:
        outcome = super().validate_path(config_path)
        return ValidationOutcome(
            classification=ValidationClassification.INVALID,
            errors=outcome.errors,
            warnings=outcome.warnings,
            round_trip_preserved=outcome.round_trip_preserved,
        )


def make_backup_service(tmp_path: Path, writer: object | None = None) -> BackupService:
    return BackupService(
        backup_dir=tmp_path / "backups",
        register_db_path=tmp_path / "register.sqlite",
        writer=writer,  # type: ignore[arg-type]
    )


# ----------------------------------------------------------------------
# prepare — artefak preview→apply (Q2)
# ----------------------------------------------------------------------
def test_preview_mengekspos_teks_emit_usulan() -> None:
    preview = make_preview()
    assert preview.proposed_emitted_text is not None
    assert "rapor.sekolah.sch.id" in preview.proposed_emitted_text


def test_prepare_membuat_artefak_lengkap(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    service = make_service(tmp_path)
    artifact = service.prepare(target, make_preview(), ORIGINAL)
    assert artifact.target_path == target
    assert artifact.source_sha256 == sha256_hex(target.read_bytes())
    assert artifact.proposed_text == make_preview().proposed_emitted_text
    assert artifact.proposed_sha256 == sha256_hex(
        artifact.proposed_text.encode("utf-8")
    )
    assert artifact.original_not_canonical is False
    assert artifact.preview.proposed_emitted_text == artifact.proposed_text


def test_prepare_menolak_preview_ditolak(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    service = make_service(tmp_path)
    preview_ditolak = ConfigPreview(
        rejected=True,
        rejection_reason="sintaks",
        rejection_errors=(),
        original_classification=None,
        proposed_classification=None,
        contains_unknown_structure=False,
        original_not_canonical=False,
        diff=None,
        notes=(),
    )
    with pytest.raises(ArtifactRejectedError) as info:
        service.prepare(target, preview_ditolak, ORIGINAL)
    assert info.value.reason == "ARTIFACT_INVALID"


def test_prepare_menolak_usulan_tidak_valid(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    rusak = PROPOSED.replace("tunnel:", "tunel:")  # kunci asing → UNKNOWN
    preview = make_preview(ORIGINAL, rusak)
    service = make_service(tmp_path)
    with pytest.raises(ArtifactRejectedError) as info:
        service.prepare(target, preview, ORIGINAL)
    assert info.value.reason == "ARTIFACT_INVALID"


def test_prepare_menolak_source_berubah_sejak_preview(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    service = make_service(tmp_path)
    # Preview dibuat dari ORIGINAL, tetapi original_text kini tidak
    # sama dengan isi file → preview basi (verifikasi byte-per-byte).
    with pytest.raises(ArtifactRejectedError) as info:
        service.prepare(target, make_preview(), ORIGINAL + "# tambahan\n")
    assert info.value.reason == "PREVIEW_STALE"


def test_prepare_menolak_file_hilang(tmp_path: Path) -> None:
    target = tmp_path / "hilang.yml"
    service = make_service(tmp_path)
    with pytest.raises(ArtifactRejectedError) as info:
        service.prepare(target, make_preview(), ORIGINAL)
    assert info.value.reason == "PREVIEW_STALE"


def test_prepare_menolak_path_relatif(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    with pytest.raises(ArtifactRejectedError) as info:
        service.prepare(Path("config.yml"), make_preview(), ORIGINAL)
    assert info.value.reason == "PATH_REJECTED"


# ----------------------------------------------------------------------
# apply — konfirmasi (Q5) & konkurensi hash-based
# ----------------------------------------------------------------------
def test_apply_tanpa_konfirmasi_ditolak_tanpa_io(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    service = make_service(tmp_path)
    outcome = service.apply(artifact)  # confirm default False
    assert outcome.status is ApplyStatus.APPLY_NOT_CONFIRMED
    assert outcome.ok is False
    assert target.read_bytes() == ORIGINAL.encode("utf-8")
    assert not (tmp_path / "backups").exists()  # backup tidak dibuat


def test_apply_sukses_byte_persis_artefak(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    service = make_service(tmp_path)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.APPLIED
    assert outcome.ok is True
    assert outcome.applied is True
    # Byte file === byte artefak (Q2 — tanpa serialisasi ulang YAML).
    assert target.read_bytes() == artifact.proposed_text.encode("utf-8")
    assert outcome.written_sha256 == artifact.proposed_sha256
    assert outcome.post_write_validation is not None
    assert (
        outcome.post_write_validation.classification
        is ValidationClassification.VALID
    )
    assert outcome.backup_path is not None and outcome.backup_path.exists()
    assert outcome.backup_id is not None


def test_apply_stale_artefak_ditolak(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    target.write_text(ORIGINAL + "# diubah eksternal\n", encoding="utf-8")
    service = make_service(tmp_path)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.SOURCE_CHANGED
    assert target.read_bytes() == ORIGINAL.encode("utf-8") + b"# diubah eksternal\n"
    assert not (tmp_path / "backups").exists()  # batal sebelum backup


def test_apply_file_hilang_setelah_prepare_ditolak(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    target.unlink()
    service = make_service(tmp_path)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.SOURCE_CHANGED


def test_apply_target_terganti_file_lain_ditolak(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    target.write_text(ORIGINAL.replace("404", "503"), encoding="utf-8")
    service = make_service(tmp_path)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.SOURCE_CHANGED


def test_apply_path_ditolak_tanpa_tulis(tmp_path: Path) -> None:
    dilarang = tmp_path / "dilarang"
    dilarang.mkdir()
    target = dilarang / "config.yml"
    target.write_text(ORIGINAL, encoding="utf-8")
    artifact = make_artifact(tmp_path, target=target)
    service = make_service(tmp_path)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.PATH_REJECTED
    assert outcome.path_status is not None
    assert target.read_bytes() == ORIGINAL.encode("utf-8")


# ----------------------------------------------------------------------
# apply — validasi pra-tulis & backup pra-apply (Q4/D-17)
# ----------------------------------------------------------------------
def test_apply_validasi_pra_tulis_mencegah_perubahan(tmp_path: Path) -> None:
    """Kegagalan validasi mencegah perubahan diterapkan (Fase 2):
    credentials-file dirujuk tetapi tidak ada → pra-tulis INVALID →
    batal tanpa tulis, tanpa backup."""
    target = make_config(tmp_path, with_credentials=False)
    preview = make_preview()
    service = make_service(tmp_path)
    artifact = service.prepare(target, preview, ORIGINAL)  # VALID di preview
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.VALIDATION_FAILED
    assert target.read_bytes() == ORIGINAL.encode("utf-8")
    assert not (tmp_path / "backups").exists()
    assert outcome.post_write_validation is not None
    assert (
        outcome.post_write_validation.classification
        is ValidationClassification.INVALID
    )


def test_apply_backup_gagal_membatalkan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    service = make_service(tmp_path)

    def backup_gagal(*args: object, **kwargs: object) -> BackupCopyResult:
        return BackupCopyResult(
            BackupCopyStatus.WRITE_ERROR,
            ok=False,
            detail="simulasi disk penuh",
        )

    monkeypatch.setattr(
        "tunneldesk.application.backup_service.create_backup_copy",
        backup_gagal,
    )
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.BACKUP_FAILED
    assert target.read_bytes() == ORIGINAL.encode("utf-8")  # tidak ditulis


# ----------------------------------------------------------------------
# apply — kegagalan tulis & rollback otomatis (Q1)
# ----------------------------------------------------------------------
def test_apply_write_failed_target_utuh(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    service = make_service(tmp_path, writer=StubWriter(fail_calls=(1,)))
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.WRITE_FAILED
    assert target.read_bytes() == ORIGINAL.encode("utf-8")  # jaminan port
    assert outcome.backup_path is not None  # backup pra-apply tersedia
    assert outcome.applied is False


def test_apply_hash_mismatch_memicu_rollback_otomatis(tmp_path: Path) -> None:
    """Tulis sukses tapi byte salah → hash target ≠ artefak → rollback
    OTOMATIS byte asli + verifikasi hash (Q1)."""
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    service = make_service(tmp_path, writer=StubWriter(corrupt_calls=(1,)))
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.WRITE_HASH_MISMATCH
    assert outcome.ok is False
    assert outcome.rolled_back is True
    assert outcome.rollback_sha256 == sha256_hex(ORIGINAL.encode("utf-8"))
    assert target.read_bytes() == ORIGINAL.encode("utf-8")  # kembali persis
    assert outcome.backup_path is not None and outcome.backup_path.exists()


def test_apply_validasi_ulang_gagal_memicu_rollback(tmp_path: Path) -> None:
    """Validasi ulang pasca-tulis tidak VALID → rollback otomatis
    (keputusan Q1; IMPLEMENTATION_PLAN 2.5 "rollback otomatis bila
    validasi ulang gagal")."""
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    service = make_service(
        tmp_path, validator=FailingPostWriteValidator()
    )
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.POST_WRITE_VALIDATION_FAILED
    assert outcome.rolled_back is True
    assert outcome.rollback_sha256 == sha256_hex(ORIGINAL.encode("utf-8"))
    assert target.read_bytes() == ORIGINAL.encode("utf-8")
    assert outcome.post_write_validation is not None
    assert (
        outcome.post_write_validation.classification
        is ValidationClassification.INVALID
    )


def test_rollback_tulis_gagal_rollback_failed(tmp_path: Path) -> None:
    """Rollback sendiri gagal (tulis) → ROLLBACK_FAILED jujur + lokasi
    backup pemulihan (Q1) — tanpa klaim target pulih."""
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    writer = StubWriter(fail_calls=(2,), corrupt_calls=(1,))
    service = make_service(tmp_path, writer=writer)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.ROLLBACK_FAILED
    assert outcome.rolled_back is False
    assert outcome.backup_path is not None and outcome.backup_path.exists()
    assert "backup" in outcome.detail
    assert target.read_bytes() != ORIGINAL.encode("utf-8")  # tidak diklaim


def test_rollback_hash_mismatch_rollback_failed(tmp_path: Path) -> None:
    """Rollback tertulis tapi hash ≠ hash asli → ROLLBACK_FAILED —
    sukses rollback tidak pernah diklaim tanpa verifikasi (Q1)."""
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    writer = StubWriter(corrupt_calls=(1, 2))
    service = make_service(tmp_path, writer=writer)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.ROLLBACK_FAILED
    assert outcome.rolled_back is False
    assert outcome.rollback_sha256 is None
    assert outcome.backup_path is not None


def test_rollback_tidak_memicu_backup_kedua(tmp_path: Path) -> None:
    """Tanpa loop backup: satu apply = tepat satu backup (rollback
    menulis langsung via writer, tanpa create_backup lagi)."""
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    service = make_service(tmp_path, writer=StubWriter(corrupt_calls=(1,)))
    outcome = service.apply(artifact, confirm=True)
    assert outcome.rolled_back is True
    records = service._backup.list_backups()  # noqa: SLF001 — uji internal
    assert len(records) == 1
    assert records[0].trigger == "pre-apply"


# ----------------------------------------------------------------------
# Preview/apply konsistensi byte (Q2 + Task 2.3)
# ----------------------------------------------------------------------
def test_preview_apply_byte_konsistensi_dengan_diff(tmp_path: Path) -> None:
    """Kriteria Fase 2: preview sesuai perubahan yang diterapkan —
    diff ulang (asli vs hasil apply) identik dengan diff preview."""
    target = make_config(tmp_path)
    preview = make_preview()
    service = make_service(tmp_path)
    artifact = service.prepare(target, preview, ORIGINAL)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.applied is True
    hasil = target.read_bytes().decode("utf-8")
    diff_baru = ConfigPreviewService().preview(ORIGINAL, hasil)
    assert diff_baru.diff is not None and preview.diff is not None
    for kind in ("ADDED", "REMOVED"):
        awal = [item.text for item in preview.diff.lines if item.kind.name == kind]
        hasil_diff = [
            item.text for item in diff_baru.diff.lines if item.kind.name == kind
        ]
        assert awal == hasil_diff, kind


def test_apply_kunci_tidak_dikenal_ditolak_target_utuh(tmp_path: Path) -> None:
    """Kunci asing pada usulan → UNKNOWN → prepare menolak (PRD-02
    §3.2: tidak dikenal tidak diubah otomatis); target tidak tersentuh."""
    target = make_config(tmp_path)
    dengan_asing = PROPOSED + "original-config-extra: true\n"
    preview = make_preview(ORIGINAL, dengan_asing)
    assert preview.contains_unknown_structure is True
    service = make_service(tmp_path)
    with pytest.raises(ArtifactRejectedError):
        service.prepare(target, preview, ORIGINAL)
    assert target.read_bytes() == ORIGINAL.encode("utf-8")


def test_apply_normalisasi_kanonis_diflag_jujur(tmp_path: Path) -> None:
    """Diff kosong pada dokumen non-kanonis ≠ byte tidak berubah —
    artefak membawa flag normalisasi (A-02) dan apply menulis format
    kanonis (byte file berubah meski diff kosong)."""
    non_kanonis = (
        "tunnel: 11111111-2222-3333-4444-555555555555\n"
        "credentials-file: credentials-dummy.json\n"
        "ingress:\n"
        "     - service: http_status:404\n"  # indentasi non-kanonis
    )
    target = make_config(tmp_path, non_kanonis)
    preview = make_preview(non_kanonis, non_kanonis)
    assert preview.has_changes is False
    assert preview.original_not_canonical is True
    service = make_service(tmp_path)
    artifact = service.prepare(target, preview, non_kanonis)
    assert artifact.original_not_canonical is True
    outcome = service.apply(artifact, confirm=True)
    assert outcome.applied is True
    # Byte berubah (format kanonis) walau diff kosong — di-flag jujur.
    assert target.read_bytes() != non_kanonis.encode("utf-8")
    assert target.read_bytes() == artifact.proposed_text.encode("utf-8")


# ----------------------------------------------------------------------
# Keamanan
# ----------------------------------------------------------------------
def test_token_dummy_tidak_muncul_di_detail_gagal(tmp_path: Path) -> None:
    """Secret terdaftar (mis. dari credential yang ditemukan E-5) tidak
    bocor ke detail/status gagal (D-18)."""
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    engine = RedactionEngine()
    engine.register_secret(DUMMY_TOKEN, "TUNNEL_SECRET")
    writer = StubWriter(
        fail_calls=(1,),
        error_message=f"tulis gagal di {DUMMY_TOKEN}",
    )
    service = make_service(tmp_path, writer=writer, redaction=engine)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.status is ApplyStatus.WRITE_FAILED
    assert DUMMY_TOKEN not in outcome.detail
    assert DUMMY_TOKEN not in str(outcome)


def test_credential_file_tidak_dibaca_atau_tersalin(tmp_path: Path) -> None:
    """Isi credential tidak pernah dibaca; backup hanya berisi config
    (kebijakan Task 2.4 dipertahankan)."""
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    service = make_service(tmp_path)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.applied is True
    assert outcome.backup_path is not None
    isi_backup = outcome.backup_path.read_text(encoding="utf-8")
    assert DUMMY_TOKEN not in isi_backup
    assert DUMMY_TOKEN not in str(outcome)


def test_temp_tidak_tersisa_setelah_semua_jalur_gagal(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    skenario: tuple[StubWriter, ...] = (
        StubWriter(fail_calls=(1,)),
        StubWriter(fail_calls=(2,), corrupt_calls=(1,)),
        StubWriter(corrupt_calls=(1,)),
    )
    for writer in skenario:
        service = make_service(tmp_path, writer=writer)
        service.apply(artifact, confirm=True)
        sisa = [p for p in tmp_path.rglob("*") if ".tmp-" in p.name]
        assert sisa == [], f"temp tersisa untuk skenario {writer}"


def test_apply_detail_tidak_menyimpan_isi_konfigurasi(tmp_path: Path) -> None:
    """Metadata/detail tidak memuat isi konfigurasi (pola Task 2.4)."""
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    service = make_service(tmp_path)
    outcome = service.apply(artifact, confirm=True)
    assert outcome.detail != ""
    for rahasia in ("11111111-2222", "credentials-dummy", "http_status"):
        assert rahasia not in outcome.detail


# ----------------------------------------------------------------------
# Integrasi Task 2.4 — restore produksi aktif + backup pra-restore (Q4)
# ----------------------------------------------------------------------
def test_restore_dengan_writer_nyata_aktif(tmp_path: Path) -> None:
    """PENDING_ATOMIC_WRITE tertutup: BackupService + writer nyata
    mengaktifkan restore produksi (kontrak Task 2.4 utuh)."""
    target = make_config(tmp_path)
    backup_service = make_backup_service(tmp_path, AtomicConfigFileWriter())
    created = backup_service.create_backup(target, "manual")
    assert created.ok and created.backup_id is not None
    target.write_text(PROPOSED, encoding="utf-8")  # kondisi terkini lain
    outcome = backup_service.restore(created.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.RESTORED
    assert outcome.copied is True
    assert outcome.restored_sha256 == created.sha256
    assert target.read_bytes() == ORIGINAL.encode("utf-8")


def test_restore_backup_pra_restore_target_dibuat(tmp_path: Path) -> None:
    """Q4: sebelum menimpa target yang ada, kondisi terkininya dibackup
    (trigger pre-restore) — TERPISAH dari backup sumber."""
    target = make_config(tmp_path)
    backup_service = make_backup_service(tmp_path, AtomicConfigFileWriter())
    sumber = backup_service.create_backup(target, "manual")
    assert sumber.ok and sumber.backup_id is not None
    target.write_text(ORIGINAL + "# versi lain\n", encoding="utf-8")
    outcome = backup_service.restore(sumber.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.RESTORED
    assert outcome.pre_restore_backup_path is not None
    assert outcome.pre_restore_backup_id is not None
    assert outcome.pre_restore_backup_id != outcome.backup_id
    triggers = sorted(r.trigger for r in backup_service.list_backups())
    assert triggers == ["manual", "pre-restore"]


def test_restore_tanpa_target_backup_pra_restore_dilewati(
    tmp_path: Path,
) -> None:
    """Target tidak ada → restore membuat ulang file; tidak ada backup
    pra-restore (tidak ada yang perlu dibackup)."""
    (tmp_path / "src").mkdir()
    sumber_config = make_config(tmp_path / "src")
    target = tmp_path / "config.yml"
    backup_service = make_backup_service(tmp_path, AtomicConfigFileWriter())
    sumber = backup_service.create_backup(sumber_config, "manual")
    assert sumber.ok and sumber.backup_id is not None
    assert not target.exists()
    outcome = backup_service.restore(sumber.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.RESTORED
    assert outcome.pre_restore_backup_path is None
    assert target.read_bytes() == ORIGINAL.encode("utf-8")


def test_restore_backup_pra_restore_gagal_memblokir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Backup pra-restore gagal → restore DIBATALKAN sebelum menulis
    (keputusan Q4); target tetap versi terkininya."""
    target = make_config(tmp_path)
    backup_service = make_backup_service(tmp_path, AtomicConfigFileWriter())
    sumber = backup_service.create_backup(target, "manual")
    assert sumber.ok and sumber.backup_id is not None
    target.write_text(ORIGINAL + "# versi lain\n", encoding="utf-8")

    asli_create = BackupService.create_backup

    def create_gagal(
        self: BackupService, path: Path, trigger: str = "manual"
    ) -> BackupResult:
        if trigger == "pre-restore":
            return BackupResult(
                status=BackupStatus.WRITE_ERROR, ok=False, detail="simulasi"
            )
        return asli_create(self, path, trigger)

    monkeypatch.setattr(BackupService, "create_backup", create_gagal)
    outcome = backup_service.restore(sumber.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.PRE_RESTORE_BACKUP_FAILED
    assert outcome.copied is False
    assert target.read_bytes() == ORIGINAL.encode("utf-8") + b"# versi lain\n"


def test_restore_tanpa_writer_tetap_pending(tmp_path: Path) -> None:
    """Regresi kontrak Task 2.4: tanpa writer → PENDING_ATOMIC_WRITE,
    nol byte, TANPA backup pra-restore (tidak ada tulis sama sekali)."""
    target = make_config(tmp_path)
    backup_service = make_backup_service(tmp_path)
    sumber = backup_service.create_backup(target, "manual")
    assert sumber.ok and sumber.backup_id is not None
    outcome = backup_service.restore(sumber.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.PENDING_ATOMIC_WRITE
    assert target.read_bytes() == ORIGINAL.encode("utf-8")


def test_restore_pra_restore_bukan_rekursi(tmp_path: Path) -> None:
    """create_backup pra-restore tidak pernah memicu restore/apply —
    register berisi tepat 2 entri (sumber + pra-restore)."""
    target = make_config(tmp_path)
    backup_service = make_backup_service(tmp_path, AtomicConfigFileWriter())
    sumber = backup_service.create_backup(target, "manual")
    assert sumber.backup_id is not None
    target.write_text(ORIGINAL + "# x\n", encoding="utf-8")
    outcome = backup_service.restore(sumber.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.RESTORED
    assert len(backup_service.list_backups()) == 2


def test_restore_hash_register_integritas_dipertahankan(
    tmp_path: Path,
) -> None:
    """Integritas SHA-256 Task 2.4 tetap: hash backup ≠ register →
    ditolak, tanpa tulis, tanpa backup pra-restore."""
    target = make_config(tmp_path)
    backup_service = make_backup_service(tmp_path, AtomicConfigFileWriter())
    sumber = backup_service.create_backup(target, "manual")
    assert sumber.backup_id is not None
    assert sumber.backup_path is not None
    sumber.backup_path.write_bytes(b"dirusak\n")  # hash ≠ register
    outcome = backup_service.restore(sumber.backup_id, target, confirm=True)
    assert outcome.status is RestoreStatus.BACKUP_HASH_MISMATCH
    assert target.read_bytes() == ORIGINAL.encode("utf-8")


# ----------------------------------------------------------------------
# Artefak — integritas hash (optik konkurensi)
# ----------------------------------------------------------------------
def test_artefak_sha_konsisten_dengan_isi(tmp_path: Path) -> None:
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    assert artifact.source_sha256 == hashlib.sha256(
        ORIGINAL.encode("utf-8")
    ).hexdigest()
    assert artifact.proposed_sha256 == hashlib.sha256(
        artifact.proposed_text.encode("utf-8")
    ).hexdigest()


def test_apply_artefak_immutable(tmp_path: Path) -> None:
    """Artefak frozen — byte yang akan ditulis tidak dapat diganti
    diam-diam (Q2: satu artefak, satu byte)."""
    target = make_config(tmp_path)
    artifact = make_artifact(tmp_path, target=target)
    with pytest.raises(Exception):  # noqa: B017 — FrozenInstanceError
        artifact.proposed_text = "dirusak"  # type: ignore[misc]
