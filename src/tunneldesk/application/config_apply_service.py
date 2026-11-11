"""ConfigApplyService (Task 2.5) — apply atomik + rollback otomatis.

Komponen resmi (IMPLEMENTATION_PLAN 2.5, PRD-01 §10/§7.4, D-17):
penulisan atomik + validasi path + pembatasan izin file + rollback
otomatis bila validasi ulang gagal.

Keputusan PO yang diimplementasikan (2026-11-12, mengikat):
- **Q1** — validasi ulang pasca-tulis gagal → rollback OTOMATIS byte
  asli + verifikasi hash rollback; rollback gagal → ``ROLLBACK_FAILED``
  jujur + lokasi backup pemulihan. Tidak ada klaim sukses tanpa
  verifikasi.
- **Q2** — preview dan apply memakai artefak byte yang sama:
  ``prepare()`` mengikat ``ConfigPreview.proposed_emitted_text`` (field
  aditif Task 2.3) + SHA-256 file sumber + path target; ``apply()``
  menulis PERSIS byte itu (tanpa serialisasi ulang YAML), memverifikasi
  ulang hash sumber (artefak basi ditolak), dan memverifikasi hash
  target pasca-tulis. Diff kosong TIDAK berarti byte file tidak
  berubah (normalisasi kanonis A-02 — di-flag ``original_not_canonical``).
- **Q3a** — izin: file lama dipertahankan, file baru ketat (0o600
  POSIX); perilaku nyata di adapter writer (Windows = ACL profil,
  didokumentasikan terpisah).
- **Q3b** — kebijakan path ``path_policy`` + deny-prefix direktori data
  TunnelDesk sendiri; kegagalan path = batal tanpa menyentuh target.
- **Q4** — backup pra-tulis memakai ``BackupService.create_backup``
  (Task 2.4, trigger ``pre-apply``) — TIDAK ada duplikasi; gagal backup
  → batal tanpa menulis. Tidak ada loop: create_backup hanya membaca
  sumber dan menulis ke direktori backup.
- **Q5** — ``confirm=True`` eksplisit wajib; tanpa konfirmasi → ditolak
  tanpa satu byte pun I/O tulis (UI konfirmasi = E-8, bukan di sini).

Kondisi TIDAK boleh disamakan (pola Task 2.4): byte tertulis ≠ hash
cocok ≠ validasi VALID ≠ konfigurasi siap dijalankan — masing-masing
ada di field hasil terpisah. Validasi VALID tidak pernah berarti
tunnel siap (klaim "siap jalan" bukan milik modul ini).

Jaminan konkurensi (jujur): hash-based optimistic concurrency —
perubahan sumber terdeteksi di titik cek (prepare, apply, pra-tulis)
dan ditolak tanpa menulis; jendela TOCTOU mikro antara cek terakhir
dan ``os.replace`` tidak dapat dihilangkan tanpa lock OS (diluar scope)
— diakui terdokumentasi, bukan diklaim tertutup.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from tunneldesk.application.backup_service import BackupService
from tunneldesk.application.config_preview import ConfigPreview
from tunneldesk.application.config_validator import ConfigValidator
from tunneldesk.application.settings_store import default_app_deny_prefixes
from tunneldesk.domain.config.backup import (
    BackupResult,
    ConfigFileWriter,
    sha256_hex,
)
from tunneldesk.domain.config.model import (
    ValidationClassification,
    ValidationOutcome,
)
from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.infrastructure.config_io.path_policy import (
    PathValidationResult,
    PathValidationStatus,
    validate_config_write_path,
)

__all__ = [
    "ApplyArtifact",
    "ApplyOutcome",
    "ApplyStatus",
    "ArtifactRejectedError",
    "ConfigApplyService",
]


class ApplyStatus(enum.Enum):
    """Status apply — kategori tertutup."""

    APPLIED = "APPLIED"
    APPLY_NOT_CONFIRMED = "APPLY_NOT_CONFIRMED"
    #: Preview ditolak / tanpa teks emit usulan / usulan tidak VALID /
    #: isi artefak tidak konsisten dengan hash-nya.
    ARTIFACT_INVALID = "ARTIFACT_INVALID"
    #: File sumber berubah (atau hilang / bukan UTF-8) sejak preview.
    PREVIEW_STALE = "PREVIEW_STALE"
    PATH_REJECTED = "PATH_REJECTED"
    #: Validasi pra-tulis (E-6) menolak usulan — IMPLEMENTATION_PLAN
    #: Fase 2: "Kegagalan validasi mencegah perubahan diterapkan".
    VALIDATION_FAILED = "VALIDATION_FAILED"
    #: Backup pra-apply (Q4/D-17) gagal — batal tanpa menulis.
    BACKUP_FAILED = "BACKUP_FAILED"
    #: Sumber berubah antara prepare dan apply (hash ≠ artefak).
    SOURCE_CHANGED = "SOURCE_CHANGED"
    #: OSError dari writer — target terjamin utuh (jaminan port).
    WRITE_FAILED = "WRITE_FAILED"
    #: Hash target pasca-tulis ≠ artefak — rollback otomatis (Q1).
    WRITE_HASH_MISMATCH = "WRITE_HASH_MISMATCH"
    #: Validasi ulang pasca-tulis tidak VALID — rollback otomatis (Q1).
    POST_WRITE_VALIDATION_FAILED = "POST_WRITE_VALIDATION_FAILED"
    #: Rollback gagal/tidak terverifikasi — pemulihan manual via backup.
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


@dataclass(frozen=True)
class ApplyArtifact:
    """Artefak preview→apply yang tak berubah (keputusan PO Q2).

    Mengikat: path target, SHA-256 file sumber saat prepare, dan teks
    emit usulan PERSIS (dari ``ConfigPreview.proposed_emitted_text``)
    beserta hash-nya — satu-satunya byte yang boleh ditulis ``apply()``.
    """

    target_path: Path
    source_sha256: str
    proposed_text: str
    proposed_sha256: str
    #: Kejujuran normalisasi A-02 (warisan preview): True berarti apply
    #: akan menulis ulang dokumen dalam format kanonis.
    original_not_canonical: bool
    #: Preview sumber artefak (ketertelusuran; frozen).
    preview: ConfigPreview


@dataclass(frozen=True)
class ApplyOutcome:
    """Hasil apply — hasil tulis, hash, validasi, dan rollback TERPISAH."""

    status: ApplyStatus
    ok: bool
    detail: str = ""
    target_path: Path | None = None
    #: True bila byte benar-benar tertulis ke target (terverifikasi hash).
    applied: bool = False
    written_sha256: str | None = None
    #: Validasi ulang pasca-tulis (E-6) — terpisah dari hasil tulis.
    post_write_validation: ValidationOutcome | None = None
    #: True bila rollback berjalan DAN hashnya terverifikasi.
    rolled_back: bool = False
    rollback_sha256: str | None = None
    #: Backup pra-apply (Q4) — jaring pemulihan untuk ROLLBACK_FAILED.
    backup_id: str | None = None
    backup_path: Path | None = None
    #: Status kebijakan path bila PATH_REJECTED (ketertelusuran).
    path_status: PathValidationStatus | None = None


class ArtifactRejectedError(RuntimeError):
    """``prepare()`` menolak membuat artefak (kesalahan pemanggil/file).

    ``reason`` = nilai ``ApplyStatus`` terkait; ``detail`` sudah
    disanitasi (D-18). Pola konsisten dengan ``PreviewRejectedError``
    (Task 2.3).
    """

    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")


class ConfigApplyService:
    """Orkestrator apply konfigurasi (rantai D-17: preview → backup →
    validasi → konfirmasi → apply → validasi ulang → rollback)."""

    def __init__(
        self,
        writer: ConfigFileWriter,
        backup_service: BackupService,
        validator: ConfigValidator | None = None,
        redaction: RedactionEngine | None = None,
        deny_prefixes: Sequence[Path] | None = None,
    ) -> None:
        self._writer = writer
        #: BackupService Task 2.4 — hanya create_backup yang dipakai
        #: (Q4: tanpa duplikasi mekanisme backup).
        self._backup = backup_service
        self._validator = validator or ConfigValidator()
        self._redaction = redaction or RedactionEngine()
        #: Deny-prefix aplikasi (Q3b-8) — SATU SUMBER dengan jalur
        #: restore (koreksi audit T-2): default_app_deny_prefixes().
        self._deny_prefixes: tuple[Path, ...] = tuple(
            deny_prefixes
            if deny_prefixes is not None
            else default_app_deny_prefixes()
        )

    # ------------------------------------------------------------------
    # prepare — artefak preview→apply (Q2)
    # ------------------------------------------------------------------
    def prepare(
        self,
        target_path: Path,
        preview: ConfigPreview,
        original_text: str,
    ) -> ApplyArtifact:
        """Buat artefak tulis dari preview — TANPA menulis apa pun.

        ``original_text`` wajib teks PERSIS yang diberikan ke
        ``preview()`` dan dibaca dari ``target_path`` (utf-8) —
        diverifikasi byte-per-byte agar preview tidak bisa basi lolos.
        """
        target_path = Path(target_path)
        if preview.rejected or preview.proposed_emitted_text is None:
            raise ArtifactRejectedError(
                "ARTIFACT_INVALID",
                "preview tidak memuat artefak tulis (ditolak atau tanpa "
                "teks emit usulan)",
            )
        if preview.proposed_classification is not (
            ValidationClassification.VALID
        ):
            raise ArtifactRejectedError(
                "ARTIFACT_INVALID",
                "konfigurasi usulan tidak VALID (E-6) — tidak dapat "
                "disiapkan untuk apply",
            )
        if not target_path.is_absolute():
            raise ArtifactRejectedError(
                "PATH_REJECTED", "path target wajib absolut"
            )
        try:
            source_bytes = target_path.read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactRejectedError(
                "PREVIEW_STALE",
                "file konfigurasi tidak ditemukan — preview basi",
            ) from exc
        except OSError as exc:
            raise ArtifactRejectedError(
                "PREVIEW_STALE",
                f"file konfigurasi tidak dapat dibaca: "
                f"{self._sanitize(str(exc))}",
            ) from exc
        try:
            decoded = source_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ArtifactRejectedError(
                "PREVIEW_STALE",
                "file konfigurasi bukan UTF-8 valid — preview basi",
            ) from exc
        if decoded != original_text:
            raise ArtifactRejectedError(
                "PREVIEW_STALE",
                "isi file konfigurasi berubah sejak preview — ulangi "
                "preview",
            )
        proposed_text = preview.proposed_emitted_text
        return ApplyArtifact(
            target_path=target_path,
            source_sha256=sha256_hex(source_bytes),
            proposed_text=proposed_text,
            proposed_sha256=sha256_hex(proposed_text.encode("utf-8")),
            original_not_canonical=preview.original_not_canonical,
            preview=preview,
        )

    # ------------------------------------------------------------------
    # apply — tulis atomik + rollback otomatis (Q1/Q5)
    # ------------------------------------------------------------------
    def apply(self, artifact: ApplyArtifact, confirm: bool = False) -> ApplyOutcome:
        """Terapkan artefak ke target — wajib ``confirm=True`` (Q5).

        Urutan (instruksi Task 2.5 §6): konfirmasi → kebijakan path →
        verifikasi hash sumber (artefak basi ditolak) → integritas
        artefak → validasi pra-tulis (E-6) → backup pra-apply (Q4) →
        verifikasi ulang sumber (perkecil TOCTOU) → tulis atomik →
        verifikasi hash target → validasi ulang → rollback otomatis
        bila gagal (Q1).
        """
        target = artifact.target_path
        if not confirm:
            return ApplyOutcome(
                ApplyStatus.APPLY_NOT_CONFIRMED,
                ok=False,
                detail="apply membutuhkan konfirmasi eksplisit "
                "(confirm=True) — tidak ada byte yang disentuh",
                target_path=target,
            )

        path_result = self._check_path(target)
        if not path_result.ok:
            return ApplyOutcome(
                ApplyStatus.PATH_REJECTED,
                ok=False,
                detail=f"kebijakan path menolak target: {path_result.detail}",
                target_path=target,
                path_status=path_result.status,
            )

        source_bytes = self._read_source(target)
        if isinstance(source_bytes, ApplyOutcome):
            return source_bytes
        assert source_bytes is not None
        if sha256_hex(source_bytes) != artifact.source_sha256:
            return ApplyOutcome(
                ApplyStatus.SOURCE_CHANGED,
                ok=False,
                detail="file konfigurasi berubah sejak artefak dibuat — "
                "artefak basi ditolak, tidak ada yang ditulis",
                target_path=target,
            )

        proposed_bytes = artifact.proposed_text.encode("utf-8")
        if sha256_hex(proposed_bytes) != artifact.proposed_sha256:
            return ApplyOutcome(
                ApplyStatus.ARTIFACT_INVALID,
                ok=False,
                detail="isi artefak tidak konsisten dengan hash-nya — "
                "ditolak",
                target_path=target,
            )

        pre_validation = self._validate_text_for_target(
            artifact.proposed_text, target
        )
        if pre_validation.classification is not (
            ValidationClassification.VALID
        ):
            return ApplyOutcome(
                ApplyStatus.VALIDATION_FAILED,
                ok=False,
                detail="validasi pra-tulis menolak usulan — tidak ada "
                "perubahan diterapkan (IMPLEMENTATION_PLAN Fase 2)",
                target_path=target,
                post_write_validation=pre_validation,
            )

        backup = self._create_pre_write_backup(target, "pre-apply")
        if isinstance(backup, ApplyOutcome):
            return backup
        assert backup is not None

        original_bytes = self._read_source(target)
        if isinstance(original_bytes, ApplyOutcome):
            return original_bytes
        assert original_bytes is not None
        original_sha = sha256_hex(original_bytes)
        if original_sha != artifact.source_sha256:
            return self._failed_with_backup(
                ApplyStatus.SOURCE_CHANGED,
                target,
                backup,
                detail="file konfigurasi berubah saat persiapan apply — "
                "dibatalkan, tidak ada yang ditulis",
            )

        try:
            self._writer.write_config_bytes(target, proposed_bytes)
        except OSError as exc:
            return self._failed_with_backup(
                ApplyStatus.WRITE_FAILED,
                target,
                backup,
                detail=f"penulisan atomik gagal (target utuh): "
                f"{self._sanitize(str(exc))}",
            )

        written_sha = self._read_sha(target)
        if written_sha != artifact.proposed_sha256:
            return self._rollback(
                status=ApplyStatus.WRITE_HASH_MISMATCH,
                detail_prefix="hash target pasca-tulis tidak cocok dengan "
                "artefak",
                target=target,
                original_bytes=original_bytes,
                original_sha=original_sha,
                backup=backup,
            )

        post_validation = self._validator.validate_path(target)
        if post_validation.classification is not (
            ValidationClassification.VALID
        ):
            return self._rollback(
                status=ApplyStatus.POST_WRITE_VALIDATION_FAILED,
                detail_prefix="validasi ulang pasca-tulis tidak VALID",
                target=target,
                original_bytes=original_bytes,
                original_sha=original_sha,
                backup=backup,
                post_validation=post_validation,
            )

        return ApplyOutcome(
            ApplyStatus.APPLIED,
            ok=True,
            detail="konfigurasi diterapkan dan tervalidasi ulang VALID "
            "(bukan klaim tunnel siap dijalankan)",
            target_path=target,
            applied=True,
            written_sha256=written_sha,
            post_write_validation=post_validation,
            backup_id=backup.backup_id,
            backup_path=backup.backup_path,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _check_path(self, target: Path) -> PathValidationResult:
        """Kebijakan Q3b + deny-prefix direktori data aplikasi."""
        return validate_config_write_path(
            target, deny_prefixes=self._deny_prefixes
        )

    def _read_source(self, target: Path) -> bytes | ApplyOutcome:
        """Baca sumber; gagal → SOURCE_CHANGED terstruktur."""
        try:
            return target.read_bytes()
        except OSError as exc:
            return ApplyOutcome(
                ApplyStatus.SOURCE_CHANGED,
                ok=False,
                detail=f"file konfigurasi tidak dapat dibaca: "
                f"{self._sanitize(str(exc))}",
                target_path=target,
            )

    def _read_sha(self, target: Path) -> str | None:
        """Hash target pasca-tulis; None bila tidak terbaca."""
        try:
            return sha256_hex(target.read_bytes())
        except OSError:
            return None

    def _validate_text_for_target(
        self, text: str, target: Path
    ) -> ValidationOutcome:
        """Validasi E-6 teks dengan resolusi credentials-file relatif
        terhadap direktori target — semantik SAMA dengan
        ``validate_path`` agar pra- dan pasca-tulis dapat dibandingkan
        adil. Isi credential tidak pernah dibaca."""
        def credentials_exists(reference: str) -> bool:
            candidate = Path(reference)
            if not candidate.is_absolute():
                candidate = target.parent / candidate
            return candidate.is_file()

        return self._validator.validate_text(
            text, credentials_file_exists=credentials_exists
        )

    def _create_pre_write_backup(
        self, target: Path, trigger: str
    ) -> ApplyOutcome | BackupResult:
        """Backup pra-tulis via Task 2.4 (Q4) — tanpa duplikasi, tanpa
        loop (create_backup hanya membaca sumber). Gagal → outcome."""
        result = self._backup.create_backup(target, trigger)
        if not result.ok:
            return self._failed_with_backup(
                ApplyStatus.BACKUP_FAILED,
                target,
                None,
                detail=f"backup pra-tulis gagal ({result.status.value}) — "
                "apply dibatalkan, tidak ada yang ditulis",
                fallback_detail=result.detail,
            )
        return result

    def _rollback(
        self,
        *,
        status: ApplyStatus,
        detail_prefix: str,
        target: Path,
        original_bytes: bytes,
        original_sha: str,
        backup: BackupResult,
        post_validation: ValidationOutcome | None = None,
    ) -> ApplyOutcome:
        """Rollback OTOMATIS (Q1): tulis ulang byte asli via writer
        atomik + verifikasi hash. Gagal → ROLLBACK_FAILED jujur dengan
        lokasi backup (jaring keselamatan Task 2.4)."""
        backup_id = backup.backup_id
        backup_path = backup.backup_path
        recovery = (
            f"pemulihan manual tersedia: backup {backup_path} "
            f"(id {backup_id})"
        )
        try:
            self._writer.write_config_bytes(target, original_bytes)
        except OSError as exc:
            return ApplyOutcome(
                ApplyStatus.ROLLBACK_FAILED,
                ok=False,
                detail=f"{detail_prefix}; rollback GAGAL (tulis): "
                f"{self._sanitize(str(exc))}; {recovery}",
                target_path=target,
                post_write_validation=post_validation,
                backup_id=backup_id,
                backup_path=backup_path,
            )
        rollback_sha = self._read_sha(target)
        if rollback_sha != original_sha:
            return ApplyOutcome(
                ApplyStatus.ROLLBACK_FAILED,
                ok=False,
                detail=f"{detail_prefix}; rollback TIDAK terverifikasi "
                f"(hash target kini ≠ hash awal) — kondisi target tidak "
                f"diklaim; {recovery}",
                target_path=target,
                post_write_validation=post_validation,
                backup_id=backup_id,
                backup_path=backup_path,
            )
        return ApplyOutcome(
            status,
            ok=False,
            detail=f"{detail_prefix}; rollback otomatis berhasil dan "
            f"terverifikasi (hash cocok); {recovery}",
            target_path=target,
            post_write_validation=post_validation,
            rolled_back=True,
            rollback_sha256=rollback_sha,
            backup_id=backup_id,
            backup_path=backup_path,
        )

    def _failed_with_backup(
        self,
        status: ApplyStatus,
        target: Path,
        backup: BackupResult | None,
        detail: str,
        fallback_detail: str = "",
    ) -> ApplyOutcome:
        """Outcome gagal yang tetap melaporkan info backup bila ada."""
        suffix = f"; {fallback_detail}" if fallback_detail else ""
        return ApplyOutcome(
            status,
            ok=False,
            detail=f"{detail}{suffix}",
            target_path=target,
            backup_id=backup.backup_id if backup else None,
            backup_path=backup.backup_path if backup else None,
        )

    def _sanitize(self, text: str) -> str:
        return self._redaction.redact(text)
