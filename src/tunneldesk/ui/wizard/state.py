"""State Setup Wizard (Task 2.6) — hasil per langkah + agregasi cek.

Pemegang state sederhana (dataclass mutable) berisi hasil per langkah;
setiap hasil adalah objek frozen dari backend (kontrak tidak diubah).
``CheckOutcome``/``OriginRow`` adalah agregasi UI atas hasil validasi
E-6 dan probe origin — bukan kontrak domain baru.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from tunneldesk.application.config_apply_service import (
    ApplyArtifact,
    ApplyOutcome,
    ApplyStatus,
)
from tunneldesk.application.config_preview import ConfigPreview
from tunneldesk.application.config_proposal import ProposalResult, WizardProposal
from tunneldesk.domain.config.model import (
    ValidationClassification,
    ValidationOutcome,
)
from tunneldesk.domain.diagnostics.origin import (
    OriginCheckResult,
    OriginTarget,
)
from tunneldesk.domain.tunnel.detection import DetectionReport

__all__ = [
    "OriginRow",
    "CheckOutcome",
    "WizardState",
    "apply_status_text_key",
]

#: Pemetaan ApplyStatus → kunci string Q-06 (tabel error mapping tahap 8).
_APPLY_STATUS_KEYS: dict[ApplyStatus, str] = {
    ApplyStatus.APPLIED: "wiz.st.applied",
    ApplyStatus.APPLY_NOT_CONFIRMED: "wiz.st.apply_not_confirmed",
    ApplyStatus.ARTIFACT_INVALID: "wiz.st.artifact_invalid",
    ApplyStatus.PREVIEW_STALE: "wiz.st.preview_stale",
    ApplyStatus.PATH_REJECTED: "wiz.st.path_rejected",
    ApplyStatus.VALIDATION_FAILED: "wiz.st.validation_failed",
    ApplyStatus.BACKUP_FAILED: "wiz.st.backup_failed",
    ApplyStatus.SOURCE_CHANGED: "wiz.st.source_changed",
    ApplyStatus.WRITE_FAILED: "wiz.st.write_failed",
    ApplyStatus.WRITE_HASH_MISMATCH: "wiz.st.write_hash_mismatch",
    ApplyStatus.POST_WRITE_VALIDATION_FAILED: (
        "wiz.st.post_write_validation_failed"
    ),
    ApplyStatus.ROLLBACK_FAILED: "wiz.st.rollback_failed",
}


def apply_status_text_key(status: ApplyStatus) -> str:
    """Kunci string untuk status apply — KeyError berarti mapping belum
    lengkap (dijaga penuh oleh uji)."""
    return _APPLY_STATUS_KEYS[status]


@dataclass(frozen=True)
class OriginRow:
    """Satu baris hasil pemeriksaan origin pada halaman cek."""

    service: str
    target: OriginTarget | None = None
    error: str | None = None       # alasan tidak dapat dipetakan (PC-2)
    skipped: bool = False          # catch-all http_status: — dilewati
    result: OriginCheckResult | None = None


@dataclass(frozen=True)
class CheckOutcome:
    """Agregasi halaman cek: validasi skema + origin lokal (W-3)."""

    validation: ValidationOutcome
    origin_rows: tuple[OriginRow, ...]

    @property
    def blocked(self) -> bool:
        """Lanjut ke preview diblokir bila usulan tidak VALID (W-4:
        credentials hilang termasuk INVALID — blokir jujur)."""
        return self.validation.classification is not (
            ValidationClassification.VALID
        )

    @property
    def credentials_missing(self) -> bool:
        return any(
            item.code == "CREDENTIALS_FILE_MISSING"
            for item in self.validation.errors
        )


@dataclass
class WizardState:
    """Pemegang hasil antar-langkah wizard (diolah dialog, dibaca halaman)."""

    detection: DetectionReport | None = None
    target_path: Path | None = None
    original_text: str | None = None
    proposal: WizardProposal | None = None
    proposal_result: ProposalResult | None = None
    check: CheckOutcome | None = None
    preview: ConfigPreview | None = None
    artifact: ApplyArtifact | None = None
    outcome: ApplyOutcome | None = None
    settings_note: str = ""
    error: str = field(default="")
