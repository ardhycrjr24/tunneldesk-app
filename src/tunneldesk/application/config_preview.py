"""ConfigPreviewService (Task 2.3) — preview/diff read-only.

Kontrak (TASK_2_3_SCOPE_REVIEW §4/§8, disetujui):
- Input: teks konfigurasi **awal** dan **usulan** (keduanya di-emit
  dengan konfigurasi emitter E-6 yang identik — emit-vs-emit).
- Preview ditolak bila salah satu sisi sintaksnya rusak (tidak ada
  dasar diff yang berarti).
- UNKNOWN → preview + peringatan eksplisit; INVALID usulan → preview +
  label tidak siap diterapkan (keputusan apply = Task 2.5, bukan di sini).
- Kunci tak dikenal **dipertahankan dan ditandai**.
- Semua teks (baris diff, pesan) disanitasi RedactionEngine E-1 (D-18).
- Read-only: tidak ada penulisan file, tidak ada file sementara di
  direktori konfigurasi.

Preview bukan persetujuan untuk apply; mekanisme apply = Task 2.5.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from tunneldesk.domain.config.diff import (
    ConfigDiff,
    ConfigDiffLine,
    compute_config_diff,
)
from tunneldesk.domain.config.model import (
    ValidationClassification,
    ValidationErrorItem,
)
from tunneldesk.domain.config.schema import validate_tunnel_config
from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.infrastructure.config_io.yaml_parser import (
    ParsedYaml,
    RoundTripYamlParser,
)

__all__ = [
    "ConfigPreview",
    "PreviewRejectedError",
    "ConfigPreviewService",
]

_UNKNOWN_NOTE = (
    "dokumen memuat struktur yang tidak dikenali skema TunnelDesk — "
    "bagian tersebut akan dipertahankan apa adanya dan tidak akan "
    "diubah otomatis"
)
_REJECTED_ORIGINAL = (
    "konfigurasi awal memiliki kesalahan sintaks — preview tidak dapat dibuat"
)
_REJECTED_PROPOSED = (
    "konfigurasi usulan memiliki kesalahan sintaks — preview tidak dapat dibuat"
)


@dataclass(frozen=True)
class ConfigPreview:
    """Hasil preview/diff — read-only, siap ditampilkan (sudah disanitasi)."""

    #: True bila preview ditolak (sintaks salah) — fields lain minimal.
    rejected: bool
    rejection_reason: str | None
    #: Item penolakan yang sudah disanitasi (kosong bila tidak ditolak).
    rejection_errors: tuple[ValidationErrorItem, ...]
    original_classification: ValidationClassification | None
    proposed_classification: ValidationClassification | None
    #: True bila sisi mana pun memuat kunci/struktur tak dikenal.
    contains_unknown_structure: bool
    #: True bila teks emit awal ternyata dinormalkan parser (indentasi/CRLF).
    original_not_canonical: bool
    diff: ConfigDiff | None
    #: Catatan untuk pengguna (sudah disanitasi).
    notes: tuple[str, ...]

    @property
    def has_changes(self) -> bool:
        if self.diff is None:
            return False
        return self.diff.has_changes

    @property
    def proposed_ready_to_apply(self) -> bool:
        """Label kejujuran: INVALID/UNKNOWN/rejected **bukan** siap apply.
        Keputusan dan mekanisme apply tetap milik Task 2.5."""
        return (
            not self.rejected
            and self.proposed_classification is ValidationClassification.VALID
            and self.diff is not None
            and self.diff.has_changes
        )


class PreviewRejectedError(RuntimeError):
    """Preview ditolak karena salah satu sisi sintaksnya rusak.

    ``errors`` berisi item yang **sudah disanitasi** (D-18)."""

    def __init__(
        self, reason: str, errors: tuple[ValidationErrorItem, ...]
    ) -> None:
        self.reason = reason
        self.errors = errors
        super().__init__(reason)


class _ValidatedSide:
    """Hasil validasi satu sisi (awal/usulan) — internal."""

    __slots__ = (
        "classification",
        "sanitized_errors",
        "sanitized_warnings",
        "syntax_rejected",
    )

    def __init__(
        self,
        classification: ValidationClassification,
        sanitized_errors: tuple[ValidationErrorItem, ...],
        sanitized_warnings: tuple[ValidationErrorItem, ...],
        syntax_rejected: bool,
    ) -> None:
        self.classification = classification
        self.sanitized_errors = sanitized_errors
        self.sanitized_warnings = sanitized_warnings
        self.syntax_rejected = syntax_rejected


class ConfigPreviewService:
    """Preview/diff emit-vs-emit — read-only, deterministik, tersanitasi."""

    def __init__(
        self,
        parser: RoundTripYamlParser | None = None,
        redaction: RedactionEngine | None = None,
    ) -> None:
        self._parser = parser or RoundTripYamlParser()
        self._redaction = redaction or RedactionEngine()

    def register_secret(self, value: str, label: str = "SECRET") -> bool:
        """Daftarkan nilai rahasia yang diketahui (mis. TunnelSecret dari
        credential yang ditemukan E-5) — tidak pernah lolos ke preview."""
        return self._redaction.register_secret(value, label)

    # ------------------------------------------------------------------
    # Preview utama
    # ------------------------------------------------------------------
    def preview(self, original_text: str, proposed_text: str) -> ConfigPreview:
        """Bandingkan konfigurasi awal vs usulan (emit-vs-emit).

        Kedua teks **tidak pernah ditulis ke disk**; file konfigurasi
        pengguna tidak disentuh.
        """
        original = self._parser.parse(original_text)
        proposed = self._parser.parse(proposed_text)

        original_side = self._validated_side(original)
        proposed_side = self._validated_side(proposed)

        if original_side.syntax_rejected:
            raise PreviewRejectedError(
                _REJECTED_ORIGINAL, original_side.sanitized_errors
            )
        if proposed_side.syntax_rejected:
            raise PreviewRejectedError(
                _REJECTED_PROPOSED, proposed_side.sanitized_errors
            )

        assert original.emitted_text is not None
        assert proposed.emitted_text is not None
        raw_diff = compute_config_diff(
            original.emitted_text, proposed.emitted_text
        )
        sanitized_diff = ConfigDiff(
            tuple(
                ConfigDiffLine(
                    kind=line.kind,
                    text=self._sanitize(line.text),
                    old_number=line.old_number,
                    new_number=line.new_number,
                )
                for line in raw_diff.lines
            )
        )

        notes: list[str] = []
        contains_unknown = False
        if (
            original_side.classification is ValidationClassification.UNKNOWN
        ):
            contains_unknown = True
            notes.append("Konfigurasi awal: " + _UNKNOWN_NOTE)
        if (
            proposed_side.classification is ValidationClassification.UNKNOWN
        ):
            contains_unknown = True
            notes.append("Konfigurasi usulan: " + _UNKNOWN_NOTE)
        if not original.round_trip_preserved:
            notes.append(
                "format konfigurasi awal akan dinormalkan (indentasi/urutan "
                "baris) agar konsisten — perubahan format ini tampil di diff"
            )
        # Pelanggaran skema tetap dilaporkan (informasi), walau klasifikasi
        # kini UNKNOWN akibat kunci tak dikenal.
        for label_sisi, side in (
            ("awal", original_side),
            ("usulan", proposed_side),
        ):
            for item in side.sanitized_errors:
                if item.code == "UNKNOWN_TOP_LEVEL_KEY":
                    continue
                notes.append(
                    f"Kesalahan skema (konfigurasi {label_sisi}) "
                    f"{item.code}: {item.message}"
                )

        return ConfigPreview(
            rejected=False,
            rejection_reason=None,
            rejection_errors=(),
            original_classification=original_side.classification,
            proposed_classification=proposed_side.classification,
            contains_unknown_structure=contains_unknown,
            original_not_canonical=not original.round_trip_preserved,
            diff=sanitized_diff,
            notes=tuple(notes),
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _validated_side(self, parsed: ParsedYaml) -> _ValidatedSide:
        """Validasi satu sisi + sanitasi; sintaks rusak → ditolak."""
        if parsed.syntax_errors:
            sanitized = tuple(
                ValidationErrorItem(
                    code="SYNTAX_ERROR",
                    message=self._sanitize(message),
                    line=line,
                    column=column,
                )
                for message, line, column in parsed.syntax_errors
            )
            return _ValidatedSide(
                classification=ValidationClassification.INVALID,
                sanitized_errors=sanitized,
                sanitized_warnings=(),
                syntax_rejected=True,
            )
        assert parsed.document is not None
        classification, errors, warnings = validate_tunnel_config(
            cast("Mapping[Any, Any]", parsed.document)
        )
        return _ValidatedSide(
            classification=classification,
            sanitized_errors=tuple(
                self._sanitized_item(item) for item in errors
            ),
            sanitized_warnings=tuple(
                self._sanitized_item(item) for item in warnings
            ),
            syntax_rejected=False,
        )

    def _sanitized_item(self, item: ValidationErrorItem) -> ValidationErrorItem:
        return ValidationErrorItem(
            code=item.code,
            message=self._sanitize(item.message),
            line=item.line,
            column=item.column,
            location=item.location,
            is_warning=item.is_warning,
        )

    def _sanitize(self, text: str) -> str:
        # RedactionEngine E-1 fail-safe: tidak melempar dan tidak
        # mengembalikan nilai terdaftar.
        return self._redaction.redact(text)
