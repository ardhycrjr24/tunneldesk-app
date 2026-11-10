"""ConfigValidator (E-6) — orkestrasi validasi read-only.

Alur: baca teks config (read-only) → parse round-trip (A-02) → validasi
skema domain → sanitasi semua pesan (D-18) → :class:`ValidationOutcome`.

Jaminan:
- **Tidak ada penulisan file** — diverifikasi uji hash sebelum/sesudah.
- Isi credential file tidak pernah dibaca (hanya keberadaan, via
  callback yang diinjeksikan).
- Exception parser yang meng-echo baris YAML disanitasi sebelum masuk
  pesan; kegagalan sanitasi → fail-safe placeholder (E-1).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

from tunneldesk.domain.config.model import (
    ValidationClassification,
    ValidationErrorItem,
    ValidationOutcome,
)
from tunneldesk.domain.config.schema import validate_tunnel_config
from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.infrastructure.config_io.yaml_parser import RoundTripYamlParser

__all__ = ["ConfigValidator"]


class ConfigValidator:
    """Validator read-only untuk satu file konfigurasi tunnel."""

    def __init__(
        self,
        parser: RoundTripYamlParser | None = None,
        redaction: RedactionEngine | None = None,
    ) -> None:
        self._parser = parser or RoundTripYamlParser()
        self._redaction = redaction or RedactionEngine()

    def register_secret(self, value: str, label: str = "SECRET") -> bool:
        """Daftarkan nilai rahasia yang diketahui (mis. dari credential
        file yang ditemukan E-5) ke engine redaksi — D-18."""
        return self._redaction.register_secret(value, label)

    # ------------------------------------------------------------------
    # Validasi dari path (integrasi ConfigCandidate E-5)
    # ------------------------------------------------------------------
    def validate_path(self, config_path: Path) -> ValidationOutcome:
        """Baca (read-only) dan validasi file konfigurasi.

        ``credentials-file`` relatif diselesaikan terhadap direktori file
        konfigurasi; keberadaan dicek via callback ke filesystem, isi file
        credential tidak pernah dibaca.
        """
        config_path = Path(config_path)
        try:
            text = config_path.read_text(encoding="utf-8")
        except OSError as exc:
            return self._outcome_from_error(
                f"file konfigurasi tidak dapat dibaca: {self._sanitize(str(exc))}"
            )

        def credentials_exists(reference: str) -> bool:
            candidate = Path(reference)
            if not candidate.is_absolute():
                candidate = config_path.parent / candidate
            return candidate.is_file()

        return self.validate_text(
            text, credentials_file_exists=credentials_exists
        )

    # ------------------------------------------------------------------
    # Validasi dari teks (murni — dipakai uji & worker)
    # ------------------------------------------------------------------
    def validate_text(
        self,
        text: str,
        credentials_file_exists: bool | Callable[[str], bool] | None = None,
    ) -> ValidationOutcome:
        """Validasi teks YAML.

        ``credentials_file_exists``: ``bool`` = jawaban tetap untuk semua
        referensi; ``callable`` = pemeriksa per referensi; ``None`` =
        pemeriksaan keberadaan dilewati (hanya validitas referensi).
        """
        parsed = self._parser.parse(text)

        if parsed.syntax_errors:
            errors = tuple(
                ValidationErrorItem(
                    code="SYNTAX_ERROR",
                    message=self._sanitize(message),
                    line=line,
                    column=column,
                )
                for message, line, column in parsed.syntax_errors
            )
            return ValidationOutcome(
                classification=ValidationClassification.INVALID,
                errors=errors,
                round_trip_preserved=parsed.round_trip_preserved,
            )

        exists_checker: Callable[[str], bool] | None = None
        if isinstance(credentials_file_exists, bool):
            answer = credentials_file_exists
            exists_checker = lambda reference: answer  # noqa: E731
        elif credentials_file_exists is not None:
            exists_checker = credentials_file_exists

        classification, errors, warnings = validate_tunnel_config(
            cast("Mapping[Any, Any]", parsed.document),
            credentials_file_exists=exists_checker,
        )

        return ValidationOutcome(
            classification=classification,
            errors=tuple(self._sanitized_item(item) for item in errors),
            warnings=tuple(self._sanitized_item(item) for item in warnings),
            round_trip_preserved=parsed.round_trip_preserved,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
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
        # RedactionEngine E-1 sudah fail-safe: tidak pernah melempar dan
        # tidak pernah mengembalikan nilai terdaftar.
        return self._redaction.redact(text)

    @staticmethod
    def _outcome_from_error(message: str) -> ValidationOutcome:
        return ValidationOutcome(
            classification=ValidationClassification.INVALID,
            errors=(
                ValidationErrorItem(
                    code="CONFIG_UNREADABLE", message=message
                ),
            ),
        )
