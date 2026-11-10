"""Model hasil validasi konfigurasi (E-6, tugas 2.2 — PRD-01 §7.4).

Klasifikasi tertutup (PRD-02 §3.2):
- VALID    : struktur & nilai yang didukung lulus validasi.
- INVALID  : kesalahan sintaks atau pelanggaran skema yang dapat dipastikan.
- UNKNOWN  : terdapat struktur/field yang tidak dapat dipastikan didukung —
             **tidak pernah** dikonversi menjadi VALID melalui asumsi.

Modul murni domain: tanpa ruamel/Qt/subprocess (A-08). Pesan error yang
melewati modul ini tetap wajib disanitasi RedactionEngine (D-18) di
lapisan application.
"""

from __future__ import annotations

import enum

__all__ = [
    "ValidationClassification",
    "ValidationErrorItem",
    "ValidationOutcome",
]


class ValidationClassification(enum.Enum):
    """Klasifikasi hasil validasi — kategori tertutup (PRD-02 §3.2)."""

    VALID = "VALID"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"


class ValidationErrorItem:
    """Satu temuan validasi — kode, lokasi, dan pesan yang aman.

    ``message`` dijamin sudah disanitasi oleh lapisan application sebelum
    dipublikasikan; model tidak menambahkan nilai mentah pengguna selain
    potongan pendek yang diperlukan untuk diagnostik.
    """

    __slots__ = ("code", "message", "line", "column", "location", "is_warning")

    def __init__(
        self,
        code: str,
        message: str,
        line: int | None = None,
        column: int | None = None,
        location: str | None = None,
        is_warning: bool = False,
    ) -> None:
        self.code = code
        self.message = message
        self.line = line
        self.column = column
        self.location = location
        self.is_warning = is_warning

    def __repr__(self) -> str:
        lokasi = f" @ {self.location}" if self.location else ""
        posisi = f" (baris {self.line})" if self.line is not None else ""
        jenis = " [peringatan]" if self.is_warning else ""
        return f"{self.code}{lokasi}{posisi}{jenis}: {self.message}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ValidationErrorItem):
            return NotImplemented
        return (
            self.code == other.code
            and self.message == other.message
            and self.line == other.line
            and self.column == other.column
            and self.location == other.location
            and self.is_warning == other.is_warning
        )

    def __hash__(self) -> int:
        return hash(
            (self.code, self.message, self.line, self.column, self.location,
             self.is_warning)
        )


class ValidationOutcome:
    """Hasil akhir validasi satu dokumen konfigurasi.

    Aturan klasifikasi (deterministik, ditegakkan ``schema.py``):
    INVALID > UNKNOWN > VALID.
    """

    __slots__ = (
        "classification",
        "errors",
        "warnings",
        "round_trip_preserved",
    )

    def __init__(
        self,
        classification: ValidationClassification,
        errors: tuple[ValidationErrorItem, ...] = (),
        warnings: tuple[ValidationErrorItem, ...] = (),
        round_trip_preserved: bool | None = None,
    ) -> None:
        self.classification = classification
        self.errors = errors
        self.warnings = warnings
        self.round_trip_preserved = round_trip_preserved

    def __repr__(self) -> str:
        return (
            f"ValidationOutcome({self.classification.value}, "
            f"errors={len(self.errors)}, warnings={len(self.warnings)})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ValidationOutcome):
            return NotImplemented
        return (
            self.classification == other.classification
            and self.errors == other.errors
            and self.warnings == other.warnings
            and self.round_trip_preserved == other.round_trip_preserved
        )
