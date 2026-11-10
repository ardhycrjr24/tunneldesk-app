"""Engine diff konfigurasi (Task 2.3) — murni dan deterministik.

Kontrak (TASK_2_3_SCOPE_REVIEW §4, disetujui Project Control):
- Input: **dua teks hasil emit** (konfigurasi awal & usulan) dari
  konfigurasi emitter ruamel yang identik (warisan E-6: indent
  mapping=2/sequence=4/offset=2) — sehingga normalisasi indentasi
  tidak muncul sebagai perubahan palsu, dan perubahan yang tampil =
  perubahan yang benar-benar akan diterapkan Task 2.5 (yang menulis
  teks emit usulan apa adanya).
- Deterministik: input sama → output identik (difflib, autojunk off).
- Konfigurasi identik → diff kosong (tanpa baris perubahan).
- Modifikasi direpresentasikan pasangan REMOVED+ADDED (urutan tetap).

Modul murni: stdlib saja, tanpa I/O, tanpa ruamel.
"""

from __future__ import annotations

import difflib
import enum

__all__ = [
    "DiffLineKind",
    "ConfigDiffLine",
    "ConfigDiff",
    "compute_config_diff",
]


class DiffLineKind(enum.Enum):
    """Jenis baris diff."""

    CONTEXT = "CONTEXT"    # tidak berubah (ada di kedua sisi)
    ADDED = "ADDED"        # hanya di usulan
    REMOVED = "REMOVED"    # hanya di awal


class ConfigDiffLine:
    """Satu baris diff. ``old_number``/``new_number`` 1-based, None bila
    tidak ada di sisi tersebut."""

    __slots__ = ("kind", "text", "old_number", "new_number")

    def __init__(
        self,
        kind: DiffLineKind,
        text: str,
        old_number: int | None = None,
        new_number: int | None = None,
    ) -> None:
        self.kind = kind
        self.text = text
        self.old_number = old_number
        self.new_number = new_number

    def __repr__(self) -> str:
        posisi = ""
        if self.old_number is not None:
            posisi += f" lama={self.old_number}"
        if self.new_number is not None:
            posisi += f" baru={self.new_number}"
        return f"ConfigDiffLine({self.kind.value}{posisi}): {self.text!r}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConfigDiffLine):
            return NotImplemented
        return (
            self.kind == other.kind
            and self.text == other.text
            and self.old_number == other.old_number
            and self.new_number == other.new_number
        )

    def __hash__(self) -> int:
        return hash((self.kind, self.text, self.old_number, self.new_number))


class ConfigDiff:
    """Diff penuh dua dokumen emit — baris context disertakan agar
    preview dapat dibaca operator nonteknis (PRD-01 §2)."""

    __slots__ = ("lines",)

    def __init__(self, lines: tuple[ConfigDiffLine, ...]) -> None:
        self.lines = lines

    @property
    def has_changes(self) -> bool:
        return any(line.kind is not DiffLineKind.CONTEXT for line in self.lines)

    @property
    def added_count(self) -> int:
        return sum(1 for line in self.lines if line.kind is DiffLineKind.ADDED)

    @property
    def removed_count(self) -> int:
        return sum(1 for line in self.lines if line.kind is DiffLineKind.REMOVED)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConfigDiff):
            return NotImplemented
        return self.lines == other.lines

    def __repr__(self) -> str:
        return (
            f"ConfigDiff(lines={len(self.lines)}, added={self.added_count}, "
            f"removed={self.removed_count})"
        )


def compute_config_diff(
    original_emitted: str, proposed_emitted: str
) -> ConfigDiff:
    """Hitung diff deterministik antara dua teks emit.

    Kedua teks WAJIB dihasilkan konfigurasi emitter yang sama (lihat
    docstring modul). Konfigurasi identik → diff tanpa baris perubahan.
    """
    original_lines = original_emitted.splitlines()
    proposed_lines = proposed_emitted.splitlines()
    matcher = difflib.SequenceMatcher(
        a=original_lines, b=proposed_lines, autojunk=False
    )

    lines: list[ConfigDiffLine] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                lines.append(
                    ConfigDiffLine(
                        DiffLineKind.CONTEXT,
                        original_lines[i1 + offset],
                        old_number=i1 + offset + 1,
                        new_number=j1 + offset + 1,
                    )
                )
            continue
        for offset in range(i2 - i1):
            lines.append(
                ConfigDiffLine(
                    DiffLineKind.REMOVED,
                    original_lines[i1 + offset],
                    old_number=i1 + offset + 1,
                )
            )
        for offset in range(j2 - j1):
            lines.append(
                ConfigDiffLine(
                    DiffLineKind.ADDED,
                    proposed_lines[j1 + offset],
                    new_number=j1 + offset + 1,
                )
            )
    return ConfigDiff(tuple(lines))
