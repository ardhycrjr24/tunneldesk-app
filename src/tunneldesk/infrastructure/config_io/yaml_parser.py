"""Parser YAML round-trip (E-6, A-02) — infrastruktur atas ruamel.yaml.

- Memisahkan parsing sintaks dari validasi skema (skema = domain).
- ``round_trip_preserved`` dihitung **jujur**: emit round-trip dibandingkan
  dengan teks asal (normalisasi baris kosong di akhir saja) — tanpa klaim
  format identik 100% (ketentuan A-02).
- Pesan exception parser bisa meng-echo baris sumber — sanitasi dilakukan
  lapisan application; parser hanya melaporkan posisi.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

__all__ = ["ParsedYaml", "RoundTripYamlParser"]


@dataclass(frozen=True)
class ParsedYaml:
    """Hasil parse satu dokumen YAML."""

    #: Dokumen hasil parse (CommentedMap/CommentedSeq/primitif) — None bila gagal.
    document: object | None
    #: Error sintaks: (pesan_mentah, line, column) — line/column 1-based.
    syntax_errors: tuple[tuple[str, int | None, int | None], ...] = ()
    #: True bila emit round-trip identik dengan teks asal (normalisasi
    #: trailing newline). None bila parse gagal.
    round_trip_preserved: bool | None = None
    #: Hasil emit round-trip (untuk verifikasi komentar/preview E-7).
    emitted_text: str | None = None


class RoundTripYamlParser:
    """Parser round-trip ruamel.yaml (A-02)."""

    def __init__(self) -> None:
        self._yaml = YAML(typ="rt")
        self._yaml.preserve_quotes = True
        self._yaml.width = 4096  # hindari wrapping yang merusak format
        # Gaya emit menyamai gaya konfigurasi cloudflared umum:
        # mapping 2 spasi, sequence 4 spasi, dash offset 2.
        self._yaml.indent(mapping=2, sequence=4, offset=2)

    def parse(self, text: str) -> ParsedYaml:
        """Parse ``text``; sintaks rusak → syntax_errors, tanpa exception."""
        try:
            document = self._yaml.load(text)
        except YAMLError as exc:
            return ParsedYaml(
                document=None,
                syntax_errors=self._error_positions(exc),
                round_trip_preserved=None,
            )
        except Exception as exc:  # noqa: BLE001 — fail-safe parser
            return ParsedYaml(
                document=None,
                syntax_errors=((f"parser gagal: {exc}", None, None),),
                round_trip_preserved=None,
            )
        emitted = self._emit(document)
        preserved = emitted is not None and (
            emitted.rstrip("\n") == text.rstrip("\n")
        )
        return ParsedYaml(
            document=document,
            syntax_errors=(),
            round_trip_preserved=preserved,
            emitted_text=emitted,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    @staticmethod
    def _error_positions(
        exc: YAMLError,
    ) -> tuple[tuple[str, int | None, int | None], ...]:
        errors: list[tuple[str, int | None, int | None]] = []
        mark = getattr(exc, "problem_mark", None)
        problem = getattr(exc, "problem", None) or str(exc)
        if mark is not None:
            errors.append((str(problem), mark.line + 1, mark.column + 1))
        else:
            errors.append((str(problem), None, None))
        return tuple(errors)

    def _emit(self, document: object) -> str | None:
        """Emit ulang dokumen dengan gaya yang sama; None bila gagal."""
        try:
            buffer = io.StringIO()
            self._yaml.dump(document, buffer)
            return buffer.getvalue()
        except Exception:  # noqa: BLE001 — tidak dapat memastikan dipertahankan
            return None
