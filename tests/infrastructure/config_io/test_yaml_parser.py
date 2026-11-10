"""Uji RoundTripYamlParser (E-6, A-02) — round-trip jujur & posisi error."""

from __future__ import annotations

from tunneldesk.infrastructure.config_io.yaml_parser import RoundTripYamlParser

PARSER = RoundTripYamlParser()

F1_TEXT = """tunnel: 11111111-2222-3333-4444-555555555555
credentials-file: ../F6/credentials-dummy.json

ingress:
  - hostname: aplikasi-sekolah.example.com
    service: http://localhost:8080
  - service: http_status:404
"""

F2_TEXT = """# F2 — F1 + komentar dan format tak beraturan
# Tujuan: memastikan round-trip (A-02) mempertahankan komentar/format
# pengguna sejauh didukung library, dan diff preview tetap jujur.

   # indentasi komentar sengaja tidak rapi
tunnel:      99999999-8888-7777-6666-555555555555   # tunnel ID dummy sekolah contoh

credentials-file:  ../F6/credentials-dummy.json

ingress:
  # ingress pertama — aplikasi rapor lokal (port dummy)
  - hostname: rapor-sekolah-contoh.example.com
    service: http://localhost:8443
    originRequest:
            connectTimeout: 30

  # catch-all
  - service: http_status:404
"""


def test_parse_valid_dokumen_mapping() -> None:
    parsed = PARSER.parse(F1_TEXT)
    assert parsed.syntax_errors == ()
    assert parsed.document is not None
    assert parsed.document["tunnel"] == "11111111-2222-3333-4444-555555555555"


def test_round_trip_preserved_f1() -> None:
    assert PARSER.parse(F1_TEXT).round_trip_preserved is True


def test_round_trip_f2_komentar_utuh_indentasi_dinormalkan() -> None:
    """A-02 jujur: komentar dipertahankan; indentasi/spasi tak beraturan
    DINORMALKAN ruamel → round_trip_preserved = False (bukan klaim
    identik 100%)."""
    parsed = PARSER.parse(F2_TEXT)
    assert parsed.round_trip_preserved is False
    # isi komentar tetap utuh pada hasil emit (untuk preview E-7)
    assert parsed.emitted_text is not None
    assert "tunnel ID dummy sekolah contoh" in parsed.emitted_text


def test_crlf_dilaporkan_tidak_preserved_jujur() -> None:
    """CRLF vs LF adalah perbedaan byte — dilaporkan jujur sebagai tidak
    preserved (tanpa klaim identik 100%, ketentuan A-02)."""
    parsed = PARSER.parse(F1_TEXT.replace("\n", "\r\n"))
    assert parsed.round_trip_preserved is False


def test_syntax_error_dengan_posisi() -> None:
    rusak = "tunnel: [unclosed\ningress:\n"
    parsed = PARSER.parse(rusak)
    assert parsed.document is None
    assert parsed.round_trip_preserved is None
    assert len(parsed.syntax_errors) >= 1
    message, line, column = parsed.syntax_errors[0]
    assert line is not None and line >= 1
    assert message


def test_scalar_bukan_mapping() -> None:
    parsed = PARSER.parse("hello\n")
    assert parsed.syntax_errors == ()
    assert parsed.document == "hello"


def test_parser_melaporkan_mentah_sanitasi_di_application() -> None:
    """Parser melaporkan pesan apa adanya — sanitasi adalah tanggung
    jawab application (ConfigValidator, diuji terpisah). Kontrak ini
    dikunci agar tidak ada dua mekanisme redaksi."""
    token = "DUMMY-TOKEN-999999-FOR-PARSER-TEST"
    rusak = f"tunnel: [broken {token}\n"
    parsed = PARSER.parse(rusak)
    assert parsed.document is None
    # pesan mentah dipertahankan untuk disanitasi lapisan application
    assert parsed.syntax_errors
