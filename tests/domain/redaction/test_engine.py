"""Uji redaction engine (E-1, PRD-01 §7.5/§10, PRD-02 §3.3).

Mencakup cakupan minimum instruksi E-1: token/credential dummy,
Authorization header, password/secret, URL berkredensial, multiline,
format tidak dikenal, string kosong, non-string, false positive, dan
fail-safe. Fixture memakai data sintetis F6/F7 (tanpa data produksi).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tunneldesk.domain.redaction.engine import (
    UNPARSED_PLACEHOLDER,
    RedactionEngine,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
F6 = FIXTURES / "F6"

DUMMY_TUNNEL_SECRET = "DUMMY_TUNNEL_SECRET_0123456789abcdef_FOR_REDACTION_TESTS_ONLY"


@pytest.fixture()
def engine() -> RedactionEngine:
    return RedactionEngine()


@pytest.fixture()
def engine_dengan_sekrete_terdaftar(engine: RedactionEngine) -> RedactionEngine:
    engine.register_secret(DUMMY_TUNNEL_SECRET, "TunnelSecret")
    return engine


# ---------------------------------------------------------------------------
# Kontrak dasar
# ---------------------------------------------------------------------------


def test_string_kosong_dikembalikan_apa_adanya(engine: RedactionEngine) -> None:
    assert engine.redact("") == ""


def test_input_non_string_ditolak_tegas(engine: RedactionEngine) -> None:
    for nilai in (None, 123, 4.5, b"bytes", ["teks"]):
        with pytest.raises(TypeError):
            engine.redact(nilai)  # type: ignore[arg-type]


def test_register_secret_tolak_nilai_pendan_kotor(
    engine: RedactionEngine,
) -> None:
    assert engine.register_secret("abc") is False          # terlalu pendek
    assert engine.register_secret("        ") is False     # spasi saja
    assert (
        engine.register_secret(DUMMY_TUNNEL_SECRET, "TunnelSecret") is True
    )
    # terdaftar ulang → tetap True (idempoten)
    assert (
        engine.register_secret(DUMMY_TUNNEL_SECRET, "TunnelSecret") is True
    )
    with pytest.raises(TypeError):
        engine.register_secret(123, "X")  # type: ignore[arg-type]


def test_deterministik(engine_dengan_sekrete_terdaftar: RedactionEngine) -> None:
    teks = f"error token={DUMMY_TUNNEL_SECRET} saat handshake"
    hasil_pertama = engine_dengan_sekrete_terdaftar.redact(teks)
    for _ in range(3):
        assert engine_dengan_sekrete_terdaftar.redact(teks) == hasil_pertama


# ---------------------------------------------------------------------------
# Pola sensitif minimum
# ---------------------------------------------------------------------------


def test_authorization_header_tersaring_nilainya(
    engine: RedactionEngine,
) -> None:
    hasil = engine.redact("Authorization: Bearer abc.def.ghi status=200")
    assert "abc.def.ghi" not in hasil
    assert "Authorization:" in hasil
    assert "REDACTED" in hasil


def test_cookie_header_tersaring(engine: RedactionEngine) -> None:
    hasil = engine.redact("Cookie: session=r4hasia; theme=dark")
    assert "r4hasia" not in hasil
    assert "Cookie:" in hasil


def test_password_dan_secret_key_value(engine: RedactionEngine) -> None:
    teks = "login gagal password=sand1rahasia | secret=t00r4hasia | api_key=AKIADUMMY123"
    hasil = engine.redact(teks)
    assert "sand1rahasia" not in hasil
    assert "t00r4hasia" not in hasil
    assert "AKIADUMMY123" not in hasil
    # kunci dipertahankan agar diagnostik tetap terbaca
    assert "password=" in hasil and "secret=" in hasil and "api_key=" in hasil


def test_json_field_tersaring(engine: RedactionEngine) -> None:
    tunnel_id = "11111111-2222-3333-4444-555555555555"
    payload = f'{{"TunnelSecret": "{DUMMY_TUNNEL_SECRET}", "TunnelID": "{tunnel_id}"}}'
    hasil = engine.redact(payload)
    assert DUMMY_TUNNEL_SECRET not in hasil
    assert "TunnelSecret" in hasil
    # TunnelID bukan secret — dipertahankan untuk diagnostik
    assert "11111111-2222-3333-4444-555555555555" in hasil


def test_url_dengan_kredensial_tersaring(engine: RedactionEngine) -> None:
    hasil = engine.redact(
        "gagal https://admin:sandirahasia@rapor.example.com/api — coba lagi"
    )
    assert "sandirahasia" not in hasil
    assert "admin" not in hasil
    # skema dan host tetap terbaca
    assert "https://" in hasil and "rapor.example.com/api" in hasil


def test_jwt_tersaring(engine: RedactionEngine) -> None:
    jwt = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX2NvbnRvaA"
    hasil = engine.redact(f"got identity {jwt} ok")
    assert jwt not in hasil
    assert "got identity" in hasil and "ok" in hasil


def test_flag_token_cloudflared_tersaring(engine: RedactionEngine) -> None:
    hasil = engine.redact("run: cloudflared tunnel run --token DUMMYTOKEN123456")
    assert "DUMMYTOKEN123456" not in hasil
    assert "--token" in hasil


def test_multiline_diproses_per_baris_tanpa_kebocoran(
    engine: RedactionEngine,
) -> None:
    teks = "\n".join(
        [
            "INFO mulai",
            "Authorization: Bearer abc123.def456.ghi789",
            "INFO selesai",
            "password=sandirahasia",
        ]
    )
    hasil = engine.redact(teks)
    assert "abc123" not in hasil and "sandirahasia" not in hasil
    assert hasil.count("\n") == teks.count("\n")  # struktur baris utuh
    assert "INFO mulai" in hasil and "INFO selesai" in hasil


def test_format_log_tidak_dikenal_aman_dipertahankan(
    engine: RedactionEngine,
) -> None:
    teks = "@@weird format ~~~ tanpa pola sensitif apa pun <<<>>>"
    assert engine.redact(teks) == teks


def test_fixture_f7_tidak_mengandung_yang_harus_diredaksi(
    engine: RedactionEngine,
) -> None:
    """Log tiruan F7 tidak memuat secret; hasil redaksi mempertahankan
    informasi diagnostiknya."""
    teks = (FIXTURES / "F7" / "cloudflared-log-tiruan.log").read_text(
        encoding="utf-8"
    )
    hasil = engine.redact(teks)
    assert "Starting tunnel" in hasil
    assert "Failed to serve tunnel" in hasil
    assert "192.0.2.10" in hasil  # IP dokumentasi dipertahankan


# ---------------------------------------------------------------------------
# Known-secret injection — jaminan tidak pernah lolos
# ---------------------------------------------------------------------------


def test_sekrete_terdaftar_tidak_pernah_lolos_bahkan_tanpa_pola(
    engine_dengan_sekrete_terdaftar: RedactionEngine,
) -> None:
    hasil = engine_dengan_sekrete_terdaftar.redact(
        f"nilai tak berpola: {DUMMY_TUNNEL_SECRET} (akhir)"
    )
    assert DUMMY_TUNNEL_SECRET not in hasil
    assert "REDACTED:TunnelSecret" in hasil


def test_sekrete_di_dalam_json_f6_tidak_lolos(
    engine: RedactionEngine,
) -> None:
    payload = (F6 / "credentials-dummy.json").read_text(encoding="utf-8")
    engine.register_secret(DUMMY_TUNNEL_SECRET, "TunnelSecret")
    hasil = engine.redact(payload)
    assert DUMMY_TUNNEL_SECRET not in hasil
    # kunci JSON tetap terbaca untuk diagnostik
    assert "TunnelSecret" in hasil
    assert "TunnelID" in hasil


def test_sekrete_sama_muncul_berkali_kali_semua_terganti(
    engine_dengan_sekrete_terdaftar: RedactionEngine,
) -> None:
    teks = f"{DUMMY_TUNNEL_SECRET}\n{DUMMY_TUNNEL_SECRET}\n{DUMMY_TUNNEL_SECRET}"
    hasil = engine_dengan_sekrete_terdaftar.redact(teks)
    assert DUMMY_TUNNEL_SECRET not in hasil
    assert hasil.count("REDACTED:TunnelSecret") == 3


# ---------------------------------------------------------------------------
# False positive — teks normal dipertahankan
# ---------------------------------------------------------------------------


def test_teks_normal_tidak_teredaksi(engine: RedactionEngine) -> None:
    teks = (
        "Panduan mengganti password akan diterbitkan. "
        "Tunnel berjalan pada port 8080. "
        "Lihat dokumentasi token API di halaman bantuan. "
        "Hostname aplikasi-sekolah.example.com sudah dikonfigurasi."
    )
    assert engine.redact(teks) == teks


def test_nilai_kosong_pada_kata_kunci_tidak_merusak(
    engine: RedactionEngine,
) -> None:
    teks = 'pengaturan token="" kosong tetap terbaca'
    assert engine.redact(teks) == teks


# ---------------------------------------------------------------------------
# Fail-safe
# ---------------------------------------------------------------------------


def test_fail_safe_aturan_gagal_tidak_mengirim_teks_asli(
    monkeypatch: pytest.MonkeyPatch,
    engine: RedactionEngine,
) -> None:
    engine.register_secret("RAHASIA_PANJANG_000000", "uji")

    def meledak(match: object, tag: str) -> str:  # pragma: no cover
        raise RuntimeError("simulasi kegagalan aturan")

    monkeypatch.setattr(RedactionEngine, "_replace", staticmethod(meledak))
    hasil = engine.redact("Authorization: Bearer abc.def.ghi RAHASIA_PANJANG_000000")
    # fail-safe: hasil konservatif; secret terdaftar tetap tidak lolos
    assert "Authorization: Bearer abc.def.ghi" not in hasil
    assert "RAHASIA_PANJANG_000000" not in hasil


def test_placeholder_unparsed_tersedia() -> None:
    assert UNPARSED_PLACEHOLDER.startswith("[REDACTED:")
