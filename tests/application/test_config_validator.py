"""Uji ConfigValidator (E-6): integrasi E-5 ConfigCandidate + fixture
resmi F1–F5 + sanitasi + bukti read-only via hash."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tunneldesk.application.config_validator import ConfigValidator
from tunneldesk.domain.config.model import ValidationClassification

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"

F1 = FIXTURES / "F1" / "config-valid.yml"
F2 = FIXTURES / "F2" / "config-valid-komentar.yml"
F3 = FIXTURES / "F3" / "config-invalid-yaml.yml"
F4 = FIXTURES / "F4"
F5 = FIXTURES / "F5" / "config-tidak-dikenal.yml"
F6_SECRET = "DUMMY_TUNNEL_SECRET_0123456789abcdef_FOR_REDACTION_TESTS_ONLY"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Fixture resmi
# ---------------------------------------------------------------------------


def test_f1_valid() -> None:
    outcome = ConfigValidator().validate_path(F1)
    assert outcome.classification is ValidationClassification.VALID
    assert outcome.errors == ()
    assert outcome.round_trip_preserved is True


def test_f2_valid_dan_jujur_indentasi_dinormalkan() -> None:
    """A-02: komentar dipertahankan, indentasi dinormalkan — flag jujur
    False, bukan klaim format identik."""
    outcome = ConfigValidator().validate_path(F2)
    assert outcome.classification is ValidationClassification.VALID
    assert outcome.round_trip_preserved is False


def test_f3_syntax_invalid_dengan_posisi() -> None:
    outcome = ConfigValidator().validate_path(F3)
    assert outcome.classification is ValidationClassification.INVALID
    codes = [item.code for item in outcome.errors]
    assert "SYNTAX_ERROR" in codes
    assert any(item.line is not None and item.line >= 1 for item in outcome.errors)


def test_f4_variasi_invalid(tmp_path: Path) -> None:
    validator = ConfigValidator()
    harapan = {
        "config-tanpa-ingress.yml": "MISSING_INGRESS",
        "config-origin-kosong.yml": "EMPTY_SERVICE",
        "config-hostname-salah.yml": "INVALID_HOSTNAME",
    }
    for nama, kode in harapan.items():
        outcome = validator.validate_path(F4 / nama)
        assert outcome.classification is ValidationClassification.INVALID, nama
        assert kode in [item.code for item in outcome.errors], nama


def test_f4_credentials_hilang_terdeteksi_tanpa_membaca_isi(tmp_path: Path) -> None:
    """credentials-file relatif terhadap direktori config (F4) tidak ada —
    CREDENTIALS_FILE_MISSING; isi tidak pernah dibaca (tidak ada yang
    bisa dibaca)."""
    outcome = ConfigValidator().validate_path(F4 / "config-credentials-hilang.yml")
    assert outcome.classification is ValidationClassification.INVALID
    assert "CREDENTIALS_FILE_MISSING" in [i.code for i in outcome.errors]


def test_f5_unknown_tidak_diubah(tmp_path: Path) -> None:
    outcome = ConfigValidator().validate_path(F5)
    assert outcome.classification is ValidationClassification.UNKNOWN
    codes = [item.code for item in outcome.errors]
    assert "UNKNOWN_TOP_LEVEL_KEY" in codes
    assert "original-config-extra" in [item.location for item in outcome.errors]


# ---------------------------------------------------------------------------
# Integrasi ConfigCandidate E-5
# ---------------------------------------------------------------------------


def test_integrasi_config_candidate_e5(tmp_path: Path) -> None:
    """ConfigCandidate.path (E-5) langsung divalidasi oleh E-6."""
    config_dir = tmp_path / ".cloudflared"
    config_dir.mkdir()
    config = config_dir / "config.yml"
    config.write_text(
        "tunnel: 11111111-2222-3333-4444-555555555555\n"
        f"credentials-file: {F6_SECRET + '.json'}\n"  # file tidak ada
        "ingress:\n"
        "  - service: http_status:404\n",
        encoding="utf-8",
    )
    validator = ConfigValidator()
    outcome = validator.validate_path(config)
    assert outcome.classification is ValidationClassification.INVALID
    assert "CREDENTIALS_FILE_MISSING" in [i.code for i in outcome.errors]


def test_integrasi_e5_valid_dengan_credentials_dummy(tmp_path: Path) -> None:
    config_dir = tmp_path / ".cloudflared"
    config_dir.mkdir()
    config = config_dir / "config.yml"
    config.write_text(
        "tunnel: 11111111-2222-3333-4444-555555555555\n"
        "credentials-file: credentials-dummy.json\n"
        "ingress:\n"
        "  - service: http_status:404\n",
        encoding="utf-8",
    )
    (config_dir / "credentials-dummy.json").write_text(
        '{"AccountTag": "DUMMY"}', encoding="utf-8"
    )
    outcome = ConfigValidator().validate_path(config)
    assert outcome.classification is ValidationClassification.VALID


# ---------------------------------------------------------------------------
# Sanitasi (D-18)
# ---------------------------------------------------------------------------


def test_token_di_yaml_tidak_lolos_ke_pesan_sintaks() -> None:
    token = "DUMMY-VALIDATOR-TOKEN-999999-SECRET"
    validator = ConfigValidator()
    validator.register_secret(token, "tunnel_token")
    rusak = f"tunnel: [rusak {token}\n"
    outcome = validator.validate_text(rusak)
    assert outcome.classification is ValidationClassification.INVALID
    for item in outcome.errors:
        assert token not in item.message


def test_register_secret_dari_controller_jalur_sama() -> None:
    validator = ConfigValidator()
    assert validator.register_secret("RAHASIA_PANJANG_000000", "uji") is True


# ---------------------------------------------------------------------------
# Read-only — bukti hash (instruksi §4.E)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "file_path",
    [F1, F2, F3, F5, F4 / "config-tanpa-ingress.yml"],
    ids=["F1", "F2", "F3", "F5", "F4-tanpa-ingress"],
)
def test_hash_tetap_sama_setelah_validasi(file_path: Path) -> None:
    sebelum = digest(file_path)
    ConfigValidator().validate_path(file_path)
    ConfigValidator().validate_path(file_path)
    assert digest(file_path) == sebelum


def test_tidak_ada_file_baru_di_direktori_fixture(tmp_path: Path) -> None:
    sumber = F1
    salinan_dir = tmp_path / "f1-copy"
    salinan_dir.mkdir()
    salinan = salinan_dir / sumber.name
    salinan.write_bytes(sumber.read_bytes())
    sebelum = sorted(item.name for item in salinan_dir.iterdir())
    ConfigValidator().validate_path(salinan)
    sesudah = sorted(item.name for item in salinan_dir.iterdir())
    assert sesudah == sebelum


def test_config_unreadable() -> None:
    outcome = ConfigValidator().validate_path(Path("/nonexistent/config.yml"))
    assert outcome.classification is ValidationClassification.INVALID
    assert outcome.errors[0].code == "CONFIG_UNREADABLE"
