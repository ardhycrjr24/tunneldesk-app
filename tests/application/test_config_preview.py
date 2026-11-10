"""Uji ConfigPreviewService (Task 2.3): emit-vs-emit, UNKNOWN/INVALID,
kunci tak dikenal, sanitasi, read-only hash. Fixture resmi F1–F6."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tunneldesk.application.config_preview import (
    ConfigPreviewService,
    PreviewRejectedError,
)
from tunneldesk.domain.config.model import (
    ValidationClassification,
)

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"

F1 = FIXTURES / "F1" / "config-valid.yml"
F2 = FIXTURES / "F2" / "config-valid-komentar.yml"
F5 = FIXTURES / "F5" / "config-tidak-dikenal.yml"
F6_SECRET = "DUMMY_TUNNEL_SECRET_0123456789abcdef_FOR_REDACTION_TESTS_ONLY"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture()
def service() -> ConfigPreviewService:
    service = ConfigPreviewService()
    service.register_secret(F6_SECRET, "TunnelSecret")
    return service


# ---------------------------------------------------------------------------
# Skenario wajib §5
# ---------------------------------------------------------------------------


def test_1_identik_diff_kosong(service: ConfigPreviewService) -> None:
    preview = service.preview(read(F1), read(F1))
    assert preview.rejected is False
    assert preview.has_changes is False
    assert preview.proposed_ready_to_apply is False  # tanpa perubahan


def test_2_penambahan_item(service: ConfigPreviewService) -> None:
    usulan = read(F1) + "  - hostname: baru.example.com\n    service: http://x\n"
    preview = service.preview(read(F1), usulan)
    assert preview.has_changes is True
    teks_diff = "\n".join(
        line.text for line in preview.diff.lines if line.kind.value == "ADDED"
    )
    assert "baru.example.com" in teks_diff


def test_3_penghapusan_kunci(service: ConfigPreviewService) -> None:
    usulan = read(F1).replace(
        "credentials-file: ../F6/credentials-dummy.json\n", ""
    )
    preview = service.preview(read(F1), usulan)
    assert preview.has_changes is True
    removed = "\n".join(
        line.text
        for line in preview.diff.lines
        if line.kind.value == "REMOVED"
    )
    assert "credentials-file" in removed


def test_4_modifikasi_nilai(service: ConfigPreviewService) -> None:
    usulan = read(F1).replace("8080", "9999")
    preview = service.preview(read(F1), usulan)
    added = "\n".join(
        line.text for line in preview.diff.lines if line.kind.value == "ADDED"
    )
    removed = "\n".join(
        line.text for line in preview.diff.lines if line.kind.value == "REMOVED"
    )
    assert "9999" in added
    assert "8080" in removed  # nilai lama sah tampil sebagai baris dihapus


def test_5_multi_perubahan_sekaligus(service: ConfigPreviewService) -> None:
    usulan = read(F1).replace("8080", "9999").replace("404", "503")
    preview = service.preview(read(F1), usulan)
    assert preview.has_changes is True
    assert preview.diff.added_count >= 2


def test_6_perubahan_komentar_jujur(service: ConfigPreviewService) -> None:
    original = read(F1)
    usulan = "# komentar baru ditambahkan pengguna\n" + original
    preview = service.preview(original, usulan)
    teks = "\n".join(line.text for line in preview.diff.lines)
    assert "# komentar baru ditambahkan pengguna" in teks


def test_7_identik_non_kanonis_diff_kosong_tapi_ditandai(
    service: ConfigPreviewService,
) -> None:
    """F2 (komentar + indentasi tak beraturan) vs dirinya sendiri:
    konfigurasi logis identik → diff kosong (emit-vs-emit, tanpa
    perubahan palsu), namun apply nanti akan menulis ulang format —
    dilaporkan jujur via original_not_canonical + notes."""
    original = read(F2)
    preview = service.preview(original, original)
    assert preview.has_changes is False
    assert preview.original_not_canonical is True
    assert any("dinormalkan" in note for note in preview.notes)


def test_7b_normalisasi_f2_ke_f1_tampil_jujur(
    service: ConfigPreviewService,
) -> None:
    """F2 (awal, non-kanonis) → F1 (usulan): perubahan format yang akan
    benar-benar ditulis Task 2.5 tampil di diff (transparan penuh)."""
    preview = service.preview(read(F2), read(F1))
    assert preview.has_changes is True
    assert preview.original_not_canonical is True
    teks = "\n".join(line.text for line in preview.diff.lines)
    assert "rapor-sekolah-contoh.example.com" in teks  # konten F2 hilang
    assert "aplikasi-sekolah.example.com" in teks  # konten F1 muncul


def test_8_kunci_tidak_dikenal_dipertahankan(service: ConfigPreviewService) -> None:
    usulan = read(F5)  # mengandung warp-routing + original-config-extra
    preview = service.preview(read(F1), usulan)
    teks = "\n".join(line.text for line in preview.diff.lines)
    assert "original-config-extra" in teks  # dipertahankan, tidak dibuang
    assert preview.contains_unknown_structure is True
    assert any("tidak akan diubah otomatis" in note for note in preview.notes)


def test_9_status_unknown_preview_dengan_peringatan(
    service: ConfigPreviewService,
) -> None:
    preview = service.preview(read(F5), read(F5))  # identik, tapi UNKNOWN
    assert preview.rejected is False
    assert (
        preview.original_classification is ValidationClassification.UNKNOWN
    )
    assert preview.contains_unknown_structure is True
    assert preview.proposed_ready_to_apply is False


def test_10_kunci_tak_kenal_usulan_unknown_tidak_siap_apply(
    service: ConfigPreviewService,
) -> None:
    """Ganti nama kunci 'ingress' → kunci tak dikenal → usulan UNKNOWN
    (PRD-02 §3.2: tidak diubah otomatis); MISSING_INGRESS tetap
    dilaporkan; tidak siap apply."""
    usulan = read(F1).replace("ingress:", "ingress_lain:")
    preview = service.preview(read(F1), usulan)
    assert preview.rejected is False  # preview tetap ditampilkan
    assert (
        preview.proposed_classification is ValidationClassification.UNKNOWN
    )
    assert preview.proposed_ready_to_apply is False
    assert any(
        "MISSING_INGRESS" in note for note in preview.notes
    )  # pelanggaran skema tetap dilaporkan sebagai informasi


def test_11_sintaks_rusak_ditolak(service: ConfigPreviewService) -> None:
    """Sintaks rusak (awal maupun usulan) → PreviewRejectedError dengan
    pesan aman (sanitasi D-18)."""
    with pytest.raises(PreviewRejectedError) as excinfo:
        service.preview(read(F1), "tunnel: [rusak\n")
    assert "usulan" in excinfo.value.reason
    assert excinfo.value.errors[0].code == "SYNTAX_ERROR"

    with pytest.raises(PreviewRejectedError) as excinfo_awal:
        service.preview("tunnel: [rusak\n", read(F1))
    assert "awal" in excinfo_awal.value.reason
    assert excinfo_awal.value.errors[0].code == "SYNTAX_ERROR"


# ---------------------------------------------------------------------------
# Keamanan (D-18)
# ---------------------------------------------------------------------------


def test_12_token_dalam_usulan_tidak_lolos(service: ConfigPreviewService) -> None:
    usulan = read(F1).replace(
        "credentials-file: ../F6/credentials-dummy.json",
        f"credentials-file: c.json\ntunnel-secret: {F6_SECRET}",
    )
    preview = service.preview(read(F1), usulan)
    teks = "\n".join(line.text for line in preview.diff.lines)
    assert F6_SECRET not in teks


def test_12b_exception_preview_tidak_memuat_secret(
    service: ConfigPreviewService,
) -> None:
    dengan_secret = read(F1) + f"# {F6_SECRET}\n"
    dengan_secret_rusak = "tunnel: [rusak\n" + f"# {F6_SECRET}\n"
    with pytest.raises(PreviewRejectedError) as excinfo:
        service.preview(dengan_secret, dengan_secret_rusak)
    assert F6_SECRET not in str(excinfo.value)
    for item in excinfo.value.errors:
        assert F6_SECRET not in item.message


def test_13_isi_credentials_file_tidak_dibaca(service: ConfigPreviewService) -> None:
    """File credential (F6) berisi dummy secret — preview tidak pernah
    membacanya: teks isinya tidak muncul di mana pun."""
    usulan = read(F1)  # merujuk ../F6/credentials-dummy.json
    preview = service.preview(usulan, usulan)
    isi_f6 = (FIXTURES / "F6" / "credentials-dummy.json").read_text(
        encoding="utf-8"
    )
    teks = "\n".join(line.text for line in preview.diff.lines)
    assert "DUMMY_ACCOUNT_TAG" not in teks  # isi file tidak dibaca
    assert isi_f6 not in teks


# ---------------------------------------------------------------------------
# Determinisme & read-only (hash)
# ---------------------------------------------------------------------------


def test_14_deterministik(service: ConfigPreviewService) -> None:
    usulan = read(F1).replace("8080", "9999")
    pertama = service.preview(read(F1), usulan)
    kedua = service.preview(read(F1), usulan)
    assert pertama == kedua


def test_15_16_hash_tetap_dan_tidak_ada_file_baru(
    service: ConfigPreviewService, tmp_path: Path
) -> None:
    salinan_dir = tmp_path / "config-copy"
    salinan_dir.mkdir()
    salinan = salinan_dir / F1.name
    salinan.write_bytes(F1.read_bytes())
    sebelum_hash = digest(salinan)
    sebelum_files = sorted(item.name for item in salinan_dir.iterdir())

    usulan = read(F1).replace("8080", "9999")
    service.preview(read(F1), usulan)
    service.preview(read(F1), usulan)

    assert digest(salinan) == sebelum_hash
    assert sorted(item.name for item in salinan_dir.iterdir()) == sebelum_files
