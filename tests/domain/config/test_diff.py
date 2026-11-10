"""Uji engine diff murni (Task 2.3): deterministik, identik = kosong."""

from __future__ import annotations

from tunneldesk.domain.config.diff import (
    DiffLineKind,
    compute_config_diff,
)

F1_TEXT = """tunnel: 11111111-2222-3333-4444-555555555555
credentials-file: ../F6/credentials-dummy.json

ingress:
  - hostname: aplikasi-sekolah.example.com
    service: http://localhost:8080
  - service: http_status:404
"""


def test_identik_menghasilkan_diff_tanpa_perubahan() -> None:
    diff = compute_config_diff(F1_TEXT, F1_TEXT)
    assert diff.has_changes is False
    assert diff.added_count == 0
    assert diff.removed_count == 0
    assert all(line.kind is DiffLineKind.CONTEXT for line in diff.lines)


def test_kedua_dokumen_kosong() -> None:
    diff = compute_config_diff("", "")
    assert diff.has_changes is False
    assert diff.lines == ()


def test_modifikasi_nilai_menghasilkan_removed_ditambah_added() -> None:
    usulan = F1_TEXT.replace("http://localhost:8080", "http://localhost:9999")
    diff = compute_config_diff(F1_TEXT, usulan)
    assert diff.has_changes is True
    removed = [line.text for line in diff.lines if line.kind is DiffLineKind.REMOVED]
    added = [line.text for line in diff.lines if line.kind is DiffLineKind.ADDED]
    assert removed == ["    service: http://localhost:8080"]
    assert added == ["    service: http://localhost:9999"]
    assert diff.added_count == 1 and diff.removed_count == 1


def test_penambahan_baris() -> None:
    usulan = F1_TEXT + "  - hostname: baru.example.com\n    service: http://x\n"
    diff = compute_config_diff(F1_TEXT, usulan)
    added = [line.text for line in diff.lines if line.kind is DiffLineKind.ADDED]
    assert "  - hostname: baru.example.com" in added


def test_penghapusan_baris() -> None:
    usulan = F1_TEXT.replace("credentials-file: ../F6/credentials-dummy.json\n", "")
    diff = compute_config_diff(F1_TEXT, usulan)
    removed = [line.text for line in diff.lines if line.kind is DiffLineKind.REMOVED]
    assert removed == ["credentials-file: ../F6/credentials-dummy.json"]


def test_multi_perubahan_sekaligus() -> None:
    usulan = (
        F1_TEXT.replace(
            "11111111-2222-3333-4444-555555555555",
            "99999999-8888-7777-6666-555555555555",
        )
        .replace("http://localhost:8080", "http://localhost:9999")
        + "  - service: http_status:503\n"
    )
    diff = compute_config_diff(F1_TEXT, usulan)
    assert diff.has_changes is True
    assert diff.added_count >= 2
    assert diff.removed_count >= 1


def test_deterministik_dua_panggilan_identik() -> None:
    usulan = F1_TEXT.replace("http://localhost:8080", "http://localhost:9999")
    pertama = compute_config_diff(F1_TEXT, usulan)
    kedua = compute_config_diff(F1_TEXT, usulan)
    assert pertama == kedua


def test_nomor_baris_1based() -> None:
    usulan = F1_TEXT.replace("http://localhost:8080", "http://localhost:9999")
    diff = compute_config_diff(F1_TEXT, usulan)
    removed = next(line for line in diff.lines if line.kind is DiffLineKind.REMOVED)
    # konstanta F1_TEXT (tanpa header komentar): service = baris ke-6
    assert removed.old_number == 6


def test_teks_emit_usulan_apa_adanya_terwakili() -> None:
    """PRD-02 §3.2: preview = perubahan yang benar-benar diterapkan —
    seluruh baris emit usulan tercakup (context+added)."""
    usulan = F1_TEXT.replace("8080", "9999")
    diff = compute_config_diff(F1_TEXT, usulan)
    tercakup = {
        line.text for line in diff.lines if line.kind in (DiffLineKind.CONTEXT, DiffLineKind.ADDED)
    }
    for baris in usulan.splitlines():
        assert baris in tercakup
