"""Uji pytest-qt SetupWizardDialog (Task 2.6) — navigasi, guard, alur
end-to-end dengan service backend AKTUAL (tmp_path), zero-I/O pra-konfirmasi.

Catatan determinisme: dialog mulai di halaman 0; klik pertama (0→1)
sinkron tanpa worker; klik pada halaman 1 memicu worker baca+validasi.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from tunneldesk.application.config_apply_service import ApplyOutcome, ApplyStatus
from tunneldesk.application.settings_store import JsonSettingsStore
from tunneldesk.ui.wizard.pages.hasil import ResultPage
from tunneldesk.ui.wizard.services import build_wizard_services
from tunneldesk.ui.wizard.wizard_dialog import SetupWizardDialog

VALID_CONFIG = (
    "tunnel: 11111111-2222-3333-4444-555555555555\n"
    "credentials-file: credentials-dummy.json\n"
    "ingress:\n"
    "  - hostname: rapor.sekolah.sch.id\n"
    "    service: http://localhost:8080\n"
    "  - service: http_status:404\n"
)


class GagalLauncher:
    """Launcher simulasi — deteksi fail-safe cepat."""

    def launch(self, spec: object) -> object:  # pragma: no cover
        raise OSError("simulasi launcher tidak tersedia")


def make_dialog(
    tmp_path: Path, qtbot: object
) -> tuple[SetupWizardDialog, JsonSettingsStore]:
    """Dialog dengan service nyata di tmp_path (deteksi fail-safe cepat)."""
    store = JsonSettingsStore(tmp_path / "settings.json")
    services = build_wizard_services(store, launcher=GagalLauncher())  # type: ignore[arg-type]
    dialog = SetupWizardDialog(services)
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: dialog.state.detection is not None, timeout=20000)
    return dialog, store


def _tunggu(dialog: SetupWizardDialog, qtbot: object, index: int) -> None:
    qtbot.waitUntil(
        lambda: dialog.current_index() == index and not dialog.is_busy(),
        timeout=20000,
    )


def _ke_pilih(
    dialog: SetupWizardDialog, qtbot: object, target: Path
) -> None:
    """Halaman 0 → 1 (sinkron) → isi path → 1 → 2 (worker baca+validasi)."""
    dialog.next_button().click()
    _tunggu(dialog, qtbot, 1)
    dialog._page_pilih.set_path(target)  # noqa: SLF001 — akses uji
    dialog.next_button().click()
    _tunggu(dialog, qtbot, 2)


def test_dialog_membangun_7_halaman(tmp_path: Path, qtbot: object) -> None:
    dialog, _store = make_dialog(tmp_path, qtbot)
    assert len(dialog.pages()) == 7
    assert dialog.current_index() == 0
    assert not dialog.back_button().isEnabled()


def test_navigasi_pilih_form_kembali(tmp_path: Path, qtbot: object) -> None:
    dialog, _store = make_dialog(tmp_path, qtbot)
    target = tmp_path / "config.yml"
    target.write_bytes(VALID_CONFIG.encode("utf-8"))
    (tmp_path / "credentials-dummy.json").write_bytes(b"{}")

    _ke_pilih(dialog, qtbot, target)  # 0 → 1 → 2 (form)

    dialog.back_button().click()  # 2 → 1
    _tunggu(dialog, qtbot, 1)
    dialog.next_button().click()  # 1 → 2 (baca ulang)
    _tunggu(dialog, qtbot, 2)


def test_pilih_tanpa_path_menampilkan_error(
    tmp_path: Path, qtbot: object
) -> None:
    dialog, _store = make_dialog(tmp_path, qtbot)
    dialog.next_button().click()  # 0 → 1
    _tunggu(dialog, qtbot, 1)
    dialog.next_button().click()  # 1 → tanpa path → tetap di 1 + error
    _tunggu(dialog, qtbot, 1)
    from tunneldesk.ui import strings

    pilih = dialog.pages()["pilih"]
    assert strings.text("wiz.p2.must_select") in pilih._status_label.text()  # noqa: SLF001


def test_alur_bahagia_end_to_end(tmp_path: Path, qtbot: object) -> None:
    """Prasyarat → pilih → form → cek → preview → konfirmasi → apply →
    hasil APPLIED; byte file = teks emit usulan; settings tersimpan (W-5)."""
    dialog, store = make_dialog(tmp_path, qtbot)
    target = tmp_path / "config.yml"
    target.write_bytes(VALID_CONFIG.encode("utf-8"))
    (tmp_path / "credentials-dummy.json").write_bytes(b"{}")

    _ke_pilih(dialog, qtbot, target)  # 0 → 1 → 2

    # Langkah 3: ubah tunnel + service ingress pertama via formulir
    # (prefill dari asal) → Lanjut (builder + cek).
    dialog._page_form._tunnel_edit.setText(  # noqa: SLF001
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    )
    dialog._page_form._table.item(0, 1).setText(  # noqa: SLF001
        "http://127.0.0.1:9090"
    )
    dialog.next_button().click()
    _tunggu(dialog, qtbot, 3)  # halaman cek (run_check selesai)
    dialog.next_button().click()
    _tunggu(dialog, qtbot, 4)  # preview

    # Preview menampilkan perubahan (+- marker) — ada tulis "9090".
    preview = dialog.state.preview
    assert preview is not None and preview.diff is not None
    assert preview.diff.has_changes

    dialog.next_button().click()  # prepare artefak → konfirmasi
    _tunggu(dialog, qtbot, 5)

    # Pra-apply: nol tulis (zero-I/O sebelum konfirmasi eksplisit).
    hash_sebelum = target.read_bytes()
    assert not list(tmp_path.glob("*.backup-*"))

    dialog.next_button().click()  # apply (confirm=True, backup internal)
    _tunggu(dialog, qtbot, 6)  # hasil

    assert dialog.state.outcome is not None
    assert dialog.state.outcome.status is ApplyStatus.APPLIED
    assert dialog.state.outcome.applied is True
    hasil = target.read_bytes().decode("utf-8")
    assert hasil != hash_sebelum.decode("utf-8")
    assert "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in hasil
    assert "9090" in hasil
    assert "rapor.sekolah.sch.id" in hasil
    assert "http_status:404" in hasil
    # Backup pra-apply tampil + filenya ada.
    assert dialog.state.outcome.backup_path is not None
    assert dialog.state.outcome.backup_path.exists()
    assert "backup" in dialog._detail_view_text()
    # W-5: settings tersimpan dari formulir (satu origin).
    assert store.load().origin_host == "127.0.0.1"
    assert store.load().origin_port == 9090
    assert "ulang aplikasi" in dialog._settings_note_text()
    # Tombol berubah jadi Selesai di halaman hasil.
    assert dialog.next_button().text() == "Selesai"


def test_tanpa_file_write_sebelum_konfirmasi(
    tmp_path: Path, qtbot: object
) -> None:
    """Sampai halaman konfirmasi: file utuh, tanpa backup, settings utuh."""
    dialog, store = make_dialog(tmp_path, qtbot)
    target = tmp_path / "config.yml"
    target.write_bytes(VALID_CONFIG.encode("utf-8"))
    (tmp_path / "credentials-dummy.json").write_bytes(b"{}")
    settings_sebelum = store.load()

    _ke_pilih(dialog, qtbot, target)
    dialog.next_button().click()  # builder + cek
    _tunggu(dialog, qtbot, 3)
    dialog.next_button().click()  # preview
    _tunggu(dialog, qtbot, 4)
    dialog.next_button().click()  # prepare → konfirmasi
    _tunggu(dialog, qtbot, 5)

    assert target.read_bytes() == VALID_CONFIG.encode("utf-8")
    assert store.load() == settings_sebelum
    assert not list(tmp_path.glob("*.backup-*"))
    # Batal (reject) — tanpa jejak.
    dialog.cancel_button().click()
    assert target.read_bytes() == VALID_CONFIG.encode("utf-8")


def test_double_submission_dicegah(
    tmp_path: Path, qtbot: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Selama worker lambat berjalan, tombol nonaktif (anti double-submit)."""
    dialog, _store = make_dialog(tmp_path, qtbot)
    target = tmp_path / "config.yml"
    target.write_bytes(VALID_CONFIG.encode("utf-8"))

    real_validate = dialog._services.validator.validate_path

    def validate_lambat(path: Path):  # type: ignore[no-untyped-def]
        time.sleep(0.6)  # operasi "lambat" deterministik singkat
        return real_validate(path)

    monkeypatch.setattr(
        dialog._services.validator, "validate_path", validate_lambat
    )
    dialog._page_pilih.set_path(target)  # noqa: SLF001
    dialog.next_button().click()  # 0 → 1
    _tunggu(dialog, qtbot, 1)
    dialog.next_button().click()  # 1 → 2 (worker lambat)
    qtbot.waitUntil(lambda: dialog.is_busy(), timeout=5000)
    assert not dialog.next_button().isEnabled()
    assert not dialog.back_button().isEnabled()
    assert not dialog.cancel_button().isEnabled()  # dinonaktifkan saat busy
    _tunggu(dialog, qtbot, 2)


def test_unknown_keys_memblokir_lanjut(tmp_path: Path, qtbot: object) -> None:
    """Usulan berkunci tak dikenal → halaman cek memblokir tombol Lanjut
    (constraint: UNKNOWN tidak dipaksakan VALID)."""
    dialog, _store = make_dialog(tmp_path, qtbot)
    target = tmp_path / "config.yml"
    dengan_asing = VALID_CONFIG + "original-config-extra: true\n"
    target.write_bytes(dengan_asing.encode("utf-8"))
    (tmp_path / "credentials-dummy.json").write_bytes(b"{}")

    _ke_pilih(dialog, qtbot, target)
    dialog.next_button().click()  # builder + cek
    _tunggu(dialog, qtbot, 3)
    assert dialog.state.check is not None and dialog.state.check.blocked
    assert not dialog.next_button().isEnabled()  # diblokir jujur


def test_halaman_hasil_rollback_failed_kritis() -> None:
    """ROLLBACK_FAILED = gaya KRITIS + lokasi backup (bukan keberhasilan)."""
    page = ResultPage()
    outcome = ApplyOutcome(
        status=ApplyStatus.ROLLBACK_FAILED,
        ok=False,
        detail="simulasi rollback gagal",
        target_path=Path("/x/config.yml"),
        backup_id="abc123",
        backup_path=Path("/x/backups/config.yml.backup-1"),
        applied=True,
    )
    page.refresh(outcome, "")
    assert "KRITIS" in page._status_label.text()  # noqa: SLF001
    assert "backup-1" in page._detail_view.toPlainText()  # noqa: SLF001
    assert "b00020" in page._status_label.styleSheet()  # noqa: SLF001


def test_halaman_hasil_rollback_sukses_bukan_kritis() -> None:
    page = ResultPage()
    outcome = ApplyOutcome(
        status=ApplyStatus.POST_WRITE_VALIDATION_FAILED,
        ok=False,
        detail="validasi ulang gagal — dikembalikan",
        rolled_back=True,
        rollback_sha256="f" * 64,
        backup_path=Path("/x/backups/config.yml.backup-2"),
    )
    page.refresh(outcome, "")
    assert "KRITIS" not in page._status_label.text()  # noqa: SLF001
    assert "dikembalikan otomatis" in page._status_label.text()  # noqa: SLF001


def test_r3_exception_internal_tidak_tampil_mentah(
    tmp_path: Path, qtbot: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Repro R-3/Y-3: exception internal berisi token → UI menampilkan
    versi tersanitasi (RedactionEngine), bukan teks mentah."""
    from PySide6.QtWidgets import QMessageBox

    dialog, _store = make_dialog(tmp_path, qtbot)
    target = tmp_path / "config.yml"
    target.write_bytes(VALID_CONFIG.encode("utf-8"))
    token = "rahasia-dummy-wizard-1234567890"
    dialog._services.redaction.register_secret(token, "SIMULASI")  # noqa: SLF001

    tampil: list[str] = []
    monkeypatch.setattr(
        QMessageBox, "warning", lambda *a, **k: tampil.append(str(a[-1]))
    )
    def validate_pecah(path: Path):  # type: ignore[no-untyped-def]
        raise RuntimeError(f"baca konfigurasi gagal dekat {token}")

    monkeypatch.setattr(
        dialog._services.validator, "validate_path", validate_pecah
    )
    dialog._page_pilih.set_path(target)  # noqa: SLF001
    dialog.next_button().click()  # 0 → 1
    _tunggu(dialog, qtbot, 1)
    dialog.next_button().click()  # 1 → worker gagal → show_error halaman
    qtbot.waitUntil(lambda: not dialog.is_busy(), timeout=10000)

    # Jalur gagal langkah 2 = tampil di halaman pilih (tersanitasi R-3).
    pilih = dialog.pages()["pilih"]
    teks = pilih._status_label.text()  # noqa: SLF001
    assert token not in teks  # token tidak tampil mentah (R-3)
    assert "File tidak dapat dibaca" in teks  # kerangka pesan standar
