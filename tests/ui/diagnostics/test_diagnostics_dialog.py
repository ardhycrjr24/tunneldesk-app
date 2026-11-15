"""Uji dialog Diagnostik (Task 2.7) — pytest-qt offscreen.

On-demand (P-5), review-first (ekspor terkunci sampai laporan tampil),
TXT/clipboard representasi sama (P-3/AC-08), tutup-aman saat worker
berjalan, anti double-submit.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tunneldesk.application.config_validator import ConfigValidator
from tunneldesk.application.diagnostics_service import (
    DiagnosticsService,
)
from tunneldesk.application.settings_store import JsonSettingsStore
from tunneldesk.domain.diagnostics.origin import (
    OriginCheckResult,
    OriginStatus,
)
from tunneldesk.infrastructure.network.dns_probe import DnsOutcome, DnsStatus
from tunneldesk.infrastructure.network.https_tls_probe import (
    TlsKind,
    TlsOutcome,
)
from tunneldesk.infrastructure.network.public_probe import (
    PublicKind,
    PublicOutcome,
)
from tunneldesk.ui.diagnostics.diagnostics_dialog import DiagnosticsDialog

VALID_CONFIG = (
    "tunnel: 11111111-2222-3333-4444-555555555555\n"
    "credentials-file: credentials-dummy.json\n"
    "ingress:\n"
    "  - hostname: rapor.sekolah.sch.id\n"
    "    service: http://localhost:8080\n"
    "  - service: http_status:404\n"
)


class ControllerStub:
    def status(self, probe_origin: bool = False):  # type: ignore[no-untyped-def]
        class S:
            tunnel_state = "RUNNING"
            pid = 42
            crashed = None
            origin = None

        return S()

    def check_origin(self) -> OriginCheckResult:
        return OriginCheckResult(OriginStatus.HEALTHY, "origin merespons")


def make_dialog(
    tmp_path: Path, qtbot: object
) -> tuple[DiagnosticsDialog, JsonSettingsStore]:
    store = JsonSettingsStore(tmp_path / "settings.json")
    config = tmp_path / "config.yml"
    config.write_bytes(VALID_CONFIG.encode("utf-8"))
    (tmp_path / "credentials-dummy.json").write_bytes(b"{}")
    store.save(store.load().with_updates(config_path=str(config)))

    # Dialog membangun service sendiri; untuk determinisme, ganti probe
    # nyata dengan stub SETELAH konstruktor (atribut privat service).
    dialog = DiagnosticsDialog(ControllerStub(), store)
    qtbot.addWidget(dialog)

    class StubDns:
        def resolve(self, hostname: str) -> DnsOutcome:
            return DnsOutcome(DnsStatus.RESOLVED, ("104.21.5.9",))

    class StubTls:
        def check(self, hostname: str) -> TlsOutcome:
            return TlsOutcome(
                TlsKind.VERIFIED,
                "koneksi TLS berhasil",
                cert_subject="sni.example",
                cert_issuer="CloudFlare",
                cert_not_after="Jan 1 2030",
            )

    class StubPublic:
        def check(self, hostname: str) -> PublicOutcome:
            return PublicOutcome(
                PublicKind.RESPONDING, 200, "respons HTTP 200"
            )

    service = dialog._service  # noqa: SLF001 — injeksi uji

    dialog._service = DiagnosticsService(  # noqa: SLF001
        controller=service._controller,  # noqa: SLF001
        validator=ConfigValidator(),
        dns_probe=StubDns(),  # type: ignore[arg-type]
        tls_probe=StubTls(),  # type: ignore[arg-type]
        public_probe=StubPublic(),  # type: ignore[arg-type]
        version_provider=lambda: "9.9.9-uji",
        clock=lambda: 1700000000.0,
    )
    return dialog, store


def _tunggu(qtbot: object, kondisi, timeout: int = 20000) -> None:
    qtbot.waitUntil(kondisi, timeout=timeout)


def test_ekspor_terkunci_sebelum_laporan(tmp_path: Path, qtbot: object) -> None:
    """Review-first (PRD §7.5): tombol Ekspor/Copy terkunci sampai
    pengguna menjalankan diagnostik DAN laporan tampil."""
    dialog, _store = make_dialog(tmp_path, qtbot)
    assert not dialog.export_button().isEnabled()
    assert not dialog.copy_button().isEnabled()


def test_jalankan_membuka_ekspor_dan_preview(
    tmp_path: Path, qtbot: object
) -> None:
    dialog, _store = make_dialog(tmp_path, qtbot)
    dialog.run_button().click()
    _tunggu(qtbot, lambda: bool(dialog.report_text()))
    assert dialog.export_button().isEnabled()
    assert dialog.copy_button().isEnabled()
    # Preview = hasil per kelompok + laporan utuh.
    assert "[PROSES]" in dialog.results_text()
    assert "LAPORAN DIAGNOSTIK TUNNELDESK" in dialog.report_text()
    assert "Versi aplikasi: 9.9.9-uji" in dialog.report_text()


def test_ekspor_txt_menulis_representasi_sama(
    tmp_path: Path, qtbot: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P-3/AC-08: file TXT = render_report_text (representasi identik)."""
    dialog, _store = make_dialog(tmp_path, qtbot)
    dialog.run_button().click()
    _tunggu(qtbot, lambda: bool(dialog.report_text()))
    target = tmp_path / "laporan.txt"
    monkeypatch.setattr(
        "tunneldesk.ui.diagnostics.diagnostics_dialog.QFileDialog.getSaveFileName",
        lambda *a, **k: (str(target), ""),
    )
    dialog._on_export()  # noqa: SLF001 — aksi uji
    assert target.exists()
    assert target.read_text(encoding="utf-8") == dialog.report_text()


def test_clipboard_representasi_sama(
    tmp_path: Path, qtbot: object
) -> None:
    dialog, _store = make_dialog(tmp_path, qtbot)
    dialog.run_button().click()
    _tunggu(qtbot, lambda: bool(dialog.report_text()))
    dialog._on_copy()  # noqa: SLF001 — aksi uji
    from PySide6.QtWidgets import QApplication

    clipboard = QApplication.clipboard()
    assert clipboard is not None
    assert clipboard.text() == dialog.report_text()


def test_tutup_ditolak_saat_worker_berjalan(
    tmp_path: Path, qtbot: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Worker berjalan → reject() ditolak dengan pesan; dialog tetap."""
    import time as _time

    dialog, _store = make_dialog(tmp_path, qtbot)
    service = dialog._service  # noqa: SLF001
    asli_status = service._controller.status  # noqa: SLF001

    def status_lambat(probe_origin: bool = False):  # type: ignore[no-untyped-def]
        _time.sleep(0.5)
        return asli_status(probe_origin)

    monkeypatch.setattr(
        service._controller, "status", status_lambat  # noqa: SLF001
    )
    dialog.show()  # diperlukan agar isVisible bermakna di offscreen
    dialog.run_button().click()
    _tunggu(qtbot, lambda: dialog.is_busy())
    dialog.reject()  # harus DITOLAK saat busy (tutup-aman §5)
    assert dialog.isVisible()  # dialog TIDAK tertutup paksa
    _tunggu(qtbot, lambda: not dialog.is_busy())
    dialog.close()


def test_laporan_bebas_rahasia_dummy(
    tmp_path: Path, qtbot: object
) -> None:
    """AC-08: tanpa isi config/credential dalam laporan."""
    dialog, _store = make_dialog(tmp_path, qtbot)
    dialog.run_button().click()
    _tunggu(qtbot, lambda: bool(dialog.report_text()))
    teks = dialog.report_text()
    for rahasia in ("11111111-2222", "credentials-dummy", "TunnelSecret"):
        assert rahasia not in teks
