"""Dialog Diagnostik (Task 2.7, PRD-01 §7.5) — on-demand + review-first.

Aturan (keputusan PO P-1..P-5 + batasan §5):
- Pemeriksaan berjalan **hanya** saat pengguna menekan tombol (P-5) —
  tanpa polling otomatis; tombol nonaktif selama worker berjalan
  (anti double-submit).
- Hasil tiap kelompok tampil terpisah; laporan preview **sebelum**
  Ekspor TXT / Copy aktif (review-first — PRD-01 §7.5 "ditinjau pengguna
  sebelum disalin atau dibagikan").
- TXT dan clipboard memakai representasi teks yang SAMA
  (`render_report_text`).
- Tutup saat worker berjalan ditangani aman: dialog menolak ditutup dan
  menampilkan keterangan (hasil read-only — tidak ada half-state).
- Semua pesan kegagalan melalui RedactionEngine (D-18).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from tunneldesk.application.diagnostics_service import (
    DiagnosticsService,
    build_hostname_mask,
    render_report_text,
)
from tunneldesk.domain.diagnostics.checks import DiagnosticReport
from tunneldesk.infrastructure.network.dns_probe import DnsProbe
from tunneldesk.infrastructure.network.https_tls_probe import HttpsTlsProbe
from tunneldesk.infrastructure.network.public_probe import PublicAccessProbe
from tunneldesk.ui import strings
from tunneldesk.ui.workers import FunctionWorker

if TYPE_CHECKING:
    from tunneldesk.application.tunnel_controller import TunnelController

__all__ = ["DiagnosticsDialog"]


class DiagnosticsDialog(QDialog):
    """Diagnostik on-demand: jalankan → hasil → tinjau → ekspor/salin."""

    def __init__(
        self,
        controller: TunnelController,
        settings_store: object,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        # Komposisi layanan (pola build_wizard_services Task 2.6) —
        # deny-prefix/probe stdlib; konfigurasi aktif dari pengaturan.
        from tunneldesk.application.config_validator import ConfigValidator

        self._settings_store = settings_store
        self._settings = settings_store.load()  # type: ignore[attr-defined]
        self._config_path = self._settings.config_path
        self._service = DiagnosticsService(
            controller=controller,
            validator=ConfigValidator(),
            dns_probe=DnsProbe(),
            tls_probe=HttpsTlsProbe(),
            public_probe=PublicAccessProbe(),
        )
        self._worker: FunctionWorker | None = None
        self._report_text: str = ""
        self.state_report: DiagnosticReport | None = None  # akses uji

        self.setWindowTitle(strings.text("diag.title"))
        self.setModal(True)
        layout = QVBoxLayout(self)

        self._status_label = QLabel("", self)
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

        self._results_view = QPlainTextEdit(self)
        self._results_view.setReadOnly(True)
        layout.addWidget(self._results_view, stretch=2)

        self._report_title = QLabel(strings.text("diag.report_title"), self)
        layout.addWidget(self._report_title)

        self._report_view = QPlainTextEdit(self)
        self._report_view.setReadOnly(True)
        layout.addWidget(self._report_view, stretch=3)

        self._mask_warning = QLabel(strings.text("diag.mask.warning"), self)
        self._mask_warning.setWordWrap(True)
        self._mask_warning.setVisible(False)

        self._mask_checkbox = QCheckBox(strings.text("diag.mask.checkbox"), self)
        self._mask_checkbox.setVisible(False)  # tampil setelah laporan siap

        buttons = QHBoxLayout()
        self._run_button = QPushButton(strings.text("diag.run"), self)
        self._run_button.clicked.connect(self._on_run)
        self._export_button = QPushButton(strings.text("diag.export_txt"), self)
        self._export_button.clicked.connect(self._on_export)
        self._copy_button = QPushButton(strings.text("diag.copy"), self)
        self._copy_button.clicked.connect(self._on_copy)
        self._close_button = QPushButton(strings.text("btn.cancel"), self)
        self._close_button.clicked.connect(self.reject)
        buttons.addWidget(self._run_button)
        buttons.addStretch(1)
        buttons.addWidget(self._export_button)
        buttons.addWidget(self._copy_button)
        buttons.addWidget(self._close_button)
        layout.addLayout(buttons)

        self._refresh_buttons()

    # ------------------------------------------------------------------
    # Worker (satu worker aktif; tombol dinonaktifkan — anti double-submit)
    # ------------------------------------------------------------------
    def _on_run(self) -> None:
        if self.is_busy():
            return
        # T-3/R-05: run baru selalu dimulai tanpa masking (checkbox reset OFF).
        self._mask_checkbox.setChecked(False)
        self._status_label.setText(strings.text("diag.running"))
        self._results_view.setPlainText("")
        self._report_view.setPlainText("")
        self._report_text = ""
        self._worker = FunctionWorker(
            lambda: self._service.run_report(self._config_path)
        )
        self._worker.finished.connect(self._on_report_ready)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()
        # Nonaktifkan tombol SETELAH thread hidup (pola wizard Task 2.6).
        self._refresh_buttons()

    def _on_report_ready(self, report: DiagnosticReport) -> None:
        self._worker = None
        self.state_report = report
        self._status_label.setText("")
        self._mask_checkbox.setVisible(True)  # opsi "bila diminta" (T-2)
        # Hasil langsung per kelompok (T-4: tetap asli — tanpa masking).
        hasil = report.results  # type: ignore[attr-defined]
        self._results_view.setPlainText(
            "\n".join(f"[{r.kind.value}] {r.ringkasan}" for r in hasil)
        )
        # Laporan dibangun dari field yang sudah disanitasi di service.
        self._refresh_report_render()
        self._refresh_buttons()

    def _refresh_report_render(self) -> None:
        """Render ulang preview sesuai keadaan checkbox saat itu (R-05):
        masking dinilai pada batas render/ekspor."""
        self._report_text = self._current_report_text()
        self._report_view.setPlainText(self._report_text)
        self._mask_warning.setVisible(self._mask_checkbox.isChecked())

    def _current_report_text(self) -> str:
        """R-06/PC-02: SATU sumber teks untuk preview/TXT/clipboard —
        selalu melalui render + masking fail-closed; report mentah tidak
        pernah diekspos saat masking aktif."""
        if self.state_report is None:
            return ""
        if not self._mask_checkbox.isChecked():
            return render_report_text(self.state_report)
        origin_host = self._settings.origin_host
        mask = build_hostname_mask(self.state_report, origin_host)
        if not mask:
            return render_report_text(self.state_report)  # tanpa kandidat
        return render_report_text(self.state_report, mask)

    def _on_failed(self, message: str) -> None:
        self._worker = None
        self._refresh_buttons()
        QMessageBox.warning(
            self,
            strings.text("diag.title"),
            strings.text("diag.err.failed", detail=message),
        )

    def is_busy(self) -> bool:
        return self._worker is not None and self._worker.is_running()

    def _refresh_buttons(self) -> None:
        busy = self.is_busy()
        ada_laporan = bool(self._current_report_text())
        self._run_button.setEnabled(not busy)
        self._export_button.setEnabled(ada_laporan)  # review-first
        self._copy_button.setEnabled(ada_laporan)    # review-first
        self._close_button.setEnabled(not busy)

    # ------------------------------------------------------------------
    # Ekspor (P-3) — TXT dan clipboard memakai representasi yang sama
    # ------------------------------------------------------------------
    def _on_export(self) -> None:
        isi = self._current_report_text()
        if not isi:
            return
        path, _filter = QFileDialog.getSaveFileName(
            self,
            strings.text("diag.export_txt"),
            "laporan-diagnostik.txt",
            "Teks (*.txt);;Semua (*)",
        )
        if not path:
            return
        try:
            Path(path).write_text(isi, encoding="utf-8")
        except OSError as exc:
            # Gagal ekspor ditangani dengan pesan aman; hasil tidak hilang.
            QMessageBox.warning(
                self,
                strings.text("diag.title"),
                strings.text("diag.export_failed", detail=str(exc)),
            )
            return
        self._status_label.setText(
            strings.text("diag.export_ok", path=path)
        )

    def _on_copy(self) -> None:
        isi = self._current_report_text()
        if not isi:
            return
        try:
            from PySide6.QtWidgets import QApplication

            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(isi)
            self._status_label.setText(strings.text("diag.copy_ok"))
        except Exception as exc:  # noqa: BLE001 — pesan aman (R-3 pola)
            QMessageBox.warning(
                self,
                strings.text("diag.title"),
                strings.text("diag.copy_failed", detail=str(exc)),
            )

    # ------------------------------------------------------------------
    # Tutup aman saat worker berjalan (batasan §5)
    # ------------------------------------------------------------------
    def reject(self) -> None:  # noqa: D102 — override QDialog.reject
        if self.is_busy():
            self._status_label.setText(strings.text("diag.close_busy"))
            return
        super().reject()

    # ------------------------------------------------------------------
    # Akses uji
    # ------------------------------------------------------------------
    def report_text(self) -> str:
        return self._report_text

    def run_button(self) -> QPushButton:
        return self._run_button

    def export_button(self) -> QPushButton:
        return self._export_button

    def copy_button(self) -> QPushButton:
        return self._copy_button

    def status_text(self) -> str:
        return self._status_label.text()

    def results_text(self) -> str:
        return self._results_view.toPlainText()
