"""SetupWizardDialog (Task 2.6, PRD-01 §7.4, D-17) — orkestrasi 7 halaman.

Aturan yang ditegakkan di sini (constraint Task 2.6):
- Semua panggilan backend berjalan di ``FunctionWorker`` (PRD-01 §11);
  tombol dinonaktifkan selama worker aktif (anti double-submission).
- **Nol penulisan file sebelum konfirmasi eksplisit**: langkah 1-6
  read-only; tulis pertama = backup pra-apply di DALAM ``apply()``
  (UI tidak memanggil create_backup terpisah).
- Artefak Q2: preview dan apply memakai ``ApplyArtifact`` yang sama
  (dibuat ``prepare`` saat memasuki halaman konfirmasi); tanpa
  serialisasi ulang.
- Kembali dari langkah mana pun mereset hasil langkah di depannya
  (cek/preview/artefak/outcome) — tidak ada artefak basi dipakai ulang.
- Batal dinonaktifkan selama worker apply berjalan (tulis atomik tidak
  dapat "dibatalkan" dari UI; jujur).
- W-5: setelah APPLIED, AppSettings diperbarui via SettingsStore +
  keterangan mulai-ulang (controller TIDAK direkonstruksi dinamis).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from tunneldesk.application.config_apply_service import (
    ApplyOutcome,
    ApplyStatus,
)
from tunneldesk.domain.tunnel.detection import DetectionReport
from tunneldesk.ui import strings
from tunneldesk.ui.wizard.pages.cek import CheckPage
from tunneldesk.ui.wizard.pages.form import FormPage
from tunneldesk.ui.wizard.pages.hasil import ResultPage
from tunneldesk.ui.wizard.pages.konfirmasi import ConfirmPage
from tunneldesk.ui.wizard.pages.pilih import ConfigPickPage
from tunneldesk.ui.wizard.pages.prasyarat import PrasyaratPage
from tunneldesk.ui.wizard.pages.preview import PreviewPage
from tunneldesk.ui.wizard.services import (
    WizardServices,
    run_check,
    save_origin_settings,
)
from tunneldesk.ui.wizard.state import WizardState
from tunneldesk.ui.workers import FunctionWorker

__all__ = ["SetupWizardDialog"]

#: Indeks halaman dalam tumpukan.
_P_PRASYARAT = 0
_P_PILIH = 1
_P_FORM = 2
_P_CEK = 3
_P_PREVIEW = 4
_P_KONFIRMASI = 5
_P_HASIL = 6


class SetupWizardDialog(QDialog):
    """Wizard modal: prasyarat → pilih → form → cek → preview →
    konfirmasi → apply → hasil."""

    def __init__(
        self,
        services: WizardServices,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._services = services
        self.state = WizardState()
        self._worker: FunctionWorker | None = None

        self.setWindowTitle(strings.text("wiz.title"))
        self.setModal(True)
        root = QVBoxLayout(self)

        self._stack = QStackedWidget(self)
        self._page_prasyarat = PrasyaratPage()
        self._page_pilih = ConfigPickPage()
        self._page_form = FormPage()
        self._page_cek = CheckPage()
        self._page_preview = PreviewPage()
        self._page_konfirmasi = ConfirmPage()
        self._page_hasil = ResultPage()
        for page in (
            self._page_prasyarat,
            self._page_pilih,
            self._page_form,
            self._page_cek,
            self._page_preview,
            self._page_konfirmasi,
            self._page_hasil,
        ):
            self._stack.addWidget(page)
        root.addWidget(self._stack, stretch=1)

        buttons = QHBoxLayout()
        self._back_button = QPushButton(strings.text("wiz.back"), self)
        self._next_button = QPushButton(strings.text("wiz.next"), self)
        self._cancel_button = QPushButton(strings.text("wiz.cancel"), self)
        self._back_button.clicked.connect(self._on_back)
        self._next_button.clicked.connect(self._on_next)
        self._cancel_button.clicked.connect(self.reject)
        buttons.addWidget(self._back_button)
        buttons.addStretch(1)
        buttons.addWidget(self._cancel_button)
        buttons.addWidget(self._next_button)
        root.addLayout(buttons)

        self._stack.setCurrentIndex(_P_PRASYARAT)
        self._refresh_buttons()
        self._start_detection()

    # ------------------------------------------------------------------
    # Worker (satu worker aktif; tombol dinonaktifkan — anti double-submit)
    # ------------------------------------------------------------------
    def _run(self, function: Callable[[], object], on_done: Callable[[object], None]) -> None:
        """Jalankan ``function`` di worker; hasil/gagal via callback."""
        self._worker = FunctionWorker(function)
        self._worker.finished.connect(on_done)
        self._worker.failed.connect(self._on_worker_failed)
        self._worker.start()
        # Nonaktifkan tombol SETELAH thread hidup (is_running() butuh
        # thread berjalan — pelajaran uji double-submission).
        self._refresh_buttons()

    def _on_worker_failed(self, message: str) -> None:
        self._worker = None
        self._refresh_buttons()
        QMessageBox.warning(
            self, strings.text("wiz.title"), message
        )

    def _busy(self) -> bool:
        return self._worker is not None and self._worker.is_running()

    # ------------------------------------------------------------------
    # Deteksi awal (halaman 1)
    # ------------------------------------------------------------------
    def _start_detection(self) -> None:
        self._page_prasyarat.refresh(None)
        self._run(
            self._services.detection.detect,
            self._on_detection_done,
        )

    def _on_detection_done(self, report: object) -> None:
        self._worker = None
        self.state.detection = cast("DetectionReport", report)
        detection = self.state.detection
        assert detection is not None
        self._page_prasyarat.refresh(detection)
        self._page_pilih.set_candidates(
            tuple(str(c.path) for c in detection.config_candidates)
        )
        self._refresh_buttons()

    # ------------------------------------------------------------------
    # Navigasi
    # ------------------------------------------------------------------
    def _on_next(self) -> None:
        if self._busy():
            return
        index = self._stack.currentIndex()
        if index == _P_PRASYARAT:
            self._goto(_P_PILIH)
        elif index == _P_PILIH:
            self._load_target()
        elif index == _P_FORM:
            self._build_proposal()
        elif index == _P_CEK:
            if self.state.check is not None and self.state.check.blocked:
                return  # sudah ditampilkan halaman; tetap
            self._make_preview()
        elif index == _P_PREVIEW:
            self._prepare_artifact()
        elif index == _P_KONFIRMASI:
            self._apply()

    def _on_back(self) -> None:
        if self._busy():
            return
        index = self._stack.currentIndex()
        if index <= _P_PRASYARAT or index == _P_HASIL:
            return
        target = index - 1
        # Reset hasil langkah di depan — tidak ada artefak basi.
        if target < _P_CEK:
            self.state.check = None
        if target < _P_PREVIEW:
            self.state.preview = None
        if target < _P_KONFIRMASI:
            self.state.artifact = None
        self.state.outcome = None
        self._goto(target)

    def _goto(self, index: int) -> None:
        self._stack.setCurrentIndex(index)
        self._refresh_buttons()

    def _refresh_buttons(self) -> None:
        index = self._stack.currentIndex()
        busy = self._busy()
        at_apply = index == _P_KONFIRMASI
        at_result = index == _P_HASIL
        self._back_button.setEnabled(
            not busy and index > _P_PRASYARAT and not at_result
        )
        self._cancel_button.setEnabled(not busy)
        if at_result:
            self._next_button.setText(strings.text("wiz.finish"))
            self._next_button.setEnabled(not busy)
        else:
            self._next_button.setText(
                strings.text("wiz.apply")
                if at_apply
                else strings.text("wiz.next")
            )
            # Halaman cek: usulan tidak VALID → lanjut diblokir jujur
            # (constraint: kegagalan validasi mencegah penerapan).
            blocked = (
                index == _P_CEK
                and self.state.check is not None
                and self.state.check.blocked
            )
            self._next_button.setEnabled(not busy and not blocked)

    def is_busy(self) -> bool:
        """Status worker aktif (akses uji + pola dashboard)."""
        return self._busy()

    # ------------------------------------------------------------------
    # Akses uji tambahan (pola dashboard)
    # ------------------------------------------------------------------
    def _detail_view_text(self) -> str:
        return self._page_hasil._detail_view.toPlainText()  # noqa: SLF001

    def _settings_note_text(self) -> str:
        return self._page_hasil._settings_note.text()  # noqa: SLF001

    def status_label_text(self) -> str:
        return self._page_hasil._status_label.text()  # noqa: SLF001

    # ------------------------------------------------------------------
    # Langkah 2: baca target + status awal (read-only)
    # ------------------------------------------------------------------
    def _load_target(self) -> None:
        raw = self._page_pilih.selected_path()
        if not raw:
            self._page_pilih.show_error(strings.text("wiz.p2.must_select"))
            return
        target = Path(raw)

        def read() -> object:
            text = target.read_text(encoding="utf-8")
            outcome = self._services.validator.validate_path(target)
            return (text, outcome.classification.value)

        def done(result: object) -> None:
            self._worker = None
            text, status = cast("tuple[str, str]", result)
            self.state.original_text = text
            self.state.target_path = target
            self._page_pilih.show_initial(status)
            # Prefill formulir dari dokumen asal (W-1).
            parsed = self._services.parser.parse(text)
            if parsed.document is not None:
                from tunneldesk.application.config_proposal import (
                    WizardProposal,
                )

                self._page_form.prefill(
                    WizardProposal.from_document(parsed.document)  # type: ignore[arg-type]
                )
            self._goto(_P_FORM)

        def failed(message: str) -> None:
            self._worker = None
            self._refresh_buttons()
            self._page_pilih.show_error(message)

        self._run_with_failure(read, done, failed)

    def _run_with_failure(
        self,
        function: Callable[[], object],
        on_done: Callable[[object], None],
        on_failed: Callable[[str], None],
    ) -> None:
        """Varian ``_run`` dengan callback gagal khusus langkah (halaman
        menampilkan error-nya sendiri, bukan kotak pesan)."""
        self._worker = FunctionWorker(function)
        self._worker.finished.connect(on_done)
        self._worker.failed.connect(on_failed)
        self._worker.start()
        # Nonaktifkan tombol SETELAH thread hidup (lihat _run).
        self._refresh_buttons()

    # ------------------------------------------------------------------
    # Langkah 3: susun usulan (builder — murni, tanpa I/O)
    # ------------------------------------------------------------------
    def _build_proposal(self) -> None:
        if self._page_form.has_empty_service():
            QMessageBox.warning(
                self,
                strings.text("wiz.title"),
                strings.text("wiz.p3.empty_service"),
            )
            return
        proposal = self._page_form.collect()
        original = self.state.original_text or ""

        def build() -> object:
            return self._services.builder.build(original, proposal)

        def done(result: object) -> None:
            self._worker = None
            self.state.proposal = proposal
            self.state.proposal_result = result  # type: ignore[assignment]
            proposal_result = self.state.proposal_result
            assert proposal_result is not None
            if not proposal_result.ok:
                QMessageBox.warning(
                    self,
                    strings.text("wiz.title"),
                    "\n".join(
                        [msg for msg, _l, _c in proposal_result.syntax_errors]
                        + list(proposal_result.notes)
                    ),
                )
                self._refresh_buttons()
                return
            # Masuk halaman cek: jalankan validasi + probe origin (W-3).
            self._goto(_P_CEK)
            target = self.state.target_path
            proposed = proposal_result.proposed_text or ""
            self._run(
                lambda: run_check(
                    self._services, proposed, target or Path("."), proposal
                ),
                self._on_check_done,
            )

        def failed(message: str) -> None:
            self._worker = None
            self._refresh_buttons()
            QMessageBox.warning(self, strings.text("wiz.title"), message)

        self._run_with_failure(build, done, failed)

    def _on_check_done(self, result: object) -> None:
        self._worker = None
        self.state.check = result  # type: ignore[assignment]
        self._page_cek.refresh(self.state.check)
        self._refresh_buttons()

    # ------------------------------------------------------------------
    # Langkah 5: preview (Task 2.3 — artefak Q2)
    # ------------------------------------------------------------------
    def _make_preview(self) -> None:
        original = self.state.original_text or ""
        proposal_result = self.state.proposal_result

        def make() -> object:
            assert proposal_result is not None
            return self._services.preview.preview(
                original, proposal_result.proposed_text or ""
            )

        def done(result: object) -> None:
            self._worker = None
            self.state.preview = result  # type: ignore[assignment]
            self._page_preview.refresh(self.state.preview)
            self._goto(_P_PREVIEW)

        def failed(message: str) -> None:
            self._worker = None
            self._refresh_buttons()
            QMessageBox.warning(
                self,
                strings.text("wiz.title"),
                strings.text("wiz.err.rejected", reason=message),
            )

        self._run_with_failure(make, done, failed)

    # ------------------------------------------------------------------
    # Langkah 6: siapkan artefak (read-only) → tampilkan konfirmasi
    # ------------------------------------------------------------------
    def _prepare_artifact(self) -> None:
        preview = self.state.preview
        target = self.state.target_path
        original = self.state.original_text or ""

        def prepare() -> object:
            assert preview is not None and target is not None
            return self._services.apply.prepare(target, preview, original)

        def done(result: object) -> None:
            self._worker = None
            self.state.artifact = result  # type: ignore[assignment]
            self._page_konfirmasi.refresh(self.state)
            self._goto(_P_KONFIRMASI)

        def failed(message: str) -> None:
            self._worker = None
            self._refresh_buttons()
            QMessageBox.warning(self, strings.text("wiz.title"), message)

        self._run_with_failure(prepare, done, failed)

    # ------------------------------------------------------------------
    # Langkah 7: apply (backup internal) → hasil (+W-5)
    # ------------------------------------------------------------------
    def _apply(self) -> None:
        artifact = self.state.artifact
        proposal = self.state.proposal

        def do_apply() -> object:
            assert artifact is not None
            outcome = self._services.apply.apply(artifact, confirm=True)
            note = ""
            if outcome.status is ApplyStatus.APPLIED and proposal is not None:
                note = save_origin_settings(self._services, proposal)
            return (outcome, note)

        def done(result: object) -> None:
            self._worker = None
            outcome, note = cast("tuple[ApplyOutcome, str]", result)
            self.state.outcome = outcome
            self.state.settings_note = note
            self._page_hasil.refresh(outcome, note)
            self._goto(_P_HASIL)

        def failed(message: str) -> None:
            self._worker = None
            self._refresh_buttons()
            QMessageBox.warning(self, strings.text("wiz.title"), message)

        self._run_with_failure(do_apply, done, failed)

    # ------------------------------------------------------------------
    # Akses uji
    # ------------------------------------------------------------------
    def current_index(self) -> int:
        return self._stack.currentIndex()

    def pages(self) -> dict[str, QWidget]:
        return {
            "prasyarat": self._page_prasyarat,
            "pilih": self._page_pilih,
            "form": self._page_form,
            "cek": self._page_cek,
            "preview": self._page_preview,
            "konfirmasi": self._page_konfirmasi,
            "hasil": self._page_hasil,
        }

    def next_button(self) -> QPushButton:
        return self._next_button

    def back_button(self) -> QPushButton:
        return self._back_button

    def cancel_button(self) -> QPushButton:
        return self._cancel_button
