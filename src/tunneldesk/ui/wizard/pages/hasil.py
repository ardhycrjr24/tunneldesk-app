"""Halaman 7 — Hasil apply, error mapping, rollback (Task 2.6, W-5).

`ROLLBACK_FAILED` tampil sebagai kondisi KRITIS + lokasi backup —
bukan keberhasilan (constraint). Detail status berasal dari backend
(sudah disanitasi); mapping kunci string via ``apply_status_text_key``.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from tunneldesk.application.config_apply_service import (
    ApplyOutcome,
    ApplyStatus,
)
from tunneldesk.ui import strings
from tunneldesk.ui.wizard.state import apply_status_text_key

__all__ = ["ResultPage"]


class ResultPage(QWidget):
    """Status akhir wizard + info pemulihan + catatan pengaturan (W-5)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self._title = QLabel(strings.text("wiz.p7.title"), self)
        self._title.setWordWrap(True)
        layout.addWidget(self._title)

        self._status_label = QLabel("", self)
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

        self._detail_view = QPlainTextEdit(self)
        self._detail_view.setReadOnly(True)
        layout.addWidget(self._detail_view, stretch=2)

        self._settings_note = QLabel("", self)
        self._settings_note.setWordWrap(True)
        layout.addWidget(self._settings_note)
        layout.addStretch(1)

    def refresh(self, outcome: ApplyOutcome, settings_note: str) -> None:
        kritis = outcome.status is ApplyStatus.ROLLBACK_FAILED
        text = strings.text(apply_status_text_key(outcome.status))
        if kritis:
            # Kondisi kritis: gaya mencolok + detail pemulihan manual.
            self._status_label.setStyleSheet(
                "color: #b00020; font-weight: bold;"
            )
        else:
            self._status_label.setStyleSheet("")
        self._status_label.setText(text)

        baris: list[str] = []
        if outcome.detail:
            baris.append(outcome.detail)
        if outcome.backup_path is not None:
            baris.append(
                strings.text(
                    "wiz.p7.backup_path", path=outcome.backup_path
                )
            )
        if outcome.written_sha256 is not None:
            baris.append(
                strings.text(
                    "wiz.p7.written_hash", sha=outcome.written_sha256
                )
            )
        if outcome.rolled_back:
            baris.append(
                f"rollback terverifikasi: {outcome.rollback_sha256}"
            )
        self._detail_view.setPlainText("\n".join(baris) or "—")

        if outcome.status is ApplyStatus.APPLIED:
            self._settings_note.setText(
                strings.text("wiz.p7.restart_note")
                + (f" ({settings_note})" if settings_note else "")
            )
        elif settings_note:
            self._settings_note.setText(
                strings.text("wiz.p7.settings_skipped", reason=settings_note)
            )
        else:
            self._settings_note.setText("")
