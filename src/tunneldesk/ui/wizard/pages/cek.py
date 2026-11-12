"""Halaman 4 — Validasi & pemeriksaan origin lokal (Task 2.6, W-3/W-4)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from tunneldesk.domain.config.model import ValidationClassification
from tunneldesk.ui import strings
from tunneldesk.ui.wizard.state import CheckOutcome

__all__ = ["CheckPage"]


class CheckPage(QWidget):
    """Hasil skema E-6 + probe origin per baris + banner W-4."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self._title = QLabel(strings.text("wiz.p4.title"), self)
        self._title.setWordWrap(True)
        layout.addWidget(self._title)

        self._status_label = QLabel("", self)
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)

        self._items_view = QPlainTextEdit(self)
        self._items_view.setReadOnly(True)
        layout.addWidget(self._items_view, stretch=2)

        self._origin_title = QLabel(strings.text("wiz.p4.origin_title"), self)
        self._origin_title.setWordWrap(True)
        layout.addWidget(self._origin_title)

        self._origin_view = QPlainTextEdit(self)
        self._origin_view.setReadOnly(True)
        layout.addWidget(self._origin_view, stretch=1)

        self._credentials_banner = QLabel("", self)
        self._credentials_banner.setWordWrap(True)
        self._credentials_banner.setStyleSheet("color: #7a3b00;")
        layout.addWidget(self._credentials_banner)
        layout.addStretch(1)

    def refresh(self, outcome: CheckOutcome | None) -> None:
        if outcome is None:
            self._status_label.setText(strings.text("wiz.busy"))
            return
        classification = outcome.validation.classification
        if classification is ValidationClassification.VALID:
            self._status_label.setText(strings.text("wiz.p4.valid"))
        elif classification is ValidationClassification.UNKNOWN:
            self._status_label.setText(strings.text("wiz.p4.unknown"))
        else:
            self._status_label.setText(strings.text("wiz.p4.invalid"))

        items = list(outcome.validation.errors) + list(
            outcome.validation.warnings
        )
        self._items_view.setPlainText(
            "\n".join(f"{item!r}" for item in items) or "—"
        )

        lines: list[str] = []
        for row in outcome.origin_rows:
            if row.skipped:
                lines.append(
                    strings.text(
                        "wiz.p4.origin_skip_catchall", service=row.service
                    )
                )
            elif row.error is not None:
                lines.append(
                    strings.text(
                        "wiz.p4.origin_not_mappable",
                        service=row.service,
                        reason=row.error,
                    )
                )
            elif row.result is not None:
                lines.append(
                    f"{row.service} — {row.result.status.value}: "
                    f"{row.result.detail}"
                )
        self._origin_view.setPlainText("\n".join(lines) or "—")

        self._credentials_banner.setText(
            strings.text("wiz.p4.blocked_credentials")
            if outcome.credentials_missing
            else ""
        )
