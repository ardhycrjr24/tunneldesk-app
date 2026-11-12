"""Halaman 5 — Preview/diff (Task 2.6; teks SUDAH tersanitasi backend)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from tunneldesk.application.config_preview import ConfigPreview
from tunneldesk.domain.config.diff import DiffLineKind
from tunneldesk.ui import strings

__all__ = ["PreviewPage"]


class PreviewPage(QWidget):
    """Diff emit-vs-emit (Task 2.3) + notes jujur (normalisasi dsb.)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self._title = QLabel(strings.text("wiz.p5.title"), self)
        self._title.setWordWrap(True)
        layout.addWidget(self._title)

        self._diff_view = QPlainTextEdit(self)
        self._diff_view.setReadOnly(True)
        layout.addWidget(self._diff_view, stretch=3)

        self._notes_label = QLabel("", self)
        self._notes_label.setWordWrap(True)
        layout.addWidget(self._notes_label)
        layout.addStretch(1)

    def refresh(self, preview: ConfigPreview | None) -> None:
        if preview is None or preview.diff is None:
            self._diff_view.setPlainText(strings.text("wiz.busy"))
            self._notes_label.setText("")
            return
        if not preview.diff.has_changes:
            self._diff_view.setPlainText(strings.text("wiz.p5.no_changes"))
        else:
            lines: list[str] = []
            for line in preview.diff.lines:
                if line.kind is DiffLineKind.ADDED:
                    marker = "+ "
                elif line.kind is DiffLineKind.REMOVED:
                    marker = "- "
                else:
                    marker = "  "
                lines.append(marker + line.text)
            self._diff_view.setPlainText("\n".join(lines))
        catatan = strings.text("wiz.p5.notes_title")
        for note in preview.notes:
            catatan += "\n• " + note
        self._notes_label.setText(catatan)
