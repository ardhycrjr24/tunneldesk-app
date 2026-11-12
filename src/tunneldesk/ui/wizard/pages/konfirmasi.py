"""Halaman 6 — Konfirmasi eksplisit (Task 2.6, Q5/D-17)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QLabel,
    QVBoxLayout,
    QWidget,
)

from tunneldesk.ui import strings
from tunneldesk.ui.wizard.state import WizardState

__all__ = ["ConfirmPage"]


class ConfirmPage(QWidget):
    """Ringkasan sebelum apply: target, hash, jumlah perubahan, backup."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self._title = QLabel(strings.text("wiz.p6.title"), self)
        self._title.setWordWrap(True)
        layout.addWidget(self._title)

        self._summary = QLabel("", self)
        self._summary.setWordWrap(True)
        layout.addWidget(self._summary)

        self._backup_note = QLabel(strings.text("wiz.p6.backup_note"), self)
        self._backup_note.setWordWrap(True)
        layout.addWidget(self._backup_note)

        self._apply_hint = QLabel(strings.text("wiz.p6.apply_hint"), self)
        self._apply_hint.setWordWrap(True)
        layout.addWidget(self._apply_hint)
        layout.addStretch(1)

    def refresh(self, state: WizardState) -> None:
        preview = state.preview
        target = state.target_path
        added = removed = 0
        if preview is not None and preview.diff is not None:
            added = preview.diff.added_count
            removed = preview.diff.removed_count
        self._summary.setText(
            "\n".join(
                (
                    strings.text(
                        "wiz.p6.target", path=target or "(belum dipilih)"
                    ),
                    strings.text(
                        "wiz.p6.source_hash",
                        sha=(state.artifact.source_sha256 if state.artifact
                             else "—"),
                    ),
                    strings.text(
                        "wiz.p6.changes", added=added, removed=removed
                    ),
                )
            )
        )
