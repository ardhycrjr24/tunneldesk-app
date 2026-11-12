"""Halaman 1 — Prasyarat (Task 2.6, W-2, A-09)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QLabel,
    QListWidget,
    QVBoxLayout,
    QWidget,
)

from tunneldesk.domain.tunnel.detection import DetectionReport, InstallMode
from tunneldesk.ui import strings

__all__ = ["PrasyaratPage"]


class PrasyaratPage(QWidget):
    """Status deteksi: cloudflared (W-2 warning non-blok), kandidat, mode."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self._title = QLabel(strings.text("wiz.p1.title"), self)
        self._title.setWordWrap(True)
        layout.addWidget(self._title)

        self._executable_label = QLabel("—", self)
        self._executable_label.setWordWrap(True)
        layout.addWidget(self._executable_label)

        self._mode_label = QLabel("", self)
        self._mode_label.setWordWrap(True)
        layout.addWidget(self._mode_label)

        self._candidates_label = QLabel("", self)
        self._candidates_label.setWordWrap(True)
        layout.addWidget(self._candidates_label)

        self._candidates_list = QListWidget(self)
        layout.addWidget(self._candidates_list, stretch=1)
        layout.addStretch(1)

    def refresh(self, report: DetectionReport | None) -> None:
        if report is None:
            self._executable_label.setText(strings.text("wiz.busy"))
            self._candidates_list.clear()
            return
        if report.executables:
            pertama = report.executables[0]
            if pertama.version:
                self._executable_label.setText(
                    strings.text(
                        "wiz.p1.executable_found",
                        path=pertama.path,
                        version=pertama.version,
                    )
                )
            else:
                self._executable_label.setText(
                    strings.text(
                        "wiz.p1.executable_found_noversion", path=pertama.path
                    )
                )
        else:
            self._executable_label.setText(
                strings.text("wiz.p1.executable_missing")
            )

        mode_text = strings.text("wiz.p1.mode", mode=report.mode.value)
        if report.mode is InstallMode.TOKEN:
            mode_text += "\n" + strings.text("wiz.p1.mode_token")
        elif report.mode is InstallMode.SERVICE:
            mode_text += "\n" + strings.text("wiz.p1.mode_service")
        self._mode_label.setText(mode_text)

        self._candidates_list.clear()
        if report.config_candidates:
            self._candidates_label.setText(
                strings.text(
                    "wiz.p1.candidates", count=len(report.config_candidates)
                )
            )
            for candidate in report.config_candidates:
                self._candidates_list.addItem(str(candidate.path))
        else:
            self._candidates_label.setText(
                strings.text("wiz.p1.candidates_none")
            )
