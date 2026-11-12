"""Halaman 2 — Pilih/konfirmasi file konfigurasi (Task 2.6)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from tunneldesk.ui import strings

__all__ = ["ConfigPickPage"]


class ConfigPickPage(QWidget):
    """Pilihan target: kandidat deteksi (klik → isi) atau path kustom."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self._title = QLabel(strings.text("wiz.p2.title"), self)
        self._title.setWordWrap(True)
        layout.addWidget(self._title)

        row = QHBoxLayout()
        row.addWidget(QLabel(strings.text("wiz.p2.path_label"), self))
        self._path_edit = QLineEdit(self)
        row.addWidget(self._path_edit, stretch=1)
        browse = QPushButton(strings.text("btn.browse"), self)
        browse.clicked.connect(self._on_browse)
        row.addWidget(browse)
        layout.addLayout(row)

        self._candidates_list = QListWidget(self)
        self._candidates_list.itemClicked.connect(self._on_candidate)
        layout.addWidget(self._candidates_list, stretch=1)

        self._status_label = QLabel("", self)
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)
        layout.addStretch(1)

    def _on_browse(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self, strings.text("wiz.p2.title"), "", "YAML (*.yml *.yaml);;Semua (*)"
        )
        if path:
            self._path_edit.setText(path)

    def _on_candidate(self, item: object) -> None:
        self._path_edit.setText(item.text())  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Akses dialog/uji
    # ------------------------------------------------------------------
    def set_candidates(self, paths: tuple[str, ...]) -> None:
        self._candidates_list.clear()
        for path in paths:
            self._candidates_list.addItem(path)

    def selected_path(self) -> str:
        return self._path_edit.text().strip()

    def show_initial(self, status: str) -> None:
        self._status_label.setText(
            strings.text("wiz.p2.initial_status", status=status)
        )

    def show_error(self, detail: str) -> None:
        self._status_label.setText(
            strings.text("wiz.p2.read_failed", detail=detail)
        )

    def set_path(self, path: Path | str) -> None:
        self._path_edit.setText(str(path))
