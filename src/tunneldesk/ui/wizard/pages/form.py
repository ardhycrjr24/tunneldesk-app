"""Halaman 3 — Guided Form (Task 2.6, W-1: satu-satunya model MVP)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from tunneldesk.application.config_proposal import (
    IngressRule,
    WizardProposal,
)
from tunneldesk.ui import strings

__all__ = ["FormPage"]


class FormPage(QWidget):
    """Formulir tiga kelompok kunci: tunnel, credentials-file, ingress."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self._title = QLabel(strings.text("wiz.p3.title"), self)
        self._title.setWordWrap(True)
        layout.addWidget(self._title)

        form = QFormLayout()
        self._tunnel_edit = QLineEdit(self)
        self._credentials_edit = QLineEdit(self)
        form.addRow(strings.text("wiz.p3.tunnel"), self._tunnel_edit)
        form.addRow(
            strings.text("wiz.p3.credentials"), self._credentials_edit
        )
        layout.addLayout(form)

        layout.addWidget(QLabel(strings.text("wiz.p3.ingress_title"), self))
        self._table = QTableWidget(0, 2, self)
        self._table.setHorizontalHeaderLabels(
            [
                strings.text("wiz.p3.col_hostname"),
                strings.text("wiz.p3.col_service"),
            ]
        )
        layout.addWidget(self._table, stretch=1)

        row = QHBoxLayout()
        add_button = QPushButton(strings.text("wiz.p3.add_row"), self)
        remove_button = QPushButton(strings.text("wiz.p3.remove_row"), self)
        add_button.clicked.connect(self._on_add)
        remove_button.clicked.connect(self._on_remove)
        row.addWidget(add_button)
        row.addWidget(remove_button)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addStretch(1)

    # ------------------------------------------------------------------
    # Aksi tabel
    # ------------------------------------------------------------------
    def _on_add(self) -> None:
        self.append_row()

    def _on_remove(self) -> None:
        index = self._table.currentRow()
        if 0 <= index < self._table.rowCount():
            self._table.removeRow(index)

    def append_row(self, hostname: str = "", service: str = "") -> None:
        """Tambah baris ingress (dipakai prefill dan uji)."""
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._table.setItem(row, 0, _item(hostname))
        self._table.setItem(row, 1, _item(service))

    # ------------------------------------------------------------------
    # Kontrak dialog/uji
    # ------------------------------------------------------------------
    def prefill(self, proposal: WizardProposal) -> None:
        self._tunnel_edit.setText(proposal.tunnel)
        self._credentials_edit.setText(proposal.credentials_file)
        self._table.setRowCount(0)
        for rule in proposal.ingress:
            self.append_row(rule.hostname, rule.service)

    def collect(self) -> WizardProposal:
        rules: list[IngressRule] = []
        for row in range(self._table.rowCount()):
            hostname = _cell(self._table, row, 0)
            service = _cell(self._table, row, 1)
            rules.append(
                IngressRule(service=service.strip(), hostname=hostname.strip())
            )
        return WizardProposal(
            tunnel=self._tunnel_edit.text().strip(),
            credentials_file=self._credentials_edit.text().strip(),
            ingress=tuple(rules),
        )

    def has_empty_service(self) -> bool:
        return any(
            not _cell(self._table, row, 1).strip()
            for row in range(self._table.rowCount())
        )


def _item(text: str) -> QTableWidgetItem:
    return QTableWidgetItem(text)


def _cell(table: QTableWidget, row: int, column: int) -> str:
    item = table.item(row, column)
    return item.text() if item is not None else ""
