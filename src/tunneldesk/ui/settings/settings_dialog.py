"""Dialog pengaturan dasar (E-4, PRD-01 §7.7).

Field: lokasi cloudflared, file konfigurasi, direktori log, direktori
backup. Preferensi notifikasi ditunda (K-08 — gerbang Fase 2); auto-start
tidak ada (default mati, PRD-01 §7.7).
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from tunneldesk.application.settings_store import (
    AppSettings,
    SettingsStore,
)
from tunneldesk.ui import strings

__all__ = ["SettingsDialog"]


class SettingsDialog(QDialog):
    """Form pengaturan lokasi — simpan via :class:`SettingsStore`."""

    def __init__(self, settings_store: SettingsStore, parent: object = None) -> None:
        super().__init__()
        self._store = settings_store
        self._settings: AppSettings = settings_store.load()

        self.setWindowTitle(strings.text("settings.title"))
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self._cloudflared_field = QLineEdit(self._settings.cloudflared_path, self)
        self._config_field = QLineEdit(self._settings.config_path, self)
        self._log_field = QLineEdit(self._settings.log_dir, self)
        self._backup_field = QLineEdit(self._settings.backup_dir, self)
        form.addRow(strings.text("settings.fld_cloudflared"), self._cloudflared_field)
        form.addRow(strings.text("settings.fld_config"), self._config_field)
        form.addRow(strings.text("settings.fld_log_dir"), self._log_field)
        form.addRow(strings.text("settings.fld_backup_dir"), self._backup_field)
        layout.addLayout(form)

        self._note_label = QLabel(strings.text("settings.note"), self)
        self._note_label.setWordWrap(True)
        layout.addWidget(self._note_label)

        buttons = QHBoxLayout()
        save_button = QPushButton(strings.text("btn.save"), self)
        cancel_button = QPushButton(strings.text("btn.cancel"), self)
        save_button.clicked.connect(self._on_save)
        cancel_button.clicked.connect(self.reject)
        buttons.addWidget(save_button)
        buttons.addWidget(cancel_button)
        layout.addLayout(buttons)

    def _on_save(self) -> None:
        self._store.save(
            self._settings.with_updates(
                cloudflared_path=self._cloudflared_field.text().strip(),
                config_path=self._config_field.text().strip(),
                log_dir=self._log_field.text().strip(),
                backup_dir=self._backup_field.text().strip(),
            )
        )
        self._note_label.setText(strings.text("settings.saved"))
        self.accept()

    # ------------------------------------------------------------------
    # Akses uji
    # ------------------------------------------------------------------
    def field_values(self) -> dict[str, str]:
        return {
            "cloudflared_path": self._cloudflared_field.text(),
            "config_path": self._config_field.text(),
            "log_dir": self._log_field.text(),
            "backup_dir": self._backup_field.text(),
        }

    def set_field_values(self, **values: str) -> None:
        mapping = {
            "cloudflared_path": self._cloudflared_field,
            "config_path": self._config_field,
            "log_dir": self._log_field,
            "backup_dir": self._backup_field,
        }
        for key, widget in mapping.items():
            if key in values:
                widget.setText(values[key])
