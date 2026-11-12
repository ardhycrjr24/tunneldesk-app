"""Dashboard utama (E-4, PRD-01 §7.1) — tampilan status & kontrol tunnel.

Aturan UI (Q-06): semua teks dari ``ui.strings`` — tidak ada literal.
Operasi blocking (start/stop/restart/probe origin) berjalan di worker
thread (PRD-01 §11); refresh status berkala tanpa I/O jaringan.
Status lisensi menampilkan "belum tersedia" — lisensi adalah E-11.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from tunneldesk.application.settings_store import SettingsStore
from tunneldesk.application.tunnel_controller import (
    TunnelController,
    TunnelStatusSnapshot,
)
from tunneldesk.domain.diagnostics.origin import OriginStatus
from tunneldesk.domain.tunnel.states import TunnelState
from tunneldesk.ui import strings
from tunneldesk.ui.settings.settings_dialog import SettingsDialog
from tunneldesk.ui.workers import FunctionWorker

__all__ = ["DashboardWindow"]

_REFRESH_MS = 1000


class DashboardWindow(QMainWindow):
    """Jendela dashboard: status, kontrol Start/Stop/Restart, log."""

    def __init__(
        self,
        controller: TunnelController,
        settings_store: SettingsStore,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._controller = controller
        self._settings_store = settings_store
        self._worker: FunctionWorker | None = None

        self.setWindowTitle(strings.text("app.title"))
        self._build_ui()

        self._timer = QTimer(self)
        self._timer.setInterval(_REFRESH_MS)
        self._timer.timeout.connect(self._refresh_status)
        self._timer.start()
        self._refresh_status()

    # ------------------------------------------------------------------
    # Bangun UI
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        central = QWidget(self)
        layout = QVBoxLayout(central)

        status_group = QGroupBox(strings.text("dash.group_status"), central)
        status_layout = QVBoxLayout(status_group)

        self._tunnel_label = self._row(
            status_layout, strings.text("dash.lbl_tunnel")
        )
        self._origin_label = self._row(
            status_layout, strings.text("dash.lbl_origin")
        )
        self._pid_label = self._row(status_layout, strings.text("dash.lbl_pid"))
        self._started_label = self._row(
            status_layout, strings.text("dash.lbl_started_at")
        )
        self._last_exit_label = self._row(
            status_layout, strings.text("dash.lbl_last_exit")
        )
        self._license_label = self._row(
            status_layout, strings.text("dash.lbl_license")
        )
        self._license_label.setText(strings.text("dash.license_unavailable"))
        layout.addWidget(status_group)

        problems_group = QGroupBox(strings.text("dash.group_problems"), central)
        problems_layout = QVBoxLayout(problems_group)
        self._problems_label = QLabel(
            strings.text("dash.problem_none"), problems_group
        )
        self._problems_label.setWordWrap(True)
        problems_layout.addWidget(self._problems_label)
        layout.addWidget(problems_group)

        buttons_layout = QHBoxLayout()
        self._start_button = QPushButton(strings.text("dash.btn_start"), central)
        self._stop_button = QPushButton(strings.text("dash.btn_stop"), central)
        self._restart_button = QPushButton(
            strings.text("dash.btn_restart"), central
        )
        self._origin_button = QPushButton(
            strings.text("dash.btn_check_origin"), central
        )
        self._wizard_button = QPushButton(
            strings.text("dash.btn_wizard"), central
        )
        self._settings_button = QPushButton(
            strings.text("menu.settings"), central
        )
        for button in (
            self._start_button,
            self._stop_button,
            self._restart_button,
            self._origin_button,
            self._wizard_button,
            self._settings_button,
        ):
            buttons_layout.addWidget(button)
        layout.addLayout(buttons_layout)

        log_group = QGroupBox(strings.text("dash.group_log"), central)
        log_layout = QVBoxLayout(log_group)
        self._log_view = QPlainTextEdit(log_group)
        self._log_view.setReadOnly(True)
        log_layout.addWidget(self._log_view)
        layout.addWidget(log_group)

        self._start_button.clicked.connect(self._on_start)
        self._stop_button.clicked.connect(self._on_stop)
        self._restart_button.clicked.connect(self._on_restart)
        self._origin_button.clicked.connect(self._on_check_origin)
        self._wizard_button.clicked.connect(self._on_open_wizard)
        self._settings_button.clicked.connect(self._on_open_settings)

        self.setCentralWidget(central)

    def _row(self, layout: QVBoxLayout, label_text: str) -> QLabel:
        row = QHBoxLayout()
        caption = QLabel(label_text, self)
        value = QLabel("—", self)
        row.addWidget(caption)
        row.addWidget(value, stretch=1)
        layout.addLayout(row)
        return value

    # ------------------------------------------------------------------
    # Refresh status (tanpa I/O jaringan — aman di UI thread)
    # ------------------------------------------------------------------
    def _refresh_status(self) -> None:
        snapshot = self._controller.status(probe_origin=False)
        self._tunnel_label.setText(snapshot.tunnel_state)
        self._pid_label.setText(
            str(snapshot.pid) if snapshot.pid is not None else "—"
        )
        started_at = self._controller_started_at()
        self._started_label.setText(
            datetime.fromtimestamp(started_at).strftime("%Y-%m-%d %H:%M:%S")
            if started_at is not None
            else "—"
        )
        last_exit = snapshot.last_result
        self._last_exit_label.setText(
            f"exit {last_exit.exit_code}"
            + (" (forced)" if last_exit.forced else "")
            if last_exit is not None
            else strings.text("dash.lbl_last_exit_none")
        )
        self._origin_label.setText(
            snapshot.origin.detail
            if snapshot.origin is not None
            else strings.text("dash.lbl_origin_unknown")
        )
        self._update_buttons(snapshot.tunnel_state)
        self._update_problems(snapshot)
        self._update_log()

    def _controller_started_at(self) -> float | None:
        return self._controller.started_at()

    def _update_buttons(self, state_text: str) -> None:
        busy = self._worker is not None and self._worker.is_running()
        state = TunnelState(state_text)
        self._start_button.setEnabled(
            not busy and state in (TunnelState.STOPPED, TunnelState.ERROR)
        )
        self._stop_button.setEnabled(
            not busy and state is TunnelState.RUNNING
        )
        self._restart_button.setEnabled(
            not busy and state is TunnelState.RUNNING
        )
        self._origin_button.setEnabled(not busy)
        self._settings_button.setEnabled(not busy)

    def _update_problems(self, snapshot: TunnelStatusSnapshot) -> None:
        problems: list[str] = []
        if snapshot.crashed is not None:
            problems.append(
                strings.text(
                    "dash.problem_crashed", code=snapshot.crashed.exit_code
                )
            )
        origin = snapshot.origin
        if origin is not None and origin.status in (
            OriginStatus.UNREACHABLE,
            OriginStatus.MISCONFIGURED,
        ):
            problems.append(
                strings.text("dash.problem_origin", detail=origin.detail)
            )
        self._problems_label.setText(
            "\n".join(problems)
            if problems
            else strings.text("dash.problem_none")
        )

    def _update_log(self) -> None:
        lines = self._controller.recent_output()
        if lines:
            self._log_view.setPlainText("\n".join(lines))
        elif not self._log_view.toPlainText():
            self._log_view.setPlainText(strings.text("dash.log_empty"))

    # ------------------------------------------------------------------
    # Operasi via worker (blocking → thread)
    # ------------------------------------------------------------------
    def _run_worker(self, function: Callable[[], object]) -> None:
        if self._worker is not None and self._worker.is_running():
            return
        self._worker = FunctionWorker(function, self)
        self._worker.finished.connect(lambda _result: self._on_worker_done())
        self._worker.failed.connect(self._on_worker_failed)
        self._worker.start()
        self._update_buttons(
            self._controller.status(probe_origin=False).tunnel_state
        )

    def _on_worker_done(self) -> None:
        self._worker = None
        self._refresh_status()

    def _on_worker_failed(self, message: str) -> None:
        self._worker = None
        self._refresh_status()
        self._problems_label.setText(
            strings.text("err.operation_failed", detail=message)
        )

    def _on_start(self) -> None:
        self._run_worker(self._controller.start)

    def _on_stop(self) -> None:
        self._run_worker(self._controller.stop)

    def _on_restart(self) -> None:
        self._run_worker(self._controller.restart)

    def _on_check_origin(self) -> None:
        self._run_worker(self._controller.check_origin)

    def _on_open_settings(self) -> None:
        dialog = SettingsDialog(self._settings_store, self)
        dialog.exec()
        self._refresh_status()

    def _on_open_wizard(self) -> None:
        """Buka Setup Wizard (Task 2.6) — komposisi layanan dengan
        deny-prefix direktori data AKTUAL (T-2)."""
        from tunneldesk.ui.wizard.services import build_wizard_services
        from tunneldesk.ui.wizard.wizard_dialog import SetupWizardDialog

        services = build_wizard_services(self._settings_store)
        dialog = SetupWizardDialog(services, self)
        dialog.exec()
        self._refresh_status()

    # ------------------------------------------------------------------
    # Akses untuk uji (pytest-qt)
    # ------------------------------------------------------------------
    def tunnel_status_text(self) -> str:
        return self._tunnel_label.text()

    def origin_status_text(self) -> str:
        return self._origin_label.text()

    def problems_text(self) -> str:
        return self._problems_label.text()

    def log_text(self) -> str:
        return self._log_view.toPlainText()

    def is_busy(self) -> bool:
        return self._worker is not None and self._worker.is_running()
