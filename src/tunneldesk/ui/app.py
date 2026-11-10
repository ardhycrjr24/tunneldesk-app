"""Titik masuk aplikasi (E-4): bootstrap lock, settings, controller, UI.

Urutan startup (sign-off review §12 rekomendasi):
1. QApplication.
2. ``InstanceLock.acquire()`` — sebelum controller dibuat (A-13).
   Instance lain aktif → dialog kesalahan → keluar dengan kode 1.
3. Muat pengaturan (A-11) → bangun ``TunnelRunConfig`` + controller.
4. Tampilkan dashboard.

Origin **tidak diasumsikan**: bila belum tersedia (E-6 akan menyediakan
dari YAML tunnel), target kosong → status MISCONFIGURED dengan penjelasan
pada dashboard — bukan default port tersembunyi (PRD-01 §14).
"""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox

from tunneldesk.application.settings_store import (
    AppSettings,
    JsonSettingsStore,
    default_settings_dir,
)
from tunneldesk.application.single_instance import (
    InstanceAlreadyRunningError,
    InstanceLock,
)
from tunneldesk.application.tunnel_controller import (
    TunnelController,
    TunnelRunConfig,
)
from tunneldesk.domain.tunnel.lifecycle import ProcessLifecycle
from tunneldesk.domain.tunnel.process_contracts import (
    ProcessLauncher,
    ProcessSpec,
)
from tunneldesk.infrastructure.process.posix.adapter import PosixProcessLauncher
from tunneldesk.infrastructure.process.windows.adapter import (
    WindowsProcessLauncher,
)
from tunneldesk.ui import strings
from tunneldesk.ui.dashboard.dashboard_window import DashboardWindow

__all__ = ["build_controller", "create_main_window", "main"]


def _default_launcher() -> ProcessLauncher:
    if sys.platform == "win32":
        return WindowsProcessLauncher()
    return PosixProcessLauncher()


def build_controller(settings: AppSettings) -> TunnelController:
    """Bangun controller dari pengaturan (launcher sesuai platform)."""
    argv: list[str] = [
        settings.cloudflared_path or "cloudflared",
        "tunnel",
        "--config",
        settings.config_path or "config.yml",
        "run",
    ]
    config = TunnelRunConfig(
        spec=ProcessSpec.from_sequence(argv),
        origin_host=settings.origin_host,
        origin_port=settings.origin_port,
    )
    lifecycle = ProcessLifecycle(_default_launcher())
    return TunnelController(config, lifecycle)


def create_main_window(
    settings_dir: Path | None = None,
) -> tuple[InstanceLock, TunnelController, DashboardWindow]:
    """Bangun lock + controller + dashboard (dipakai main dan uji)."""
    directory = settings_dir or default_settings_dir()
    settings_store = JsonSettingsStore(directory / "settings.json")
    settings = settings_store.load()

    lock = InstanceLock(directory / "instance.lock")
    lock.acquire()  # InstanceAlreadyRunningError dilempar ke pemanggil

    controller = build_controller(settings)
    window = DashboardWindow(controller, settings_store)
    return lock, controller, window


def main(argv: list[str] | None = None) -> int:
    app = QApplication(argv or sys.argv)
    app.setApplicationName(strings.text("app.title"))
    try:
        lock, _controller, window = create_main_window()
    except InstanceAlreadyRunningError as exc:
        QMessageBox.critical(
            None,
            strings.text("app.title"),
            strings.text("app.instance_running", pid=exc.pid),
        )
        return 1
    window.show()
    exit_code = app.exec()
    lock.release()
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
