"""Uji dashboard pytest-qt (E-4): integrasi E-1..E-3 via fake-cloudflared.

Membuktikan PRD-01 §7.1 & §11: status tampil, tombol berfungsi, UI tidak
membeku (operasi blocking di worker thread). Tanpa data produksi.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from tunneldesk.application.settings_store import AppSettings
from tunneldesk.application.tunnel_controller import (
    TunnelController,
    TunnelRunConfig,
)
from tunneldesk.domain.diagnostics.origin import (
    OriginProbeKind,
    OriginProbeOutcome,
)
from tunneldesk.domain.tunnel.lifecycle import ProcessLifecycle
from tunneldesk.domain.tunnel.process_contracts import ProcessSpec
from tunneldesk.infrastructure.process.fake.fake import (
    SCENARIO_NORMAL,
    FakeProcessLauncher,
)
from tunneldesk.ui import strings
from tunneldesk.ui.dashboard.dashboard_window import DashboardWindow

SPEC = ProcessSpec.from_sequence(["fake-cloudflared", "tunnel", "run"])


class StaticProbe:
    """Probe palsu yang selalu mengembalikan outcome tetap."""

    def __init__(self, outcome: OriginProbeOutcome) -> None:
        self.outcome = outcome

    def probe(
        self, target: object, timeout_seconds: float
    ) -> OriginProbeOutcome:
        return self.outcome


class MemorySettingsStore:
    """Store minimal di memori untuk uji dashboard."""

    def __init__(self) -> None:
        self.saved: AppSettings | None = None

    def load(self) -> AppSettings:
        return AppSettings()

    def save(self, settings: AppSettings) -> None:
        self.saved = settings
        (Path(self._dir) / "settings.json").write_text("{}", encoding="utf-8")

    _dir: str = "."


@pytest.fixture()
def dashboard(
    qtbot: QtBot, tmp_path: Path
) -> tuple[DashboardWindow, FakeProcessLauncher]:
    launcher = FakeProcessLauncher(SCENARIO_NORMAL)
    lifecycle = ProcessLifecycle(launcher)
    config = TunnelRunConfig(
        spec=SPEC, origin_host="127.0.0.1", origin_port=18080
    )
    controller = TunnelController(config, lifecycle)
    store = MemorySettingsStore()
    store._dir = str(tmp_path)  # noqa: SLF001 — injeksi direktori uji
    window = DashboardWindow(controller, store)
    qtbot.addWidget(window)
    qtbot.waitUntil(window._refresh_status, timeout=2000)
    return window, launcher


# ---------------------------------------------------------------------------
# Tampilan awal (PRD-01 §7.1)
# ---------------------------------------------------------------------------


def test_dashboard_awal_state_stopped(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    window, _ = dashboard
    assert window.tunnel_status_text() == "STOPPED"
    assert window._start_button.isEnabled() is True
    assert window._stop_button.isEnabled() is False
    assert window._restart_button.isEnabled() is False


def test_license_label_menandakan_belum_tersedia(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    window, _ = dashboard
    assert "belum tersedia" in window._license_label.text()


def test_problems_awal_tidak_ada(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    window, _ = dashboard
    assert window.problems_text() == strings.text("dash.problem_none")


# ---------------------------------------------------------------------------
# Start / stop / restart via tombol (worker thread — UI responsif)
# ---------------------------------------------------------------------------


def test_start_via_tombol_memperbarui_status(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    window, _ = dashboard
    window._start_button.click()
    qtbot.waitUntil(
        lambda: window.tunnel_status_text() == "RUNNING", timeout=3000
    )
    assert window._stop_button.isEnabled() is True


def test_stop_via_tombol_kembali_stopped(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    window, _ = dashboard
    window._start_button.click()
    qtbot.waitUntil(
        lambda: window.tunnel_status_text() == "RUNNING", timeout=3000
    )
    window._stop_button.click()
    qtbot.waitUntil(
        lambda: window.tunnel_status_text() == "STOPPED", timeout=3000
    )


def test_restart_via_tombol(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    window, launcher = dashboard
    window._start_button.click()
    qtbot.waitUntil(
        lambda: window.tunnel_status_text() == "RUNNING", timeout=3000
    )
    window._restart_button.click()
    qtbot.waitUntil(
        lambda: len(launcher._started) == 2
        and window.tunnel_status_text() == "RUNNING",
        timeout=3000,
    )


def test_ui_tidak_membeku_saat_start_stop(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    """PRD-01 §11: tiga siklus start/stop penuh tanpa blocking UI."""
    window, _ = dashboard
    for _ in range(3):
        window._start_button.click()
        qtbot.waitUntil(
            lambda: window.tunnel_status_text() == "RUNNING", timeout=3000
        )
        window._stop_button.click()
        qtbot.waitUntil(
            lambda: window.tunnel_status_text() == "STOPPED", timeout=3000
        )
    assert window.is_busy() is False


# ---------------------------------------------------------------------------
# Origin (terpisah dari tunnel)
# ---------------------------------------------------------------------------


def test_origin_belum_diperiksa_awal(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    window, _ = dashboard
    assert (
        window.origin_status_text()
        == strings.text("dash.lbl_origin_unknown")
    )


def test_origin_diperiksa_via_tombol(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    """Probe nyata (SocketOriginProbe) tanpa server — hasil REFUSED/TIMEOUT
    (tergantung platform) keduanya bukan "belum diperiksa"."""
    window, _ = dashboard
    window._origin_button.click()
    qtbot.waitUntil(
        lambda: window.origin_status_text()
        != strings.text("dash.lbl_origin_unknown"),
        timeout=5000,
    )


def test_problems_muncul_saat_origin_unreachable(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    window, _ = dashboard
    window._probe = StaticProbe(  # noqa: SLF001 — injeksi uji
        OriginProbeOutcome(OriginProbeKind.REFUSED)
    )
    window._origin_button.click()
    qtbot.waitUntil(
        lambda: "ditolak" in window.problems_text(), timeout=3000
    )


# ---------------------------------------------------------------------------
# Log
# ---------------------------------------------------------------------------


def test_log_tampil_setelah_start(
    qtbot: QtBot, dashboard: tuple[DashboardWindow, FakeProcessLauncher]
) -> None:
    window, _ = dashboard
    window._start_button.click()
    qtbot.waitUntil(
        lambda: window.tunnel_status_text() == "RUNNING", timeout=3000
    )
    qtbot.waitUntil(
        lambda: "fake tunnel" in window.log_text(), timeout=3000
    )
