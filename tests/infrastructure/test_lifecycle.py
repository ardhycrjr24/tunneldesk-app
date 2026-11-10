"""Uji lifecycle proses (E-2) via ProcessLifecycle + fake-cloudflared.

Mencakup skenario instruksi E-2: start sukses/gagal, stop normal, stop
saat sudah berhenti, start saat berjalan, crash, graceful timeout,
forced termination, parent shutdown, child cleanup, duplicate
start/stop, dan validasi kepemilikan. Tanpa cloudflared sungguhan.
"""

from __future__ import annotations

import threading
import time

import pytest

from tunneldesk.domain.tunnel.lifecycle import (
    ProcessLifecycle,
    ProcessStartError,
)
from tunneldesk.domain.tunnel.ownership import NotOwnedProcessError
from tunneldesk.domain.tunnel.process_contracts import ProcessSpec
from tunneldesk.domain.tunnel.states import (
    InvalidTransitionError,
    TunnelState,
)
from tunneldesk.infrastructure.process.fake.fake import (
    SCENARIO_DELAYED_SHUTDOWN,
    SCENARIO_HUNG,
    SCENARIO_NORMAL,
    SCENARIO_RUNTIME_CRASH,
    SCENARIO_SPAWNS_CHILD,
    SCENARIO_STARTUP_FAILURE,
    FakeProcessLauncher,
    FakeScenario,
)

SPEC = ProcessSpec.from_sequence(["fake-cloudflared", "tunnel", "--config", "f.yml"])


def make_lifecycle(scenario: FakeScenario) -> tuple[ProcessLifecycle, FakeProcessLauncher]:
    launcher = FakeProcessLauncher(scenario)
    return ProcessLifecycle(launcher), launcher


def run_to_running(scenario: FakeScenario) -> tuple[ProcessLifecycle, FakeProcessLauncher]:
    lifecycle, launcher = make_lifecycle(scenario)
    lifecycle.start(SPEC)
    return lifecycle, launcher


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------


def test_start_berhasil_state_running_dan_kepemilikan_terdaftar() -> None:
    lifecycle, launcher = run_to_running(SCENARIO_NORMAL)
    assert lifecycle.state is TunnelState.RUNNING
    handle = launcher._started[-1]
    assert lifecycle.owned_pids() == frozenset({handle.pid_number})


def test_start_gagal_state_error_dan_start_error() -> None:
    lifecycle, _ = make_lifecycle(SCENARIO_STARTUP_FAILURE)
    with pytest.raises(ProcessStartError) as excinfo:
        lifecycle.start(SPEC)
    assert excinfo.value.exit_code == 1
    assert lifecycle.state is TunnelState.ERROR
    assert lifecycle.owned_pids() == frozenset()


def test_start_saat_berjalan_ditolak() -> None:
    lifecycle, _ = run_to_running(SCENARIO_NORMAL)
    with pytest.raises(InvalidTransitionError):
        lifecycle.start(SPEC)
    assert lifecycle.state is TunnelState.RUNNING


def test_start_duplikat_saat_running_ditolak_tanpa_spawn_baru() -> None:
    """Start ganda saat RUNNING ditolak state machine (PRD-02 §3.1)."""
    lifecycle, launcher = run_to_running(SCENARIO_NORMAL)
    with pytest.raises(InvalidTransitionError):
        lifecycle.start(SPEC)
    assert len(launcher._started) == 1  # tidak ada spawn kedua
    assert lifecycle.state is TunnelState.RUNNING


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------


def test_stop_normal_state_stopped_dan_exit_code() -> None:
    lifecycle, _ = run_to_running(SCENARIO_NORMAL)
    result = lifecycle.stop()
    assert lifecycle.state is TunnelState.STOPPED
    assert result.exit_code == 0
    assert result.forced is False
    assert lifecycle.owned_pids() == frozenset()


def test_stop_saat_sudah_stopped_idempoten() -> None:
    lifecycle, _ = run_to_running(SCENARIO_NORMAL)
    pertama = lifecycle.stop()
    kedua = lifecycle.stop()
    assert kedua is pertama
    assert lifecycle.state is TunnelState.STOPPED


def test_stop_berulang_idempoten_saat_stopping() -> None:
    lifecycle, _ = run_to_running(SCENARIO_DELAYED_SHUTDOWN)

    hasil_worker: list[object] = []

    def worker() -> None:
        hasil_worker.append(lifecycle.stop(graceful_timeout_seconds=5))

    thread = threading.Thread(target=worker)
    thread.start()
    time.sleep(0.05)  # biarkan worker memegang lock & memulai stop
    hasil_utama = lifecycle.stop(graceful_timeout_seconds=5)
    thread.join(timeout=5)
    assert lifecycle.state is TunnelState.STOPPED
    assert hasil_utama.exit_code == 0
    assert hasil_worker and getattr(hasil_worker[0], "exit_code", None) == 0


def test_graceful_timeout_memicu_forced_termination() -> None:
    lifecycle, _ = run_to_running(SCENARIO_HUNG)
    result = lifecycle.stop(graceful_timeout_seconds=0.1)
    assert result.forced is True
    assert result.exit_code == 137
    assert lifecycle.state is TunnelState.STOPPED


def test_stop_setelah_crash_menghasilkan_invalid_transition() -> None:
    """Crash detection bersifat lazy (poll_exit); setelah terdeteksi,
    state ERROR dan stop ditolak state machine."""
    lifecycle, _ = run_to_running(SCENARIO_RUNTIME_CRASH)
    time.sleep(0.3)
    assert lifecycle.poll_exit() is not None
    assert lifecycle.state is TunnelState.ERROR
    with pytest.raises(InvalidTransitionError):
        lifecycle.stop()


# ---------------------------------------------------------------------------
# Crash & exit tak terduga
# ---------------------------------------------------------------------------


def test_crash_terdeteksi_via_poll_exit() -> None:
    lifecycle, _ = run_to_running(SCENARIO_RUNTIME_CRASH)
    assert lifecycle.poll_exit() is None  # belum crash

    time.sleep(0.3)
    result = lifecycle.poll_exit()
    assert result is not None
    assert result.exit_code == 70
    assert lifecycle.state is TunnelState.ERROR


def test_poll_exit_saat_tidak_berjalan_mengembalikan_none() -> None:
    lifecycle, _ = make_lifecycle(SCENARIO_NORMAL)
    assert lifecycle.poll_exit() is None


# ---------------------------------------------------------------------------
# Kepemilikan proses
# ---------------------------------------------------------------------------


def test_stop_pid_bukan_milik_ditolak() -> None:
    lifecycle, launcher = run_to_running(SCENARIO_NORMAL)
    pid_asing = launcher._started[-1].pid_number + 999
    registry = lifecycle._ownership
    with pytest.raises(NotOwnedProcessError):
        registry.require_owned(pid_asing)
    # proses asli tetap berjalan dan tetap bisa dihentikan
    assert lifecycle.state is TunnelState.RUNNING
    lifecycle.stop()


def test_ownership_registry_validasi_pid() -> None:
    from tunneldesk.domain.tunnel.ownership import OwnershipRegistry

    registry = OwnershipRegistry()
    with pytest.raises(ValueError):
        registry.register(0)
    registry.register(123)
    assert registry.owns(123) is True
    registry.release(123)
    assert registry.owns(123) is False
    with pytest.raises(NotOwnedProcessError):
        registry.require_owned(123)


# ---------------------------------------------------------------------------
# Parent shutdown, child cleanup, siklus berulang
# ---------------------------------------------------------------------------


def test_parent_shutdown_membersihkan_proses() -> None:
    lifecycle, launcher = run_to_running(SCENARIO_NORMAL)
    handle = launcher._started[-1]
    lifecycle.cleanup_after_parent_shutdown()
    assert handle.poll() is not None  # proses mati
    assert lifecycle.owned_pids() == frozenset()


def test_parent_shutdown_setelah_selesai_tetap_amal() -> None:
    lifecycle, _ = run_to_running(SCENARIO_NORMAL)
    lifecycle.stop()
    lifecycle.cleanup_after_parent_shutdown()  # idempoten, tanpa error
    assert lifecycle.state is TunnelState.STOPPED


def test_child_process_ikut_dibersihkan() -> None:
    lifecycle, launcher = run_to_running(SCENARIO_SPAWNS_CHILD)
    handle = launcher._started[-1]
    lifecycle.stop()
    assert handle.child_was_reaped() is True
    assert lifecycle.owned_pids() == frozenset()


def test_sepuluh_siklus_bersih_tanpa_orphan() -> None:
    """Target sign-off: minimal 10 siklus start/stop bersih."""
    lifecycle, launcher = make_lifecycle(SCENARIO_NORMAL)
    for _ in range(10):
        lifecycle.start(SPEC)
        assert lifecycle.state is TunnelState.RUNNING
        result = lifecycle.stop()
        assert result.exit_code == 0 and result.forced is False
        assert lifecycle.state is TunnelState.STOPPED
    assert len(launcher._started) == 10
    assert lifecycle.owned_pids() == frozenset()
