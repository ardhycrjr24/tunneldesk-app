"""Uji state machine proses tunnel (E-1, PRD-01 §8).

Mencakup: state awal, seluruh transisi valid, seluruh penolakan invalid,
idempotensi, determinisme, dan kontrak pengecualian.
"""

from __future__ import annotations

import pytest

from tunneldesk.domain.tunnel.state_machine import (
    RESTING_STATES,
    TunnelStateMachine,
)
from tunneldesk.domain.tunnel.states import (
    TRANSITIONS,
    InvalidTransitionError,
    TunnelEvent,
    TunnelState,
)

# ---------------------------------------------------------------------------
# State awal
# ---------------------------------------------------------------------------


def test_state_awal_adalah_stopped() -> None:
    machine = TunnelStateMachine()
    assert machine.state is TunnelState.STOPPED
    assert TunnelStateMachine.INITIAL_STATE is TunnelState.STOPPED


def test_state_awal_kustom_harus_tunnel_state() -> None:
    assert TunnelStateMachine(initial=TunnelState.ERROR).state is (
        TunnelState.ERROR
    )
    with pytest.raises(TypeError):
        TunnelStateMachine(initial="STOPPED")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Seluruh transisi valid dalam tabel — deterministik
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("start_state", "event", "expected"),
    sorted(
        ((state, event, target) for (state, event), target in TRANSITIONS.items()),
        key=lambda item: (item[0].value, item[1].value),
    ),
)
def test_semua_transisi_valid_sesuai_tabel(
    start_state: TunnelState,
    event: TunnelEvent,
    expected: TunnelState,
) -> None:
    machine = TunnelStateMachine(initial=start_state)
    assert machine.can(event) is True
    assert machine.transition(event) is expected
    assert machine.state is expected


def test_transisi_deterministik_input_sama_hasil_sama() -> None:
    hasil: list[TunnelState] = []
    for _ in range(5):
        machine = TunnelStateMachine()
        machine.transition(TunnelEvent.START)
        hasil.append(machine.transition(TunnelEvent.STARTED))
    assert hasil == [TunnelState.RUNNING] * 5


def test_siklus_lengkap_start_hingga_stop() -> None:
    machine = TunnelStateMachine()
    assert machine.transition(TunnelEvent.START) is TunnelState.STARTING
    assert machine.transition(TunnelEvent.STARTED) is TunnelState.RUNNING
    assert machine.transition(TunnelEvent.STOP) is TunnelState.STOPPING
    assert machine.transition(TunnelEvent.EXITED) is TunnelState.STOPPED


def test_siklus_gagal_start_dan_recovery() -> None:
    machine = TunnelStateMachine()
    machine.transition(TunnelEvent.START)
    assert machine.transition(TunnelEvent.START_FAILED) is TunnelState.ERROR
    # ERROR boleh start ulang atau direset
    assert machine.can(TunnelEvent.START) is True
    assert machine.can(TunnelEvent.RESET) is True
    assert machine.transition(TunnelEvent.RESET) is TunnelState.STOPPED


def test_crash_saats_running_menghasilkan_error() -> None:
    machine = TunnelStateMachine()
    machine.transition(TunnelEvent.START)
    machine.transition(TunnelEvent.STARTED)
    assert machine.transition(TunnelEvent.EXITED) is TunnelState.ERROR


def test_exit_saat_starting_diakui_gagal_start() -> None:
    machine = TunnelStateMachine()
    machine.transition(TunnelEvent.START)
    assert machine.transition(TunnelEvent.EXITED) is TunnelState.ERROR


# ---------------------------------------------------------------------------
# Idempotensi permintaan berulang (PRD-02 §3.1: tanpa proses ganda)
# ---------------------------------------------------------------------------


def test_start_berulang_idempoten_saats_starting() -> None:
    machine = TunnelStateMachine()
    machine.transition(TunnelEvent.START)
    assert machine.transition(TunnelEvent.START) is TunnelState.STARTING
    assert machine.state is TunnelState.STARTING


def test_stop_berulang_idempoten_saats_stopping() -> None:
    machine = TunnelStateMachine()
    machine.transition(TunnelEvent.START)
    machine.transition(TunnelEvent.STARTED)
    machine.transition(TunnelEvent.STOP)
    assert machine.transition(TunnelEvent.STOP) is TunnelState.STOPPING
    assert machine.state is TunnelState.STOPPING


# ---------------------------------------------------------------------------
# Penolakan transisi tidak valid — lengkap per (state, event) di luar tabel
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("start_state", "event"),
    [
        (state, event)
        for state in TunnelState
        for event in TunnelEvent
        if (state, event) not in TRANSITIONS
    ],
)
def test_transisi_invalid_ditolak_tanpa_mengubah_state(
    start_state: TunnelState,
    event: TunnelEvent,
) -> None:
    machine = TunnelStateMachine(initial=start_state)
    assert machine.can(event) is False
    with pytest.raises(InvalidTransitionError) as excinfo:
        machine.transition(event)
    assert excinfo.value.current is start_state
    assert excinfo.value.event is event
    # state tidak berubah setelah penolakan (deterministik)
    assert machine.state is start_state


def test_invalid_transition_error_berisi_konteks() -> None:
    error = InvalidTransitionError(TunnelState.RUNNING, TunnelEvent.START)
    assert "RUNNING" in str(error)
    assert "START" in str(error)


def test_allowed_events_konsisten_dengan_can() -> None:
    for state in TunnelState:
        machine = TunnelStateMachine(initial=state)
        allowed = machine.allowed_events()
        for event in TunnelEvent:
            assert machine.can(event) == (event in allowed)


def test_tipe_event_selain_enum_ditolak() -> None:
    machine = TunnelStateMachine()
    with pytest.raises(TypeError):
        machine.can("START")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        machine.transition("START")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# State beristirahat
# ---------------------------------------------------------------------------


def test_resting_states_adalah_stopped_dan_error() -> None:
    assert RESTING_STATES == frozenset(
        {TunnelState.STOPPED, TunnelState.ERROR}
    )
    for state in TunnelState:
        assert TunnelStateMachine.is_resting(state) is (
            state in (TunnelState.STOPPED, TunnelState.ERROR)
        )
