"""State machine proses tunnel — sumber tunggal transisi status (PRD-01 §8).

Kontrak publik:
- :class:`TunnelStateMachine` murni dan deterministik: tanpa I/O, tanpa
  waktu, tanpa threading. Adapter (E-2) memancarkan :class:`TunnelEvent`,
  application membaca ``state`` untuk UI (E-4).
- Transisi tidak valid menolak dengan :class:`InvalidTransitionError` dan
  **tidak mengubah** state.
- State awal: ``STOPPED``. Tidak ada terminal abadi — STOPPED dan ERROR
  adalah state "beristirahat" yang selalu dapat start ulang (manajer
  proses, bukan job sekali jalan); ``is_resting()`` menandainya.
"""

from __future__ import annotations

from .states import (
    TRANSITIONS,
    InvalidTransitionError,
    TunnelEvent,
    TunnelState,
)

__all__ = [
    "TunnelStateMachine",
    "InvalidTransitionError",
    "TunnelEvent",
    "TunnelState",
    "RESTING_STATES",
]

#: State tempat proses tidak berjalan dan aplikasi beristirahat.
RESTING_STATES: frozenset[TunnelState] = frozenset(
    {TunnelState.STOPPED, TunnelState.ERROR}
)


class TunnelStateMachine:
    """Mesin status deterministik untuk satu proses tunnel.

    Contoh::

        machine = TunnelStateMachine()
        machine.transition(TunnelEvent.START)    # -> STARTING
        machine.transition(TunnelEvent.STARTED)  # -> RUNNING
    """

    INITIAL_STATE = TunnelState.STOPPED

    def __init__(self, initial: TunnelState = TunnelState.STOPPED) -> None:
        if not isinstance(initial, TunnelState):
            raise TypeError("initial harus TunnelState")
        self._state: TunnelState = initial

    @property
    def state(self) -> TunnelState:
        """State saat ini (tidak pernah berubah tanpa transisi valid)."""
        return self._state

    def can(self, event: TunnelEvent) -> bool:
        """True bila ``event`` valid untuk state saat ini."""
        if not isinstance(event, TunnelEvent):
            raise TypeError("event harus TunnelEvent")
        return (self._state, event) in TRANSITIONS

    def allowed_events(self) -> tuple[TunnelEvent, ...]:
        """Event yang valid untuk state saat ini (urut definisi enum)."""
        allowed = [
            event
            for state, event in TRANSITIONS
            if state is self._state
        ]
        # urutkan sesuai urutan definisi TunnelEvent agar deterministik
        order = {event: index for index, event in enumerate(TunnelEvent)}
        return tuple(sorted(set(allowed), key=order.__getitem__))

    def transition(self, event: TunnelEvent) -> TunnelState:
        """Terapkan ``event`` dan kembalikan state baru.

        Menaikkan :class:`InvalidTransitionError` tanpa mengubah state
        bila transisi tidak valid.
        """
        if not isinstance(event, TunnelEvent):
            raise TypeError("event harus TunnelEvent")
        try:
            self._state = TRANSITIONS[(self._state, event)]
        except KeyError:
            raise InvalidTransitionError(self._state, event) from None
        return self._state

    @staticmethod
    def is_resting(state: TunnelState) -> bool:
        """True bila ``state`` adalah state beristirahat (STOPPED/ERROR)."""
        return state in RESTING_STATES
