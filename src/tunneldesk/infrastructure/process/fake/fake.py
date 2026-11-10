"""Fake-cloudflared dan fake process untuk automated tests (A-14).

Simulasi berbasis waktu (lazy, tanpa thread) yang mengimplementasikan
kontrak :class:`LaunchedProcess` dengan setia pada perilaku nyata yang
relevan untuk E-2. **Tidak menggantikan** pengujian integrasi Windows
fisik dengan cloudflared asli (A-14, PRD-02 §3.1).
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field

from tunneldesk.domain.tunnel.process_contracts import (
    LaunchedProcess,
    ProcessLauncher,
    ProcessSpec,
)

__all__ = [
    "FakeScenario",
    "FakeLaunchedProcess",
    "FakeProcessLauncher",
    "SCENARIO_NORMAL",
    "SCENARIO_STARTUP_FAILURE",
    "SCENARIO_RUNTIME_CRASH",
    "SCENARIO_HUNG",
    "SCENARIO_DELAYED_SHUTDOWN",
]

_FORCE_EXIT_CODE = 137  # konvensi SIGKILL-like


@dataclass(frozen=True)
class FakeScenario:
    """Skenario perilaku fake process (semua waktu dalam detik)."""

    name: str = "normal"
    startup_delay_s: float = 0.0
    #: tidak None → proses mati seketika saat launch (start gagal).
    startup_exit_code: int | None = None
    #: tidak None → crash setelah N detik berjalan.
    runtime_exit_after_s: float | None = None
    runtime_exit_code: int = 70
    shutdown_delay_s: float = 0.0
    #: graceful stop diabaikan; hanya force kill yang mematikan.
    hung: bool = False
    #: False → bahkan force kill tidak mematikan (hung total).
    force_kill_works: bool = True
    exits_with_code: int = 0
    spawns_child: bool = False
    #: teks keluaran kustom (mis. simulasi `cloudflared --version`).
    output_text: str = ""


SCENARIO_NORMAL = FakeScenario(name="normal")
SCENARIO_STARTUP_FAILURE = FakeScenario(
    name="startup-failure", startup_exit_code=1
)
SCENARIO_RUNTIME_CRASH = FakeScenario(
    name="runtime-crash", runtime_exit_after_s=0.2, runtime_exit_code=70
)
SCENARIO_HUNG = FakeScenario(name="hung", hung=True)
SCENARIO_DELAYED_SHUTDOWN = FakeScenario(
    name="delayed-shutdown", shutdown_delay_s=0.3
)


@dataclass
class FakeLaunchedProcess(LaunchedProcess):
    """Implementasi kontrak proses berbasis skenario + monotonic clock."""

    scenario: FakeScenario
    pid_number: int
    _started_at: float = field(default_factory=time.monotonic)
    _stop_requested_at: float | None = None
    _forced: bool = False
    _exit_code: int | None = None
    _child_reaped: bool = False

    # -- kontrak ------------------------------------------------------
    def pid(self) -> int:
        return self.pid_number

    def poll(self) -> int | None:
        now = time.monotonic()
        if self._exit_code is not None:
            return self._exit_code
        if self.scenario.startup_exit_code is not None:
            self._exit_code = self.scenario.startup_exit_code
            return self._exit_code
        runtime_after = self.scenario.runtime_exit_after_s
        if (
            runtime_after is not None
            and now - self._started_at >= runtime_after
        ):
            self._exit_code = self.scenario.runtime_exit_code
            return self._exit_code
        if self._stop_requested_at is not None and not self.scenario.hung:
            deadline = self._stop_requested_at + self.scenario.shutdown_delay_s
            if now >= deadline:
                self._exit_code = self.scenario.exits_with_code
                self._child_reaped = self.scenario.spawns_child
                return self._exit_code
        if self._forced and self.scenario.force_kill_works:
            self._exit_code = _FORCE_EXIT_CODE
            self._child_reaped = self.scenario.spawns_child
            return self._exit_code
        return None

    def graceful_stop(self) -> None:
        if self._stop_requested_at is None:
            self._stop_requested_at = time.monotonic()

    def force_kill(self) -> None:
        self._forced = True

    def wait(self, timeout_seconds: float) -> int | None:
        deadline = time.monotonic() + timeout_seconds
        while True:
            code = self.poll()
            if code is not None:
                return code
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.02)

    def output_lines(self) -> tuple[str, ...]:
        if self.scenario.output_text:
            return tuple(self.scenario.output_text.splitlines())
        return (
            f"INF fake tunnel mulai pid={self.pid_number}",
            "INF DUMMY-TOKEN-0123456789abcdef-FOR-REDACTION-TESTS-ONLY",
        )

    # -- ekstra untuk pengujian ---------------------------------------
    def child_was_reaped(self) -> bool:
        """True bila child simulasi ikut dibersihkan saat proses berakhir."""
        return self._child_reaped

    def stop_requested(self) -> bool:
        return self._stop_requested_at is not None


class FakeProcessLauncher(ProcessLauncher):
    """Launcher fake — melahirkan :class:`FakeLaunchedProcess` per skenario."""

    def __init__(self, scenario: FakeScenario) -> None:
        self.scenario = scenario
        self._started: list[FakeLaunchedProcess] = []
        self._counter = itertools.count(4200)

    def launch(self, spec: ProcessSpec) -> LaunchedProcess:
        del spec  # fake tidak mengeksekusi argv apa pun
        process = FakeLaunchedProcess(
            scenario=self.scenario,
            pid_number=next(self._counter),
        )
        self._started.append(process)
        return process


# Preset tambahan yang sering dipakai uji
SCENARIO_SPAWNS_CHILD = FakeScenario(name="spawns-child", spawns_child=True)
