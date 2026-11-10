"""Uji skenario fake-cloudflared (A-14) — deterministik, tanpa sleep panjang."""

from __future__ import annotations

import time

from tunneldesk.domain.tunnel.process_contracts import ProcessSpec
from tunneldesk.infrastructure.process.fake.fake import (
    SCENARIO_DELAYED_SHUTDOWN,
    SCENARIO_HUNG,
    SCENARIO_NORMAL,
    SCENARIO_RUNTIME_CRASH,
    SCENARIO_SPAWNS_CHILD,
    SCENARIO_STARTUP_FAILURE,
    FakeProcessLauncher,
)

SPEC = ProcessSpec.from_sequence(["fake-cloudflared"])


def test_normal_startup_dan_shutdown() -> None:
    launcher = FakeProcessLauncher(SCENARIO_NORMAL)
    process = launcher.launch(SPEC)
    assert process.poll() is None
    process.graceful_stop()
    assert process.wait(2.0) == 0


def test_startup_failure_exit_seketika() -> None:
    launcher = FakeProcessLauncher(SCENARIO_STARTUP_FAILURE)
    process = launcher.launch(SPEC)
    assert process.poll() == 1


def test_runtime_crash_dengan_exit_code_tak_terduga() -> None:
    launcher = FakeProcessLauncher(SCENARIO_RUNTIME_CRASH)
    process = launcher.launch(SPEC)
    assert process.poll() is None  # masih hidup sebelum deadline
    assert process.wait(2.0) == 70  # exit code tak terduga


def test_delayed_shutdown_hormati_waktu() -> None:
    launcher = FakeProcessLauncher(SCENARIO_DELAYED_SHUTDOWN)
    process = launcher.launch(SPEC)
    process.graceful_stop()
    time.sleep(0.1)
    assert process.poll() is None  # masih berjalan dalam masa shutdown
    assert process.wait(2.0) == 0


def test_hung_mengabaikan_graceful_tapi_taat_force() -> None:
    launcher = FakeProcessLauncher(SCENARIO_HUNG)
    process = launcher.launch(SPEC)
    process.graceful_stop()
    assert process.wait(0.3) is None  # hung: graceful diabaikan
    process.force_kill()
    assert process.wait(1.0) == 137


def test_repeated_termination_aman() -> None:
    launcher = FakeProcessLauncher(SCENARIO_NORMAL)
    process = launcher.launch(SPEC)
    process.graceful_stop()
    process.graceful_stop()
    process.graceful_stop()
    assert process.wait(2.0) == 0
    process.force_kill()  # setelah mati — harus tanpa efek samping
    assert process.poll() == 0


def test_child_cleanup_flag() -> None:
    launcher = FakeProcessLauncher(SCENARIO_SPAWNS_CHILD)
    process = launcher.launch(SPEC)
    assert process.child_was_reaped() is False
    process.force_kill()
    assert process.wait(1.0) == 137
    assert process.child_was_reaped() is True


def test_output_lines_memuat_teredaksi_dummy_token() -> None:
    launcher = FakeProcessLauncher(SCENARIO_NORMAL)
    process = launcher.launch(SPEC)
    lines = process.output_lines()
    assert any("fake tunnel" in line for line in lines)
    # token dummy pada output fake berada di baris yang harusnya
    # tersaring ketika melewati RedactionEngine (diuji di test_engine).
    assert any("DUMMY-TOKEN" in line for line in lines)
