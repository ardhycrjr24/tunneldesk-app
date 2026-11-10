"""Uji TunnelController (E-3): integrasi E-1 + E-2 + origin detection.

Semua proses memakai fake-cloudflared (A-14); origin memakai probe
palsu/nyata terhadap socket lokal. Tanpa data produksi.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from tunneldesk.application.tunnel_controller import (
    TunnelController,
    TunnelRunConfig,
)
from tunneldesk.domain.diagnostics.origin import (
    OriginProbeKind,
    OriginProbeOutcome,
    OriginStatus,
)
from tunneldesk.domain.tunnel.lifecycle import ProcessLifecycle
from tunneldesk.domain.tunnel.process_contracts import ProcessSpec
from tunneldesk.domain.tunnel.states import TunnelState
from tunneldesk.infrastructure.process.fake.fake import (
    SCENARIO_NORMAL,
    SCENARIO_RUNTIME_CRASH,
    SCENARIO_STARTUP_FAILURE,
    FakeProcessLauncher,
)

SPEC = ProcessSpec.from_sequence(["fake-cloudflared", "tunnel", "--config", "f.yml"])

DUMMY_TOKEN = "DUMMY-CTRL-TOKEN-0123456789-REDACTION-TEST"


class FakeProbe:
    """Probe palsu — mengembalikan outcome yang ditentukan uji."""

    def __init__(self, outcome: OriginProbeOutcome) -> None:
        self.outcome = outcome
        self.calls = 0

    def probe(
        self, target: object, timeout_seconds: float
    ) -> OriginProbeOutcome:
        self.calls += 1
        return self.outcome


def make_controller(
    scenario: object = SCENARIO_NORMAL,
    probe_outcome: OriginProbeOutcome | None = None,
    **config_overrides: object,
) -> tuple[TunnelController, ProcessLifecycle, FakeProcessLauncher]:
    launcher = FakeProcessLauncher(scenario)  # type: ignore[arg-type]
    lifecycle = ProcessLifecycle(launcher)
    config_kwargs: dict[str, object] = {
        "spec": SPEC,
        "origin_host": "127.0.0.1",
        "origin_port": 18080,
    }
    config_kwargs.update(config_overrides)
    config = TunnelRunConfig(**config_kwargs)  # type: ignore[arg-type]
    probe = FakeProbe(
        probe_outcome
        or OriginProbeOutcome(OriginProbeKind.REACHABLE, http_status=200)
    )
    controller = TunnelController(config, lifecycle, probe=probe)
    return controller, lifecycle, launcher


# ---------------------------------------------------------------------------
# Start / stop / restart
# ---------------------------------------------------------------------------


def test_start_mengintegrasikan_lifecycle_dan_state() -> None:
    controller, lifecycle, _ = make_controller()
    controller.start()
    assert lifecycle.state is TunnelState.RUNNING
    snapshot = controller.status()
    assert snapshot.tunnel_state == "RUNNING"
    assert snapshot.pid is not None
    controller.stop()
    assert lifecycle.state is TunnelState.STOPPED


def test_restart_adalah_komposisi_stop_start() -> None:
    controller, lifecycle, launcher = make_controller()
    controller.start()
    controller.restart()
    assert lifecycle.state is TunnelState.RUNNING
    assert len(launcher._started) == 2  # dua proses berbeda, tanpa orphan


def test_startup_failure_pesan_tanpa_rahasia() -> None:
    controller, lifecycle, _ = make_controller(
        scenario=SCENARIO_STARTUP_FAILURE
    )
    with pytest.raises(RuntimeError) as excinfo:
        controller.start()
    assert lifecycle.state is TunnelState.ERROR
    # pesan aman: hanya exit code, tanpa argv mentah
    assert "exit code 1" in str(excinfo.value)
    assert "fake-cloudflared" not in str(excinfo.value)


def test_runtime_crash_terdeteksi_dan_state_error() -> None:
    controller, lifecycle, _ = make_controller(
        scenario=SCENARIO_RUNTIME_CRASH
    )
    controller.start()
    import time

    time.sleep(0.3)
    snapshot = controller.status()
    assert snapshot.crashed is not None
    assert snapshot.crashed.exit_code == 70
    assert snapshot.tunnel_state == "ERROR"
    assert lifecycle.state is TunnelState.ERROR


def test_operasi_berulang_aman_dan_deterministik() -> None:
    controller, lifecycle, _ = make_controller()
    for _ in range(5):
        controller.start()
        assert lifecycle.state is TunnelState.RUNNING
        controller.stop()
        assert lifecycle.state is TunnelState.STOPPED


def test_stop_melindungi_dari_pid_bukan_milik() -> None:
    controller, lifecycle, _ = make_controller()
    controller.start()
    # pid asing dimasukkan manual ke registri via jalur internal — guard
    # require_owned tetap menolak pid yang tidak terdaftar
    from tunneldesk.domain.tunnel.ownership import NotOwnedProcessError

    with pytest.raises(NotOwnedProcessError):
        lifecycle._ownership.require_owned(999999999)
    controller.stop()


# ---------------------------------------------------------------------------
# Origin detection — terpisah dari status tunnel
# ---------------------------------------------------------------------------


def test_origin_sehat_tidak_mengubah_status_tunnel() -> None:
    controller, lifecycle, _ = make_controller(
        probe_outcome=OriginProbeOutcome(
            OriginProbeKind.REACHABLE, http_status=200
        )
    )
    controller.start()
    result = controller.check_origin()
    assert result.status is OriginStatus.HEALTHY
    assert result.http_status == 200
    # tunnel tetap RUNNING — origin bukan bagian dari state tunnel
    assert lifecycle.state is TunnelState.RUNNING


def test_origin_refused_saats_tunnel_running() -> None:
    controller, lifecycle, _ = make_controller(
        probe_outcome=OriginProbeOutcome(OriginProbeKind.REFUSED)
    )
    controller.start()
    result = controller.check_origin()
    assert result.status is OriginStatus.UNREACHABLE
    assert lifecycle.state is TunnelState.RUNNING  # tunnel tetap dianggap jalan


def test_origin_timeout_hasil_belum_pasti() -> None:
    controller, _, _ = make_controller(
        probe_outcome=OriginProbeOutcome(OriginProbeKind.TIMEOUT)
    )
    result = controller.check_origin()
    assert result.status is OriginStatus.UNREACHABLE
    assert "belum dapat dipastikan" in result.detail


def test_origin_error_menghasilkan_unknown() -> None:
    controller, _, _ = make_controller(
        probe_outcome=OriginProbeOutcome(
            OriginProbeKind.ERROR, detail="dns gagal"
        )
    )
    result = controller.check_origin()
    assert result.status is OriginStatus.UNKNOWN
    assert "dns gagal" in result.detail


def test_origin_misconfigured_port_di_luar_rentang() -> None:
    controller, _, _ = make_controller(origin_port=99999)
    result = controller.check_origin()
    assert result.status is OriginStatus.MISCONFIGURED
    assert "1-65535" in result.detail


def test_origin_misconfigured_host_kosong() -> None:
    controller, _, _ = make_controller(origin_host="  ")
    result = controller.check_origin()
    assert result.status is OriginStatus.MISCONFIGURED
    assert result.detail == "host origin kosong"


def test_origin_tidak_diprobe_bila_tidak_diminta() -> None:
    controller, _, _ = make_controller()
    snapshot = controller.status(probe_origin=False)
    assert snapshot.origin is None  # tanpa I/O jaringan


def test_origin_probe_port_contract_tidak_melempar() -> None:
    """Probe port kontraknya tak melempar — error → UNKNOWN."""

    class MeledakProbe:
        def probe(self, target: object, timeout_seconds: float) -> OriginProbeOutcome:
            raise RuntimeError("koneksi meledak")

    controller, _, _ = make_controller()
    controller._probe = MeledakProbe()  # noqa: SLF001 — injeksi uji
    result = controller.check_origin()
    assert result.status is OriginStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Secret handling (D-18)
# ---------------------------------------------------------------------------


def test_sekrete_terdaftar_tidak_lolos_di_pesan_status() -> None:
    controller, _, _ = make_controller(
        probe_outcome=OriginProbeOutcome(
            OriginProbeKind.ERROR, detail=f"trace: {DUMMY_TOKEN}"
        )
    )
    controller.register_secret(DUMMY_TOKEN, "api_token")
    result = controller.check_origin()
    assert DUMMY_TOKEN not in result.detail
    assert "REDACTED:api_token" in result.detail


def test_redacted_repr_spec_tanpa_token() -> None:
    spec = ProcessSpec.from_sequence(
        ["cloudflared", "tunnel", "run", "--token", DUMMY_TOKEN]
    )
    controller, _, _ = make_controller()
    controller.register_secret(DUMMY_TOKEN, "tunnel_token")
    teks = spec.redacted_repr()
    assert DUMMY_TOKEN not in teks


def test_config_run_immutable() -> None:
    config = TunnelRunConfig(spec=SPEC, origin_host="h", origin_port=1)
    with pytest.raises(AttributeError):  # FrozenInstanceError
        config.origin_port = 2  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------


def test_shutdown_cleanup_idempoten() -> None:
    controller, lifecycle, _ = make_controller()
    controller.start()
    controller.shutdown()
    assert lifecycle.state is TunnelState.STOPPED
    controller.shutdown()  # idempoten
    assert lifecycle.owned_pids() == frozenset()


def test_status_snapshot_setelah_reconfig_scenario() -> None:
    """replace() pada konfigurasi frozen tidak mengubah controller aktif."""
    controller, _, _ = make_controller()
    config_baru = replace(controller._config, origin_port=19090)  # noqa: SLF001
    assert config_baru.origin_port == 19090
    assert controller._config.origin_port == 18080  # noqa: SLF001
