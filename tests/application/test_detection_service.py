"""Uji DetectionService (E-5): orkestrasi, mode, keamanan, fail-safe."""

from __future__ import annotations

from pathlib import Path

from tunneldesk.application.detection_service import DetectionService
from tunneldesk.domain.tunnel.detection import (
    ConfigCandidate,
    DetectionConfidence,
    DetectionSource,
    ExecutableFinding,
    InstallMode,
    ModeIndicator,
)

DUMMY_TOKEN = "DUMMY-DETECTION-TOKEN-0123456789-REDACTION-TEST"


class StubLauncher:
    """Launcher stub dengan output/exit/timeout terkonfigurasi."""

    def __init__(
        self,
        output: str = "",
        exit_code: int | None = 0,
        timeout: bool = False,
        fail_launch: bool = False,
    ) -> None:
        self.output = output
        self.exit_code = exit_code
        self.timeout = timeout
        self.fail_launch = fail_launch

    def launch(self, spec: object) -> object:
        if self.fail_launch:
            raise PermissionError(13, "akses ditolak")

        class Stub:
            pass

        stub = Stub()
        stub.pid = lambda: 4242
        stub.poll = lambda: self.exit_code
        stub.graceful_stop = lambda: None
        stub.force_kill = lambda: None

        def wait(timeout_seconds: float) -> int | None:
            return None if self.timeout else self.exit_code

        stub.wait = wait
        stub.output_lines = lambda: tuple(self.output.splitlines())
        return stub


class StubConfigLocator:
    def __init__(self, candidates: tuple) -> None:
        self._candidates = candidates

    def locate(self) -> tuple:
        return self._candidates


class StubServiceProbe:
    def __init__(self, indicator: ModeIndicator | None) -> None:
        self._indicator = indicator

    def probe(self) -> ModeIndicator | None:
        return self._indicator


# ---------------------------------------------------------------------------
# Skenario gabungan
# ---------------------------------------------------------------------------


def test_semua_komponen_ditemukan_confirmed(tmp_path: Path) -> None:
    config = tmp_path / "config.yml"
    config.write_text("tunnel: dummy\n", encoding="utf-8")
    service = ModeIndicator(
        InstallMode.SERVICE, "sc query RUNNING", definitive=True
    )
    service_probe = StubServiceProbe(service)
    exe_finding = ExecutableFinding(
        Path("/usr/local/bin/cloudflared"), DetectionSource.PATH, "2024.8.3"
    )

    class ExeLocator:
        def locate(self) -> tuple:
            return (exe_finding,)

    class ConfigLocator:
        def locate(self) -> tuple:
            return (
                ConfigCandidate(config, DetectionSource.COMMON_LOCATION),
            )

    service = DetectionService(
        StubLauncher(),  # tidak dipakai — semua locator stub
        cloudflared_locator=ExeLocator(),  # type: ignore[arg-type]
        config_locator=ConfigLocator(),  # type: ignore[arg-type]
        service_probe=service_probe,  # type: ignore[arg-type]
    )
    report = service.detect()
    assert report.has_executable
    assert report.mode is InstallMode.SERVICE  # service menang (definitif)
    assert report.mode_certain is True
    assert report.confidence is DetectionConfidence.CONFIRMED
    assert DetectionSource.SERVICE_QUERY in report.sources
    assert DetectionSource.PATH in report.sources
    assert DetectionSource.COMMON_LOCATION in report.sources


def test_exe_saja_token_tidak_pasti() -> None:
    service = DetectionService(
        StubLauncher(),
        cloudflared_locator=type(
            "L",
            (),
            {
                "locate": lambda self: (
                    ExecutableFinding(
                        Path("/usr/bin/cloudflared"),
                        DetectionSource.PATH,
                        "2024.8.3",
                    ),
                )
            },
        )(),  # type: ignore[arg-type]
        config_locator=StubConfigLocator(()),  # type: ignore[arg-type]
        service_probe=StubServiceProbe(None),  # type: ignore[arg-type]
    )
    report = service.detect()
    assert report.mode is InstallMode.TOKEN
    assert report.mode_certain is False
    assert report.confidence is DetectionConfidence.PARTIAL
    assert any("di luar kendali" in e for e in report.explanations)


def test_tidak_ditemukan_akanaman_dijelaskan() -> None:
    service = DetectionService(
        StubLauncher(),
        cloudflared_locator=type("L", (), {"locate": lambda self: ()})(),  # type: ignore[arg-type]
        config_locator=StubConfigLocator(()),  # type: ignore[arg-type]
        service_probe=StubServiceProbe(None),  # type: ignore[arg-type]
    )
    report = service.detect()
    assert report.has_executable is False
    assert report.mode is InstallMode.UNKNOWN
    assert report.confidence is DetectionConfidence.UNKNOWN
    assert any("tidak ditemukan" in e for e in report.explanations)


# ---------------------------------------------------------------------------
# Fail-safe komponen
# ---------------------------------------------------------------------------


class MeledakLocator:
    def locate(self) -> tuple:
        raise RuntimeError("simulasi kegagalan locator")


def test_locator_gagal_tidak_melempar_exception() -> None:
    service = DetectionService(
        StubLauncher(),
        cloudflared_locator=MeledakLocator(),  # type: ignore[arg-type]
        config_locator=MeledakLocator(),  # type: ignore[arg-type]
        service_probe=StubServiceProbe(None),  # type: ignore[arg-type]
    )
    report = service.detect()  # tanpa exception
    assert report.has_executable is False
    assert any("gagal" in e for e in report.explanations)


# ---------------------------------------------------------------------------
# Keamanan — secret tidak pernah lolos (D-18)
# ---------------------------------------------------------------------------


def test_output_versi_dengan_token_tidak_lolos(tmp_path: Path) -> None:
    service = DetectionService(
        StubLauncher(
            output=f"cloudflared version 2024.8.3 token={DUMMY_TOKEN}"
        ),
        cloudflared_locator=type(
            "L",
            (),
            {
                "locate": lambda self: (
                    ExecutableFinding(
                        Path("/usr/bin/cloudflared"),
                        DetectionSource.PATH,
                        "2024.8.3",
                    ),
                )
            },
        )(),  # type: ignore[arg-type]
        config_locator=StubConfigLocator(()),  # type: ignore[arg-type]
        service_probe=StubServiceProbe(None),  # type: ignore[arg-type]
    )
    service.register_secret(DUMMY_TOKEN, "tunnel_token")
    report = service.detect()
    teks = (
        "\n".join(report.explanations)
        + "\n"
        + (report.best_executable.version or "")  # type: ignore[union-attr]
        + "\n".join(f.version or "" for f in report.executables)
    )
    assert DUMMY_TOKEN not in teks


def test_read_only_tidak_ada_file_diubah(tmp_path: Path) -> None:
    config = tmp_path / "config.yml"
    config.write_text("tunnel: dummy\n", encoding="utf-8")
    sebelum = config.read_bytes()

    service = DetectionService(
        StubLauncher(),
        cloudflared_locator=type("L", (), {"locate": lambda self: ()})(),  # type: ignore[arg-type]
        config_locator=type(
            "C",
            (),
            {"locate": lambda self: (ConfigCandidate(config, DetectionSource.COMMON_LOCATION),)},
        )(),  # type: ignore[arg-type]
        service_probe=StubServiceProbe(None),  # type: ignore[arg-type]
    )
    service.detect()
    service.detect()
    assert config.read_bytes() == sebelum
