"""Uji CloudflaredLocator (E-5) — direktori sintetis, tanpa sistem nyata."""

from __future__ import annotations

from pathlib import Path

import pytest

from tunneldesk.domain.tunnel.detection import DetectionSource
from tunneldesk.domain.tunnel.process_contracts import ProcessSpec
from tunneldesk.infrastructure.detection.cloudflared_locator import (
    CloudflaredLocator,
)
from tunneldesk.infrastructure.process.fake.fake import (
    FakeProcessLauncher,
    FakeScenario,
)


def make_executable(directory: Path, name: str = "cloudflared") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    exe = directory / name
    exe.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    if sys.platform != "win32":
        exe.chmod(0o755)
    return exe


import sys  # noqa: E402


class StubLauncher:
    """Launcher stub untuk probe versi — output/exit dikonfigurasi."""

    def __init__(
        self,
        output: str = "cloudflared version 2024.8.3",
        exit_code: int | None = 0,
        timeout: bool = False,
        fail_launch: bool = False,
    ) -> None:
        self.output = output
        self.exit_code = exit_code
        self.timeout = timeout
        self.fail_launch = fail_launch
        self.launched: list[list[str]] = []

    def launch(self, spec: object) -> object:
        if self.fail_launch:
            raise PermissionError(13, "akses ditolak")
        argv = list(getattr(spec, "argv", []))
        self.launched.append(argv)
        assert "--version" in argv, "probe versi wajib memakai --version"
        assert "--version" == argv[-1], "argumen list: --version di akhir"

        class Stub:
            pass

        stub = Stub()
        stub.pid = lambda: 4242
        stub.poll = lambda: self.exit_code
        stub.graceful_stop = lambda: None
        stub.force_kill = lambda: None

        def wait(timeout_seconds: float) -> int | None:
            if self.timeout:
                return None
            return self.exit_code

        stub.wait = wait
        stub.output_lines = lambda: tuple(self.output.splitlines())
        return stub


# ---------------------------------------------------------------------------
# Skenario instruksi E-5
# ---------------------------------------------------------------------------


def test_ditemukan_via_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    exe = make_executable(tmp_path / "bindir")
    launcher = StubLauncher()
    locator = CloudflaredLocator(
        launcher, path_dirs=[tmp_path / "bindir"], common_dirs=[]
    )
    report = locator.locate()
    assert len(report) == 1
    assert report[0].path == exe
    assert report[0].source is DetectionSource.PATH
    assert report[0].version == "2024.8.3"


def test_ditemukan_di_lokasi_umum(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    make_executable(tmp_path / "common")
    launcher = StubLauncher()
    locator = CloudflaredLocator(
        launcher, path_dirs=[], common_dirs=[tmp_path / "common"]
    )
    report = locator.locate()
    assert report[0].source is DetectionSource.COMMON_LOCATION


def test_tidak_ditemukan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    locator = CloudflaredLocator(
        StubLauncher(), path_dirs=[tmp_path / "kosong"], common_dirs=[]
    )
    assert locator.locate() == ()


def test_tidak_ditemukan_di_lokasi_lain_tetapi_ada_di_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exe = make_executable(tmp_path / "bindir")
    locator = CloudflaredLocator(
        StubLauncher(),
        path_dirs=[tmp_path / "bindir"],
        common_dirs=[tmp_path / "common-kosong"],
    )
    report = locator.locate()
    assert [f.path for f in report] == [exe]


def test_dedupe_path_bertumpuk(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    make_executable(tmp_path / "dir")
    locator = CloudflaredLocator(
        StubLauncher(),
        path_dirs=[tmp_path / "dir"],
        common_dirs=[tmp_path / "dir"],  # sama → duplikat
    )
    assert len(locator.locate()) == 1


def test_versi_berhasil_dibaca(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    make_executable(tmp_path / "dir")
    launcher = StubLauncher(output="cloudflared version 2025.2.0")
    locator = CloudflaredLocator(
        launcher, path_dirs=[tmp_path / "dir"], common_dirs=[]
    )
    assert locator.locate()[0].version == "2025.2.0"


def test_versi_tidak_dikenal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    make_executable(tmp_path / "dir")
    launcher = StubLauncher(output="output aneh tanpa pola")
    locator = CloudflaredLocator(
        launcher, path_dirs=[tmp_path / "dir"], common_dirs=[]
    )
    finding = locator.locate()[0]
    assert finding.version is None
    assert "tidak dikenal" in finding.version_detail


def test_probe_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    make_executable(tmp_path / "dir")
    launcher = StubLauncher(timeout=True)
    locator = CloudflaredLocator(
        launcher, path_dirs=[tmp_path / "dir"], common_dirs=[], version_timeout_seconds=0.05
    )
    finding = locator.locate()[0]
    assert finding.version is None
    assert "timeout" in finding.version_detail


def test_executable_gagal_dijalankan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    make_executable(tmp_path / "dir")
    launcher = StubLauncher(fail_launch=True)
    locator = CloudflaredLocator(
        launcher, path_dirs=[tmp_path / "dir"], common_dirs=[]
    )
    finding = locator.locate()[0]
    assert finding.version is None
    assert "tidak dapat dijalankan" in finding.version_detail


def test_probe_pakai_argumen_list_tanpa_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    make_executable(tmp_path / "dir")
    launcher = StubLauncher()
    locator = CloudflaredLocator(
        launcher, path_dirs=[tmp_path / "dir"], common_dirs=[]
    )
    locator.locate()
    # StubLauncher memvalidasi: argv = [path, "--version"], tanpa shell
    assert launcher.launched[0][-1] == "--version"


def test_nama_executable_sesuai_platform(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    nama = "cloudflared.exe" if sys.platform == "win32" else "cloudflared"
    exe = make_executable(tmp_path / "dir", nama)
    locator = CloudflaredLocator(
        StubLauncher(), path_dirs=[tmp_path / "dir"], common_dirs=[]
    )
    assert locator.locate()[0].path == exe


# ---------------------------------------------------------------------------
# Regresi: FakeLaunchedProcess output_text (A-14 diperluas E-5)
# ---------------------------------------------------------------------------


def test_fake_output_text_untuk_probe_versi() -> None:
    launcher = FakeProcessLauncher(
        FakeScenario(output_text="cloudflared version 2026.3.3")
    )
    process = launcher.launch(ProcessSpec.from_sequence(["cloudflared", "--version"]))
    assert "2026.3.3" in "\n".join(process.output_lines())
