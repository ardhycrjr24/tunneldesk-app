"""Uji ConfigLocator (E-5): kandidat config sintetis, read-only terbukti."""

from __future__ import annotations

import hashlib
from pathlib import Path

from tunneldesk.domain.tunnel.detection import DetectionSource
from tunneldesk.infrastructure.detection.config_locator import ConfigLocator

CONFIG_CONTENT = "tunnel: dummy-tunnel-id\n"


def make_config(directory: Path, name: str = "config.yml") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    target.write_text(CONFIG_CONTENT, encoding="utf-8")
    return target


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_satu_kandidat_ditemukan(tmp_path: Path) -> None:
    config = make_config(tmp_path / ".cloudflared")
    locator = ConfigLocator(common_dirs=[tmp_path / ".cloudflared"])
    candidates = locator.locate()
    assert [c.path for c in candidates] == [config]
    assert candidates[0].source is DetectionSource.COMMON_LOCATION


def test_beberapa_kandidat_ditemukan(tmp_path: Path) -> None:
    config1 = make_config(tmp_path / "a")
    config2 = make_config(tmp_path / "b", "config.yaml")
    locator = ConfigLocator(common_dirs=[tmp_path / "a", tmp_path / "b"])
    paths = [c.path for c in locator.locate()]
    assert set(paths) == {config1, config2}


def test_tidak_ada_kandidat(tmp_path: Path) -> None:
    locator = ConfigLocator(common_dirs=[tmp_path / "kosong"])
    assert locator.locate() == ()


def test_config_yaml_juga_dikenal(tmp_path: Path) -> None:
    config = make_config(tmp_path / "c", "config.yaml")
    locator = ConfigLocator(common_dirs=[tmp_path / "c"])
    assert [c.path for c in locator.locate()] == [config]


def test_extra_dirs_sumber_instalasi(tmp_path: Path) -> None:
    config = make_config(tmp_path / "bindir")
    locator = ConfigLocator(
        common_dirs=[],
        extra_dirs=[(tmp_path / "bindir", DetectionSource.COMMON_LOCATION)],
    )
    assert [c.path for c in locator.locate()] == [config]


def test_read_only_file_tidak_berubah(tmp_path: Path) -> None:
    """Kontrak E-5: deteksi bukan perubahan — file konfigurasi utuh."""
    config = make_config(tmp_path / ".cloudflared")
    before = digest(config)
    locator = ConfigLocator(common_dirs=[tmp_path / ".cloudflared"])
    locator.locate()
    locator.locate()
    assert digest(config) == before
    assert config.read_text(encoding="utf-8") == CONFIG_CONTENT


def test_tidak_ada_file_baru_dibuat(tmp_path: Path) -> None:
    directory = tmp_path / ".cloudflared"
    make_config(directory)
    sebelum = sorted(item.name for item in directory.iterdir())
    ConfigLocator(common_dirs=[directory]).locate()
    sesudah = sorted(item.name for item in directory.iterdir())
    assert sesudah == sebelum
