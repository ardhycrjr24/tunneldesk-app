"""Uji settings store (E-4, A-11): default, persist, korup, koersi tipe."""

from __future__ import annotations

from pathlib import Path

from tunneldesk.application.settings_store import (
    AppSettings,
    JsonSettingsStore,
    default_backup_dir,
    default_log_dir,
    default_settings_dir,
)


def test_default_kosong() -> None:
    store = JsonSettingsStore(Path("/nonexistent-tunneldesk-test/settings.json"))
    assert store.load() == AppSettings()


def test_save_dan_load_round_trip(tmp_path: Path) -> None:
    store = JsonSettingsStore(tmp_path / "settings.json")
    settings = AppSettings(
        cloudflared_path="C:\\tools\\cloudflared.exe",
        config_path="C:\\data\\config.yml",
        log_dir=str(tmp_path / "logs"),
        backup_dir=str(tmp_path / "backups"),
        origin_host="127.0.0.1",
        origin_port=8080,
    )
    store.save(settings)
    assert store.load() == settings


def test_origin_port_dikoersi_dari_string(tmp_path: Path) -> None:
    store = JsonSettingsStore(tmp_path / "settings.json")
    store.save(AppSettings(origin_host="127.0.0.1", origin_port=8080))
    # tulis manual sebagai string (simulasi edit tangan)
    store._file.write_text(
        store._file.read_text(encoding="utf-8").replace(
            '"origin_port": 8080', '"origin_port": "8080"'
        ),
        encoding="utf-8",
    )
    assert store.load().origin_port == 8080


def test_file_korup_kembalikan_default(tmp_path: Path) -> None:
    file_path = tmp_path / "settings.json"
    file_path.write_text("{ korup", encoding="utf-8")
    store = JsonSettingsStore(file_path)
    assert store.load() == AppSettings()
    # simpan kembali menulis ulang dengan benar
    store.save(AppSettings(origin_host="h", origin_port=1))
    assert store.load().origin_host == "h"


def test_kunci_tak_kenal_diabaikan(tmp_path: Path) -> None:
    file_path = tmp_path / "settings.json"
    file_path.write_text(
        '{"cloudflared_path": "cf.exe", "rahasia_aneh": "nilai"}',
        encoding="utf-8",
    )
    settings = JsonSettingsStore(file_path).load()
    assert settings.cloudflared_path == "cf.exe"
    assert not hasattr(settings, "rahasia_aneh")


def test_default_dirs_ada_nilai() -> None:
    # A-11: Windows %APPDATA%/%LOCALAPPDATA%; POSIX fallback dev
    assert default_settings_dir().name == "TunnelDesk"
    assert default_log_dir().name == "logs"
    assert default_backup_dir().name == "backups"
