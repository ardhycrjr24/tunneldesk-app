"""Uji settings store (E-4, A-11): default, persist, korup, koersi tipe.

Task 2.9: preferensi ``mask_hostnames`` (boolean, opt-in — D-29.1) —
default, round-trip, kompatibilitas file lama, tipe salah, dan inspeksi
JSON (AC-01..AC-05, AC-11).
"""

from __future__ import annotations

import json
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


# ----------------------------------------------------------------------
# Task 2.9 — preferensi mask_hostnames
# ----------------------------------------------------------------------
def test_default_mask_hostnames_false(tmp_path: Path) -> None:
    # AC-01: tanpa file settings → mask_hostnames False (T-3 opt-in)
    store = JsonSettingsStore(tmp_path / "settings.json")
    assert store.load().mask_hostnames is False


def test_mask_hostnames_round_trip(tmp_path: Path) -> None:
    # AC-02: save True → load True; save False → load False
    store = JsonSettingsStore(tmp_path / "settings.json")
    store.save(AppSettings(mask_hostnames=True))
    assert store.load().mask_hostnames is True
    store.save(AppSettings(mask_hostnames=False))
    assert store.load().mask_hostnames is False


def test_mask_hostnames_round_trip_field_lain_utuh(tmp_path: Path) -> None:
    # AC-02 pelengkap: round-trip dengan seluruh field terisi
    store = JsonSettingsStore(tmp_path / "settings.json")
    settings = AppSettings(
        cloudflared_path="C:\\tools\\cloudflared.exe",
        config_path="C:\\data\\config.yml",
        log_dir=str(tmp_path / "logs"),
        backup_dir=str(tmp_path / "backups"),
        mask_hostnames=True,
        origin_host="127.0.0.1",
        origin_port=8080,
    )
    store.save(settings)
    assert store.load() == settings


def test_file_lama_tanpa_kunci_mask_default_false(tmp_path: Path) -> None:
    # AC-03: file lama tanpa kunci → default False, field lain utuh
    file_path = tmp_path / "settings.json"
    file_path.write_text(
        '{"cloudflared_path": "cf.exe", "origin_host": "127.0.0.1",'
        ' "origin_port": 8080}',
        encoding="utf-8",
    )
    settings = JsonSettingsStore(file_path).load()
    assert settings.mask_hostnames is False
    assert settings.cloudflared_path == "cf.exe"
    assert settings.origin_host == "127.0.0.1"
    assert settings.origin_port == 8080


def test_mask_hostnames_tipe_salah_dilewati(tmp_path: Path) -> None:
    # AC-04: "true" (str), 1 (int), null → dilewati → default False,
    # tanpa error (isinstance bool menolak int — bool subclass int,
    # sebaliknya tidak). Kunci eksklusif: string "true" TIDAK boleh
    # lolos lewat cabang str umum.
    file_path = tmp_path / "settings.json"
    for salah in ('"true"', "1", "null", '""', "0"):
        file_path.write_text(f'{{"mask_hostnames": {salah}}}', encoding="utf-8")
        settings = JsonSettingsStore(file_path).load()
        assert settings.mask_hostnames is False, f"tipe salah: {salah}"


def test_file_korup_mask_hostnames_default(tmp_path: Path) -> None:
    # AC-05: file JSON rusak → default penuh (perilaku existing)
    file_path = tmp_path / "settings.json"
    file_path.write_text("{ korup", encoding="utf-8")
    settings = JsonSettingsStore(file_path).load()
    assert settings.mask_hostnames is False
    assert settings == AppSettings()


def test_settings_json_boolean_dan_field_lama_utuh(tmp_path: Path) -> None:
    # AC-11 (koreksi redaksional PC): mask_hostnames disimpan sebagai
    # nilai boolean; tanpa hostname asli/mapping placeholder/credential/
    # token; field pengaturan lama tetap utuh.
    store = JsonSettingsStore(tmp_path / "settings.json")
    store.save(
        AppSettings(
            cloudflared_path="C:\\tools\\cloudflared.exe",
            config_path="C:\\data\\config.yml",
            log_dir=str(tmp_path / "logs"),
            backup_dir=str(tmp_path / "backups"),
            mask_hostnames=True,
            origin_host="127.0.0.1",
            origin_port=8080,
        )
    )
    payload = json.loads(
        (tmp_path / "settings.json").read_text(encoding="utf-8")
    )
    assert payload["mask_hostnames"] is True
    assert isinstance(payload["mask_hostnames"], bool)
    # field pengaturan lama tetap utuh
    assert payload["cloudflared_path"] == "C:\\tools\\cloudflared.exe"
    assert payload["config_path"] == "C:\\data\\config.yml"
    assert payload["log_dir"] == str(tmp_path / "logs")
    assert payload["backup_dir"] == str(tmp_path / "backups")
    assert payload["origin_host"] == "127.0.0.1"
    assert payload["origin_port"] == 8080
    assert payload["language"] == "id"
    # tanpa kunci tambahan — tidak ada hostname/mapping/credential/token
    assert set(payload) == {
        "version",
        "cloudflared_path",
        "config_path",
        "log_dir",
        "backup_dir",
        "mask_hostnames",
        "origin_host",
        "origin_port",
        "language",
    }


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
