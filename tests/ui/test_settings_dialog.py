"""Uji dialog Pengaturan (Task 2.9) — checkbox preferensi ``mask_hostnames``.

D-29.3 (settings_only): preferensi hanya disimpan & ditampilkan di
Settings — tanpa konsumen runtime; dialog diagnostik 2.8 tetap default
OFF + reset OFF per run (T-2/T-3, AC-08).
"""

from __future__ import annotations

import json
from pathlib import Path

from tunneldesk.application.settings_store import AppSettings, JsonSettingsStore
from tunneldesk.domain.diagnostics.origin import OriginCheckResult, OriginStatus
from tunneldesk.ui.diagnostics.diagnostics_dialog import DiagnosticsDialog
from tunneldesk.ui.settings.settings_dialog import SettingsDialog

VALID_CONFIG = (
    "tunnel: 11111111-2222-3333-4444-555555555555\n"
    "credentials-file: credentials-dummy.json\n"
    "ingress:\n"
    "  - hostname: rapor.sekolah.sch.id\n"
    "    service: http://localhost:8080\n"
    "  - service: http_status:404\n"
)


class ControllerStub:
    def status(self, probe_origin: bool = False):  # type: ignore[no-untyped-def]
        class S:
            tunnel_state = "RUNNING"
            pid = 42
            crashed = None
            origin = None

        return S()

    def check_origin(self) -> OriginCheckResult:
        return OriginCheckResult(OriginStatus.HEALTHY, "origin merespons")


def make_store(tmp_path: Path) -> JsonSettingsStore:
    return JsonSettingsStore(tmp_path / "settings.json")


def make_settings_dialog(
    tmp_path: Path, qtbot: object
) -> tuple[SettingsDialog, JsonSettingsStore]:
    store = make_store(tmp_path)
    dialog = SettingsDialog(store)
    qtbot.addWidget(dialog)
    return dialog, store


def test_dialog_default_tanpa_file_off(tmp_path: Path, qtbot: object) -> None:
    # AC-01/AC-06: tanpa file settings → checkbox OFF (default T-3)
    dialog, store = make_settings_dialog(tmp_path, qtbot)
    assert dialog.mask_checked() is False
    assert store.load().mask_hostnames is False


def test_dialog_menampilkan_nilai_tersimpan(tmp_path: Path, qtbot: object) -> None:
    # AC-06: checkbox mencerminkan nilai tersimpan saat dialog dibuka
    store = make_store(tmp_path)
    store.save(AppSettings(mask_hostnames=True, origin_host="127.0.0.1"))
    dialog = SettingsDialog(store)
    qtbot.addWidget(dialog)
    assert dialog.mask_checked() is True
    store.save(AppSettings(mask_hostnames=False))
    dialog2 = SettingsDialog(store)
    qtbot.addWidget(dialog2)
    assert dialog2.mask_checked() is False


def test_simpan_mask_dan_field_lain_utuh(tmp_path: Path, qtbot: object) -> None:
    # AC-07: Simpan → mask_hostnames tersimpan; field lain tidak berubah
    store = make_store(tmp_path)
    store.save(
        AppSettings(
            cloudflared_path="cf.exe",
            origin_host="127.0.0.1",
            origin_port=8080,
        )
    )
    dialog = SettingsDialog(store)
    qtbot.addWidget(dialog)
    dialog.set_mask_checked(True)
    dialog._on_save()
    saved = store.load()
    assert saved.mask_hostnames is True
    assert saved.cloudflared_path == "cf.exe"
    assert saved.origin_host == "127.0.0.1"
    assert saved.origin_port == 8080


def test_simpan_turun_mask_dan_field_lain_utuh(tmp_path: Path, qtbot: object) -> None:
    # AC-07 (arah sebaliknya): ON tersimpan → uncheck + Simpan → OFF,
    # field lain tetap utuh.
    store = make_store(tmp_path)
    store.save(AppSettings(mask_hostnames=True, origin_host="h"))
    dialog = SettingsDialog(store)
    qtbot.addWidget(dialog)
    assert dialog.mask_checked() is True
    dialog.set_mask_checked(False)
    dialog._on_save()
    saved = store.load()
    assert saved.mask_hostnames is False
    assert saved.origin_host == "h"


def test_batal_tanpa_simpan_tidak_mengubah_nilai(tmp_path: Path, qtbot: object) -> None:
    # AC-07 pelengkap: Batal/menutup tanpa Simpan → nilai tersimpan tidak
    # berubah.
    store = make_store(tmp_path)
    store.save(AppSettings(mask_hostnames=True))
    dialog = SettingsDialog(store)
    qtbot.addWidget(dialog)
    dialog.set_mask_checked(False)  # diubah di UI…
    dialog.reject()                 # …tapi tidak disimpan
    assert store.load().mask_hostnames is True


def test_json_hasil_dialog_tanpa_rahasia(tmp_path: Path, qtbot: object) -> None:
    # AC-11: settings.json hasil Simpan dialog — mask_hostnames boolean,
    # tanpa hostname/mapping/credential/token; field lama utuh.
    dialog, _store = make_settings_dialog(tmp_path, qtbot)
    dialog.set_field_values(
        cloudflared_path="cf.exe",
        config_path="config.yml",
        log_dir="logs",
        backup_dir="backups",
    )
    dialog.set_mask_checked(True)
    dialog._on_save()
    payload = json.loads(
        (tmp_path / "settings.json").read_text(encoding="utf-8")
    )
    assert payload["mask_hostnames"] is True
    assert payload["cloudflared_path"] == "cf.exe"
    assert payload["config_path"] == "config.yml"
    assert payload["log_dir"] == "logs"
    assert payload["backup_dir"] == "backups"
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


def test_preferensi_tidak_mempengaruhi_dialog_diagnostik(
    tmp_path: Path, qtbot: object
) -> None:
    # AC-08/T-2: checkbox diagnostik tetap default OFF meski preferensi
    # tersimpan True — preferensi Settings bukan konsumen runtime.
    store = make_store(tmp_path)
    config = tmp_path / "config.yml"
    config.write_bytes(VALID_CONFIG.encode("utf-8"))
    (tmp_path / "credentials-dummy.json").write_bytes(b"{}")
    store.save(
        AppSettings(mask_hostnames=True, config_path=str(config))
    )
    dialog = DiagnosticsDialog(ControllerStub(), store)
    qtbot.addWidget(dialog)
    assert dialog._mask_checkbox.isChecked() is False
