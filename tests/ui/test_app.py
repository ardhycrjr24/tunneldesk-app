"""Uji bootstrap aplikasi (E-4): lock, settings, controller, dialog.

Tanpa menjalankan app.exec() — cukup konstruksi & kontrak.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tunneldesk.application.settings_store import (
    AppSettings,
    JsonSettingsStore,
)
from tunneldesk.application.single_instance import (
    InstanceAlreadyRunningError,
)
from tunneldesk.ui import strings
from tunneldesk.ui.app import create_main_window


def test_create_main_window_sukses(tmp_path: Path, qtbot: object) -> None:
    lock, controller, window = create_main_window(settings_dir=tmp_path)
    try:
        assert lock.is_acquired() is True
        assert window.windowTitle() == strings.text("app.title")
        # origin kosong → MISCONFIGURED (tanpa asumsi host/port, PRD-01 §14)
        hasil = controller.check_origin()
        assert hasil.status.value == "MISCONFIGURED"
    finally:
        lock.release()
        window.close()


def test_instance_kedua_ditolak(tmp_path: Path, qtbot: object) -> None:
    lock1, _c1, window1 = create_main_window(settings_dir=tmp_path)
    try:
        with pytest.raises(InstanceAlreadyRunningError):
            create_main_window(settings_dir=tmp_path)
    finally:
        lock1.release()
        window1.close()


def test_lock_file_di_direktori_pengaturan(tmp_path: Path, qtbot: object) -> None:
    lock, _controller, window = create_main_window(settings_dir=tmp_path)
    try:
        assert (tmp_path / "instance.lock").exists()
    finally:
        lock.release()
        window.close()
    assert not (tmp_path / "instance.lock").exists()


def test_settings_store_dipakai_dari_direktori(tmp_path: Path, qtbot: object) -> None:
    store = JsonSettingsStore(tmp_path / "settings.json")
    store.save(
        AppSettings(origin_host="127.0.0.1", origin_port=1234)
    )
    lock, controller, window = create_main_window(settings_dir=tmp_path)
    try:
        # origin dari settings (host terisi) → bukan MISCONFIGURED
        hasil = controller.check_origin()
        assert hasil.status.value != "MISCONFIGURED"
    finally:
        lock.release()
        window.close()
