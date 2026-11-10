"""Pengaturan aplikasi & penyimpanan persisten (E-4, PRD-01 §7.7, A-11).

- ``AppSettings``: preferensi nonrahasia (lokasi cloudflared/config, log,
  backup). Tidak ada token/credential di sini (D-18).
- ``SettingsStore`` (port) + ``JsonSettingsStore`` (JSON atomik).
- ``default_*_dir()``: lokasi A-11 — Windows: %APPDATA%/%LOCALAPPDATA%;
  fallback POSIX untuk pengembangan macOS (dev-only).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Protocol

__all__ = [
    "AppSettings",
    "SettingsStore",
    "JsonSettingsStore",
    "default_settings_dir",
    "default_log_dir",
    "default_backup_dir",
    "default_settings_file",
]

SETTINGS_FILENAME = "settings.json"
_SETTINGS_VERSION = 1


@dataclass(frozen=True)
class AppSettings:
    """Preferensi pengguna. Tanpa rahasia (D-18) — token/credential tidak
    pernah disimpan di sini."""

    cloudflared_path: str = ""
    config_path: str = ""
    log_dir: str = ""
    backup_dir: str = ""
    origin_host: str = ""   # kosong → MISCONFIGURED (E-6 akan isi dari YAML)
    origin_port: int = 0
    language: str = "id"    # Q-06: Indonesia utama; EN siap ditambahkan

    def with_updates(self, **changes: object) -> AppSettings:
        return replace(self, **changes)  # type: ignore[arg-type]


class SettingsStore(Protocol):
    """Port penyimpanan pengaturan."""

    def load(self) -> AppSettings: ...

    def save(self, settings: AppSettings) -> None: ...


class JsonSettingsStore:
    """Simpan/muat pengaturan sebagai JSON (tulis atomik, A-12 ringan)."""

    def __init__(self, settings_file: Path) -> None:
        self._file = Path(settings_file)

    def load(self) -> AppSettings:
        if not self._file.exists():
            return AppSettings()
        try:
            payload = json.loads(self._file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # korup → kembalikan default (pengaturan bukan data kritis)
            return AppSettings()
        if not isinstance(payload, dict):
            return AppSettings()
        known = AppSettings()
        values: dict[str, object] = {}
        for key, value in payload.items():
            if key == "origin_port":
                try:
                    values[key] = int(value)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    continue
            elif hasattr(known, key) and isinstance(value, str):
                values[key] = value
        return known.with_updates(**values)

    def save(self, settings: AppSettings) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = self._file.with_suffix(".tmp")
        tmp_file.write_text(
            json.dumps(
                {"version": _SETTINGS_VERSION, **asdict(settings)},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        os.replace(tmp_file, self._file)


# ----------------------------------------------------------------------
# Lokasi default (A-11) — Windows utama; POSIX untuk pengembangan
# ----------------------------------------------------------------------
def _app_data_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or Path.home()
        return Path(base) / "TunnelDesk"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "TunnelDesk"
    base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(base) / "TunnelDesk"


def _local_data_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or Path.home()
        return Path(base) / "TunnelDesk"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / "TunnelDesk"
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / "TunnelDesk"


def default_settings_dir() -> Path:
    """%APPDATA%\\TunnelDesk (A-11) — preferensi + SQLite + lock."""
    return _app_data_dir()


def default_log_dir() -> Path:
    """%LOCALAPPDATA%\\TunnelDesk\\logs (A-11)."""
    return _local_data_dir() / "logs"


def default_backup_dir() -> Path:
    """%LOCALAPPDATA%\\TunnelDesk\\backups (A-11)."""
    return _local_data_dir() / "backups"


def default_settings_file() -> Path:
    return default_settings_dir() / SETTINGS_FILENAME
