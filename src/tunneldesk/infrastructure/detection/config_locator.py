"""Locator kandidat file konfigurasi (E-5, tugas 2.1).

- Kandidat diperiksa di lokasi umum per platform (`%USERPROFILE%` /
  `%HOME%` `.cloudflared`, `/etc/cloudflared`, `/usr/local/etc/cloudflared`)
  dan lokasi yang relevan dengan instalasi (direktori executable).
- Hanya **keberadaan** yang dilaporkan — isi file **tidak dibaca**
  (validasi isi adalah E-6; keamanan E-5).
- File didukung: `config.yml` dan `config.yaml` — bukan hanya satu lokasi
  (kontrak E-5: jangan asumsi satu lokasi).
"""

from __future__ import annotations

import os
from pathlib import Path

from tunneldesk.domain.tunnel.detection import (
    ConfigCandidate,
    DetectionSource,
)

__all__ = ["ConfigLocator", "common_config_dirs"]

_CONFIG_NAMES = ("config.yml", "config.yaml")


def common_config_dirs() -> list[Path]:
    home = Path.home()
    candidates: list[Path] = [home / ".cloudflared"]
    if os.name == "nt":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        candidates.append(Path(program_data) / "cloudflared")
    else:
        candidates += [Path("/etc/cloudflared"), Path("/usr/local/etc/cloudflared")]
    return candidates



class ConfigLocator:
    """Pencari kandidat file konfigurasi — read-only, fail-safe.

    ``common_dirs`` dan ``extra_dirs`` (mis. direktori executable) dapat
    diinjeksi untuk uji deterministik.
    """

    def __init__(
        self,
        common_dirs: list[Path] | None = None,
        extra_dirs: list[tuple[Path, DetectionSource]] | None = None,
    ) -> None:
        self._common_dirs = (
            common_dirs if common_dirs is not None else common_config_dirs()
        )
        self._extra_dirs = extra_dirs or []

    def locate(self) -> tuple[ConfigCandidate, ...]:
        candidates: list[ConfigCandidate] = []
        seen: set[Path] = set()
        for directory, source in self._roots():
            for name in _CONFIG_NAMES:
                candidate = directory / name
                if candidate.is_file() and candidate.resolve() not in seen:
                    resolved = candidate.resolve()
                    seen.add(resolved)
                    candidates.append(
                        ConfigCandidate(path=resolved, source=source)
                    )
        return tuple(candidates)

    def _roots(self) -> list[tuple[Path, DetectionSource]]:
        roots: list[tuple[Path, DetectionSource]] = [
            (directory, DetectionSource.COMMON_LOCATION)
            for directory in self._common_dirs
        ]
        roots.extend(self._extra_dirs)
        return roots
