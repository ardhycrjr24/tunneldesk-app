"""Konfigurasi pytest global.

Qt berjalan headless (offscreen) sebelum PySide6 diimpor — wajib untuk
CI tanpa display.
"""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def pytest_configure(config: object) -> None:
    """Arahkan root sementara pytest ke luar /private/var (T-3).

    Kebijakan path Task 2.5 (koreksi T-3) menolak /var, /tmp DAN bentuk
    kanonis macOS-nya (/private/var, /private/tmp) sebagai target tulis
    konfigurasi. Default pytest ``tmp_path`` di macOS berada di bawah
    /private/var/folders sehingga akan tertolak kebijakan tersebut;
    root uji dipindah ke $HOME/.cache agar berada di luar semua daftar
    sistem di setiap platform (Windows CI tidak terdampak).
    """
    basetemp = getattr(config, "option", None)
    if basetemp is not None and not getattr(basetemp, "basetemp", None):
        # Diisi hanya bila pemanggil tidak menentukan --basetemp sendiri.
        basetemp.basetemp = str(
            Path.home() / ".cache" / "tunneldesk-pytest-tmp"
        )
