# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec TunnelDesk (Task 3.1 — Windows packaging spike).

Prinsip (keputusan proyek):
- Mode **windowed** (``console=False``) — aplikasi desktop PySide6.
- Mode **onedir** (bukan onefile) untuk spike: startup lebih cepat dan
  heuristik AV lebih rendah (R-04); onefile dievaluasi terpisah.
- **TANPA cloudflared** (K-05 Opsi A / A-10: tidak dibundel — pengguna
  mengunduh dari sumber resmi Cloudflare + verifikasi SHA-256).
- **TANPA credential/token/private key/data sekolah** (D-18): fixture
  F6/F7 hanya untuk pytest, tidak dikumpulkan ke runtime.
- Tidak ada asumsi resource di direktori source: aplikasi memuat teks
  UI dari modul ``strings.py`` dan data pengguna dari AppData (A-11) —
  ``datas`` sengaja kosong; smoke test membuktikan exe berjalan tanpa
  file source (``packaging/smoke_test_frozen.py``).
- UPX dinonaktifkan (R-04 — kompresi UPX memicu heuristik AV).

Build Windows: ``pyinstaller packaging/tunneldesk.spec --noconfirm``
(wajib di Windows — tidak ada cross-compile; lihat packaging/README.md).
"""

import os
import sys

# SPECPATH = direktori berisi spec ini (packaging/) — path di spec
# diselesaikan relatif terhadap spec, bukan CWD pemanggil.
ROOT = os.path.normpath(os.path.join(SPECPATH, ".."))

from PyInstaller.utils.hooks import copy_metadata

hiddenimports: list[str] = []
if sys.platform == "win32":
    # pywin32 diimpor lazy di adapter Windows (fungsi, bukan level modul)
    # — wajib eksplisit agar terkumpul; win32timezone adalah dependensi
    # runtime pywin32 yang klasik hilang di frozen build.
    hiddenimports += ["win32api", "win32con", "win32job", "win32timezone"]

# Metadata paket terinstal (version 0.0.1) — dipakai
# ``diagnostics_service._app_version()`` di mode frozen (fallback konstanta
# tetap ada bila metadata tidak terkumpul).
datas = copy_metadata("tunneldesk")

a = Analysis(
    [os.path.join(ROOT, "src", "tunneldesk", "ui", "app.py")],
    pathex=[os.path.join(ROOT, "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Toolchain uji/dev tidak masuk runtime frozen (AC-4: tanpa
        # credential/data sensitif; permukaan binary seminimal mungkin).
        "pytest",
        "pytest-qt",
        "tests",
        "setuptools",
        "pip",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="TunnelDesk",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # windowed — aplikasi desktop
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="TunnelDesk",
)
