# Packaging TunnelDesk (Task 3.1 — packaging spike)

Spike packaging Windows x64 dengan **PyInstaller** — bukan sistem
distribusi final. Status, hasil, dan keterbatasan: lihat
`docs/TASK_3_1_PACKAGING_SPIKE_REPORT.md` di workspace manajemen proyek.

## Isi direktori

| File | Fungsi |
|---|---|
| `tunneldesk.spec` | Konfigurasi PyInstaller (windowed, onedir, tanpa cloudflared/secret, UPX off) |
| `smoke_test_frozen.py` | Uji runtime frozen (Windows-only): startup, AppData, dir-install bersih, pindai secret |

## Prasyarat build

- **Windows** (build Windows WAJIB di Windows — tidak ada cross-compile,
  keputusan A-01/A-06); Python **3.12** dipin.
- Instalasi: `python -m pip install . "pyinstaller>=6"`
  (atau `python -m pip install ".[build]"` setelah grup `build` tersedia).

## Build

Dari root repo (Windows):

```powershell
pyinstaller packaging/tunneldesk.spec --noconfirm --distpath dist --workpath build/pyinstaller
```

Hasil: `dist/TunnelDesk/TunnelDesk.exe` (+ `_internal/`). Konfigurasi CI:
`.github/workflows/package-windows.yml` (juga bisa dipicu manual via
`workflow_dispatch`); artifact diunggah **hanya bila smoke test lulus**.

## Smoke test frozen (Windows)

```powershell
python packaging/smoke_test_frozen.py
```

Membuktikan (build sukses **bukan** bukti runtime): exe hidup tanpa
crash saat startup ≥20 s (modul utama + Qt offscreen), `instance.lock`
tertulis di `%APPDATA%\TunnelDesk` (A-11/A-13), direktori instalasi
tidak berubah, tidak ada `*.py` di hasil build, dan artifact bebas
marker secret fixture/key.

## Keputusan yang tercakup spec

- **Windowed** (`console=False`) — aplikasi desktop.
- **Onedir** (bukan onefile) untuk spike: startup cepat, heuristik AV
  lebih rendah (R-04); onefile dievaluasi terpisah.
- **Tanpa cloudflared** (K-05 Opsi A / A-10 — pengguna mengunduh dari
  sumber resmi Cloudflare + SHA-256).
- **Tanpa secret/fixture** — excludes pytest/tests/setuptools/pip;
  pindai marker secret F6 di smoke test.
- **UPX off** (R-04); hiddenimports pywin32 eksplisit (impor lazy di
  adapter Windows) + `win32timezone`.
- Metadata paket (`tunneldesk` version) dikumpulkan via `copy_metadata`
  untuk `importlib.metadata` (fallback konstanta tetap ada).

## Batasan spike (bukan produk final)

- Tanpa installer (Inno Setup = Task 3.5), tanpa ikon (Q-07: ikon
  sementara menyusul), tanpa code signing (Q-03: checksum +
  panduan SmartScreen saat distribusi), tanpa updater (K-04).
- Smoke test CI memakai `QT_QPA_PLATFORM=offscreen` — bukti startup
  headless; verifikasi UI visual & AV/SmartScreen tetap di Windows
  fisik (release gate Fase 3).
