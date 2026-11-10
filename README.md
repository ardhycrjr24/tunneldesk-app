# TunnelDesk

Pendamping desktop **Windows** untuk mengelola Cloudflare Tunnel yang dipakai
mengakses e-Rapor — dibangun untuk operator sekolah non-teknis.
Produk oleh **ANAK TERUBUK Dev**.

## Status

**Skeleton Fase 0 (tugas 0.4).** Struktur arsitektur dan tooling siap;
**belum ada implementasi fitur** (otorisasi coding belum diberikan untuk
tahap implementasi). Keputusan teknis terkunci tercatat di
`docs/PROJECT_DECISIONS.md` pada workspace manajemen proyek terpisah.

## Keputusan teknis utama (terkunci)

- Windows-only MVP; build Windows di Windows/CI (bukan cross-compile).
- Python **3.12** dipin (A-01); PySide6 (D-01); `ruamel.yaml` round-trip (A-02).
- Lisensi: Ed25519 via `cryptography` (A-03); private key **tidak pernah** di repo/binary.
- Installer MVP: Inno Setup (A-05); CI: GitHub Actions (A-06).
- `pywin32` + Job Object dengan batas kepemilikan proses ketat (A-07).
- Arsitektur **Ports & Adapters pragmatis** (A-08): domain bebas Qt/API Windows.
- MVP hanya mengelola tunnel berbasis **file config**; mode token & Windows
  Service hanya dideteksi dan dijelaskan (A-09, K-06, K-07).

## Struktur

```
src/tunneldesk/
├── domain/          # Murni: tunnel, config, backup, diagnostics, redaction, licensing, settings
├── application/     # Kasus penggunaan (controller & services)
├── infrastructure/  # Adapter platform: process (windows/posix), config_io, secrets, persistence, logging
└── ui/              # PySide6: dashboard, wizard, diagnostics, backup, settings
tests/fixtures/      # F1–F10 sintetis (tanpa data produksi)
```

Batas arsitektur dijaga CI (`lint-imports`): UI → application → domain;
domain tidak mengimpor infrastructure/UI/application.

## Perintah

```bash
python -m pip install -e ".[dev]"
ruff check src tests
mypy src
lint-imports
pytest
```

## Lisensi

Proprietary — © ANAK TERUBUK Dev.
