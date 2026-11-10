# Arsitektur — TunnelDesk (skeleton)

Rujukan lengkap: TECHNICAL_REVIEW §4 & PROJECT_DECISIONS (workspace manajemen
proyek `TunnelDesk`). Dokumen ini meringkas batas yang dijaga CI.

## Lapisan (A-08 — Ports & Adapters pragmatis)

```
ui  →  application  →  domain
            ↑
    infrastructure (adapter)
```

- **domain/** — murni Python: state machine proses (D-10), model & validasi
  konfigurasi, kebijakan backup, definisi diagnostik, mesin redaksi,
  model lisensi. **Dilarang** mengimpor Qt, `subprocess`, modul
  Windows-only, infrastructure/UI/application — dijaga kontrak
  `import-linter` (domain-purity, layers) di CI.
- **application/** — orkestrasi kasus penggunaan; mendefinisikan port;
  tidak mengetahui detail platform.
- **infrastructure/** — adapter: `process/windows` (Job Object A-07 — hanya
  proses buatan TunnelDesk), `process/posix` (dev macOS + fake-cloudflared),
  `config_io` (ruamel.yaml round-trip A-02 + tulis atomik), `secrets`
  (A-04 — **tidak ada dependensi keyring sampai kebutuhan terbukti**),
  `persistence` (SQLite, A-11), `logging` (semua keluaran lewat redaksi).
- **ui/** — PySide6 (D-01); string terpusat agar Bahasa Inggris dapat
  ditambahkan (Q-06).

## Aturan teknis yang mengikat (ringkas)

| Aturan | Keputusan |
|---|---|
| Perubahan konfigurasi selalu preview → backup → validasi → konfirmasi → rollback | D-17 |
| Hanya proses `cloudflared` buatan aplikasi yang dikelola/dihentikan | D-18, K-07, A-07 |
| Mode token & Windows Service: deteksi + penjelasan saja | A-09, K-06 |
| Verifikasi lisensi offline; online hanya refund/chargeback | K-02, A-03 |
| Log plain teredaksi, tanpa rotasi otomatis sampai Q-09 | A-12 |
| Single-instance dengan pemulihan stale lock aman | A-13 |
| Fixture uji = sintetis F1–F10; dilarang data produksi | Q-05, §5.1 |
