# F9 — File lisensi uji (BELUM tersedia)

File lisensi uji (valid, tampered, salah produk, kedaluwarsa update,
`payload_version` tak dikenal) **tidak dapat dibuat pada skeleton** karena
membutuhkan **tool penerbit lisensi uji (A-15)** dengan kunci uji Ed25519
terpisah — kunci uji **tidak pernah disimpan di repository** (A-03).

Rencana pembuatan: epik E-11 (Fase 3, disiapkan sejak Fase 2).

Kontrak fixture (PROJECT_DECISIONS §5.1 F9):
- `license-valid.json` — payload + signature valid dari kunci uji
- `license-tampered.json` — payload dimodifikasi
- `license-salah-produk.json` — `product_code` tidak cocok
- `license-update-expired.json` — `updates_until` di masa lalu
- `license-payload-version-unknown.json` — `payload_version` tak dikenal

Semua nilai pembeli/order bersifat dummy (tanpa data nyata).
