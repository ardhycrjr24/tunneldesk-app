# F10 — Cuplikan mode token & Windows Service (dianonimkan)

Rujukan pengujian deteksi mode (K-06/K-07, A-09): mode ini **tidak
dikelola** TunnelDesk pada MVP — hanya dideteksi dan dijelaskan bila
dapat dideteksi secara aman dan andal.

## Mode token (tanpa file config lokal)

```
cloudflared tunnel run --token eyJ...DUMMY_TOKEN_FOR_FIXTURE_F10
```

Ciri: tidak ada `config.yml`; tunnel dikelola dari dashboard Cloudflare
Zero Trust. TunnelDesk harus menampilkan bahwa mode ini di luar kendali
aplikasi.

## Windows Service

```
cloudflared service install  <DUMMY_SERVICE_TOKEN>
sc query cloudflared
```

Ciri: proses berjalan sebagai layanan sistem. TunnelDesk **tidak pernah**
menghentikan layanan ini; hanya menampilkan status hanya-baca bila
terdeteksi secara aman.
