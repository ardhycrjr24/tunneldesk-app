"""Adapter Windows: subprocess + Job Object via pywin32 (A-07).

Batas: hanya proses buatan aplikasi; KILL_ON_JOB_CLOSE wajib diuji
khusus (crash, force close, normal shutdown, proses anak, pemulihan).
Tidak diimpor di macOS."""
