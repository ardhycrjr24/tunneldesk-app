"""Teks UI terpusat (Q-06): Bahasa Indonesia utama, EN siap ditambahkan.

Aturan: komponen UI TIDAK BOLEH berisi literal string tampilan — ambil dari
modul ini. Menambahkan Bahasa Inggris = menambah tabel terjemahan baru,
tanpa menyentuh kode UI.
"""

from __future__ import annotations

ID: dict[str, str] = {
    "app.title": "TunnelDesk",
    "app.instance_running": "TunnelDesk sudah berjalan (pid {pid}). "
    "Tutup instance tersebut terlebih dahulu.",
    "dash.group_status": "Status",
    "dash.lbl_tunnel": "Status tunnel:",
    "dash.lbl_origin": "Status origin:",
    "dash.lbl_origin_unknown": "belum diperiksa",
    "dash.lbl_pid": "PID:",
    "dash.lbl_started_at": "Waktu mulai:",
    "dash.lbl_license": "Lisensi:",
    "dash.license_unavailable": "belum tersedia",
    "dash.lbl_last_exit": "Keluar terakhir:",
    "dash.lbl_last_exit_none": "—",
    "dash.btn_start": "Start",
    "dash.btn_stop": "Stop",
    "dash.btn_restart": "Restart",
    "dash.btn_check_origin": "Periksa origin",
    "dash.group_log": "Log (teredaksi)",
    "dash.log_empty": "(belum ada keluaran)",
    "dash.group_problems": "Ringkasan masalah",
    "dash.problem_none": "Tidak ada masalah yang perlu tindakan.",
    "dash.problem_crashed": "Proses tunnel berakhir tak terduga (exit code {code}).",
    "dash.problem_origin": "Origin: {detail}",
    "dash.refreshing": "memproses…",
    "menu.settings": "Pengaturan",
    "menu.file": "Berkas",
    "menu.exit": "Keluar",
    "dash.btn_wizard": "Setup Wizard…",
    "settings.title": "Pengaturan",
    "settings.fld_cloudflared": "Lokasi cloudflared:",
    "settings.fld_config": "Lokasi file konfigurasi:",
    "settings.fld_log_dir": "Direktori log:",
    "settings.fld_backup_dir": "Direktori backup:",
    "settings.note": "Perubahan lokasi disimpan segera dan berlaku untuk sesi berikutnya.",
    "settings.saved": "Tersimpan.",
    "btn.save": "Simpan",
    "btn.cancel": "Batal",
    "btn.browse": "Pilih…",
    "err.operation_failed": "Operasi gagal: {detail}",
    "err.start": "Start gagal: {detail}",
    "err.stop": "Stop gagal: {detail}",
    # ------------------------------------------------------------------
    # Setup Wizard (Task 2.6, PRD-01 §7.4) — Q-06
    # ------------------------------------------------------------------
    "wiz.title": "Setup Wizard — TunnelDesk",
    "wiz.next": "Lanjut",
    "wiz.back": "Kembali",
    "wiz.cancel": "Batal",
    "wiz.finish": "Selesai",
    "wiz.apply": "Terapkan Perubahan",
    "wiz.busy": "memproses…",
    "wiz.p1.title": "Langkah 1 dari 7 — Prasyarat",
    "wiz.p1.executable_found": "cloudflared ditemukan: {path} (versi {version})",
    "wiz.p1.executable_found_noversion": "cloudflared ditemukan: {path}",
    "wiz.p1.executable_missing": "cloudflared tidak ditemukan — wizard tetap "
    "dapat menyiapkan konfigurasi, namun tunnel tidak dapat dijalankan "
    "sampai cloudflared tersedia (lihat panduan instalasi).",
    "wiz.p1.mode": "Mode instalasi: {mode}",
    "wiz.p1.mode_token": "Mode token terdeteksi — TunnelDesk hanya menampilkan "
    "status dan panduan (tidak mengelola tunnel token; A-09).",
    "wiz.p1.mode_service": "Windows Service terdeteksi — TunnelDesk hanya "
    "menampilkan status (tidak mengelola service; K-07).",
    "wiz.p1.candidates": "Kandidat file konfigurasi ditemukan: {count}",
    "wiz.p1.candidates_none": "Tidak ada kandidat file konfigurasi ditemukan — "
    "pilih lokasi secara manual pada langkah berikutnya.",
    "wiz.p2.title": "Langkah 2 dari 7 — Pilih File Konfigurasi",
    "wiz.p2.path_label": "File konfigurasi:",
    "wiz.p2.must_select": "Pilih atau ketik lokasi file konfigurasi terlebih dahulu.",
    "wiz.p2.read_failed": "File tidak dapat dibaca: {detail}",
    "wiz.p2.initial_status": "Status konfigurasi saat ini: {status}",
    "wiz.p3.title": "Langkah 3 dari 7 — Susun Konfigurasi (Formulir)",
    "wiz.p3.tunnel": "ID tunnel (UUID):",
    "wiz.p3.credentials": "Referensi credentials-file (path, isi tidak dibaca):",
    "wiz.p3.ingress_title": "Aturan ingress:",
    "wiz.p3.col_hostname": "Hostname (opsional)",
    "wiz.p3.col_service": "Service / origin (wajib)",
    "wiz.p3.add_row": "Tambah baris",
    "wiz.p3.remove_row": "Hapus baris",
    "wiz.p3.empty_service": "Ada baris ingress dengan service kosong — isi "
    "atau hapus baris tersebut.",
    "wiz.p4.title": "Langkah 4 dari 7 — Validasi & Pemeriksaan",
    "wiz.p4.valid": "Konfigurasi usulan VALID menurut skema.",
    "wiz.p4.invalid": "Konfigurasi usulan INVALID — perbaiki formulir sebelum lanjut.",
    "wiz.p4.unknown": "Konfigurasi memuat struktur tak dikenal — tidak dapat "
    "diterapkan otomatis (PRD-02 §3.2); edit manual di luar TunnelDesk.",
    "wiz.p4.origin_title": "Pemeriksaan origin lokal (DNS/HTTPS publik = "
    "fitur Diagnostik):",
    "wiz.p4.origin_skip_catchall": "{service} — catch-all, dilewati",
    "wiz.p4.origin_not_mappable": "{service} — {reason}",
    "wiz.p4.blocked_credentials": "File credential yang dirujuk tidak "
    "ditemukan — apply akan diblokir. TunnelDesk tidak membuat/membaca isi "
    "credential; letakkan file credential di lokasi yang dirujuk, lalu ulangi.",
    "wiz.p5.title": "Langkah 5 dari 7 — Preview Perubahan",
    "wiz.p5.no_changes": "Tidak ada perubahan terdeteksi pada teks usulan.",
    "wiz.p5.notes_title": "Catatan:",
    "wiz.p6.title": "Langkah 6 dari 7 — Konfirmasi",
    "wiz.p6.target": "File target: {path}",
    "wiz.p6.source_hash": "SHA-256 sumber: {sha}",
    "wiz.p6.changes": "Baris ditambahkan: {added} · dihapus: {removed}",
    "wiz.p6.backup_note": "Backup otomatis dibuat TunnelDesk saat apply, "
    "sebelum file diubah.",
    "wiz.p6.apply_hint": "Dengan menekan “Terapkan Perubahan”, perubahan "
    "di atas ditulis ke file secara atomik, lalu divalidasi ulang; bila "
    "validasi ulang gagal, file dikembalikan otomatis.",
    "wiz.p7.title": "Langkah 7 dari 7 — Hasil",
    "wiz.p7.backup_path": "Backup pra-apply: {path}",
    "wiz.p7.restart_note": "Pengaturan origin tersimpan. Mulai ulang "
    "aplikasi agar TunnelController memakai konfigurasi baru (W-5).",
    "wiz.p7.settings_skipped": "Pengaturan origin tidak diubah ({reason}).",
    "wiz.p7.written_hash": "SHA-256 hasil tulis: {sha}",
    "wiz.st.applied": "Konfigurasi diterapkan dan tervalidasi ulang VALID "
    "(bukan klaim tunnel siap dijalankan).",
    "wiz.st.apply_not_confirmed": "Apply membutuhkan konfirmasi eksplisit.",
    "wiz.st.artifact_invalid": "Artefak usulan tidak valid — ulangi dari preview.",
    "wiz.st.preview_stale": "File berubah sejak preview — ulangi dari preview.",
    "wiz.st.path_rejected": "Kebijakan path menolak target: {detail}",
    "wiz.st.validation_failed": "Validasi mencegah penerapan — tidak ada "
    "perubahan pada file.",
    "wiz.st.backup_failed": "Backup pra-apply gagal — apply dibatalkan, "
    "file tidak diubah.",
    "wiz.st.source_changed": "File berubah selama proses — dibatalkan, "
    "tidak ada yang ditulis; ulangi dari preview.",
    "wiz.st.write_failed": "Penulisan atomik gagal — file tidak berubah: {detail}",
    "wiz.st.write_hash_mismatch": "Verifikasi hasil tulis gagal; file "
    "dikembalikan otomatis ke kondisi semula (terverifikasi hash).",
    "wiz.st.post_write_validation_failed": "Validasi ulang pasca-tulis "
    "gagal; file dikembalikan otomatis ke kondisi semula (terverifikasi hash).",
    "wiz.st.rollback_failed": "KRITIS: rollback GAGAL — kondisi file tidak "
    "dapat dikembalikan otomatis. Pulihkan manual dari backup di bawah.",
    "wiz.err.rejected": "Preview ditolak: {reason}",
}


def text(key: str, **format_args: object) -> str:
    """Ambil teks UI (Bahasa Indonesia). KeyError = kunci belum terdaftar
    — disengaja agar string liar terdeteksi saat pengembangan."""
    template = ID[key]
    if format_args:
        return template.format(**format_args)
    return template
