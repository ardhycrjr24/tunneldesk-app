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
}


def text(key: str, **format_args: object) -> str:
    """Ambil teks UI (Bahasa Indonesia). KeyError = kunci belum terdaftar
    — disengaja agar string liar terdeteksi saat pengembangan."""
    template = ID[key]
    if format_args:
        return template.format(**format_args)
    return template
