"""Uji single-instance lock (E-3, A-13): akuisisi, stale recovery,
perlindungan lock aktif, dan pelepasan yang aman."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tunneldesk.application.single_instance import (
    InstanceAlreadyRunningError,
    InstanceLock,
)


def make_lock(tmp_path: object, nama: str) -> InstanceLock:
    return InstanceLock(tmp_path / f"{nama}.lock", hostname="mesin-uji")


def pid_tanpa_proses() -> int:
    """Pid di luar rentang yang mungkin hidup — deterministik "tidak ada
    proses" pada macOS/Linux/Windows (di luar pid_max mana pun)."""
    return 999_999_999


# ---------------------------------------------------------------------------
# Akuisisi
# ---------------------------------------------------------------------------


def test_akuisisi_pertama_berhasil(tmp_path: Path) -> None:
    lock = make_lock(tmp_path, "uji-1")  # type: ignore[arg-type]
    lock.acquire()
    assert lock.is_acquired() is True
    lock.release()
    assert lock.is_acquired() is False


def test_lock_file_memuat_payload_identitas(
    tmp_path: pytest.TempPathFactory,
) -> None:
    lock = make_lock(tmp_path, "uji-2")  # type: ignore[arg-type]
    lock.acquire()
    payload = json.loads(lock._path.read_text(encoding="utf-8"))  # noqa: SLF001
    assert payload["app"] == "tunneldesk-instance-lock"
    assert isinstance(payload["pid"], int)
    assert payload["hostname"] == "mesin-uji"
    assert payload["token"]
    lock.release()


def test_acquire_berulang_idempoten(tmp_path: Path) -> None:
    lock = make_lock(tmp_path, "uji-3")  # type: ignore[arg-type]
    lock.acquire()
    lock.acquire()
    lock.release()


# ---------------------------------------------------------------------------
# Lock aktif — perlindungan
# ---------------------------------------------------------------------------


def test_instance_kedua_ditolak_selama_pemilik_hidup(
    tmp_path: pytest.TempPathFactory,
) -> None:
    path = tmp_path / "uji-4.lock"
    lock1 = InstanceLock(path, hostname="mesin-uji")
    lock1.acquire()
    lock2 = InstanceLock(path, hostname="mesin-uji")
    with pytest.raises(InstanceAlreadyRunningError):
        lock2.acquire()
    lock1.release()


def test_lock_pemilik_hidup_tidak_terhapus_oleh_acquisisi_gagal(
    tmp_path: pytest.TempPathFactory,
) -> None:
    path = tmp_path / "uji-5.lock"
    lock1 = InstanceLock(path, hostname="mesin-uji")
    lock1.acquire()
    lock2 = InstanceLock(path, hostname="mesin-uji")
    with pytest.raises(InstanceAlreadyRunningError):
        lock2.acquire()
    assert path.exists()  # lock aktif tetap utuh
    lock1.release()


# ---------------------------------------------------------------------------
# Stale recovery
# ---------------------------------------------------------------------------


def test_lock_pemilik_mati_adalah_stale_dan_diambil_alih(
    tmp_path: pytest.TempPathFactory,
) -> None:
    path = tmp_path / "uji-6.lock"
    pid_mati = pid_tanpa_proses()
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "app": "tunneldesk-instance-lock",
                "pid": pid_mati,
                "hostname": "mesin-uji",
                "token": "lama",
                "created_at_epoch": 0.0,
            }
        ),
        encoding="utf-8",
    )
    lock2 = InstanceLock(path, hostname="mesin-uji")
    lock2.acquire()  # stale recovery berhasil
    assert lock2.is_acquired() is True
    lock2.release()


def test_lock_korup_adalah_stale(tmp_path: Path) -> None:
    path = tmp_path / "uji-7.lock"
    path.write_text("{ ini bukan json", encoding="utf-8")
    lock = InstanceLock(path, hostname="mesin-uji")
    lock.acquire()
    lock.release()


def test_lock_bukan_milik_app_adalah_stale(
    tmp_path: pytest.TempPathFactory,
) -> None:
    path = tmp_path / "uji-8.lock"
    path.write_text(json.dumps({"aplikasi": "lain"}), encoding="utf-8")
    lock = InstanceLock(path, hostname="mesin-uji")
    lock.acquire()
    lock.release()


def test_lock_hostname_berbeda_adalah_kandidat_stale(
    tmp_path: pytest.TempPathFactory,
) -> None:
    """Lock dari mesin berbeda tidak dapat divalidasi hidup/matinya —
    diperlakukan sebagai kandidat stale (didokumentasikan di modul)."""
    path = tmp_path / "uji-9.lock"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "app": "tunneldesk-instance-lock",
                "pid": 1,
                "hostname": "mesin-lain",
                "token": "x",
                "created_at_epoch": 0.0,
            }
        ),
        encoding="utf-8",
    )
    lock = InstanceLock(path, hostname="mesin-uji")
    lock.acquire()
    lock.release()


# ---------------------------------------------------------------------------
# Pelepasan aman
# ---------------------------------------------------------------------------


def test_release_tanpa_akuisisi_aman(tmp_path: Path) -> None:
    lock = make_lock(tmp_path, "uji-10")  # type: ignore[arg-type]
    lock.release()  # tanpa error
    assert lock.is_acquired() is False


def test_release_tidak_menghapus_lock_milik_orang_lain(
    tmp_path: pytest.TempPathFactory,
) -> None:
    path = tmp_path / "uji-11.lock"
    lock_lain = InstanceLock(path, hostname="mesin-uji")
    lock_lain.acquire()
    payload_asli = path.read_text(encoding="utf-8")

    lock_kita = InstanceLock(path, hostname="mesin-uji")
    with pytest.raises(InstanceAlreadyRunningError):
        lock_kita.acquire()
    lock_kita.release()  # token kita None — tidak boleh menghapus

    assert path.read_text(encoding="utf-8") == payload_asli
    lock_lain.release()
