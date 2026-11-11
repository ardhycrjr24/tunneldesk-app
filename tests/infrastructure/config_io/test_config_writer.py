"""Uji AtomicConfigFileWriter (Task 2.5) — jaminan tulis atomik.

Portabel: byte persis, cleanup temp, verifikasi internal, kebijakan
path via writer, kegagalan terstruktur (OSError-saja). Uji izin POSIX
(skipif Windows) dan simulasi kegagalan via monkeypatch (deterministik,
tanpa operasi destruktif ke file sistem).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

from tunneldesk.domain.config.backup import sha256_hex
from tunneldesk.infrastructure.config_io.config_writer import (
    AtomicConfigFileWriter,
    file_sha256_hex,
)
from tunneldesk.infrastructure.config_io.path_policy import (
    validate_config_write_path,
)

IS_WINDOWS = sys.platform == "win32"
DATA = (
    b"tunnel: 11111111-2222-3333-4444-555555555555\n"
    b"credentials-file: credentials.json\n"
    b"ingress:\n  - service: http_status:404\n"
)

TEMP_GLOB = ".*.tmp-*"


def _temp_leftovers(directory: Path) -> list[Path]:
    return list(directory.glob(TEMP_GLOB))


# ----------------------------------------------------------------------
# Sukses
# ----------------------------------------------------------------------
def test_tulis_sukses_byte_persis_dan_bersih(tmp_path: Path) -> None:
    target = tmp_path / "config.yml"
    writer = AtomicConfigFileWriter()
    writer.write_config_bytes(target, DATA)
    assert target.read_bytes() == DATA
    assert sha256_hex(target.read_bytes()) == sha256_hex(DATA)
    assert _temp_leftovers(tmp_path) == []


def test_tulis_menimpa_dengan_byte_persis(tmp_path: Path) -> None:
    target = tmp_path / "config.yml"
    target.write_bytes(b"lama\n")
    writer = AtomicConfigFileWriter()
    writer.write_config_bytes(target, DATA)
    assert target.read_bytes() == DATA
    assert _temp_leftovers(tmp_path) == []


def test_tulis_binary_byte_persis(tmp_path: Path) -> None:
    """Byte biner (bukan teks) tetap persis — writer tidak menafsirkan."""
    target = tmp_path / "config.yml"
    payload = bytes(range(256)) + b"\r\n\x00"
    AtomicConfigFileWriter().write_config_bytes(target, payload)
    assert target.read_bytes() == payload


def test_file_sha256_hex_helper(tmp_path: Path) -> None:
    target = tmp_path / "a.yml"
    target.write_bytes(DATA)
    assert file_sha256_hex(target) == sha256_hex(DATA)


# ----------------------------------------------------------------------
# Kegagalan — target utuh + temp bersih (monkeypatch deterministik)
# ----------------------------------------------------------------------
def _bersih_dan_utuh(target: Path, original: bytes) -> None:
    assert target.read_bytes() == original
    assert _temp_leftovers(target.parent) == []


def test_gagal_fsync_target_utuh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "config.yml"
    target.write_bytes(DATA)
    writer = AtomicConfigFileWriter()

    def fsync_gagal(fd: int) -> None:
        raise OSError(5, "simulasi fsync gagal")

    monkeypatch.setattr(os, "fsync", fsync_gagal)
    with pytest.raises(OSError):
        writer.write_config_bytes(target, b"baru\n")
    _bersih_dan_utuh(target, DATA)


def test_gagal_tulis_temp_target_utuh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "config.yml"
    target.write_bytes(DATA)
    writer = AtomicConfigFileWriter()

    def open_gagal(*args: object, **kwargs: object) -> int:
        raise OSError(28, "simulasi disk penuh (tulis temp gagal)")

    monkeypatch.setattr(os, "open", open_gagal)
    with pytest.raises(OSError):
        writer.write_config_bytes(target, b"baru\n")
    _bersih_dan_utuh(target, DATA)


def test_gagal_verifikasi_temp_target_utuh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Self-verifikasi hash temp mendeteksi isi temp korup → batal."""
    target = tmp_path / "config.yml"
    target.write_bytes(DATA)
    writer = AtomicConfigFileWriter()
    monkeypatch.setattr(
        "tunneldesk.infrastructure.config_io.config_writer._sha256_of_handle",
        lambda handle: "0" * 64,  # hash palsu ≠ hash data → verifikasi gagal
    )
    with pytest.raises(OSError):
        writer.write_config_bytes(target, DATA)
    _bersih_dan_utuh(target, DATA)


def test_gagal_replace_target_utuh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulasi target terkunci (Windows: WinError 32) — gagal
    terstruktur, temp dibersihkan, target tidak tersentuh."""
    target = tmp_path / "config.yml"
    target.write_bytes(DATA)
    writer = AtomicConfigFileWriter()

    def replace_gagal(*args: object, **kwargs: object) -> None:
        raise PermissionError(32, "simulasi target terkunci proses lain")

    monkeypatch.setattr(os, "replace", replace_gagal)
    with pytest.raises(OSError):
        writer.write_config_bytes(target, b"baru\n")
    _bersih_dan_utuh(target, DATA)


def test_induk_tidak_ada_gagal_tanpa_membuat(
    tmp_path: Path,
) -> None:
    target = tmp_path / "tidak-ada" / "config.yml"
    with pytest.raises(OSError):
        AtomicConfigFileWriter().write_config_bytes(target, DATA)
    assert not (tmp_path / "tidak-ada").exists()


@pytest.mark.skipif(IS_WINDOWS, reason="chmod direktori POSIX")
def test_permission_ditolak_target_utuh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "config.yml").write_bytes(DATA)
    os.chmod(sub, 0o500)  # baca+eksekusi saja → tulis temp gagal
    try:
        with pytest.raises(OSError):
            AtomicConfigFileWriter().write_config_bytes(
                sub / "config.yml", b"baru\n"
            )
    finally:
        os.chmod(sub, 0o700)
    _bersih_dan_utuh(sub / "config.yml", DATA)


@pytest.mark.skipif(IS_WINDOWS, reason="chmod POSIX")
def test_chmod_izin_lama_gagal_dilaporkan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kegagalan pemeliharaan izin dilaporkan eksplisit (Q3a) — target
    tidak tersentuh."""
    target = tmp_path / "config.yml"
    target.write_bytes(DATA)
    os.chmod(target, 0o640)
    writer = AtomicConfigFileWriter()

    def chmod_gagal(*args: object, **kwargs: object) -> None:
        raise PermissionError(1, "simulasi chmod gagal")

    monkeypatch.setattr(os, "chmod", chmod_gagal)
    with pytest.raises(OSError):
        writer.write_config_bytes(target, b"baru\n")
    _bersih_dan_utuh(target, DATA)


# ----------------------------------------------------------------------
# Izin (keputusan PO Q3a)
# ----------------------------------------------------------------------
@pytest.mark.skipif(IS_WINDOWS, reason="mode bit POSIX")
def test_izin_file_lama_dipertahankan(tmp_path: Path) -> None:
    target = tmp_path / "config.yml"
    target.write_bytes(DATA)
    os.chmod(target, 0o640)
    AtomicConfigFileWriter().write_config_bytes(target, b"baru\n")
    assert target.read_bytes() == b"baru\n"
    assert os.stat(target).st_mode & 0o777 == 0o640


@pytest.mark.skipif(IS_WINDOWS, reason="mode bit POSIX")
def test_izin_file_baru_ketat_0600(tmp_path: Path) -> None:
    target = tmp_path / "config-baru.yml"
    AtomicConfigFileWriter().write_config_bytes(target, DATA)
    assert os.stat(target).st_mode & 0o777 == 0o600


def test_windows_tanpa_chmod_dokumentasi(tmp_path: Path) -> None:
    """Di Windows writer tidak memanggil chmod (ACL mengikuti profil);
    tulis tetap berhasil — perilaku terdokumentasi, bukan padanan POSIX."""
    target = tmp_path / "config.yml"
    AtomicConfigFileWriter(platform="windows").write_config_bytes(target, DATA)
    assert target.read_bytes() == DATA


# ----------------------------------------------------------------------
# Kebijakan path via writer (pertahanan terakhir Q3b)
# ----------------------------------------------------------------------
def test_writer_menolak_path_relatif() -> None:
    with pytest.raises(OSError):
        AtomicConfigFileWriter().write_config_bytes(Path("config.yml"), DATA)


def test_writer_menolak_traversal(tmp_path: Path) -> None:
    target = tmp_path / "sub" / ".." / "config.yml"
    with pytest.raises(OSError):
        AtomicConfigFileWriter().write_config_bytes(target, DATA)


def test_writer_menolak_symlink_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TOCTOU deterministik: path sah divalidasi, lalu target DITUKAR
    menjadi symlink — writer (pertahanan terakhir) menolak tanpa tulis."""
    if IS_WINDOWS:
        pytest.skip("pembuatan symlink butuh hak khusus di Windows")
    target = tmp_path / "config.yml"
    target.write_bytes(DATA)
    pengganti = tmp_path / "lain.yml"
    pengganti.write_bytes(b"x")
    result = validate_config_write_path(target)
    assert result.ok  # sah saat divalidasi
    target.unlink()
    target.symlink_to(pengganti)  # tukar SETELAH validasi (simulasi race)
    with pytest.raises(OSError):
        AtomicConfigFileWriter().write_config_bytes(target, b"baru\n")
    assert os.path.islink(target)  # symlink tidak ditulis/diganti


def test_writer_menolak_direktori_sistem_windows_portabel(
    tmp_path: Path,
) -> None:
    """Kebijakan Windows diuji portabel (logika string) — writer
    menolak sebelum menyentuh filesystem."""
    from pathlib import PureWindowsPath

    with pytest.raises(OSError):
        AtomicConfigFileWriter(platform="windows").write_config_bytes(
            PureWindowsPath("C:\\Windows\\notepad.cfg"), DATA
        )


def test_writer_path_non_regular_ditolak(tmp_path: Path) -> None:
    direktori = tmp_path / "config.yml"
    direktori.mkdir()
    with pytest.raises(OSError):
        AtomicConfigFileWriter().write_config_bytes(direktori, DATA)
    assert direktori.is_dir()  # direktori tidak dihapus/diganti


# ----------------------------------------------------------------------
# T-1 (koreksi audit) — adversarial parent-swap TOCTOU, deterministik
# ----------------------------------------------------------------------
def _tukar_parent_ke_terlarang(target: Path, terlarang: Path) -> None:
    """Simulasi penyerang: tukar direktori induk menjadi symlink ke
    direktori terlarang (skenario asli eksperimen audit 1).

    Berbasis rename agar bekerja meski direktori masih berisi file (mis.
    file temp yang belum direname): inode asli tetap ada di lokasi baru,
    path lama kini menunjuk direktori terlarang.
    """
    moved = target.parent.with_name(target.parent.name + "-dipindah")
    os.rename(target.parent, moved)
    target.parent.symlink_to(terlarang)


@pytest.fixture()
def panggung_t1(tmp_path: Path) -> tuple[Path, Path, Path]:
    """real_dir (sah) + terlarang (harusnya ditolak) + target di real_dir."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    terlarang = tmp_path / "terlarang"
    terlarang.mkdir()
    target = real_dir / "config.yml"
    target.write_bytes(b"original\n")
    return target, terlarang, real_dir


def _tidak_ada_yang_mendarat(terlarang: Path) -> None:
    """Direktori terlarang TIDAK berisi config maupun file temp."""
    assert not (terlarang / "config.yml").exists()
    assert list(terlarang.glob(".*.tmp-*")) == []


@pytest.mark.skipif(IS_WINDOWS, reason="jalur dir_fd POSIX")
def test_t1_parent_swap_setelah_validasi_ditolak(
    panggung_t1: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Jalur dir_fd: penukaran induk SETELAH validasi entry → os.open
    O_NOFOLLOW gagal (ELOOP) — TIDAK ada tulisan ke direktori terlarang."""
    target, terlarang, _ = panggung_t1
    import tunneldesk.infrastructure.config_io.config_writer as cw

    real_validate = cw.validate_config_write_path

    def validate_lalu_tukar(t: Path, **kwargs: object):
        result = real_validate(t, **kwargs)  # validasi SAH (sebelum tukar)
        if result.ok:
            _tukar_parent_ke_terlarang(target, terlarang)
        return result

    monkeypatch.setattr(cw, "validate_config_write_path", validate_lalu_tukar)
    with pytest.raises(OSError):
        AtomicConfigFileWriter().write_config_bytes(target, b"baru\n")
    _tidak_ada_yang_mendarat(terlarang)


@pytest.mark.skipif(IS_WINDOWS, reason="jalur dir_fd POSIX")
def test_t1_dir_fd_mengikat_tulisan_ke_direktori_tervalidasi(
    panggung_t1: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pinning fd: penukaran induk tepat sebelum replace → replace tetap
    terjadi DI DALAM inode yang tervalidasi; direktori terlarang kosong."""
    target, terlarang, _ = panggung_t1
    real_replace = os.replace

    def replace_lalu_tukar(*args: object, **kwargs: object):
        if not target.parent.is_symlink():
            _tukar_parent_ke_terlarang(target, terlarang)
        return real_replace(*args, **kwargs)  # dir_fd → inode tervalidasi

    monkeypatch.setattr(os, "replace", replace_lalu_tukar)
    AtomicConfigFileWriter().write_config_bytes(target, b"baru\n")
    _tidak_ada_yang_mendarat(terlarang)


def test_t1_fallback_penjaga_identitas_menolak(
    panggung_t1: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Jalur fallback (Windows/tanpa dir_fd): penjaga identitas (dev,ino)
    — direkam SEBELUM validasi — mendeteksi penukaran induk dan batal."""
    target, terlarang, _ = panggung_t1
    import tunneldesk.infrastructure.config_io.config_writer as cw

    monkeypatch.setattr(os, "supports_dir_fd", frozenset())  # paksa fallback
    real_validate = cw.validate_config_write_path

    def validate_lalu_tukar(t: Path, **kwargs: object):
        result = real_validate(t, **kwargs)
        if result.ok:
            _tukar_parent_ke_terlarang(target, terlarang)
        return result

    monkeypatch.setattr(cw, "validate_config_write_path", validate_lalu_tukar)
    with pytest.raises(OSError, match="berubah selama penulisan"):
        AtomicConfigFileWriter().write_config_bytes(target, b"baru\n")
    _tidak_ada_yang_mendarat(terlarang)


def test_t1_fallback_temp_di_direktori_tukar_dibersihkan(
    panggung_t1: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Jalur fallback: temp sempat tercipta di direktori tertukar →
    penjaga identitas #1 (setelah mkstemp) batal + temp dibersihkan."""
    target, terlarang, _ = panggung_t1
    monkeypatch.setattr(os, "supports_dir_fd", frozenset())  # paksa fallback
    real_mkstemp = tempfile.mkstemp

    def mkstemp_lalu_tukar(*args: object, **kwargs: object):
        _tukar_parent_ke_terlarang(target, terlarang)
        return real_mkstemp(*args, **kwargs)  # temp tercipta di terlarang

    monkeypatch.setattr(tempfile, "mkstemp", mkstemp_lalu_tukar)
    with pytest.raises(OSError, match="berubah selama penulisan"):
        AtomicConfigFileWriter().write_config_bytes(target, b"baru\n")
    _tidak_ada_yang_mendarat(terlarang)


def test_t1_fallback_verifikasi_temp_gagal(
    panggung_t1: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Jalur fallback: verifikasi hash temp gagal → batal, target utuh,
    temp bersih (jalur fallback tetap teruji di POSIX)."""
    target, terlarang, _ = panggung_t1
    monkeypatch.setattr(os, "supports_dir_fd", frozenset())  # paksa fallback
    monkeypatch.setattr(
        "tunneldesk.infrastructure.config_io.config_writer.file_sha256_hex",
        lambda path: "0" * 64,
    )
    with pytest.raises(OSError):
        AtomicConfigFileWriter().write_config_bytes(target, b"baru\n")
    assert target.read_bytes() == b"original\n"
    _tidak_ada_yang_mendarat(terlarang)
    assert not target.is_symlink()
