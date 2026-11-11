"""Uji kebijakan path tulis (Task 2.5, Q3b) — PRD-01 §10, PRD-02 §3.3.

Logika daftar direktori sistem diuji PORTABEL sebagai string murni
(injeksi platform), pemeriksaan filesystem (symlink/regular/parent)
diuji nyata di POSIX dan di-skipif di Windows.
"""

from __future__ import annotations

import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from tunneldesk.infrastructure.config_io.path_policy import (
    PathValidationStatus,
    normalize_platform,
    validate_config_write_path,
)

IS_WINDOWS = sys.platform == "win32"


# ----------------------------------------------------------------------
# Struktural + daftar direktori sistem (portabel — logika string murni,
# tanpa akses filesystem; rasa path disematkan per baris uji)
# ----------------------------------------------------------------------
def test_path_relatif_ditolak(tmp_path: Path) -> None:
    result = validate_config_write_path(Path("config.yml"))
    assert result.status is PathValidationStatus.NOT_ABSOLUTE
    assert result.ok is False


def test_path_traversal_ditolak(tmp_path: Path) -> None:
    target = tmp_path / "sub" / ".." / "config.yml"
    assert ".." in target.parts  # prekondisi: pathlib tidak menormalkan
    result = validate_config_write_path(target)
    assert result.status is PathValidationStatus.TRAVERSAL


@pytest.mark.parametrize(
    ("raw", "platform", "flavor"),
    [
        ("/etc/tunnel/config.yml", "posix", PurePosixPath),
        ("/usr/share/cloudflared/config.yml", "posix", PurePosixPath),
        ("/var/tmp/config.yml", "posix", PurePosixPath),
        ("/tmp/config.yml", "posix", PurePosixPath),
        ("/System/Library/config.yml", "posix", PurePosixPath),
        ("C:\\Windows\\config.yml", "windows", PureWindowsPath),
        ("c:\\WINDOWS\\System32\\config.yml", "windows", PureWindowsPath),
        ("C:\\Program Files\\cloudflared\\config.yml", "windows", PureWindowsPath),
        ("C:\\Program Files (x86)\\app\\config.yml", "windows", PureWindowsPath),
        ("C:\\ProgramData\\config.yml", "windows", PureWindowsPath),
    ],
)
def test_direktori_sistem_ditolak_portabel(
    raw: str, platform: str, flavor: type, tmp_path: Path
) -> None:
    """Daftar sistem diuji sebagai logika string murni — tanpa OS target."""
    result = validate_config_write_path(
        flavor(raw), platform=platform, deny_prefixes=[tmp_path]
    )
    assert result.status is PathValidationStatus.SYSTEM_DIRECTORY
    assert result.ok is False


@pytest.mark.parametrize(
    ("raw", "platform", "flavor"),
    [
        ("/etcfoo/config.yml", "posix", PurePosixPath),  # batas komponen
        ("/home/sekolah/cloudflared/config.yml", "posix", PurePosixPath),
        ("C:\\WindowsX\\config.yml", "windows", PureWindowsPath),
        ("C:\\Users\\Sekolah\\config.yml", "windows", PureWindowsPath),
    ],
)
def test_path_di_luar_direktori_sistem_lolos_struktural(
    raw: str, platform: str, flavor: type
) -> None:
    result = validate_config_write_path(flavor(raw), platform=platform)
    # Pemeriksaan berhenti di PARENT_MISSING (path tidak ada di FS nyata)
    # — bukan SYSTEM_DIRECTORY: struktur diterima, filesystem dicek.
    assert result.status is PathValidationStatus.PARENT_MISSING


def test_deny_prefixes_aplikasi_ditolak(tmp_path: Path) -> None:
    denied = tmp_path / "data-aplikasi"
    denied.mkdir()
    target = denied / "config.yml"
    (denied / "config.yml").write_bytes(b"x")
    result = validate_config_write_path(
        target, deny_prefixes=[denied]
    )
    assert result.status is PathValidationStatus.DENIED_PREFIX


def test_path_di_luar_deny_prefixes_diterima(tmp_path: Path) -> None:
    denied = tmp_path / "data-aplikasi"
    allowed = tmp_path / "lain"
    allowed.mkdir()
    result = validate_config_write_path(
        allowed / "config.yml", deny_prefixes=[denied]
    )
    assert result.status is PathValidationStatus.OK
    assert result.ok is True


def test_normalize_platform() -> None:
    assert normalize_platform("win32") == "windows"
    assert normalize_platform("windows") == "windows"
    assert normalize_platform("darwin") == "posix"
    assert normalize_platform("linux") == "posix"
    assert normalize_platform(None) == normalize_platform(sys.platform)


# ----------------------------------------------------------------------
# Filesystem nyata (POSIX; skipif Windows — butuh izin symlink/chmod)
# ----------------------------------------------------------------------
@pytest.mark.skipif(IS_WINDOWS, reason="uji symlink/chmod POSIX")
def test_symlink_target_ditolak(tmp_path: Path) -> None:
    asli = tmp_path / "asli.yml"
    asli.write_text("tunnel: x\n")
    tautan = tmp_path / "tautan.yml"
    tautan.symlink_to(asli)
    result = validate_config_write_path(tautan)
    assert result.status is PathValidationStatus.SYMLINK


@pytest.mark.skipif(IS_WINDOWS, reason="uji symlink/chmod POSIX")
def test_symlink_induk_ditolak(tmp_path: Path) -> None:
    dir_asli = tmp_path / "asli"
    dir_asli.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(dir_asli, target_is_directory=True)
    result = validate_config_write_path(alias / "config.yml")
    assert result.status is PathValidationStatus.PARENT_SYMLINK


def test_induk_tidak_ada_ditolak(tmp_path: Path) -> None:
    result = validate_config_write_path(tmp_path / "tidak-ada" / "config.yml")
    assert result.status is PathValidationStatus.PARENT_MISSING
    assert not (tmp_path / "tidak-ada").exists()  # tidak dibuat otomatis


def test_induk_bukan_direktori_ditolak(tmp_path: Path) -> None:
    berkas = tmp_path / "berkas"
    berkas.write_text("x")
    result = validate_config_write_path(berkas / "config.yml")
    assert result.status is PathValidationStatus.PARENT_NOT_DIRECTORY


def test_target_bukan_regular_file_ditolak(tmp_path: Path) -> None:
    direktori = tmp_path / "config.yml"
    direktori.mkdir()  # target ada tapi berupa direktori
    result = validate_config_write_path(direktori)
    assert result.status is PathValidationStatus.NOT_REGULAR_FILE


def test_target_reguler_baru_diterima(tmp_path: Path) -> None:
    result = validate_config_write_path(tmp_path / "config-baru.yml")
    assert result.status is PathValidationStatus.OK
    assert result.ok is True


def test_target_reguler_ada_diterima(tmp_path: Path) -> None:
    target = tmp_path / "config.yml"
    target.write_text("tunnel: x\n")
    result = validate_config_write_path(target)
    assert result.status is PathValidationStatus.OK


@pytest.mark.skipif(not IS_WINDOWS, reason="junction hanya ada di Windows")
def test_junction_target_ditolak_windows(tmp_path: Path) -> None:
    """Reparse point tipe junction ditolak (keputusan Q3b-5)."""
    import _winapi

    dir_asli = tmp_path / "asli"
    dir_asli.mkdir()
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(dir_asli), str(junction))
    result = validate_config_write_path(junction / "config.yml")
    assert result.status is PathValidationStatus.PARENT_SYMLINK
