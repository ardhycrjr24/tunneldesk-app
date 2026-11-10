"""Uji domain deteksi (E-5): parsing versi, dedupe, klasifikasi mode."""

from __future__ import annotations

from pathlib import Path

import pytest

from tunneldesk.domain.tunnel.detection import (
    DetectionConfidence,
    DetectionSource,
    ExecutableFinding,
    InstallMode,
    ModeIndicator,
    classify_mode,
    dedupe_executables,
    parse_version_output,
)

EXE = Path("/usr/local/bin/cloudflared")


# ---------------------------------------------------------------------------
# parse_version_output (R-07: toleran format)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("cloudflared version 2024.8.3 (built 2024-08-01)", "2024.8.3"),
        ("cloudflared version 2025.1.1", "2025.1.1"),
        ("Cloudflared Version 2024.8.3", "2024.8.3"),  # case-insensitive
        ("baris lain\n2026.1.0 build dev\nbaris akhir", "2026.1.0"),
    ],
)
def test_parse_version_dikenal(output: str, expected: str) -> None:
    assert parse_version_output(output) == expected


@pytest.mark.parametrize(
    "output",
    ["", "teks tanpa versi", "version format aneh: abc-def"],
)
def test_parse_version_tidak_dikenal(output: str) -> None:
    assert parse_version_output(output) is None


# ---------------------------------------------------------------------------
# dedupe executables
# ---------------------------------------------------------------------------


def test_dedupe_path_duplikat_pertama_dipertahankan() -> None:
    findings = (
        ExecutableFinding(EXE, DetectionSource.PATH, "2024.8.3"),
        ExecutableFinding(EXE, DetectionSource.COMMON_LOCATION, None, "dup"),
    )
    result = dedupe_executables(findings)
    assert len(result) == 1
    assert result[0].source is DetectionSource.PATH
    assert result[0].version == "2024.8.3"


def test_dedupe_path_berbeda_semua_dipertahankan() -> None:
    findings = (
        ExecutableFinding(EXE, DetectionSource.PATH, "2024.8.3"),
        ExecutableFinding(Path("/usr/bin/cloudflared"), DetectionSource.COMMON_LOCATION),
    )
    assert len(dedupe_executables(findings)) == 2


# ---------------------------------------------------------------------------
# classify_mode — matriks keputusan
# ---------------------------------------------------------------------------


def test_service_terdaftar_menang_dan_pasti() -> None:
    indicators = (
        ModeIndicator(InstallMode.CONFIG_FILE, "config.yml ada", True),
        ModeIndicator(InstallMode.SERVICE, "sc query RUNNING", True),
    )
    mode, certain, explanation = classify_mode(indicators)
    assert mode is InstallMode.SERVICE
    assert certain is True
    assert "di luar TunnelDesk" in explanation


def test_config_file_saja_pasti() -> None:
    indicators = (ModeIndicator(InstallMode.CONFIG_FILE, "config.yml ada"),)
    mode, certain, explanation = classify_mode(indicators)
    assert mode is InstallMode.CONFIG_FILE
    assert certain is True
    assert "config.yml" in explanation


def test_token_saja_tidak_pasti() -> None:
    indicators = (
        ModeIndicator(InstallMode.TOKEN, "tanpa file konfigurasi", False),
    )
    mode, certain, explanation = classify_mode(indicators)
    assert mode is InstallMode.TOKEN
    assert certain is False
    assert "tidak pasti" in explanation


def test_mode_tidak_diketahui_tanpa_indikator() -> None:
    mode, certain, explanation = classify_mode(())
    assert mode is InstallMode.UNKNOWN
    assert certain is False
    assert explanation


def test_service_non_definitif_tidak_menang() -> None:
    indicators = (
        ModeIndicator(InstallMode.CONFIG_FILE, "config.yml ada", True),
        ModeIndicator(InstallMode.SERVICE, "probe ragu", False),
    )
    mode, certain, _ = classify_mode(indicators)
    assert mode is InstallMode.CONFIG_FILE
    assert certain is True


def test_confidence_enum_tersedia() -> None:
    assert DetectionConfidence.CONFIRMED is not None
    assert DetectionSource.SERVICE_QUERY is not None
