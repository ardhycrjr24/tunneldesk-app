"""Uji klasifikasi origin murni (E-3, PRD-01 §8) — tanpa jaringan."""

from __future__ import annotations

import pytest

from tunneldesk.domain.diagnostics.origin import (
    OriginProbeKind,
    OriginProbeOutcome,
    OriginStatus,
    OriginTarget,
    classify_probe_error,
    classify_probe_outcome,
    validate_origin_target,
)

TARGET = OriginTarget(host="127.0.0.1", port=8080)


def test_target_valid() -> None:
    assert validate_origin_target(TARGET) is None


@pytest.mark.parametrize(
    ("host", "port", "potongan_pesan"),
    [
        ("", 80, "host origin kosong"),
        ("   ", 80, "host origin kosong"),
        ("127.0.0.1", 0, "1-65535"),
        ("127.0.0.1", -1, "1-65535"),
        ("127.0.0.1", 65536, "1-65535"),
        ("127.0.0.1", "8080", "bilangan bulat"),
    ],
)
def test_target_invalid(
    host: str, port: object, potongan_pesan: str
) -> None:
    target = OriginTarget(host=host, port=port)  # type: ignore[arg-type]
    pesan = validate_origin_target(target)
    assert pesan is not None
    assert potongan_pesan in pesan


def test_reachable_dengan_http_status_adalah_healthy() -> None:
    hasil = classify_probe_outcome(
        TARGET, OriginProbeOutcome(OriginProbeKind.REACHABLE, http_status=404)
    )
    # server merespons (walau 404) = origin hidup; kode tercatat untuk diagnostik
    assert hasil.status is OriginStatus.HEALTHY
    assert hasil.http_status == 404
    assert "404" in hasil.detail


def test_refused_adalah_unreachable() -> None:
    hasil = classify_probe_outcome(
        TARGET, OriginProbeOutcome(OriginProbeKind.REFUSED)
    )
    assert hasil.status is OriginStatus.UNREACHABLE
    assert "ditolak" in hasil.detail
    assert "127.0.0.1:8080" in hasil.detail


def test_timeout_adalah_unreachable_dengan_catatan_ketidakpastian() -> None:
    hasil = classify_probe_outcome(
        TARGET, OriginProbeOutcome(OriginProbeKind.TIMEOUT)
    )
    assert hasil.status is OriginStatus.UNREACHABLE
    assert "belum dapat dipastikan" in hasil.detail


def test_error_adalah_unknown() -> None:
    hasil = classify_probe_outcome(
        TARGET, OriginProbeOutcome(OriginProbeKind.ERROR, detail="dns gagal")
    )
    assert hasil.status is OriginStatus.UNKNOWN
    assert "dns gagal" in hasil.detail


def test_target_invalid_menghasilkan_misconfigured_meski_probe_reachable() -> None:
    target = OriginTarget(host="", port=80)
    hasil = classify_probe_outcome(
        target, OriginProbeOutcome(OriginProbeKind.REACHABLE, http_status=200)
    )
    assert hasil.status is OriginStatus.MISCONFIGURED


def test_classify_error_adalah_unknown() -> None:
    hasil = classify_probe_error(TARGET, "peledak")
    assert hasil.status is OriginStatus.UNKNOWN
    assert "peledak" in hasil.detail
