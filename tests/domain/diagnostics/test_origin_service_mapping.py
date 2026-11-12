"""Uji origin_target_from_service (PC-2, Task 2.6) — pemetaan murni.

Kontrak tuple: (target, None) probe-able; (None, None) catch-all; (None,
pesan) tidak dapat dipetakan. Tanpa I/O — sesuai PC-2.
"""

from __future__ import annotations

import pytest

from tunneldesk.domain.diagnostics.origin import (
    OriginTarget,
    origin_target_from_service,
)


def test_http_dengan_port_eksplisit() -> None:
    target, error = origin_target_from_service("http://localhost:8080")
    assert error is None
    assert target == OriginTarget(host="localhost", port=8080, scheme="http")


def test_https_dengan_port_eksplisit() -> None:
    target, error = origin_target_from_service("https://10.0.0.5:8443")
    assert error is None
    assert target == OriginTarget(host="10.0.0.5", port=8443, scheme="https")


def test_http_tanpa_port_pakai_default_80() -> None:
    """Port tanpa nilai eksplisit = semantik URL standar (80/443)."""
    target, error = origin_target_from_service("http://localhost")
    assert error is None
    assert target is not None
    assert target.port == 80


def test_https_tanpa_port_pakai_default_443() -> None:
    target, error = origin_target_from_service("https://rapor.sekolah.sch.id")
    assert error is None
    assert target is not None
    assert target.port == 443


def test_scheme_dan_spasi_dinormalkan() -> None:
    target, error = origin_target_from_service("  HTTP://LocalHost:9000  ")
    assert error is None
    assert target == OriginTarget(host="localhost", port=9000, scheme="http")


def test_ipv6_dalam_kurung() -> None:
    target, error = origin_target_from_service("http://[::1]:8080")
    assert error is None
    assert target is not None
    assert target.host == "::1"
    assert target.port == 8080


@pytest.mark.parametrize(
    "service",
    ["http_status:404", "http_status:200", "http_status:"],
)
def test_catch_all_bukan_error(service: str) -> None:
    """``http_status:`` = (None, None) — dilewati dengan catatan, bukan gagal."""
    target, error = origin_target_from_service(service)
    assert target is None
    assert error is None


@pytest.mark.parametrize(
    ("service", "potongan"),
    [
        ("ftp://localhost:21", "tidak didukung"),
        ("ssh://git@host", "tidak didukung"),
        ("unix:/tmp/sock", "tidak didukung"),
        ("http://:8080", "host origin tidak ditemukan"),
        ("http://localhost:99999", "port origin tidak valid"),
        ("", "service kosong"),
        ("   ", "service kosong"),
    ],
)
def test_tidak_dapat_dipetakan_dengan_pesan(service: str, potongan: str) -> None:
    target, error = origin_target_from_service(service)
    assert target is None
    assert error is not None
    assert potongan in error


def test_port_nol_ditolak_validasi_target() -> None:
    """Port 0 lolos urlparse namun ditolak validasi OriginTarget."""
    target, error = origin_target_from_service("http://localhost:0")
    assert target is None
    assert error is not None
    assert "di luar rentang" in error


def test_service_bukan_string() -> None:
    target, error = origin_target_from_service(None)  # type: ignore[arg-type]
    assert target is None
    assert error is not None
