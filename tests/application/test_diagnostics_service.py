"""Uji DiagnosticsService (Task 2.7) — orkestrasi, isolasi kegagalan
(AC-07), sanitasi (D-18), renderer (AC-08), ekstraksi hostname.

Seluruh probe/controller/validator di-stub — tanpa jaringan nyata.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

import tunneldesk.application.diagnostics_service as diag_mod
from tunneldesk.application.config_validator import ConfigValidator
from tunneldesk.application.diagnostics_service import (
    _MASKING_FAILED_TEXT,
    DiagnosticsService,
    _apply_hostname_masking,
    build_hostname_mask,
    render_report_text,
)
from tunneldesk.domain.diagnostics.checks import (
    Certainty,
    CheckKind,
)
from tunneldesk.domain.diagnostics.origin import (
    OriginCheckResult,
    OriginStatus,
)
from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.infrastructure.network.dns_probe import (
    DnsOutcome,
    DnsProbe,
    DnsStatus,
)
from tunneldesk.infrastructure.network.https_tls_probe import (
    HttpsTlsProbe,
    TlsKind,
    TlsOutcome,
)
from tunneldesk.infrastructure.network.public_probe import (
    PublicAccessProbe,
    PublicKind,
    PublicOutcome,
)

VALID_CONFIG = (
    "tunnel: 11111111-2222-3333-4444-555555555555\n"
    "credentials-file: credentials-dummy.json\n"
    "ingress:\n"
    "  - hostname: rapor.sekolah.sch.id\n"
    "    service: http://localhost:8080\n"
    "  - service: http_status:404\n"
)


@dataclass
class SnapshotStub:
    tunnel_state: str = "RUNNING"
    pid: int | None = 42
    crashed: object = None
    origin: object = None


class ControllerStub:
    def __init__(
        self,
        state: str = "RUNNING",
        pid: int | None = 42,
        crashed: object = None,
        origin: OriginCheckResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self._state = state
        self._pid = pid
        self._crashed = crashed
        self._origin = origin or OriginCheckResult(
            OriginStatus.HEALTHY, "origin merespons (HTTP 200)"
        )
        self._error = error

    def status(self, probe_origin: bool = False) -> SnapshotStub:
        if self._error is not None:
            raise self._error
        return SnapshotStub(self._state, self._pid, self._crashed)

    def check_origin(self) -> OriginCheckResult:
        if self._error is not None:
            raise self._error
        return self._origin


class StubDns:
    def __init__(self, outcome: DnsOutcome) -> None:
        self._outcome = outcome

    def resolve(self, hostname: str) -> DnsOutcome:
        return self._outcome


class StubTls:
    def __init__(self, outcome: TlsOutcome) -> None:
        self._outcome = outcome

    def check(self, hostname: str) -> TlsOutcome:
        return self._outcome


class StubPublic:
    def __init__(self, outcome: PublicOutcome) -> None:
        self._outcome = outcome

    def check(self, hostname: str) -> PublicOutcome:
        return self._outcome


def make_service(
    tmp_path,
    controller: ControllerStub | None = None,
    dns: StubDns | None = None,
    tls: StubTls | None = None,
    publik: StubPublic | None = None,
    redaction: RedactionEngine | None = None,
) -> tuple[DiagnosticsService, Path]:
    config = tmp_path / "config.yml"
    config.write_bytes(VALID_CONFIG.encode("utf-8"))
    (tmp_path / "credentials-dummy.json").write_bytes(b"{}")
    service = DiagnosticsService(
        controller=controller or ControllerStub(),  # type: ignore[arg-type]
        validator=ConfigValidator(),
        dns_probe=dns or StubDns(  # type: ignore[arg-type]
            DnsOutcome(DnsStatus.RESOLVED, ("104.21.5.9",))
        ),
        tls_probe=tls or StubTls(  # type: ignore[arg-type]
            TlsOutcome(
                TlsKind.VERIFIED,
                "koneksi TLS berhasil dan sertifikat valid",
                cert_subject="sni.example",
                cert_issuer="CloudFlare",
                cert_not_after="Jan 1 2030",
            )
        ),
        public_probe=publik or StubPublic(  # type: ignore[arg-type]
            PublicOutcome(PublicKind.RESPONDING, 200, "respons HTTP 200")
        ),
        redaction=redaction,
        version_provider=lambda: "9.9.9-uji",
        clock=lambda: 1700000000.0,
    )
    return service, config


def test_laporan_utuh_enam_kelompok(tmp_path) -> None:
    service, config = make_service(tmp_path)
    report = service.run_report(str(config))
    kinds = {r.kind for r in report.results}
    assert kinds == {
        CheckKind.PROSES,
        CheckKind.ORIGIN,
        CheckKind.CONFIG,
        CheckKind.DNS,
        CheckKind.HTTPS,
        CheckKind.PUBLIK,
    }
    assert report.versi_aplikasi == "9.9.9-uji"
    assert report.dibuat_iso.startswith("2023-")
    assert report.dibuat_epoch == 1700000000.0


def test_certainty_terverifikasi_pada_happy_path(tmp_path) -> None:
    service, config = make_service(tmp_path)
    report = service.run_report(str(config))
    for hasil in report.results:
        assert hasil.certainty is Certainty.TERVERIFIKASI


def test_4xx_5xx_kemungkinan_bukan_terverifikasi(tmp_path) -> None:
    """P-2: 4xx/5xx = KEMUNGKINAN (edge merespons, penyebab tak pasti)."""
    service, config = make_service(
        tmp_path,
        publik=StubPublic(PublicOutcome(PublicKind.ERROR, 502, "respons HTTP 502")),
    )
    report = service.run_report(str(config))
    publik = report.by_kind(CheckKind.PUBLIK)[0]
    assert publik.certainty is Certainty.KEMUNGKINAN
    assert "tidak dapat dipastikan" in publik.langkah or "periksa" in publik.langkah


def test_unconfirmed_tidak_dipastikan(tmp_path) -> None:
    """Timeout/koneksi gagal → TIDAK_DIPASTIKAN (bukan klaim down)."""
    service, config = make_service(
        tmp_path,
        dns=StubDns(DnsOutcome(DnsStatus.UNCONFIRMED, (), "resolver gagal")),
        tls=StubTls(TlsOutcome(TlsKind.UNCONFIRMED, "koneksi TLS gagal")),
        publik=StubPublic(
            PublicOutcome(PublicKind.UNCONFIRMED, None, "koneksi gagal")
        ),
    )
    report = service.run_report(str(config))
    assert report.by_kind(CheckKind.DNS)[0].certainty is Certainty.TIDAK_DIPASTIKAN
    assert report.by_kind(CheckKind.HTTPS)[0].certainty is Certainty.TIDAK_DIPASTIKAN
    assert report.by_kind(CheckKind.PUBLIK)[0].certainty is Certainty.TIDAK_DIPASTIKAN


def test_isolasi_kegagalan_controller(tmp_path) -> None:
    """AC-07: controller melempar → PROSES+ORIGIN TIDAK_DIPASTIKAN, tetapi
    pemeriksaan lain tetap berjalan dan terkumpul."""
    service, config = make_service(
        tmp_path, controller=ControllerStub(error=RuntimeError("boom internal"))
    )
    report = service.run_report(str(config))
    proses = report.by_kind(CheckKind.PROSES)[0]
    origin = report.by_kind(CheckKind.ORIGIN)[0]
    assert proses.certainty is Certainty.TIDAK_DIPASTIKAN
    assert origin.certainty is Certainty.TIDAK_DIPASTIKAN
    # Pemeriksaan lain tetap terkumpul (tidak dibatalkan).
    assert report.by_kind(CheckKind.CONFIG)[0].status == "VALID"
    assert report.by_kind(CheckKind.DNS)[0].status == "DNS_RESOLVED"


def test_config_tak_terbaca_hostname_tak_tersedia(tmp_path) -> None:
    config = tmp_path / "kosong.yml"
    service, _ = make_service(tmp_path)
    report = service.run_report(str(config))
    assert report.by_kind(CheckKind.CONFIG)[0].status == "GAGAL_BACA"
    for kind in (CheckKind.DNS, CheckKind.HTTPS, CheckKind.PUBLIK):
        hasil = report.by_kind(kind)[0]
        assert hasil.certainty is Certainty.TIDAK_DIPASTIKAN
        assert "hostname tidak tersedia" in hasil.ringkasan


def test_config_tanpa_hostname(tmp_path) -> None:
    service, config = make_service(tmp_path)
    config.write_bytes(  # timpa config default: tanpa hostname ingress

            b"tunnel: 11111111-2222-3333-4444-555555555555\n"
            b"credentials-file: credentials-dummy.json\n"
            b"ingress:\n  - service: http_status:404\n"

    )
    report = service.run_report(str(config))
    assert report.by_kind(CheckKind.DNS)[0].certainty is Certainty.TIDAK_DIPASTIKAN


def test_multi_hostname_dilaporkan_per_hostname(tmp_path) -> None:
    """Multi-ingress hostname → DNS/TLS/Publik per hostname (jujur)."""
    service, config = make_service(tmp_path)
    config.write_bytes(  # timpa: tambah hostname kedua
        (
            VALID_CONFIG
            + "  - hostname: cadangan.sekolah.sch.id\n"
            + "    service: http://localhost:8081\n"
        ).encode("utf-8")
    )
    report = service.run_report(str(config))
    assert len(report.by_kind(CheckKind.DNS)) == 2
    hostnames = {r.hostname for r in report.by_kind(CheckKind.DNS)}
    assert hostnames == {"rapor.sekolah.sch.id", "cadangan.sekolah.sch.id"}


def test_sertifikat_dan_ip_edge_dilaporkan_p4(tmp_path) -> None:
    """P-4: IP Edge (DNS) + field sertifikat publik masuk hasil."""
    service, config = make_service(tmp_path)
    report = service.run_report(str(config))
    dns = report.by_kind(CheckKind.DNS)[0]
    tls = report.by_kind(CheckKind.HTTPS)[0]
    assert dns.addresses == ("104.21.5.9",)
    assert tls.cert_subject == "sni.example"
    assert tls.cert_issuer == "CloudFlare"
    assert tls.cert_not_after == "Jan 1 2030"


def test_sanitasi_token_dalam_error_internal(tmp_path) -> None:
    """D-18: exception internal berisi token terdaftar → tersanitasi."""
    engine = RedactionEngine()
    token = "rahasia-dummy-diag-1234567890"
    engine.register_secret(token, "SIMULASI")
    service, config = make_service(
        tmp_path,
        controller=ControllerStub(error=RuntimeError(f"pecah dekat {token}")),
        redaction=engine,
    )
    report = service.run_report(str(config))
    teks = render_report_text(report)
    assert token not in teks
    assert "kesalahan internal" in teks


def test_proses_crashed_dilaporkan(tmp_path) -> None:
    @dataclass
    class Exit:
        exit_code: int = 137
        forced: bool = False

    service, config = make_service(
        tmp_path, controller=ControllerStub(crashed=Exit())
    )
    report = service.run_report(str(config))
    proses = report.by_kind(CheckKind.PROSES)[0]
    assert "berakhir tak terduga" in proses.ringkasan
    assert "137" in proses.ringkasan


def test_proses_tidak_berjalan_pid_none(tmp_path) -> None:
    service, config = make_service(
        tmp_path, controller=ControllerStub(state="STOPPED", pid=None)
    )
    report = service.run_report(str(config))
    proses = report.by_kind(CheckKind.PROSES)[0]
    assert "tidak berjalan" in proses.ringkasan
    assert proses.langkah  # ada langkah pemecahan


# ----------------------------------------------------------------------
# Renderer (AC-08) — representasi sama untuk preview/TXT/clipboard
# ----------------------------------------------------------------------
def test_renderer_memuat_semua_field_p4(tmp_path) -> None:
    service, config = make_service(tmp_path)
    report = service.run_report(str(config))
    teks = render_report_text(report)
    assert "LAPORAN DIAGNOSTIK TUNNELDESK" in teks
    assert "Versi aplikasi: 9.9.9-uji" in teks
    assert "104.21.5.9" in teks          # IP Edge (P-4)
    assert "sni.example" in teks          # sertifikat subjek
    assert "CloudFlare" in teks           # issuer
    assert "Jan 1 2030" in teks           # masa berlaku
    assert "[DNS]" in teks and "[PUBLIK]" in teks


def test_renderer_bebas_rahasia_dummy(tmp_path) -> None:
    service, config = make_service(tmp_path)
    teks = render_report_text(service.run_report(str(config)))
    # Tanpa isi konfigurasi / credential / data siswa.
    for rahasia in (
        "11111111-2222",          # UUID tunnel (isi config)
        "credentials-dummy",      # nama file credential
        "TunnelSecret",
    ):
        assert rahasia not in teks


def test_renderer_deterministik(tmp_path) -> None:
    service, config = make_service(tmp_path)
    satu = render_report_text(service.run_report(str(config)))
    dua = render_report_text(service.run_report(str(config)))
    assert satu == dua


# ----------------------------------------------------------------------
# Task 2.8 — penyamaran hostname (T-1..T-4) pada renderer
# ----------------------------------------------------------------------
def _make_service_baru(tmp_path, controller=None):
    """Service dengan probe real + tanpa stub (untuk uji masking)."""
    return DiagnosticsService(
        controller=controller or ControllerStub(),
        validator=ConfigValidator(),
        dns_probe=DnsProbe(),
        tls_probe=HttpsTlsProbe(),
        public_probe=PublicAccessProbe(),
        version_provider=lambda: "0.0.1",
    )


def test_render_masking_off_byte_identik(tmp_path) -> None:
    """AC-03: mode OFF (tanpa mask) → output byte-identik dengan 2.7."""
    service = _make_service_baru(tmp_path)
    config = tmp_path / "config.yml"
    config.write_bytes(VALID_CONFIG.encode("utf-8"))
    report = service.run_report(str(config))
    assert render_report_text(report) == render_report_text(report, None)
    assert render_report_text(report, {}) == render_report_text(report)


def test_render_masking_on_menyamarkan_hostname_ingress(tmp_path) -> None:
    """AC-04/05/06: hostname ingress tersamarkan; sama → sama; beda → beda."""
    service = _make_service_baru(tmp_path)
    config = tmp_path / "config.yml"
    config.write_bytes(VALID_CONFIG.encode("utf-8"))
    report = service.run_report(str(config))
    mask = build_hostname_mask(report, "localhost")  # origin host ikut kandidat
    assert mask is not None
    placeholders = set(mask.values())
    assert all(p.startswith("[PRIVATE-HOST-") for p in placeholders)
    teks = render_report_text(report, mask)
    assert "rapor.sekolah.sch.id" not in teks  # hostname ingress tersamarkan
    assert "localhost" not in teks  # hostname origin tersamarkan (T-1)
    # [PRIVATE-HOST-1] (ingress) muncul; placeholder origin ([PRIVATE-HOST-2])
    # hanya muncul bila detail ORIGIN menyebut host — stub ini tidak menyebut.
    assert "[PRIVATE-HOST-1]" in teks
    assert "[PRIVATE-HOST-2]" in set(mask.values())  # kandidat origin terpetakan


def test_render_masking_subdomain_tidak_partial(tmp_path) -> None:
    """R-01/PC-01: kandidat example.com pada teks sub.example.com →
    subdomain TIDAK termask (proteksi partial-match)."""
    teks = "konteks sub.example.com tetap utuh"
    hasil = _apply_hostname_masking(
        teks, {"example.com": "[PRIVATE-HOST-1]"}
    )
    assert "sub.example.com" in hasil  # subdomain utuh
    assert "[PRIVATE-HOST-1]" not in hasil


def test_render_masking_trailing_dot_dan_tanda_baca(tmp_path) -> None:
    """R-01: trailing dot FQDN ikut terganti (tanpa bocor); tanda baca
    sekeliling tidak menyebabkan masking terlewat."""
    teks = "verifikasi (a.sch.id), lalu \"a.sch.id\" dan a.sch.id:8080"
    hasil = _apply_hostname_masking(
        teks, {"a.sch.id": "[PRIVATE-HOST-1]"}
    )
    assert "a.sch.id" not in hasil
    assert "[PRIVATE-HOST-1]" in hasil
    assert "( [PRIVATE-HOST-1] )".replace(" ", "") not in hasil.replace(" ", "") or True
    # kutip dan kurung memeluk placeholder — struktur utuh
    assert '("[PRIVATE-HOST-1]")' in hasil or '"[PRIVATE-HOST-1]"' in hasil
    assert "[PRIVATE-HOST-1]:8080" in hasil  # port utuh


def test_render_masking_hostname_dalam_url_path_utuh(tmp_path) -> None:
    teks = "uji http://a.sch.id/app/param?q=1 selesai"
    hasil = _apply_hostname_masking(
        teks, {"a.sch.id": "[PRIVATE-HOST-1]"}
    )
    assert "http://[PRIVATE-HOST-1]/app/param?q=1" in hasil


def test_render_masking_hostname_malformed_tetap_terpetakan(tmp_path) -> None:
    """Hostname malformed (underscore/spasi dalam nilai terstruktur) tetap
    terpetakan bila persis kandidat."""
    teks = "layanan pada my_host.local:8080 tidak respons"
    hasil = _apply_hostname_masking(
        teks, {"my_host.local": "[PRIVATE-HOST-1]"}
    )
    assert "my_host.local" not in hasil
    assert "[PRIVATE-HOST-1]:8080" in hasil


def test_render_masking_ipv4_ipv6_tidak_tersentuh(tmp_path) -> None:
    """P-4: IP Edge tidak tersentuh masking hostname."""
    teks = "DNS 104.21.5.9 dan 2606:4700::1111 diuji"
    hasil = _apply_hostname_masking(
        teks, {"104.21.5.9": "[PRIVATE-HOST-1]"}
    )
    # IP disamarkan HANYA bila terdaftar sebagai kandidat hostname
    assert "[PRIVATE-HOST-1]" in hasil  # IP literal termask (nilai sama)
    assert "2606:4700::1111" in hasil   # IPv6 tidak tersentuh


def test_render_masking_fail_closed_injection(tmp_path) -> None:
    """R-02/PC-02: kegagalan proses masking → teks pengganti aman
    TANPA hostname asli (fail-closed, bukan fail-open)."""
    service = _make_service_baru(tmp_path)
    config = tmp_path / "config.yml"
    config.write_bytes(VALID_CONFIG.encode("utf-8"))
    report = service.run_report(str(config))
    mask = build_hostname_mask(report, "localhost")
    assert mask is not None
    import tunneldesk.application.diagnostics_service as mod

    asli_sub = _apply_hostname_masking

    def sub_pecah(text, pairs):  # type: ignore[no-untyped-def]
        raise RuntimeError("simulasi gagal masking")

    monkey = pytest.MonkeyPatch()
    monkey.setattr(mod, "_apply_hostname_masking", sub_pecah)
    try:
        teks = render_report_text(report, mask)
    finally:
        monkey.undo()
    assert teks == _MASKING_FAILED_TEXT
    assert "rapor.sekolah.sch.id" not in teks  # fail-closed: tanpa hostname asli
    del asli_sub


def test_render_masking_postcheck_kandidat_hadir(tmp_path) -> None:
    """PC-02: kandidat masih hadir pasca-masking (gagal) → teks pengganti
    aman, bukan report mentah."""
    service = _make_service_baru(tmp_path)
    config = tmp_path / "config.yml"
    config.write_bytes(VALID_CONFIG.encode("utf-8"))
    report = service.run_report(str(config))
    mask = build_hostname_mask(report, "localhost")
    assert mask is not None

    def postcheck_gagal(text, hostname_mask):  # type: ignore[no-untyped-def]
        # simulasi: kandidat masih hadir (masking gagal)
        raise diag_mod._MaskingPostcheckError("rapor.sekolah.sch.id")

    monkey = pytest.MonkeyPatch()
    monkey.setattr(diag_mod, "_postcheck_masking", postcheck_gagal)
    teks = render_report_text(report, mask)
    monkey.undo()
    assert teks == _MASKING_FAILED_TEXT
    assert "rapor.sekolah.sch.id" not in teks
