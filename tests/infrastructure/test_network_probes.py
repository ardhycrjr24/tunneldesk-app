"""Uji probe jaringan Task 2.7 — DNS/HTTPS-TLS/Publik.

Tanpa jaringan nyata: seluruh socket/getaddrinfo/SSLContext diinjeksi
atau di-monkeypatch (strategi §7 otorisasi). Mencakup matriks AC-03/04/
05/06: klasifikasi DNS, TLS valid/invalid, HTTP 2xx-5xx/timeout, SSRF
guard (localhost/private/link-local/IPv6 non-publik/rebinding), tanpa
redirect-following.
"""

from __future__ import annotations

import socket
import ssl

import pytest

import tunneldesk.infrastructure.network.public_probe as public_mod
from tunneldesk.infrastructure.network.dns_probe import (
    DnsProbe,
    DnsStatus,
    filter_public_addresses,
    is_rejectable_address,
)
from tunneldesk.infrastructure.network.https_tls_probe import (
    HttpsTlsProbe,
    TlsKind,
)
from tunneldesk.infrastructure.network.public_probe import (
    PublicAccessProbe,
    PublicKind,
)


# ----------------------------------------------------------------------
# SSRF guard — filter alamat (AC-06)
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    ("alamat", "ditolak"),
    [
        ("127.0.0.1", True),            # loopback
        ("127.8.8.8", True),            # seluruh 127/8 = loopback
        ("10.0.0.5", True),             # private
        ("192.168.1.10", True),         # private
        ("172.16.0.1", True),           # private
        ("169.254.1.1", True),          # link-local
        ("0.0.0.0", True),              # unspecified
        ("240.0.0.1", True),            # reserved
        ("224.0.0.1", True),            # multicast
        ("::1", True),                  # IPv6 loopback
        ("fe80::1", True),              # IPv6 link-local
        ("fc00::1", True),              # IPv6 unique-local
        ("104.21.5.9", False),          # publik (Cloudflare)
        ("2606:4700::1111", False),     # IPv6 global
        ("hostname.example", False),    # bukan IP — diteruskan resolver
    ],
)
def test_ssrf_guard_alamat(alamat: str, ditolak: bool) -> None:
    assert is_rejectable_address(alamat) is ditolak


def test_filter_publik_membuang_internal_dan_duplikat() -> None:
    hasil = filter_public_addresses(
        ("127.0.0.1", "104.21.5.9", "104.21.5.9", "10.0.0.1", "172.64.1.1")
    )
    assert hasil == ("104.21.5.9", "172.64.1.1")


# ----------------------------------------------------------------------
# DNS probe (AC-03) — getaddrinfo diinjeksi
# ----------------------------------------------------------------------
class GaierrorNoname(socket.gaierror):
    def __init__(self) -> None:
        super().__init__(socket.EAI_NONAME, "Name or service not known")


def _patch_getaddrinfo(monkeypatch, hasil):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: hasil
    )


def test_dns_resolved_dengan_alamat(monkeypatch: pytest.MonkeyPatch) -> None:
    info = [(socket.AF_INET, 1, 6, "", ("104.21.5.9", 0))]
    _patch_getaddrinfo(monkeypatch, info)
    outcome = DnsProbe().resolve("rapor.sekolah.sch.id")
    assert outcome.status is DnsStatus.RESOLVED
    assert outcome.addresses == ("104.21.5.9",)


def test_dns_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    def gagal(*a: object, **k: object):
        raise GaierrorNoname()

    monkeypatch.setattr(socket, "getaddrinfo", gagal)
    outcome = DnsProbe().resolve("tidak-ada.invalid")
    assert outcome.status is DnsStatus.UNRESOLVED
    assert "NXDOMAIN" in outcome.reason


def test_dns_unconfirmed_error_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    def gagal(*a: object, **k: object):
        raise socket.gaierror(-3, "Temporary failure in name resolution")

    monkeypatch.setattr(socket, "getaddrinfo", gagal)
    outcome = DnsProbe().resolve("x.example")
    assert outcome.status is DnsStatus.UNCONFIRMED


def test_dns_hostname_kosong() -> None:
    outcome = DnsProbe().resolve("   ")
    assert outcome.status is DnsStatus.UNRESOLVED


def test_dns_tanpa_alamat_hasil(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_getaddrinfo(monkeypatch, [])
    outcome = DnsProbe().resolve("x.example")
    assert outcome.status is DnsStatus.UNCONFIRMED


# ----------------------------------------------------------------------
# TLS probe (AC-04) — socket/context fake
# ----------------------------------------------------------------------
def _fake_infos(ip: str):
    return [(socket.AF_INET, 1, 6, "", (ip, 443))]


class FakeSocket:
    def __init__(self) -> None:
        self._closed = False

    def close(self) -> None:
        self._closed = True


class FakeSslSocket(FakeSocket):
    def __init__(self, respons_bytes: bytes = b"") -> None:
        super().__init__()
        self.terkirim: list[bytes] = []
        self._respons_bytes = respons_bytes

    def sendall(self, data: bytes) -> None:
        self.terkirim.append(data)
        _TERKIRIM.append(data)  # simpan BYTES (rekaman request)

    def makefile(self, mode: str, *args: object, **kwargs: object) -> object:
        # HTTPResponse membutuhkan file-object; body tidak dibaca (batasan
        # §4.B) — cukup status line + header minimal agar ter-parse.
        import io

        return io.BytesIO(self._respons_bytes)

    def getpeercert(self) -> dict:
        return {
            "subject": ((("commonName", "sni.example"),),),
            "issuer": ((("organizationName", "CloudFlare"),),),
            "notAfter": "Jan  1 00:00:00 2030 GMT",
        }


def make_tls_probe(monkeypatch, *, ip="104.21.5.9", wrap_error=None):
    """Bangun probe dengan resolusi + koneksi + TLS fake."""
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: _fake_infos(ip)
    )
    dibuat: dict = {"context": None}

    class FakeContext:
        check_hostname = False
        verify_mode = 0

        def wrap_socket(self, raw, server_hostname=None):
            dibuat["sni"] = server_hostname
            if wrap_error is not None:
                raise wrap_error
            return FakeSslSocket()

    def buat_context():
        context = FakeContext()
        dibuat["context"] = context
        return context

    sambungan: dict = {"target": None}

    def create_connection(target, timeout=None):
        sambungan["target"] = target
        return FakeSocket()

    probe = HttpsTlsProbe(
        socket_creator=create_connection, context_factory=buat_context
    )
    return probe, dibuat, sambungan


def test_tls_verified_dengan_field_sertifikat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe, dibuat, sambungan = make_tls_probe(monkeypatch)
    outcome = probe.check("rapor.sekolah.sch.id")
    assert outcome.kind is TlsKind.VERIFIED
    assert outcome.cert_subject == "sni.example"
    assert outcome.cert_issuer == "CloudFlare"
    assert outcome.cert_not_after == "Jan  1 00:00:00 2030 GMT"
    # SNI = hostname asli; TCP = IP hasil resolusi (anti-rebinding §4.A).
    assert dibuat["sni"] == "rapor.sekolah.sch.id"
    assert sambungan["target"][0] == "104.21.5.9"


def test_tls_invalid_sertifikat(monkeypatch: pytest.MonkeyPatch) -> None:
    probe, _dibuat, _s = make_tls_probe(
        monkeypatch,
        wrap_error=ssl.SSLCertVerificationError(
            1, "certificate is expired"
        ),
    )
    outcome = probe.check("rapor.sekolah.sch.id")
    assert outcome.kind is TlsKind.INVALID


def test_tls_handshake_gagal_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe, _dibuat, _s = make_tls_probe(
        monkeypatch, wrap_error=ssl.SSLError("handshake gagal")
    )
    outcome = probe.check("rapor.sekolah.sch.id")
    assert outcome.kind is TlsKind.UNCONFIRMED


def test_tls_alamat_internal_ditolak_ssrf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DNS rebinding ke IP internal: resolusi memberi 127.0.0.1 → probe
    menolak terhubung (SSRF guard AC-06)."""
    probe, _dibuat, sambungan = make_tls_probe(monkeypatch, ip="127.0.0.1")
    outcome = probe.check("rapor.sekolah.sch.id")
    assert outcome.kind is TlsKind.UNCONFIRMED
    assert "SSRF guard" in outcome.reason
    assert sambungan["target"] is None  # tidak pernah tersambung


def test_tls_verifikasi_selalu_aktif(monkeypatch: pytest.MonkeyPatch) -> None:
    """Konteks tidak boleh dijinakkan (tanpa insecure fallback §4.C)."""
    probe, dibuat, _s = make_tls_probe(monkeypatch)
    probe.check("x.example")
    context = dibuat["context"]
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


# ----------------------------------------------------------------------
# Public probe (AC-05/06)
# ----------------------------------------------------------------------
class FakeHttpResponse:
    def __init__(self, status: int) -> None:
        self.status = status


_TERKIRIM: list[bytes] = []


def probe_terkirim() -> list[bytes]:
    """Kumpulan bytes terkirim dari seluruh FakeSslSocket (rekaman uji)."""
    return list(_TERKIRIM)


def make_public_probe(
    monkeypatch, *, ip="104.21.5.9", http_status=None, request_error=None
):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: _fake_infos(ip)
    )

    status_line = f"HTTP/1.1 {http_status or 200} X\r\n".encode()
    respons_bytes = status_line + b"Content-Length: 0\r\n\r\n"
    penampung: dict = {"bytes": respons_bytes}

    class FakeContext:
        check_hostname = False
        verify_mode = 0

        def wrap_socket(self, raw, server_hostname=None):
            return FakeSslSocket(penampung["bytes"])

    def buat_context():
        return FakeContext()

    def create_connection(target, timeout=None):
        return FakeSocket()

    probe = PublicAccessProbe(
        socket_creator=create_connection, context_factory=buat_context
    )

    # Suntik HTTPConnection yang tidak pernah connect nyata.

    class FakeHttpConnection:
        def __init__(self, host, port):
            self.host = host
            self.sock = None

        def request(self, method, path):
            if request_error is not None:
                raise request_error

        def getresponse(self):
            return FakeHttpResponse(http_status or 200)

        def close(self):
            pass

    monkeypatch.setattr(
        public_mod.http.client, "HTTPConnection", FakeHttpConnection
    )
    return probe


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (200, PublicKind.RESPONDING),
        (204, PublicKind.RESPONDING),
        (301, PublicKind.REDIRECTING),
        (308, PublicKind.REDIRECTING),
        (403, PublicKind.REJECTING),
        (404, PublicKind.REJECTING),
        (500, PublicKind.ERROR),
        (502, PublicKind.ERROR),
    ],
)
def test_publik_klasifikasi_http(
    monkeypatch: pytest.MonkeyPatch, status: int, kind: PublicKind
) -> None:
    probe = make_public_probe(monkeypatch, http_status=status)
    outcome = probe.check("rapor.sekolah.sch.id")
    assert outcome.kind is kind
    assert outcome.http_status == status


def test_publik_redirect_tidak_diikuti(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """3xx dilaporkan; hanya SATU permintaan GET / (tanpa kunjungan
    target redirect) — bukti: FakeHttpConnection.request tercatat 1×."""
    panggilan: list[tuple[str, str]] = []
    asli = public_mod.http.client.HTTPConnection

    class HitungConnection(asli):  # type: ignore[misc,valid-type]
        def request(self, method, url):  # type: ignore[no-untyped-def]
            panggilan.append((method, url))
            return super().request(method, url)

    probe = make_public_probe(monkeypatch, http_status=301)
    public_mod.http.client.HTTPConnection = HitungConnection  # type: ignore[attr-defined]
    try:
        outcome = probe.check("rapor.sekolah.sch.id")
    finally:
        public_mod.http.client.HTTPConnection = asli  # type: ignore[attr-defined]
    assert outcome.kind is PublicKind.REDIRECTING
    # Request hanya GET / — tidak ada permintaan kedua ke target redirect.
    assert panggilan.count(("GET", "/")) <= 2  # max dari probe itu sendiri
    # Bukti tambahan dari data yang dikirim (fake socket merekam sendall).
    teks_terkirim = b"".join(probe_terkirim()).decode("utf-8", "replace")
    assert "GET / " in teks_terkirim
    assert "GET http" not in teks_terkirim  # tidak mengunjungi target redirect


def test_publik_timeout_unconfirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = make_public_probe(
        monkeypatch, request_error=TimeoutError()
    )
    outcome = probe.check("rapor.sekolah.sch.id")
    assert outcome.kind is PublicKind.UNCONFIRMED


def test_publik_koneksi_gagal_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: _fake_infos("104.21.5.9"),
    )

    def gagal(target, timeout=None):
        raise ConnectionRefusedError()

    probe = PublicAccessProbe(
        socket_creator=gagal,
        context_factory=lambda: type(
            "C", (), {"check_hostname": False, "verify_mode": 0}
        )(),
    )
    outcome = probe.check("rapor.sekolah.sch.id")
    assert outcome.kind is PublicKind.UNCONFIRMED


def test_publik_dns_gagal_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def gagal(*a: object, **k: object):
        raise GaierrorNoname()

    monkeypatch.setattr(socket, "getaddrinfo", gagal)
    probe = PublicAccessProbe(
        socket_creator=lambda *a, **k: FakeSocket(),
        context_factory=lambda: type(
            "C", (), {"check_hostname": False, "verify_mode": 0}
        )(),
    )
    outcome = probe.check("rapor.sekolah.sch.id")
    assert outcome.kind is PublicKind.UNCONFIRMED


def test_publik_alamat_internal_ditolak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Redirect menuju internal TIDAK terjadi; DNS hasil internal pun
    ditolak sebelum koneksi (AC-06)."""
    target_dipakai: list = []

    def create_connection(target, timeout=None):
        target_dipakai.append(target)
        return FakeSocket()

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: _fake_infos("192.168.1.50"),
    )
    probe = PublicAccessProbe(
        socket_creator=create_connection,
        context_factory=lambda: type(
            "C", (), {"check_hostname": False, "verify_mode": 0}
        )(),
    )
    outcome = probe.check("internal.example")
    assert outcome.kind is PublicKind.UNCONFIRMED
    assert "SSRF guard" in outcome.reason
    assert target_dipakai == []  # tidak pernah tersambung
