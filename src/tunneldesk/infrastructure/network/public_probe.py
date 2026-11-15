"""Probe akses publik via Cloudflare edge (Task 2.7, FR-6) — stdlib saja.

- TCP ke alamat IP hasil resolusi yang **sudah divalidasi global**
  (anti DNS-rebinding/TOCTOU, batasan §4.A); TLS SNI + verifikasi
  hostname tetap memakai hostname asli; HTTP ``Host`` = hostname asli.
- ``GET /`` saja — tanpa Authorization/Cookie/token, **tanpa** membaca
  response body, **tanpa** mengikuti redirect (status 3xx dilaporkan,
  target redirect TIDAK dikunjungi — batasan §4.B).
- Tanpa retry otomatis; tiap alamat publik dicoba sekali (maks 3) —
  terbatas dan terkendali (batasan §4.B).
- Respons edge (2xx/3xx/4xx/5xx) **bukan** bukti origin lokal sehat —
  klasifikasi tingkat kepastian ditentukan pemanggil (P-2).
"""

from __future__ import annotations

import enum
import http.client
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass

from tunneldesk.infrastructure.network.dns_probe import (
    filter_public_addresses,
)

__all__ = ["PublicAccessProbe", "PublicOutcome", "PublicKind", "PUBLIC_TIMEOUT_SECONDS"]

PUBLIC_TIMEOUT_SECONDS = 3.0  # konservatif; terdokumentasi dan mudah diuji
MAX_ADDRESSES_TRIED = 3  # terbatas (§4.B) — alamat publik berbeda, bukan retry


class PublicKind(enum.Enum):
    """Status HTTP publik — bentuk infrastruktur (domain memetakan ke P-2)."""

    RESPONDING = "PUBLIC_ENDPOINT_RESPONDING"    # 2xx
    REDIRECTING = "PUBLIC_ENDPOINT_REDIRECTING"  # 3xx — TIDAK diikuti
    REJECTING = "PUBLIC_ENDPOINT_REJECTING"      # 4xx
    ERROR = "PUBLIC_ENDPOINT_ERROR"              # 5xx
    UNCONFIRMED = "PUBLIC_ENDPOINT_UNCONFIRMED"  # timeout/koneksi gagal/DNS


@dataclass(frozen=True)
class PublicOutcome:
    """Hasil akses publik — tanpa body, tanpa data sensitif."""

    kind: PublicKind
    http_status: int | None = None
    reason: str = ""


class PublicAccessProbe:
    """Akses publik GET / melalui Cloudflare edge (FR-6) — never-raises.

    ``socket_creator``/``context_factory`` dapat diinjeksikan untuk uji
    deterministik. Respons body **tidak dibaca** (batasan §4.B).
    """

    def __init__(
        self,
        socket_creator: Callable[..., socket.socket] | None = None,
        context_factory: Callable[[], ssl.SSLContext] | None = None,
        timeout_seconds: float = PUBLIC_TIMEOUT_SECONDS,
    ) -> None:
        self._socket_creator = socket_creator or socket.create_connection
        self._context_factory = context_factory or ssl.create_default_context
        self._timeout = timeout_seconds

    def check(self, hostname: str) -> PublicOutcome:
        """Akses ``https://<hostname>/`` via IP tervalidasi (SNI + Host =
        hostname asli). 3xx dilaporkan tanpa mengikuti redirect."""
        host = hostname.strip()
        if not host:
            return PublicOutcome(PublicKind.UNCONFIRMED, reason="hostname kosong")

        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return PublicOutcome(
                PublicKind.UNCONFIRMED, reason="hostname tidak dapat diresolusi"
            )
        except OSError as exc:
            return PublicOutcome(
                PublicKind.UNCONFIRMED, reason=f"resolusi gagal: {exc}"
            )

        addresses: list[str] = []
        for info in infos:
            address = str(info[4][0])
            if address not in addresses:
                addresses.append(address)
        publik = filter_public_addresses(tuple(addresses))
        if not publik:
            return PublicOutcome(
                PublicKind.UNCONFIRMED,
                reason=(
                    "tidak ada alamat publik hasil resolusi — pemeriksaan "
                    "publik dilewati (SSRF guard)"
                ),
            )

        context = self._context_factory()
        context.check_hostname = True   # hostname verification tetap aktif (§4.C)
        context.verify_mode = ssl.CERT_REQUIRED

        alasan_terakhir = ""
        for address in publik[:MAX_ADDRESSES_TRIED]:
            try:
                raw_socket = self._socket_creator(
                    (address, 443), timeout=self._timeout
                )
            except OSError as exc:
                alasan_terakhir = str(exc)
                continue
            try:
                tls_socket = context.wrap_socket(
                    raw_socket, server_hostname=host
                )
            except ssl.SSLCertVerificationError as exc:
                # Sertifikat tidak valid = akses publik tidak dapat
                # dipastikan aman; faktual, dipisahkan dari error edge.
                # exc.reason hanya ada pada error _ssl asli → akses aman.
                alasan = getattr(exc, "reason", None) or str(exc)
                return PublicOutcome(
                    PublicKind.UNCONFIRMED,
                    http_status=None,
                    reason=f"verifikasi sertifikat gagal: {alasan}",
                )
            except ssl.SSLError as exc:
                alasan_terakhir = str(exc)
                continue
            except OSError as exc:
                alasan_terakhir = str(exc)
                continue
            try:
                return self._http_get(tls_socket, host)
            finally:
                tls_socket.close()
        return PublicOutcome(
            PublicKind.UNCONFIRMED,
            reason="koneksi gagal"
            + (f": {alasan_terakhir}" if alasan_terakhir else ""),
        )

    def _http_get(self, tls_socket: object, host: str) -> PublicOutcome:
        """GET / pada koneksi TLS yang sudah tersambung — tanpa body."""
        connection = http.client.HTTPConnection(host, 443)  # tak pernah connect
        connection.sock = tls_socket  # paksa pakai koneksi IP tervalidasi
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            status = response.status
            # Body TIDAK dibaca/diunduh (batasan §4.B) — tutup langsung.
            if 200 <= status < 300:
                kind = PublicKind.RESPONDING
            elif 300 <= status < 400:
                kind = PublicKind.REDIRECTING  # status dilaporkan; TIDAK diikuti
            elif 400 <= status < 500:
                kind = PublicKind.REJECTING
            else:
                kind = PublicKind.ERROR
            return PublicOutcome(
                kind,
                http_status=status,
                reason=f"respons HTTP {status}",
            )
        except http.client.RemoteDisconnected:
            return PublicOutcome(
                PublicKind.UNCONFIRMED, reason="koneksi terputus tanpa respons"
            )
        except TimeoutError:
            return PublicOutcome(PublicKind.UNCONFIRMED, reason="tidak ada respons")
        except OSError as exc:
            return PublicOutcome(
                PublicKind.UNCONFIRMED, reason=f"permintaan gagal: {exc}"
            )
        finally:
            connection.close()
