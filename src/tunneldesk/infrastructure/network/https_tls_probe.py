"""Probe HTTPS/TLS + sertifikat publik (Task 2.7, FR-5) — stdlib saja.

- Verifikasi sertifikat + hostname **selalu aktif**
  (``ssl.create_default_context()`` — tanpa insecure fallback; batasan
  §4.C).
- **Anti DNS-rebinding/TOCTOU** (batasan §4.A): TCP tersambung ke alamat
  IP hasil resolusi yang **sudah divalidasi global**, sedangkan SNI dan
  verifikasi hostname tetap memakai hostname asli
  (``wrap_socket(server_hostname=...)``).
- Tanpa retry otomatis; timeout eksplisit (konstanta konservatif,
  dapat diuji via parameter).
- Komentar multi-token dipertahankan oleh builder — modul ini tidak
  berhubungan dengan komentar.

Klasifikasi: TLS_VERIFIED / TLS_INVALID (faktual: expired, hostname
mismatch, issuer tidak dipercaya) / TLS_UNCONFIRMED (koneksi, handshake,
resolver — penyebab tidak dapat dipastikan).
"""

from __future__ import annotations

import enum
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from tunneldesk.infrastructure.network.dns_probe import (
    filter_public_addresses,
)

__all__ = ["HttpsTlsProbe", "TlsOutcome", "TlsKind", "DEFAULT_TIMEOUT_SECONDS"]

DEFAULT_TIMEOUT_SECONDS = 3.0  # konservatif; terdokumentasi dan mudah diuji


class TlsKind(enum.Enum):
    """Status TLS — bentuk infrastruktur (domain memetakan ke TLS_*)."""

    VERIFIED = "TLS_VERIFIED"
    INVALID = "TLS_INVALID"
    UNCONFIRMED = "TLS_UNCONFIRMED"


@dataclass(frozen=True)
class TlsOutcome:
    """Hasil pemeriksaan TLS — field sertifikat publik saja (P-4)."""

    kind: TlsKind
    reason: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_not_after: str = ""


def _ringkas_cert(cert: dict[str, Any]) -> tuple[str, str, str]:
    """Ekstrak field publik sertifikat: subjek CN, issuer CN/O, notAfter."""

    def ambil(rdn: object) -> str:
        entries = cast("tuple[tuple[str, str], ...]", rdn)
        for pasangan in entries:
            for pasangan_dalam in pasangan:  # mpy: (nama, nilai)
                nama = pasangan_dalam[0]
                nilai = pasangan_dalam[1]
                if nama in ("commonName", "organizationName"):
                    return str(nilai)
        return ""

    subject = cast("tuple[tuple[str, str], ...]", cert.get("subject") or ())
    issuer = cast("tuple[tuple[str, str], ...]", cert.get("issuer") or ())
    return (
        ambil(subject),
        ambil(issuer),
        str(cert.get("notAfter", "")),
    )


class HttpsTlsProbe:
    """Pemeriksaan koneksi HTTPS/TLS hostname publik (FR-5) — never-raises.

    ``socket_creator``/``context_factory`` dapat diinjeksikan untuk uji
    deterministik (pola injeksi proyek — backup_io/origin_probe).
    """

    def __init__(
        self,
        socket_creator: Callable[..., socket.socket] | None = None,
        context_factory: Callable[[], ssl.SSLContext] | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._socket_creator = socket_creator or socket.create_connection
        self._context_factory = context_factory or ssl.create_default_context
        self._timeout = timeout_seconds

    def check(self, hostname: str) -> TlsOutcome:
        """Periksa TLS ``hostname`` publik: resolve → validasi alamat →
        sambung IP tervalidasi (SNI + verifikasi hostname asli)."""
        host = hostname.strip()
        if not host:
            return TlsOutcome(
                TlsKind.UNCONFIRMED, "hostname kosong"
            )

        # Resolusi + SSRF guard (§4.A): hanya alamat global yang dituju.
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return TlsOutcome(
                TlsKind.UNCONFIRMED, "hostname tidak dapat diresolusi"
            )
        except OSError as exc:
            return TlsOutcome(TlsKind.UNCONFIRMED, f"resolusi gagal: {exc}")

        addresses: list[str] = []
        for info in infos:
            address = str(info[4][0])
            if address not in addresses:
                addresses.append(address)
        publik = filter_public_addresses(tuple(addresses))
        if not publik:
            return TlsOutcome(
                TlsKind.UNCONFIRMED,
                "tidak ada alamat publik hasil resolusi — pemeriksaan "
                "publik dilewati (SSRF guard)",
            )

        context = self._context_factory()
        # Verifikasi SELALU aktif (§4.C) — tanpa insecure fallback.
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        kesalahan_terakhir = ""
        for address in publik[:3]:  # terbatas: maks 3 alamat publik, tanpa retry
            try:
                raw_socket = self._socket_creator(
                    (address, 443), timeout=self._timeout
                )
            except OSError as exc:
                kesalahan_terakhir = str(exc)
                continue
            try:
                tls_socket = context.wrap_socket(
                    raw_socket, server_hostname=host  # SNI + verifikasi hostname asli
                )
            except ssl.SSLCertVerificationError as exc:
                # Faktual: sertifikat tidak valid (expired/mismatch/
                # untrusted) — dipisahkan dari "tidak pasti". exc.reason
                # hanya ada pada error _ssl asli (bukan buatan) → akses
                # aman (pelajaran CI).
                alasan = getattr(exc, "reason", None) or str(exc)
                return TlsOutcome(
                    TlsKind.INVALID,
                    f"verifikasi sertifikat gagal: {alasan}",
                )
            except ssl.SSLError as exc:
                kesalahan_terakhir = str(exc)
                continue
            except OSError as exc:
                kesalahan_terakhir = str(exc)
                continue
            try:
                cert = tls_socket.getpeercert() or {}
                subject, issuer, not_after = _ringkas_cert(cert)
                return TlsOutcome(
                    TlsKind.VERIFIED,
                    "koneksi TLS berhasil dan sertifikat valid",
                    cert_subject=subject,
                    cert_issuer=issuer,
                    cert_not_after=not_after,
                )
            finally:
                tls_socket.close()
        return TlsOutcome(
            TlsKind.UNCONFIRMED,
            "koneksi TLS gagal"
            + (f": {kesalahan_terakhir}" if kesalahan_terakhir else ""),
        )
