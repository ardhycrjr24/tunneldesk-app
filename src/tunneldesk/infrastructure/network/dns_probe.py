"""Probe resolusi DNS (Task 2.7, FR-4) — stdlib, tanpa dependensi baru.

- ``DnsProbe.resolve(hostname)``: ``socket.getaddrinfo`` (AF_UNSPEC) —
  never-raises; kegagalan dipetakan ke status tertutup
  (DNS_RESOLVED/DNS_UNRESOLVED/DNS_UNCONFIRMED).
- ``filter_public_addresses``: gerbang SSRF (keputusan PO §4.A) — hanya
  alamat **global** yang boleh dipakai pemeriksaan endpoint publik;
  loopback/private/link-local/multicast/reserved/unspecified ditolak.
- Batasan jujur: ``getaddrinfo`` tidak memiliki parameter timeout —
  durasi mengikuti resolver OS; dipanggil dalam worker UI.

Hostname tidak pernah diasumsikan (PRD-01 §14) — selalu dari
konfigurasi yang telah dibaca/divalidasi pemanggil.
"""

from __future__ import annotations

import enum
import ipaddress
import socket
from dataclasses import dataclass

__all__ = [
    "DnsProbe",
    "DnsOutcome",
    "filter_public_addresses",
    "is_rejectable_address",
]


class DnsStatus(enum.Enum):
    """Status resolusi — duplikat bentuk domain agar infrastruktur tidak
    mengimpor domain berlapis (pola yang sama dipakai origin_probe)."""

    RESOLVED = "DNS_RESOLVED"
    UNRESOLVED = "DNS_UNRESOLVED"
    UNCONFIRMED = "DNS_UNCONFIRMED"


@dataclass(frozen=True)
class DnsOutcome:
    """Hasil resolusi — alamat terurut sesuai jawaban resolver."""

    status: DnsStatus
    addresses: tuple[str, ...] = ()
    reason: str = ""


def is_rejectable_address(address: str) -> bool:
    """True bila alamat TIDAK boleh dituju pemeriksaan publik (SSRF guard).

    Menolak: loopback, private, link-local, multicast, reserved,
    unspecified, dan non-global lainnya (termasuk IPv6 non-global).
    ``ipaddress.ip_address`` melempar ValueError untuk teks bukan-IP —
    hostname diteruskan ke resolver, bukan ditolak di sini.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    # Multicast ditolak eksplisit: stdlib (3.11) melabeli is_global=True
    # untuk 224/4 (anomali terverifikasi audit) — tidak boleh dituju.
    if parsed.is_multicast:
        return True
    return not parsed.is_global


def filter_public_addresses(addresses: tuple[str, ...]) -> tuple[str, ...]:
    """Saring hanya alamat global (terurut, tanpa duplikat) — SSRF guard."""
    hasil: list[str] = []
    for address in addresses:
        if not is_rejectable_address(address) and address not in hasil:
            hasil.append(address)
    return tuple(hasil)


class DnsProbe:
    """Resolusi DNS hostname konfigurasi (FR-4) — never-raises."""

    def resolve(self, hostname: str) -> DnsOutcome:
        """Resolusi ``hostname`` via ``getaddrinfo`` (AF_UNSPEC)."""
        host = hostname.strip()
        if not host:
            return DnsOutcome(
                DnsStatus.UNRESOLVED, (), "hostname kosong"
            )
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            # EAI_NONAME/EAI_NODATA (varian nilai beda antar-platform) =
            # hostname tidak ditemukan (faktual); kegagalan lain (mis.
            # resolver tidak tersedia) = tidak pasti.
            noname = {
                socket.EAI_NONAME,
                getattr(socket, "EAI_NODATA", -5),
                -2,
                8,
            }
            if getattr(exc, "errno", None) in noname:
                return DnsOutcome(
                    DnsStatus.UNRESOLVED,
                    (),
                    "hostname tidak ditemukan (NXDOMAIN)",
                )
            return DnsOutcome(
                DnsStatus.UNCONFIRMED,
                (),
                f"resolusi gagal: {exc}",
            )
        except OSError as exc:
            return DnsOutcome(
                DnsStatus.UNCONFIRMED, (), f"resolusi gagal: {exc}"
            )

        addresses: list[str] = []
        for info in infos:
            sockaddr = info[4]
            address = str(sockaddr[0])
            if address and address not in addresses:
                addresses.append(address)
        if not addresses:
            return DnsOutcome(
                DnsStatus.UNCONFIRMED, (), "resolver tidak mengembalikan alamat"
            )
        return DnsOutcome(DnsStatus.RESOLVED, tuple(addresses))
