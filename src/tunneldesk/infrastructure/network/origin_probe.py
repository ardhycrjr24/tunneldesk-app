"""Probe origin nyata (E-3) — stdlib socket/http, tanpa dependensi baru.

Kontrak (domain/diagnostics/origin.py): **tidak melempar exception** —
semua kegagalan dipetakan menjadi :class:`OriginProbeOutcome`.
Target tidak pernah diasumsikan localhost/port tertentu (PRD-01 §14).
"""

from __future__ import annotations

import http.client

from tunneldesk.domain.diagnostics.origin import (
    OriginProbeKind,
    OriginProbeOutcome,
    OriginTarget,
)

__all__ = ["SocketOriginProbe"]


class SocketOriginProbe:
    """Probe TCP + HTTP GET minimal terhadap origin lokal."""

    def probe(self, target: OriginTarget, timeout_seconds: float) -> OriginProbeOutcome:
        try:
            connection = http.client.HTTPConnection(
                target.host,
                target.port,
                timeout=max(timeout_seconds, 0.1),
            )
        except (OSError, ValueError) as exc:
            return OriginProbeOutcome(
                kind=OriginProbeKind.ERROR, detail=f"koneksi gagal: {exc}"
            )
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            status = response.status
            response.read(64)  # buang isi; cukup status line
            return OriginProbeOutcome(
                kind=OriginProbeKind.REACHABLE,
                http_status=status,
                detail=f"respons HTTP {status}",
            )
        except http.client.RemoteDisconnected:
            # koneksi diterima tetapi tanpa respons — klasifikasikan sebagai
            # timeout, bukan refused (RemoteDisconnected adalah subclass
            # ConnectionResetError).
            return OriginProbeOutcome(
                kind=OriginProbeKind.TIMEOUT,
                detail="koneksi terputus tanpa respons",
            )
        except (ConnectionRefusedError, ConnectionResetError):
            return OriginProbeOutcome(
                kind=OriginProbeKind.REFUSED, detail="koneksi ditolak"
            )
        except TimeoutError:
            return OriginProbeOutcome(
                kind=OriginProbeKind.TIMEOUT, detail="tidak ada respons"
            )
        except OSError as exc:
            return OriginProbeOutcome(
                kind=OriginProbeKind.ERROR, detail=f"kesalahan jaringan: {exc}"
            )
        finally:
            connection.close()
