"""Uji SocketOriginProbe nyata (E-3) — server socket lokal di port acak.

Semua koneksi ke localhost port ephemeral; tanpa data produksi.
"""

from __future__ import annotations

import socket
import threading
import time

from tunneldesk.domain.diagnostics.origin import OriginProbeKind, OriginTarget
from tunneldesk.infrastructure.network.origin_probe import SocketOriginProbe

PROBE = SocketOriginProbe()


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _http_server(port: int, respond: bool) -> socket.socket:
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    server.settimeout(5)

    def serve() -> None:
        try:
            connection, _ = server.accept()
            with connection:
                connection.recv(1024)
                if respond:
                    connection.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
                else:
                    time.sleep(2)  # diam — pemicu timeout klien
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return server



def test_origin_reachable_http_200() -> None:
    port = _free_port()
    server = _http_server(port, respond=True)
    try:
        hasil = PROBE.probe(OriginTarget(host="127.0.0.1", port=port), 2.0)
        assert hasil.kind is OriginProbeKind.REACHABLE
        assert hasil.http_status == 200
    finally:
        server.close()


def test_origin_refused_port_tertutup() -> None:
    port = _free_port()  # port ditutup — tidak ada listener
    hasil = PROBE.probe(OriginTarget(host="127.0.0.1", port=port), 2.0)
    assert hasil.kind is OriginProbeKind.REFUSED


def test_origin_timeout_tanpa_respons() -> None:
    port = _free_port()
    server = _http_server(port, respond=False)  # menerima tapi diam
    try:
        hasil = PROBE.probe(OriginTarget(host="127.0.0.1", port=port), 0.3)
        assert hasil.kind is OriginProbeKind.TIMEOUT
    finally:
        server.close()


def test_host_tidak_ada_adalah_error() -> None:
    hasil = PROBE.probe(
        OriginTarget(host="tidak-ada-host.invalid", port=80), 1.0
    )
    assert hasil.kind in (OriginProbeKind.ERROR, OriginProbeKind.TIMEOUT)


def test_probe_tidak_melempar_exception_dengan_timeout_nol() -> None:
    port = _free_port()
    server = _http_server(port, respond=True)
    try:
        hasil = PROBE.probe(OriginTarget(host="127.0.0.1", port=port), 0.0)
        assert hasil.kind in (
            OriginProbeKind.REACHABLE,
            OriginProbeKind.TIMEOUT,
            OriginProbeKind.ERROR,
        )
    finally:
        server.close()
