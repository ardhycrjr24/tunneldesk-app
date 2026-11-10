"""Registri kepemilikan proses (D-18, K-07, A-07).

TunnelDesk hanya boleh menghentikan proses yang dilahirkannya sendiri.
Registri ini adalah penjaga domain: pid yang tidak terdaftar tidak boleh
disentuh — tanpa adopsi berdasarkan nama executable.
"""

from __future__ import annotations

from .process_contracts import NotOwnedProcessError

__all__ = ["OwnershipRegistry", "NotOwnedProcessError"]


class OwnershipRegistry:
    """Catatan pid milik instance aplikasi ini. Bukan thread-safe —
    sinkronisasi dilakukan pemanggil (application layer, E-3)."""

    def __init__(self) -> None:
        self._owned: set[int] = set()

    def register(self, pid: int) -> None:
        """Daftarkan pid hasil launch aplikasi ini."""
        if pid <= 0:
            raise ValueError(f"pid tidak valid: {pid}")
        self._owned.add(pid)

    def release(self, pid: int) -> None:
        """Lepaskan pid dari registri setelah proses berakhir & dibersihkan."""
        self._owned.discard(pid)

    def owns(self, pid: int) -> bool:
        """True bila pid terdaftar sebagai milik aplikasi."""
        return pid in self._owned

    def require_owned(self, pid: int) -> None:
        """Naikkan :class:`NotOwnedProcessError` bila pid bukan milik kita."""
        if not self.owns(pid):
            raise NotOwnedProcessError(
                f"pid {pid} bukan proses milik TunnelDesk — tidak boleh dikelola"
            )

    def owned_pids(self) -> frozenset[int]:
        return frozenset(self._owned)
