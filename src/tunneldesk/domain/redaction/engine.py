"""Mesin redaksi terpusat (PRD-01 §7.5/§10; keputusan T-10, A-12).

Kontrak publik:
- :meth:`RedactionEngine.redact` menerima ``str`` dan mengembalikan
  ``str``; input kosong → kosong; non-``str`` → :class:`TypeError`
  (kontrak eksplisit, tanpa konversi diam-diam).
- Nilai yang didaftarkan via :meth:`register_secret` **tidak pernah**
  muncul kembali di hasil (penggantian exact-match dijalankan paling
  akhir, setelah semua pola).
- Informasi diagnostik aman dipertahankan: hanya bagian nilai yang
  ditandai sensitif yang diganti ``[REDACTED:<SUMBER>]``; kunci/header/
  skema dipertahankan agar laporan tetap dapat ditindaklanjuti.
- Fail-safe: kegagalan satu aturan tidak pernah mengirim teks asli —
  hasil menjadi ``[REDACTED:UNPARSED]`` (konservatif).

Modul ini murni domain: tanpa Qt, subprocess, atau API platform (A-08).
"""

from __future__ import annotations

import re
from collections.abc import Callable

__all__ = ["RedactionEngine", "UNPARSED_PLACEHOLDER"]

UNPARSED_PLACEHOLDER = "[REDACTED:UNPARSED]"

_REDACTED = "[REDACTED:{tag}]"

#: Nilai lebih pendek dari ini tidak didaftarkan (mencegah redaksi luas
#: yang merusak informasi diagnostik, mis. port "8080").
MIN_SECRET_LENGTH = 8

# (tag, pola). Grup "prefix"/"suffix" dipertahankan; grup "value" selalu
# diganti placeholder. Urutan: spesifik dulu, KV generik paling akhir.
_RULES: tuple[tuple[str, str], ...] = (
    (
        "AUTH_HEADER",
        r"(?P<prefix>\bauthorization\s*:\s*)(?P<value>[^\r\n]+)",
    ),
    (
        "COOKIE",
        r"(?P<prefix>\bcookie\s*:\s*)(?P<value>[^\r\n]+)",
    ),
    (
        "TOKEN_FLAG",
        r"(?P<prefix>--token(?:=|\s+))(?P<value>\S+)",
    ),
    (
        "JWT",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b",
    ),
    (
        "JSON_FIELD",
        r'(?P<prefix>"(?:password|passwd|pwd|secret|token|api[_-]?key'
        r'|access[_-]?token|refresh[_-]?token|client[_-]?secret'
        r'|tunnel[_-]?secret)"\s*:\s*")(?P<value>[^"]+)(?P<suffix>")',
    ),
    (
        "URL_CREDENTIALS",
        r"(?P<prefix>[a-zA-Z][a-zA-Z0-9+.-]*://)"
        r"(?P<value>[^:/?\s@]+:[^@\s/]+)"
        r"(?P<suffix>@)",
    ),
    (
        "KEY_VALUE",
        r"(?P<prefix>\b(?:password|passwd|pwd|secret|token|api[-_]?key"
        r"|access[-_]?token|refresh[-_]?token|client[-_]?secret"
        r"|tunnel[-_]?secret)\b\s*[:=]\s*)(?P<value>[^\s&\"']+)",
    ),
)


class RedactionEngine:
    """Redaksi teks log/laporan sebelum ditampilkan, disimpan, atau diekspor.

    Contoh::

        engine = RedactionEngine()
        engine.register_secret("DUMMY_TUNNEL_SECRET_0123", "TunnelSecret")
        safe = engine.redact('error: token=abc123 gagal')
    """

    MIN_SECRET_LENGTH = MIN_SECRET_LENGTH

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self._patterns: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
            (tag, re.compile(pattern, re.IGNORECASE))
            for tag, pattern in _RULES
        )

    # ------------------------------------------------------------------
    # Pendaftaran rahasia yang diketahui
    # ------------------------------------------------------------------
    def register_secret(self, value: str, label: str = "SECRET") -> bool:
        """Daftarkan nilai rahasia yang diketahui (mis. dari credential file).

        Nilai di-strip dari spasi tepi. Nilai lebih pendek dari
        :data:`MIN_SECRET_LENGTH` **ditolak** untuk mencegah redaksi luas
        yang merusak diagnostik. Mengembalikan ``True`` bila nilai aktif
        terdaftar (termasuk bila sudah terdaftar sebelumnya), ``False``
        bila ditolak.
        """
        if not isinstance(value, str) or not isinstance(label, str):
            raise TypeError("value dan label harus str")
        cleaned = value.strip()
        if len(cleaned) < MIN_SECRET_LENGTH:
            return False
        if not cleaned:
            return False
        self._secrets[cleaned] = label or "SECRET"
        return True

    # ------------------------------------------------------------------
    # Redaksi
    # ------------------------------------------------------------------
    def redact(self, text: str) -> str:
        """Redaksi ``text`` dan kembalikan versi aman.

        Kontrak:
        - ``text`` wajib ``str`` (non-str → :class:`TypeError`).
        - String kosong dikembalikan apa adanya.
        - Deterministik: input sama → output sama.
        - Fail-safe: kegagalan aturan individual menghasilkan
          :data:`UNPARSED_PLACEHOLDER`, bukan teks asli.
        """
        if not isinstance(text, str):
            raise TypeError("redact() menerima str; non-str ditolak")
        if not text:
            return text

        result = text
        for tag, pattern in self._patterns:
            try:
                result = pattern.sub(self._make_replacer(tag), result)
            except Exception:  # noqa: BLE001 — fail-safe disengaja
                # Aturan gagal → konservatif: jangan pernah meneruskan
                # teks yang belum diperiksa.
                return UNPARSED_PLACEHOLDER

        # Penggantian exact-match rahasia terdaftar dilakukan paling akhir
        # sehingga nilai asli dijamin tidak lolos meski pola melewatkannya.
        for secret, label in self._secrets.items():
            if secret in result:
                result = result.replace(secret, _REDACTED.format(tag=label))
        return result

    @staticmethod
    def _make_replacer(tag: str) -> Callable[[re.Match[str]], str]:
        """Kembalikan fungsi pengganti bertype eksplisit untuk satu aturan."""

        def replacer(match: re.Match[str]) -> str:
            return RedactionEngine._replace(match, tag)

        return replacer

    @staticmethod
    def _replace(match: re.Match[str], tag: str) -> str:
        """Bangun pengganti: pertahankan prefix/suffix, ganti nilai."""
        groups = match.groupdict()
        prefix = groups.get("prefix") or ""
        suffix = groups.get("suffix") or ""
        return f"{prefix}{_REDACTED.format(tag=tag)}{suffix}"
