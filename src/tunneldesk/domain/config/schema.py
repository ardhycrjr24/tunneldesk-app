"""Validator skema konfigurasi tunnel (E-6, tugas 2.2 — PRD-01 §7.4).

Fungsi murni atas dokumen hasil parse (mapping) — tanpa I/O, tanpa
ruamel, tanpa penulisan file (D-17: validasi ≠ modifikasi).

Aturan klasifikasi (deterministik): INVALID > UNKNOWN > VALID.
- Kesalahan skema yang dapat dipastikan → INVALID.
- Kunci tingkat atas di luar skema yang didukung → UNKNOWN (PRD-02 §3.2:
  "konfigurasi tidak dikenal tidak diubah otomatis").
- Bersih → VALID.

Skema yang didukung E-6 sengaja sempit (jujur — PRD-02: jangan
mengiklankan yang belum diuji): ``tunnel``, ``credentials-file``,
``ingress``. Kunci cloudflared lain (mis. warp-routing) → UNKNOWN.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from .model import ValidationClassification, ValidationErrorItem

__all__ = ["validate_tunnel_config"]

_KNOWN_TOP_LEVEL_KEYS = frozenset({"tunnel", "credentials-file", "ingress"})

_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](-*[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$"
)
_ALLOWED_SERVICE_SCHEMES = ("http://", "https://", "http_status:", "http_status:")


def _truncate(value: object, limit: int = 40) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _is_str(value: object) -> bool:
    return isinstance(value, str)


def _validate_tunnel(
    document: Mapping[Any, Any], errors: list[ValidationErrorItem]
) -> None:
    if "tunnel" not in document:
        errors.append(
            ValidationErrorItem(
                "MISSING_TUNNEL",
                "kunci 'tunnel' wajib ada (ID tunnel cloudflared)",
                location="tunnel",
            )
        )
        return
    value = document["tunnel"]
    if not _is_str(value) or not _UUID_PATTERN.match(value):
        errors.append(
            ValidationErrorItem(
                "INVALID_TUNNEL_FORMAT",
                "'tunnel' wajib berupa UUID cloudflared yang valid — "
                f"ditemukan: {_truncate(value)}",
                location="tunnel",
            )
        )


def _validate_credentials_file(
    document: Mapping[Any, Any],
    errors: list[ValidationErrorItem],
    file_exists: Callable[[str], bool] | None,
) -> None:
    if "credentials-file" not in document:
        errors.append(
            ValidationErrorItem(
                "MISSING_CREDENTIALS_FILE",
                "kunci 'credentials-file' wajib ada (path file credential "
                "tunnel)",
                location="credentials-file",
            )
        )
        return
    value = document["credentials-file"]
    if not _is_str(value) or not value.strip():
        errors.append(
            ValidationErrorItem(
                "INVALID_CREDENTIALS_FILE_REFERENCE",
                "'credentials-file' wajib berupa path yang tidak kosong",
                location="credentials-file",
            )
        )
        return
    # Keberadaan file dicek HANYA bila pemanggil menyediakan checker —
    # isi file credential tidak pernah dibaca (D-18).
    if file_exists is not None and not file_exists(value):
        errors.append(
            ValidationErrorItem(
                "CREDENTIALS_FILE_MISSING",
                "file credential yang dirujuk tidak ditemukan — isi file "
                "tidak dibaca oleh TunnelDesk",
                location="credentials-file",
            )
        )


def _validate_service(
    item: Mapping[Any, Any],
    index: int,
    errors: list[ValidationErrorItem],
) -> None:
    location = f"ingress[{index}].service"
    if "service" not in item:
        errors.append(
            ValidationErrorItem(
                "MISSING_SERVICE",
                "setiap item ingress wajib memiliki 'service' (origin)",
                location=location,
            )
        )
        return
    service = item["service"]
    if service is None:
        errors.append(
            ValidationErrorItem(
                "EMPTY_SERVICE",
                "'service' tidak boleh kosong — isi origin (mis. "
                "http://localhost:8080)",
                location=location,
            )
        )
        return
    if not _is_str(service):
        errors.append(
            ValidationErrorItem(
                "INVALID_SERVICE_TYPE",
                "'service' wajib berupa teks — ditemukan: "
                f"{_truncate(type(service).__name__)}",
                location=location,
            )
        )
        return
    normalized = service.strip()
    if not normalized.startswith(_ALLOWED_SERVICE_SCHEMES):
        errors.append(
            ValidationErrorItem(
                "INVALID_SERVICE_SCHEME",
                "'service' wajib berawalan http://, https://, atau "
                f"http_status: — ditemukan: {_truncate(normalized)}",
                location=location,
            )
        )


def _validate_hostname(
    item: Mapping[Any, Any], index: int, errors: list[ValidationErrorItem]
) -> None:
    if "hostname" not in item:
        return
    hostname = item["hostname"]
    location = f"ingress[{index}].hostname"
    if not _is_str(hostname) or not _HOSTNAME_PATTERN.match(hostname):
        errors.append(
            ValidationErrorItem(
                "INVALID_HOSTNAME",
                "'hostname' wajib berupa nama DNS yang valid — "
                f"ditemukan: {_truncate(hostname)}",
                location=location,
            )
        )


def _validate_ingress(
    document: Mapping[Any, Any], errors: list[ValidationErrorItem]
) -> None:
    if "ingress" not in document:
        errors.append(
            ValidationErrorItem(
                "MISSING_INGRESS",
                "kunci 'ingress' wajib ada (aturan routing ke origin)",
                location="ingress",
            )
        )
        return
    ingress = document["ingress"]
    if not isinstance(ingress, list):
        errors.append(
            ValidationErrorItem(
                "INVALID_INGRESS_TYPE",
                "'ingress' wajib berupa daftar item — ditemukan: "
                f"{_truncate(type(ingress).__name__)}",
                location="ingress",
            )
        )
        return
    if not ingress:
        errors.append(
            ValidationErrorItem(
                "EMPTY_INGRESS",
                "'ingress' tidak boleh kosong — minimal satu aturan routing "
                "dan catch-all",
                location="ingress",
            )
        )
        return
    for index, item in enumerate(ingress):
        if not isinstance(item, dict):
            errors.append(
                ValidationErrorItem(
                    "INVALID_INGRESS_ITEM_TYPE",
                    "setiap item ingress wajib berupa pemetaan — "
                    f"ditemukan: {_truncate(type(item).__name__)}",
                    location=f"ingress[{index}]",
                )
            )
            continue
        _validate_service(item, index, errors)
        _validate_hostname(item, index, errors)


def _warn_missing_catch_all(
    document: Mapping[Any, Any], warnings: list[ValidationErrorItem]
) -> None:
    """Rekomendasi (peringatan, bukan error): item terakhir ingress
    sebaiknya catch-all agar traffic tak tertangani tidak bocor."""
    ingress = document.get("ingress")
    if not isinstance(ingress, list) or not ingress:
        return
    last = ingress[-1]
    if isinstance(last, dict) and "hostname" in last:
        warnings.append(
            ValidationErrorItem(
                "NO_CATCH_ALL",
                "item ingress terakhir masih memiliki 'hostname' — "
                "tambahkan catch-all (mis. 'service: http_status:404') "
                "di akhir agar traffic tak tertangani tidak bocor",
                location=f"ingress[{len(ingress) - 1}]",
                is_warning=True,
            )
        )


def validate_tunnel_config(
    document: Mapping[Any, Any],
    credentials_file_exists: Callable[[str], bool] | None = None,
) -> tuple[
    ValidationClassification,
    tuple[ValidationErrorItem, ...],
    tuple[ValidationErrorItem, ...],
]:
    """Validasi skema aplikasi atas dokumen yang sudah ter-parse.

    Args:
        document: mapping hasil parser (round-trip ruamel — objeknya
            kompatibel ``Mapping`` tanpa mengimpor ruamel di domain).
        credentials_file_exists: callback opsional untuk memeriksa
            keberadaan file credential (injected — domain tanpa I/O).
            Isi file **tidak pernah dibaca**.

    Returns:
        (klasifikasi, errors, warnings) — errors menentukan INVALID,
        unknown-keys memaksa UNKNOWN bila tidak ada error.
    """
    errors: list[ValidationErrorItem] = []
    warnings: list[ValidationErrorItem] = []

    if not isinstance(document, Mapping):
        errors.append(
            ValidationErrorItem(
                "NOT_A_MAPPING",
                "dokumen konfigurasi wajib berupa pemetaan YAML — "
                f"ditemukan: {_truncate(type(document).__name__)}",
            )
        )
        return ValidationClassification.INVALID, tuple(errors), tuple(warnings)

    unknown_keys = [
        key for key in document if key not in _KNOWN_TOP_LEVEL_KEYS
    ]
    for key in unknown_keys:
        errors.append(
            ValidationErrorItem(
                "UNKNOWN_TOP_LEVEL_KEY",
                f"kunci tingkat atas '{_truncate(key)}' tidak didukung "
                "skema TunnelDesk — konfigurasi diperlakukan tidak dikenal "
                "dan tidak akan diubah otomatis",
                location=_truncate(key),
            )
        )

    _validate_tunnel(document, errors)
    _validate_credentials_file(document, errors, credentials_file_exists)
    _validate_ingress(document, errors)
    _warn_missing_catch_all(document, warnings)

    # Aturan klasifikasi deterministik (PRD-02 §3.2 + PRD-01 §7.3):
    # - kunci/struktur tingkat atas tak dikenal → UNKNOWN dan dokumen
    #   TIDAK akan disentuh (perilaku paling aman), meskipun ada
    #   pelanggaran skema lain yang terdeteksi (semua tetap dilaporkan);
    # - tanpa kunci tak dikenal tetapi ada pelanggaran skema → INVALID;
    # - bersih → VALID.
    if unknown_keys:
        return ValidationClassification.UNKNOWN, tuple(errors), tuple(warnings)
    if errors:
        return ValidationClassification.INVALID, tuple(errors), tuple(warnings)
    return ValidationClassification.VALID, tuple(errors), tuple(warnings)
