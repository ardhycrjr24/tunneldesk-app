"""Uji validator skema murni (E-6, tugas 2.2) — tanpa I/O, tanpa ruamel."""

from __future__ import annotations

from typing import Any

from tunneldesk.domain.config.model import ValidationClassification
from tunneldesk.domain.config.schema import validate_tunnel_config

VALID_DOC: dict[str, Any] = {
    "tunnel": "11111111-2222-3333-4444-555555555555",
    "credentials-file": "../F6/credentials-dummy.json",
    "ingress": [
        {"hostname": "aplikasi-sekolah.example.com", "service": "http://localhost:8080"},
        {"service": "http_status:404"},
    ],
}

CODES = lambda outcome: [item.code for item in outcome[1]]  # noqa: E731


def classify(document: dict[str, Any], exists: bool | None = None):
    checker = (lambda reference: exists) if exists is not None else None
    return validate_tunnel_config(document, credentials_file_exists=checker)


# ---------------------------------------------------------------------------
# VALID
# ---------------------------------------------------------------------------


def test_dokumen_valid_dengan_catch_all() -> None:
    classification, errors, warnings = classify(VALID_DOC)
    assert classification is ValidationClassification.VALID
    assert errors == ()
    assert warnings == ()  # catch-all ada → tanpa peringatan


def test_valid_tanpa_hostname_pada_item_pertama() -> None:
    doc = {
        "tunnel": VALID_DOC["tunnel"],
        "credentials-file": "c.json",
        "ingress": [{"service": "http://localhost:8080"}],
    }
    classification, errors, _ = classify(doc)
    # hostname opsional; item terakhir tanpa hostname → tidak ada warning
    assert classification is ValidationClassification.VALID
    assert errors == ()


def test_kunci_cloudflared_lain_dikenal_sebagian() -> None:
    """warp-routing adalah kunci cloudflared asli, tetapi skema E-6 sengaja
    sempit — dokumen diklasifikasikan UNKNOWN (jujur, PRD-02 §3.2)."""
    doc = {**VALID_DOC, "warp-routing": {"enabled": True}}
    classification, errors, _ = classify(doc)
    assert classification is ValidationClassification.UNKNOWN
    assert "UNKNOWN_TOP_LEVEL_KEY" in CODES((classification, errors))
    assert any(item.location == "warp-routing" for item in errors)


# ---------------------------------------------------------------------------
# INVALID — field wajib hilang / tipe salah
# ---------------------------------------------------------------------------


def test_missing_tunnel() -> None:
    doc = {k: v for k, v in VALID_DOC.items() if k != "tunnel"}
    classification, errors, _ = classify(doc)
    assert classification is ValidationClassification.INVALID
    assert "MISSING_TUNNEL" in CODES((classification, errors))


def test_tunnel_tipe_salah() -> None:
    classification, errors, _ = classify({**VALID_DOC, "tunnel": 12345})
    assert classification is ValidationClassification.INVALID
    assert "INVALID_TUNNEL_FORMAT" in CODES((classification, errors))


def test_tunnel_bukan_uuid() -> None:
    classification, errors, _ = classify({**VALID_DOC, "tunnel": "bukan-uuid"})
    assert classification is ValidationClassification.INVALID
    assert "INVALID_TUNNEL_FORMAT" in CODES((classification, errors))


def test_missing_credentials_file() -> None:
    doc = {k: v for k, v in VALID_DOC.items() if k != "credentials-file"}
    classification, errors, _ = classify(doc)
    assert classification is ValidationClassification.INVALID
    assert "MISSING_CREDENTIALS_FILE" in CODES((classification, errors))


def test_credentials_file_kosong() -> None:
    classification, errors, _ = classify({**VALID_DOC, "credentials-file": "   "})
    assert classification is ValidationClassification.INVALID
    assert "INVALID_CREDENTIALS_FILE_REFERENCE" in CODES((classification, errors))


def test_missing_ingress() -> None:
    doc = {k: v for k, v in VALID_DOC.items() if k != "ingress"}
    classification, errors, _ = classify(doc)
    assert classification is ValidationClassification.INVALID
    assert "MISSING_INGRESS" in CODES((classification, errors))


def test_ingress_kosong() -> None:
    classification, errors, _ = classify({**VALID_DOC, "ingress": []})
    assert classification is ValidationClassification.INVALID
    assert "EMPTY_INGRESS" in CODES((classification, errors))


def test_ingress_bukan_list() -> None:
    classification, errors, _ = classify({**VALID_DOC, "ingress": "satu-item"})
    assert classification is ValidationClassification.INVALID
    assert "INVALID_INGRESS_TYPE" in CODES((classification, errors))


def test_ingress_item_bukan_mapping() -> None:
    classification, errors, _ = classify({**VALID_DOC, "ingress": ["bukan-mapping"]})
    assert classification is ValidationClassification.INVALID
    assert "INVALID_INGRESS_ITEM_TYPE" in CODES((classification, errors))


def test_service_hilang_pada_item() -> None:
    doc = {
        **VALID_DOC,
        "ingress": [{"hostname": "a.example.com"}, {"service": "http_status:404"}],
    }
    classification, errors, _ = classify(doc)
    assert classification is ValidationClassification.INVALID
    assert "MISSING_SERVICE" in CODES((classification, errors))
    assert any(item.location == "ingress[0].service" for item in errors)


def test_service_null_adalah_empty_service() -> None:
    doc = {
        **VALID_DOC,
        "ingress": [{"hostname": "a.example.com", "service": None}],
    }
    classification, errors, _ = classify(doc)
    assert classification is ValidationClassification.INVALID
    assert "EMPTY_SERVICE" in CODES((classification, errors))


def test_service_skema_tidak_dikenal() -> None:
    doc = {
        **VALID_DOC,
        "ingress": [{"hostname": "a.example.com", "service": "ftp://localhost"}],
    }
    classification, errors, _ = classify(doc)
    assert classification is ValidationClassification.INVALID
    assert "INVALID_SERVICE_SCHEME" in CODES((classification, errors))


def test_hostname_tidak_valid() -> None:
    doc = {
        **VALID_DOC,
        "ingress": [
            {"hostname": "bukan_hostname_valid", "service": "http://localhost:8080"}
        ],
    }
    classification, errors, _ = classify(doc)
    assert classification is ValidationClassification.INVALID
    assert "INVALID_HOSTNAME" in CODES((classification, errors))


def test_hostname_bukan_string() -> None:
    doc = {**VALID_DOC, "ingress": [{"hostname": 123, "service": "http://x"}]}
    classification, errors, _ = classify(doc)
    assert "INVALID_HOSTNAME" in CODES((classification, errors))


# ---------------------------------------------------------------------------
# UNKNOWN — struktur tidak dikenal (PRD-02 §3.2)
# ---------------------------------------------------------------------------


def test_kunci_tingkat_atas_tidak_dikenal_menghasilkan_unknown() -> None:
    doc = {
        **VALID_DOC,
        "original-config-extra": {"fitur": True},
    }
    classification, errors, _ = classify(doc)
    assert classification is ValidationClassification.UNKNOWN
    assert "UNKNOWN_TOP_LEVEL_KEY" in CODES((classification, errors))


def test_unknown_tetap_melaporkan_error_skema_lain() -> None:
    """Kunci tak dikenal → UNKNOWN (dokumen tidak disentuh), namun
    pelanggaran skema lain tetap dilaporkan sebagai informasi."""
    doc = {
        "warp-routing": {"enabled": True},
        "credentials-file": "c.json",
        # tanpa tunnel → tetap dilaporkan MISSING_TUNNEL
    }
    classification, errors, _ = classify(doc)
    assert classification is ValidationClassification.UNKNOWN
    assert "MISSING_TUNNEL" in CODES((classification, errors))
    assert "UNKNOWN_TOP_LEVEL_KEY" in CODES((classification, errors))


def test_document_bukan_mapping() -> None:
    classification, errors, _ = validate_tunnel_config("bukan-mapping")
    assert classification is ValidationClassification.INVALID
    assert "NOT_A_MAPPING" in CODES((classification, errors))


# ---------------------------------------------------------------------------
# credentials-file existence (callback injected)
# ---------------------------------------------------------------------------


def test_credentials_file_missing_via_callback() -> None:
    classification, errors, _ = classify(VALID_DOC, exists=False)
    assert classification is ValidationClassification.INVALID
    assert "CREDENTIALS_FILE_MISSING" in CODES((classification, errors))
    assert "tidak dibaca" in errors[-1].message


def test_credentials_file_exists_via_callback() -> None:
    classification, errors, _ = classify(VALID_DOC, exists=True)
    assert classification is ValidationClassification.VALID
    assert errors == ()


def test_tanpa_callback_keberadaan_dilewati() -> None:
    classification, errors, _ = classify(VALID_DOC, exists=None)
    assert classification is ValidationClassification.VALID


# ---------------------------------------------------------------------------
# Peringatan catch-all
# ---------------------------------------------------------------------------


def test_tanpa_catch_all_menghasilkan_warning() -> None:
    doc = {
        "tunnel": VALID_DOC["tunnel"],
        "credentials-file": "c.json",
        "ingress": [{"hostname": "a.example.com", "service": "http://x"}],
    }
    classification, errors, warnings = classify(doc)
    assert classification is ValidationClassification.VALID
    assert errors == ()
    assert any(w.code == "NO_CATCH_ALL" for w in warnings)
    assert any(w.is_warning for w in warnings)
