"""Uji ConfigProposalBuilder (PC-1/W-1, Task 2.6) — mutasi round-trip.

Kontrak: hanya 3 kelompok kunci termutasi; kunci tak dikenal + komentar
terbawa; UNKNOWN tidak dipaksa VALID (catatan jujur); sintaks rusak /
bukan pemetaan ditolak. Tanpa I/O file.
"""

from __future__ import annotations

from tunneldesk.application.config_proposal import (
    ConfigProposalBuilder,
    IngressRule,
    WizardProposal,
)
from tunneldesk.application.config_validator import ConfigValidator
from tunneldesk.domain.config.model import ValidationClassification

VALID = (
    "tunnel: 11111111-2222-3333-4444-555555555555\n"
    "credentials-file: credentials-dummy.json\n"
    "ingress:\n"
    "  - hostname: rapor.sekolah.sch.id\n"
    "    service: http://localhost:8080\n"
    "  - service: http_status:404\n"
)

PROPOSAL = WizardProposal(
    tunnel="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    credentials_file="creds-baru.json",
    ingress=(
        IngressRule(hostname="ujung.example.sch.id", service="http://127.0.0.1:9090"),
        IngressRule(service="http_status:404"),
    ),
)

builder = ConfigProposalBuilder()


def test_sukses_tiga_kelompok_termutasi() -> None:
    result = builder.build(VALID, PROPOSAL)
    assert result.ok
    assert result.proposed_text is not None
    text = result.proposed_text
    assert "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in text
    assert "creds-baru.json" in text
    assert "ujung.example.sch.id" in text
    assert "127.0.0.1:9090" in text
    # Nilai lama ketiga kelompok tidak tersisa.
    assert "2222-3333" not in text
    assert "credentials-dummy" not in text
    assert "localhost:8080" not in text


def test_usulan_valid_secara_skema() -> None:
    result = builder.build(VALID, PROPOSAL)
    outcome = ConfigValidator().validate_text(
        result.proposed_text or "", credentials_file_exists=True
    )
    assert outcome.classification is ValidationClassification.VALID


def test_kunci_tak_dikenal_dipertahankan_dan_dicatat() -> None:
    dengan_asing = VALID + "original-config-extra: true\n"
    result = builder.build(dengan_asing, PROPOSAL)
    assert result.ok
    assert "original-config-extra: true" in result.proposed_text  # terbawa
    assert any("UNKNOWN" in note for note in result.notes)  # catatan jujur
    # UNKNOWN TIDAK dipaksa VALID (klasifikasi tetap oleh skema E-6).
    outcome = ConfigValidator().validate_text(
        result.proposed_text or "", credentials_file_exists=True
    )
    assert outcome.classification is ValidationClassification.UNKNOWN


def test_komentar_dipertahankan() -> None:
    berkomentar = (
        "# konfigurasi milik sekolah\n"
        + VALID.replace(
            "ingress:\n", "# ingress dikelola TunnelDesk\ningress:\n"
        )
    )
    result = builder.build(berkomentar, PROPOSAL)
    assert result.ok
    assert "# konfigurasi milik sekolah" in result.proposed_text
    assert "# ingress dikelola TunnelDesk" in result.proposed_text


def test_properti_tambahan_ingress_dipertahankan() -> None:
    dengan_extra = VALID.replace(
        "  - hostname: rapor.sekolah.sch.id\n",
        "  - hostname: rapor.sekolah.sch.id\n"
        "    originRequest:\n"
        "      connectTimeout: 10s\n",
    )
    result = builder.build(dengan_extra, PROPOSAL)
    assert result.ok
    assert "connectTimeout: 10s" in result.proposed_text  # tidak dihapus
    assert any("dipertahankan" in n for n in result.notes)


def test_hapus_baris_berproperti_tambahan_dicatat() -> None:
    dengan_extra = VALID.replace(
        "  - service: http_status:404\n",
        "  - service: http_status:404\n    originRequest:\n      noTLSVerify: true\n",
    )
    proposal_satu = WizardProposal(
        tunnel=PROPOSAL.tunnel,
        credentials_file=PROPOSAL.credentials_file,
        ingress=(IngressRule(service="http://localhost:8080"),),
    )
    result = builder.build(dengan_extra, proposal_satu)
    assert result.ok
    assert "noTLSVerify" not in (result.proposed_text or "")
    assert any("ikut terhapus" in n for n in result.notes)


def test_baris_baru_ditambahkan() -> None:
    proposal_tiga = WizardProposal(
        tunnel=PROPOSAL.tunnel,
        credentials_file=PROPOSAL.credentials_file,
        ingress=(
            IngressRule(hostname="a.sch.id", service="http://localhost:80"),
            IngressRule(hostname="b.sch.id", service="http://localhost:81"),
            IngressRule(service="http_status:404"),
        ),
    )
    result = builder.build(VALID, proposal_tiga)
    assert result.ok
    assert result.proposed_text is not None
    # Dua baris ber-hostname (kunci baru pada item lama dapat mengikuti
    # service — urutan kunci dalam pemetaan YAML netral, diff jujur).
    assert result.proposed_text.count("hostname:") == 2
    assert "http_status:404" in result.proposed_text


def test_hostname_dikosongkan_menghapus_kunci() -> None:
    tanpa_hostname = WizardProposal(
        tunnel=PROPOSAL.tunnel,
        credentials_file=PROPOSAL.credentials_file,
        ingress=(IngressRule(service="http://localhost:8080"),),
    )
    result = builder.build(VALID, tanpa_hostname)
    assert result.ok
    assert "hostname" not in (result.proposed_text or "")


def test_ingress_baru_dari_nol() -> None:
    minimal = "tunnel: 11111111-2222-3333-4444-555555555555\n"
    result = builder.build(minimal, PROPOSAL)
    assert result.ok
    assert "ingress:" in (result.proposed_text or "")


def test_sintaks_asal_rusak_ditolak() -> None:
    result = builder.build("tunnel: [rusak\n", PROPOSAL)
    assert not result.ok
    assert result.proposed_text is None
    assert result.syntax_errors  # posisi error asli diteruskan


def test_dokumen_bukan_pemetaan_ditolak() -> None:
    result = builder.build("- a\n- b\n", PROPOSAL)
    assert not result.ok
    assert any("pemetaan" in n for n in result.notes)


def test_emit_ulang_stabil_deterministik() -> None:
    satu = builder.build(VALID, PROPOSAL)
    dua = builder.build(VALID, PROPOSAL)
    assert satu.proposed_text == dua.proposed_text


def test_prefill_dari_dokumen() -> None:
    parsed = ConfigProposalBuilder()._parser.parse(VALID)  # noqa: SLF001
    prefill = WizardProposal.from_document(parsed.document)  # type: ignore[arg-type]
    assert prefill.tunnel == "11111111-2222-3333-4444-555555555555"
    assert prefill.credentials_file == "credentials-dummy.json"
    assert prefill.ingress == (
        IngressRule(hostname="rapor.sekolah.sch.id", service="http://localhost:8080"),
        IngressRule(service="http_status:404"),
    )
