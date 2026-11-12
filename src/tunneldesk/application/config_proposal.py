"""ConfigProposalBuilder (Task 2.6, PC-1, keputusan W-1) — penyusun usulan.

Guided Form sebagai satu-satunya model konfigurasi MVP: wizard memutasi
DOKUMEN hasil parse round-trip (ruamel, A-02) hanya pada tiga kelompok
kunci yang disetujui — ``tunnel``, ``credentials-file``, ``ingress`` —
lalu meng-emit ulang dengan konfigurasi emitter yang SAMA (metode aditif
``RoundTripYamlParser.emit``). Konsekuensi jujur (keputusan W-1):

- Kunci tingkat atas tak dikenal + komentar DIPERTAHANKAN apa adanya;
  usulan yang memuatnya tetap terklasifikasi UNKNOWN oleh skema E-6 dan
  apply diblokir kontrak Task 2.5 (PRD-02 §3.2) — builder menambah catatan
  jujur, TIDAK pernah memaksa UNKNOWN menjadi VALID.
- Properti ingress di luar ``hostname``/``service`` (mis.
  ``originRequest``) TIDAK dihapus diam-diam: baris pada posisi yang sama
  dimutasi di tempat sehingga properti tambahannya terbawa; penghapusan
  baris oleh formulir atas item bermuatan properti tambahan dilaporkan
  sebagai catatan.
- Sintaks asal rusak / dokumen bukan pemetaan → usulan DITOLAK (None)
  dengan alasan — wizard menampilkan error sebelum formulir disusun.

Modul murni orkestrasi tanpa I/O file (teks masuk, teks keluar).
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass

from tunneldesk.infrastructure.config_io.yaml_parser import RoundTripYamlParser

__all__ = [
    "IngressRule",
    "WizardProposal",
    "ProposalResult",
    "ConfigProposalBuilder",
]

#: Kelompok kunci yang dikelola Guided Form (keputusan W-1/PC-1).
_MANAGED_TOP_LEVEL = frozenset({"tunnel", "credentials-file", "ingress"})
#: Kunci item ingress yang dikelola formulir.
_MANAGED_INGRESS_KEYS = frozenset({"hostname", "service"})


@dataclass(frozen=True)
class IngressRule:
    """Satu baris ingress formulir: service wajib, hostname opsional."""

    service: str
    hostname: str = ""


@dataclass(frozen=True)
class WizardProposal:
    """Nilai Guided Form untuk tiga kelompok kunci yang dikelola."""

    tunnel: str
    credentials_file: str
    ingress: tuple[IngressRule, ...]

    @classmethod
    def from_document(cls, document: Mapping[object, object]) -> WizardProposal:
        """Prefill formulir dari dokumen asal (hostname/service per baris;
        item bukan pemetaan dilewati jujur)."""
        tunnel = document.get("tunnel", "")
        credentials = document.get("credentials-file", "")
        rules: list[IngressRule] = []
        ingress = document.get("ingress")
        if isinstance(ingress, list):
            for item in ingress:
                if isinstance(item, Mapping):
                    rules.append(
                        IngressRule(
                            service=str(item.get("service", "")),
                            hostname=str(item.get("hostname", "")),
                        )
                    )
        return cls(
            tunnel=str(tunnel),
            credentials_file=str(credentials),
            ingress=tuple(rules),
        )


@dataclass(frozen=True)
class ProposalResult:
    """Hasil penyusunan usulan.

    ``proposed_text`` ``None`` = usulan ditolak (lihat ``syntax_errors`` /
    ``notes``). ``notes`` = pengungkapan jujur untuk pengguna (aman
    ditampilkan; tanpa isi credential — referensi path saja).
    """

    proposed_text: str | None
    syntax_errors: tuple[tuple[str, int | None, int | None], ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.proposed_text is not None


class ConfigProposalBuilder:
    """Penyusun teks usulan via mutasi round-trip terkendali (PC-1)."""

    def __init__(self, parser: RoundTripYamlParser | None = None) -> None:
        self._parser = parser or RoundTripYamlParser()

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------
    def build(
        self, original_text: str, proposal: WizardProposal
    ) -> ProposalResult:
        """Susun ``proposed_text`` dari dokumen asal + nilai formulir.

        Tanpa I/O file; tanpa validasi skema (tanggung jawab halaman cek
        via ConfigValidator — pemisahan kontrak Task 2.3/2.6).
        """
        parsed = self._parser.parse(original_text)
        if parsed.syntax_errors:
            return ProposalResult(
                proposed_text=None,
                syntax_errors=parsed.syntax_errors,
                notes=(
                    "dokumen asal memiliki kesalahan sintaks — perbaiki "
                    "file sebelum menyusun usulan",
                ),
            )
        document = parsed.document
        if not isinstance(document, MutableMapping):
            return ProposalResult(
                proposed_text=None,
                notes=(
                    "dokumen asal bukan pemetaan YAML yang dapat dimutasi — "
                    "Guided Form hanya mendukung konfigurasi berbentuk "
                    "pemetaan",
                ),
            )

        notes: list[str] = []
        self._note_unknown_keys(document, notes)

        # Mutasi tiga kelompok kunci yang dikelola (sisanya tak tersentuh).
        document["tunnel"] = proposal.tunnel
        document["credentials-file"] = proposal.credentials_file
        self._apply_ingress(document, proposal.ingress, notes)

        emitted = self._parser.emit(document)
        if emitted is None:
            return ProposalResult(
                proposed_text=None,
                notes=(
                    "penyusunan teks usulan gagal — perubahan tidak dibuat",
                ),
            )
        return ProposalResult(
            proposed_text=emitted, syntax_errors=(), notes=tuple(notes)
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    @staticmethod
    def _note_unknown_keys(
        document: Mapping[object, object], notes: list[str]
    ) -> None:
        unknown = [
            str(key) for key in document if key not in _MANAGED_TOP_LEVEL
        ]
        if unknown:
            ringkas = ", ".join(sorted(unknown)[:5]) + (
                ", …" if len(unknown) > 5 else ""
            )
            notes.append(
                f"kunci tak dikenal dipertahankan apa adanya ({ringkas}) — "
                "konfigurasi tetap terklasifikasi UNKNOWN dan apply akan "
                "diblokir (PRD-02 §3.2); hapus atau edit kunci tersebut "
                "secara manual di luar TunnelDesk bila ingin menerapkan"
            )

    def _apply_ingress(
        self,
        document: MutableMapping[object, object],
        rules: tuple[IngressRule, ...],
        notes: list[str],
    ) -> None:
        """Mutasi ``ingress`` in-place: baris posisi sama diperbarui
        (properti tambahannya TERBAWA), baris baru disisipkan, kelebihan
        baris dihapus — penghapusan atas item berproperti tambahan
        dilaporkan jujur."""
        existing = document.get("ingress")
        if not isinstance(existing, list):
            existing = []
            document["ingress"] = existing

        preserved_extras: list[str] = []
        for index, rule in enumerate(rules):
            if index < len(existing) and isinstance(
                existing[index], Mapping
            ):
                item = existing[index]
                extras = [
                    str(key)
                    for key in item
                    if key not in _MANAGED_INGRESS_KEYS
                ]
                if extras:
                    preserved_extras.append(
                        f"baris {index + 1}: {', '.join(extras)}"
                    )
                self._write_row(item, rule)
            else:
                if index < len(existing):
                    notes.append(
                        f"baris ingress {index + 1} bukan pemetaan — "
                        "diganti oleh nilai formulir"
                    )
                fresh: dict[object, object] = {}
                self._write_row(fresh, rule)
                existing.insert(index, fresh)

        while len(existing) > len(rules):
            removed = existing.pop()
            if isinstance(removed, Mapping):
                extras = [
                    str(key)
                    for key in removed
                    if key not in _MANAGED_INGRESS_KEYS
                ]
                if extras:
                    notes.append(
                        "baris ingress yang dihapus formulir memuat "
                        f"properti tambahan ({', '.join(extras)}) — "
                        "properti tersebut ikut terhapus"
                    )

        if preserved_extras:
            notes.append(
                "properti ingress di luar formulir dipertahankan pada "
                f"posisinya ({'; '.join(preserved_extras)})"
            )

    @staticmethod
    def _write_row(
        item: MutableMapping[object, object], rule: IngressRule
    ) -> None:
        """Tulis satu baris ke item yang ada (in-place) atau dict baru."""
        if rule.hostname:
            item["hostname"] = rule.hostname
        elif "hostname" in item:
            del item["hostname"]  # hostname dikosongkan pengguna (kunci dikelola)
        item["service"] = rule.service
