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

from collections.abc import Mapping, MutableMapping, MutableSequence
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
        """Mutasi ``ingress`` dengan pencocokan baris dua tahap (R-1):

        Tahap 1 — pencocokan NILAI: baris formulir yang identik dengan
        baris asal (hostname+service ternormalisasi) memakai ulang baris
        asal tersebut, di posisi mana pun — komentar mengikutinya.
        Tahap 2 — fallback posisi: baris formulir tersisa (nilai berubah)
        memakai ulang baris asal tersisa secara berurutan (baris "sama
        yang diedit" tetap dianggap baris yang sama).
        Baris asal tak terpakai → dihapus (komentarnya ikut pergi — tanpa
        yatim); baris baru → tanpa komentar. R-2: catatan per-baris akurat
        berdasarkan kondisi asli. Semantik akhir = persis formulir.
        """
        existing = document.get("ingress")
        if not isinstance(existing, list):
            existing = []
            document["ingress"] = existing

        old_items = list(existing)

        def nilai(rule: IngressRule) -> tuple[str, str]:
            return (rule.hostname.strip(), rule.service.strip())

        def nilai_item(item: Mapping[object, object]) -> tuple[str, str]:
            hostname = item.get("hostname", "")
            service = item.get("service", "")
            return (
                str(hostname).strip() if isinstance(hostname, str) else "",
                str(service).strip() if isinstance(service, str) else "",
            )

        # Tahap 1: pencocokan nilai (konsumsi baris asal pertama yang cocok).
        dipakai: dict[int, int] = {}  # indeks rule → indeks asal
        terkonsumsi: set[int] = set()
        for index, rule in enumerate(rules):
            for old_index, old in enumerate(old_items):
                if old_index in terkonsumsi or not isinstance(
                    old, MutableMapping
                ):
                    continue
                if nilai_item(old) == nilai(rule):
                    dipakai[index] = old_index
                    terkonsumsi.add(old_index)
                    break

        # Tahap 2: fallback posisi untuk rule yang tak cocok nilainya.
        sisa_asal = [
            i for i in range(len(old_items)) if i not in terkonsumsi
        ]
        for index in range(len(rules)):
            if index in dipakai:
                continue
            if sisa_asal:
                old_index = sisa_asal.pop(0)
                dipakai[index] = old_index
                terkonsumsi.add(old_index)

        # Susun konten final sesuai formulir.
        new_items: list[object] = []
        comment_binding: dict[int, int] = {}  # indeks baru → indeks lama
        for index, rule in enumerate(rules):
            old_index_opt: int | None = dipakai.get(index)
            if old_index_opt is None:
                fresh: dict[object, object] = {}
                self._write_row(fresh, rule)
                new_items.append(fresh)
                continue
            old = old_items[old_index_opt]
            if isinstance(old, MutableMapping):
                extras = self._extra_keys(old)
                if extras:
                    notes.append(
                        f"properti ingress baris {index + 1} "
                        f"dipertahankan ({', '.join(extras)})"
                    )
                self._write_row(old, rule)
                new_items.append(old)
                comment_binding[index] = old_index
            else:
                # R-2 akurat: hanya baris non-pemetaan ini yang dilaporkan.
                notes.append(
                    f"baris ingress {index + 1} bukan pemetaan — "
                    "diganti oleh nilai formulir"
                )
                fresh = {}
                self._write_row(fresh, rule)
                new_items.append(fresh)

        for old_index in sorted(terkonsumsi.symmetric_difference(
            range(len(old_items)))
        ):
            removed = old_items[old_index]
            if isinstance(removed, Mapping):
                extras = self._extra_keys(removed)
                if extras:
                    notes.append(
                        "baris ingress yang dihapus formulir memuat "
                        f"properti tambahan ({', '.join(extras)}) — "
                        "properti tersebut ikut terhapus"
                    )

        # Susun ulang isi list — objek list yang sama tetap menempel di
        # dokumen (identitas node ruamel terjaga).
        del existing[:]
        existing.extend(new_items)

        # R-1: pindahkan komentar-pre baris mengikuti identitas baris.
        # Struktur ruamel (diverifikasi inspeksi): komentar sebelum baris-0
        # = parent.ca.items['ingress'][3] + seq.ca.comment[1] (redundan);
        # komentar sebelum baris-N>0 = post-comment (slot 2) kunci TERAKHIR
        # item N-1. Komentar EOL berada di slot berbeda dan ikut objek item
        # yang dipindah utuh.
        self._caravan_pre_comments(
            document, existing, old_items, comment_binding
        )

    @staticmethod
    def _extra_keys(item: Mapping[object, object]) -> list[str]:
        """Kunci item ingress di luar yang dikelola formulir (R-2)."""
        return [
            str(key) for key in item if key not in _MANAGED_INGRESS_KEYS
        ]

    @staticmethod
    def _pre_tokens_of_old(
        document: MutableMapping[object, object],
        old_items: list[object],
        old_index: int,
    ) -> object | None:
        """Ambil token komentar-pre milik baris asal ``old_index`` (R-1).

        Mengembalikan **token tunggal** (bentuk dinormalisasi — sumber
        berbeda konvensi: parent slot[3]/seq.comment[1] = list token,
        slot[2] kunci = token tunggal).
        """
        if old_index == 0:
            parent_slot = document.ca.items.get("ingress")  # type: ignore[attr-defined]
            if parent_slot is not None and len(parent_slot) > 3:
                if parent_slot[3] is not None:
                    return ConfigProposalBuilder._as_single_token(parent_slot[3])
            seq_ca = getattr(document.get("ingress"), "ca", None)
            if seq_ca is not None and seq_ca.comment is not None:
                tokens = seq_ca.comment
                if len(tokens) > 1 and tokens[1] is not None:
                    return ConfigProposalBuilder._as_single_token(tokens[1])
            return None
        prev = old_items[old_index - 1]
        ca = getattr(prev, "ca", None)
        if ca is None:
            return None
        for _key, slots in reversed(list(ca.items.items())):
            if len(slots) > 2 and slots[2] is not None:
                return slots[2]
        return None

    @staticmethod
    def _as_single_token(container: object) -> object:
        """Normalisasi kontainer komentar → token tunggal (R-1)."""
        if isinstance(container, list):
            if not container:
                return None
            if len(container) == 1:
                return container[0]
            # Multi-token: gabungkan nilai, mark diambil dari token awal.
            from ruamel.yaml.comments import CommentToken  # type: ignore[attr-defined]

            pertama = container[0]
            nilai = "".join(
                getattr(token, "value", "") for token in container
            )
            return CommentToken(  # type: ignore[no-any-return]
                nilai, pertama.start_mark, pertama.end_mark
            )
        return container

    @staticmethod
    def _set_pre_tokens_of_new(
        document: MutableMapping[object, object],
        seq: MutableSequence[object],
        new_index: int,
        token: object | None,
    ) -> None:
        """Tulis token komentar-pre ke baris final ``new_index`` (R-1).

        Bentuk sesuai target: parent slot[3] & seq.comment[1] = list
        token; slot[2] kunci terakhir item sebelumnya = token tunggal.
        """
        if token is None:
            return
        if new_index == 0:
            parent_slot: list[object] | None = document.ca.items.get(  # type: ignore[attr-defined]
                "ingress"
            )
            if parent_slot is None:
                parent_slot = [None, None, None, None]
                document.ca.items["ingress"] = parent_slot  # type: ignore[attr-defined]
            while len(parent_slot) < 4:
                parent_slot.append(None)
            parent_slot[3] = [token]
            seq_ca = getattr(seq, "ca", None)
            if seq_ca is not None and hasattr(seq_ca, "comment"):
                comment = list(seq_ca.comment) if seq_ca.comment else [None, None]
                while len(comment) < 2:
                    comment.append(None)
                comment[1] = [token]
                seq_ca.comment = comment
            return
        prev = seq[new_index - 1]
        ca = getattr(prev, "ca", None)
        if ca is None:
            return
        keys = list(ca.items.keys())
        if not keys:
            return
        last_key = keys[-1]
        slots = ca.items[last_key]
        while len(slots) < 3:
            slots.append(None)
        slots[2] = token

    @classmethod
    def _caravan_pre_comments(
        cls,
        document: MutableMapping[object, object],
        seq: MutableSequence[object],
        old_items: list[object],
        comment_binding: Mapping[int, int],
    ) -> None:
        """Pindahkan komentar-pre: baris final menerima komentar baris
        asalnya; komentar baris yang dihapus dibuang; baris baru tanpa
        komentar — tanpa yatim, tanpa perpindahan salah (R-1)."""
        seq_ca = getattr(seq, "ca", None)

        def kosongkan_header() -> None:
            parent_slot = document.ca.items.get("ingress")  # type: ignore[attr-defined]
            if parent_slot is not None and len(parent_slot) > 3:
                parent_slot[3] = None
            if seq_ca is not None and hasattr(seq_ca, "comment"):
                seq_ca.comment = [None, None]

        def kosongkan_pre(item: object) -> None:
            ca = getattr(item, "ca", None)
            if ca is None:
                return
            for slots in ca.items.values():
                if len(slots) > 2:
                    slots[2] = None

        # Baca semua token lama SEBELUM menulis (struktur masih utuh).
        tokens_per_old: dict[int, object] = {}
        for old_index in range(len(old_items)):
            tokens = cls._pre_tokens_of_old(document, old_items, old_index)
            if tokens is not None:
                tokens_per_old[old_index] = tokens

        if not tokens_per_old:
            return  # tidak ada komentar-pre — tidak ada yang dipindah

        # Bersihkan seluruh posisi lama (parent/seq + tiap item).
        kosongkan_header()
        for item in old_items:
            kosongkan_pre(item)

        # Tulis komentar ke baris final sesuai binding.
        for new_index in range(len(seq)):
            old_index_opt: int | None = comment_binding.get(new_index)
            tokens = (
                tokens_per_old.get(old_index_opt)
                if old_index_opt is not None
                else None
            )
            if tokens is not None:
                cls._set_pre_tokens_of_new(document, seq, new_index, tokens)
            elif new_index == 0:
                kosongkan_header()  # baris 0 baru — hapus pre yatim
            else:
                kosongkan_pre(seq[new_index - 1])  # hapus pre yatim

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
