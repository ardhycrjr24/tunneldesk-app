"""Komposisi layanan backend untuk Setup Wizard (Task 2.6).

Satu titik komposisi (A-08): UI menerima container layanan yang sudah
dibangun dengan dependensi platform + **deny-prefix direktori data
AKTUAL** (keputusan remediasi T-2: settings/log/backup TunnelDesk;
bila pengguna memindahkan lokasi log/backup di Pengaturan, lokasi
tersbut yang dipakai — bukan default).

Tanpa perubahan kontrak backend: seluruh service dibangun dengan
konstruktor yang ada (sama seperti uji integrasi Task 2.5).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from tunneldesk.application.backup_service import BackupService
from tunneldesk.application.config_apply_service import ConfigApplyService
from tunneldesk.application.config_preview import ConfigPreviewService
from tunneldesk.application.config_proposal import (
    ConfigProposalBuilder,
    WizardProposal,
)
from tunneldesk.application.config_validator import ConfigValidator
from tunneldesk.application.detection_service import DetectionService
from tunneldesk.application.settings_store import (
    AppSettings,
    SettingsStore,
    default_backup_dir,
    default_log_dir,
    default_settings_dir,
)
from tunneldesk.domain.diagnostics.origin import (
    OriginProbe,
    classify_probe_outcome,
    origin_target_from_service,
)
from tunneldesk.domain.redaction.engine import RedactionEngine
from tunneldesk.domain.tunnel.process_contracts import ProcessLauncher
from tunneldesk.infrastructure.config_io.config_writer import (
    AtomicConfigFileWriter,
)
from tunneldesk.infrastructure.config_io.yaml_parser import RoundTripYamlParser
from tunneldesk.infrastructure.network.origin_probe import SocketOriginProbe
from tunneldesk.ui.wizard.state import CheckOutcome, OriginRow

__all__ = [
    "WizardServices",
    "actual_deny_prefixes",
    "build_wizard_services",
    "run_check",
    "save_origin_settings",
]

#: Batas waktu probe origin lokal per baris (detik) — W-3.
PROBE_TIMEOUT_SECONDS = 1.5


@dataclass(frozen=True)
class WizardServices:
    """Container layanan wizard (semua kontrak Task 2.2-2.5 apa adanya)."""

    detection: DetectionService
    validator: ConfigValidator
    preview: ConfigPreviewService
    builder: ConfigProposalBuilder
    parser: RoundTripYamlParser
    apply: ConfigApplyService
    backup: BackupService
    probe: OriginProbe
    settings_store: SettingsStore
    #: Mesin redaksi UI (R-3): semua pesan gagal worker disanitasi sebelum tampil.
    redaction: RedactionEngine


def actual_deny_prefixes(settings: AppSettings) -> tuple[Path, ...]:
    """Deny-prefix dari direktori data AKTUAL (T-2): direktori pengaturan
    (tetap default A-11) + log/backup mengikuti AppSettings bila dipindah."""
    prefixes = [default_settings_dir()]
    prefixes.append(
        Path(settings.log_dir) if settings.log_dir else default_log_dir()
    )
    prefixes.append(
        Path(settings.backup_dir)
        if settings.backup_dir
        else default_backup_dir()
    )
    return tuple(prefixes)


def build_wizard_services(
    settings_store: SettingsStore,
    launcher: ProcessLauncher | None = None,
) -> WizardServices:
    """Bangun seluruh layanan wizard (pola komposisi app.py E-4)."""
    if launcher is None:
        if sys.platform == "win32":
            from tunneldesk.infrastructure.process.windows.adapter import (
                WindowsProcessLauncher,
            )

            launcher = WindowsProcessLauncher()
        else:
            from tunneldesk.infrastructure.process.posix.adapter import (
                PosixProcessLauncher,
            )

            launcher = PosixProcessLauncher()

    settings = settings_store.load()
    deny = actual_deny_prefixes(settings)
    backup_dir = (
        Path(settings.backup_dir) if settings.backup_dir else default_backup_dir()
    )
    writer = AtomicConfigFileWriter()
    backup = BackupService(
        backup_dir=backup_dir,
        register_db_path=backup_dir.parent / "backup-register.sqlite",
        writer=writer,
        deny_prefixes=deny,
    )
    apply_service = ConfigApplyService(
        writer=writer, backup_service=backup, deny_prefixes=deny
    )
    return WizardServices(
        detection=DetectionService(launcher),
        validator=ConfigValidator(),
        preview=ConfigPreviewService(),
        builder=ConfigProposalBuilder(),
        parser=RoundTripYamlParser(),
        apply=apply_service,
        backup=backup,
        probe=SocketOriginProbe(),
        settings_store=settings_store,
        redaction=RedactionEngine(),
    )


def run_check(
    services: WizardServices,
    proposed_text: str,
    target_path: Path,
    proposal: WizardProposal,
) -> CheckOutcome:
    """Halaman cek (W-3): validasi skema sadar-credential (relatif target)
    + probe origin lokal untuk SETIAP baris yang dapat dipetakan (PC-2:
    tidak mengasumsikan baris pertama aktif). Dijalankan dalam worker."""
    rows: list[OriginRow] = []
    for rule in proposal.ingress:
        target, error = origin_target_from_service(rule.service)
        if target is None and error is None:
            rows.append(OriginRow(service=rule.service, skipped=True))
            continue
        if target is None:
            rows.append(OriginRow(service=rule.service, error=error))
            continue
        outcome = services.probe.probe(target, PROBE_TIMEOUT_SECONDS)
        rows.append(
            OriginRow(
                service=rule.service,
                target=target,
                result=classify_probe_outcome(target, outcome),
            )
        )

    def credentials_exists(reference: str) -> bool:
        candidate = Path(reference)
        if not candidate.is_absolute():
            candidate = target_path.parent / reference
        return candidate.is_file()  # keberadaan saja — isi tak pernah dibaca

    validation = services.validator.validate_text(
        proposed_text, credentials_file_exists=credentials_exists
    )
    return CheckOutcome(validation=validation, origin_rows=tuple(rows))


def save_origin_settings(
    services: WizardServices, proposal: WizardProposal
) -> str:
    """W-5: simpan origin_host/port ke AppSettings SETELAH apply APPLIED.

    Kebijakan pemilihan (jujur, PC-2): tepat satu baris dapat-dipetakan →
    dipakai; lebih dari satu → baris PERTAMA dipakai dengan keterangan;
    tidak ada → pengaturan tidak diubah dengan keterangan. Nilai berasal
    dari formulir (bukan pembacaan ulang file). Controller TIDAK
    direkonstruksi dinamis (keputusan W-5) — berlaku setelah mulai ulang.
    """
    mappable = [
        origin_target_from_service(rule.service)
        for rule in proposal.ingress
    ]
    targets = [target for target, _error in mappable if target is not None]
    if not targets:
        return "tidak ada baris ingress yang dapat dipetakan ke origin"
    chosen = targets[0]
    note = ""
    if len(targets) > 1:
        note = (
            f"{len(targets)} origin ditemukan — memakai yang pertama "
            f"({chosen.host}:{chosen.port})"
        )
    settings = services.settings_store.load()
    services.settings_store.save(
        settings.with_updates(
            origin_host=chosen.host, origin_port=chosen.port
        )
    )
    return note
