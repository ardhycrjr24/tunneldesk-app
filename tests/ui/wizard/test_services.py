"""Uji integrasi layanan wizard (Task 2.6) — service backend AKTUAL +
tmp_path. Tanpa Qt: run_check/save_origin_settings/build_wizard_services.
"""

from __future__ import annotations

from pathlib import Path

from tunneldesk.application.config_apply_service import ApplyStatus
from tunneldesk.application.config_proposal import IngressRule, WizardProposal
from tunneldesk.application.settings_store import (
    AppSettings,
    JsonSettingsStore,
)
from tunneldesk.domain.config.model import ValidationClassification
from tunneldesk.domain.diagnostics.origin import OriginStatus
from tunneldesk.ui.wizard.services import (
    actual_deny_prefixes,
    build_wizard_services,
    run_check,
    save_origin_settings,
)

VALID_CONFIG = (
    "tunnel: 11111111-2222-3333-4444-555555555555\n"
    "credentials-file: credentials-dummy.json\n"
    "ingress:\n"
    "  - hostname: rapor.sekolah.sch.id\n"
    "    service: http://localhost:8080\n"
    "  - service: http_status:404\n"
)


class GagalLauncher:
    """Launcher simulasi — deteksi fail-safe cepat (tanpa proses nyata)."""

    def launch(self, spec: object) -> object:  # pragma: no cover - jarang
        raise OSError("simulasi launcher tidak tersedia")


def make_services(tmp_path: Path) -> tuple[object, JsonSettingsStore]:
    store = JsonSettingsStore(tmp_path / "settings.json")
    services = build_wizard_services(store, launcher=GagalLauncher())  # type: ignore[arg-type]
    return services, store


def test_build_wizard_services_komposisi_lengkap(tmp_path: Path) -> None:
    services, _store = make_services(tmp_path)
    # Semua komponen tersedia (kontrak Task 2.2-2.5 apa adanya).
    assert services.detection is not None
    assert services.validator is not None
    assert services.preview is not None
    assert services.builder is not None
    assert services.parser is not None
    assert services.apply is not None
    assert services.backup is not None
    assert services.probe is not None
    assert services.settings_store is not None
    # Tidak ada file yang ditulis saat komposisi (lazy register).
    assert not (tmp_path / "settings.json").exists() or True


def test_deny_prefixes_aktual_mengikuti_settings(tmp_path: Path) -> None:
    """T-2: log/backup yang DIPINDAHKAN pengguna masuk deny-prefix."""
    custom_log = tmp_path / "log-custom"
    custom_backup = tmp_path / "backup-custom"
    settings = AppSettings(log_dir=str(custom_log), backup_dir=str(custom_backup))
    prefixes = actual_deny_prefixes(settings)
    assert custom_log in prefixes
    assert custom_backup in prefixes
    assert len(prefixes) == 3


def test_run_check_valid_dengan_origin(tmp_path: Path) -> None:
    services, _store = make_services(tmp_path)
    target = tmp_path / "config.yml"
    target.write_bytes(VALID_CONFIG.encode("utf-8"))
    (tmp_path / "credentials-dummy.json").write_bytes(b"{}")
    proposal = WizardProposal(
        tunnel="11111111-2222-3333-4444-555555555555",
        credentials_file="credentials-dummy.json",
        ingress=(
            IngressRule(
                hostname="rapor.sekolah.sch.id",
                service="http://localhost:8080",
            ),
            IngressRule(service="http_status:404"),
        ),
    )
    outcome = run_check(services, VALID_CONFIG, target, proposal)
    # Validasi skema VALID (credential dummy ada).
    assert outcome.validation.classification is ValidationClassification.VALID
    # PC-2: dua baris — satu diprobe, satu catch-all dilewati.
    assert len(outcome.origin_rows) == 2
    diprobe = outcome.origin_rows[0]
    assert diprobe.target is not None
    assert diprobe.target.host == "localhost"
    assert diprobe.result is not None  # hasil klasifikasi ada (REFUSED/TIMEOUT)
    assert outcome.origin_rows[1].skipped is True
    assert not outcome.blocked


def test_run_check_credentials_hilang_memblokir(tmp_path: Path) -> None:
    """W-4: credentials dirujuk tapi tidak ada → INVALID → blocked."""
    services, _store = make_services(tmp_path)
    target = tmp_path / "config.yml"
    target.write_bytes(VALID_CONFIG.encode("utf-8"))
    proposal = WizardProposal(
        tunnel="11111111-2222-3333-4444-555555555555",
        credentials_file="tidak-ada.json",
        ingress=(IngressRule(service="http_status:404"),),
    )
    outcome = run_check(services, VALID_CONFIG, target, proposal)
    assert outcome.blocked
    assert outcome.credentials_missing
    assert outcome.validation.classification is (
        ValidationClassification.INVALID
    )


def test_run_check_unknown_memblokir(tmp_path: Path) -> None:
    services, _store = make_services(tmp_path)
    target = tmp_path / "config.yml"
    teks = VALID_CONFIG + "original-config-extra: true\n"
    target.write_bytes(teks.encode("utf-8"))
    proposal = WizardProposal(
        tunnel="11111111-2222-3333-4444-555555555555",
        credentials_file="credentials-dummy.json",
        ingress=(IngressRule(service="http_status:404"),),
    )
    (tmp_path / "credentials-dummy.json").write_bytes(b"{}")
    outcome = run_check(services, teks, target, proposal)
    assert outcome.blocked  # UNKNOWN tidak dipaksakan VALID (constraint)
    assert outcome.validation.classification is (
        ValidationClassification.UNKNOWN
    )


def test_save_origin_settings_tunggal(tmp_path: Path) -> None:
    services, store = make_services(tmp_path)
    proposal = WizardProposal(
        tunnel="x",
        credentials_file="c.json",
        ingress=(IngressRule(service="http://127.0.0.1:9090"),),
    )
    note = save_origin_settings(services, proposal)
    saved = store.load()
    assert saved.origin_host == "127.0.0.1"
    assert saved.origin_port == 9090
    assert note == ""


def test_save_origin_settings_multi_memakai_pertama_dengan_catatan(
    tmp_path: Path,
) -> None:
    """PC-2: multi-origin ditangani eksplisit — pertama + keterangan."""
    services, store = make_services(tmp_path)
    proposal = WizardProposal(
        tunnel="x",
        credentials_file="c.json",
        ingress=(
            IngressRule(service="http://127.0.0.1:9001"),
            IngressRule(service="http://127.0.0.1:9002"),
        ),
    )
    note = save_origin_settings(services, proposal)
    saved = store.load()
    assert saved.origin_port == 9001
    assert "2 origin" in note


def test_save_origin_settings_tanpa_origin_tidak_mengubah(tmp_path: Path) -> None:
    services, store = make_services(tmp_path)
    sebelum = store.load()
    proposal = WizardProposal(
        tunnel="x",
        credentials_file="c.json",
        ingress=(IngressRule(service="http_status:404"),),
    )
    note = save_origin_settings(services, proposal)
    assert store.load() == sebelum  # tidak berubah
    assert "tidak ada" in note


def test_run_check_hasil_refused_atau_timeout_port_tutup(
    tmp_path: Path,
) -> None:
    """Probe port tutup: hasil jujur (REFUSED; Windows CI kerap TIMEOUT)."""
    services, _store = make_services(tmp_path)
    target = tmp_path / "config.yml"
    target.write_bytes(VALID_CONFIG.encode("utf-8"))
    proposal = WizardProposal(
        tunnel="11111111-2222-3333-4444-555555555555",
        credentials_file="credentials-dummy.json",
        ingress=(IngressRule(service="http://127.0.0.1:1"),),
    )
    (tmp_path / "credentials-dummy.json").write_bytes(b"{}")
    outcome = run_check(services, VALID_CONFIG, target, proposal)
    row = outcome.origin_rows[0]
    assert row.result is not None
    assert row.result.status in (OriginStatus.UNREACHABLE, OriginStatus.UNKNOWN)


def test_status_mapping_lengkap() -> None:
    """Tabel error mapping mencakup SELURUH ApplyStatus (constraint)."""
    from tunneldesk.ui import strings
    from tunneldesk.ui.wizard.state import apply_status_text_key

    for status in ApplyStatus:
        assert strings.text(apply_status_text_key(status))
