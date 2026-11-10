"""Smoke test skeleton Fase 0 — bukan uji fitur.

Memastikan paket dapat diimpor dan metadata konsisten. Uji fitur
(state machine, redaksi, validasi YAML, dsb.) menyusul di epik E-1
ke atas sesuai IMPLEMENTATION_PLAN §11.
"""

import tunneldesk
import tunneldesk.application  # noqa: F401  (memastikan subpaket impor bersih)
import tunneldesk.domain  # noqa: F401
import tunneldesk.infrastructure  # noqa: F401
import tunneldesk.ui  # noqa: F401


def test_package_metadata() -> None:
    assert tunneldesk.__version__ == "0.0.1"


def test_domain_package_tersedia() -> None:
    # Domain wajib dapat diimpor tanpa dependensi GUI/OS (A-08).
    import tunneldesk.domain.redaction  # noqa: F401
    import tunneldesk.domain.tunnel  # noqa: F401
