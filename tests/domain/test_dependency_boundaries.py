"""Regresi batas dependensi domain (A-08) — pelengkap import-linter di CI.

Mem-parsing AST setiap modul domain dan menolak impor terlarang.
Import-linter tetap penjaga utama; uji ini membuat aturan dasar terlihat
langsung di pytest. Docstring yang menyebut nama modul tidak dihitung —
hanya impor aktual yang dicek.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

DOMAIN_DIR = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "tunneldesk"
    / "domain"
)

#: Akar modul pihak ketiga / internal yang dilarang di domain (A-08, D-01).
FORBIDDEN_ROOTS: frozenset[str] = frozenset(
    {
        "PySide6",
        "subprocess",
        "ctypes",
        "socket",
        "requests",
        "win32api",
        "win32job",
        "win32process",
        "pythoncom",
        "tunneldesk.infrastructure",
        "tunneldesk.ui",
        "tunneldesk.application",
    }
)


def domain_python_files() -> list[Path]:
    return sorted(DOMAIN_DIR.rglob("*.py"))


def imported_roots(path: Path) -> set[str]:
    """Kembalikan akar modul yang diimpor oleh file (via AST)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_domain_punya_berkas_sumber() -> None:
    files = domain_python_files()
    assert files, "domain kosong — struktur salah?"


@pytest.mark.parametrize("path", domain_python_files(), ids=lambda p: p.name)
def test_domain_hanya_mengimpor_yang_diizinkan(path: Path) -> None:
    roots = imported_roots(path)
    forbidden = roots & FORBIDDEN_ROOTS
    assert not forbidden, (
        f"{path.name} mengimpor dependensi terlarang: {sorted(forbidden)}"
    )


def test_domain_tidak_mengimpor_apapun_selain_stdlib_dan_diri_sendiri() -> None:
    """Domain E-1 saat ini murni stdlib + paket sendiri — kunci baseline."""
    allowed_self = {"tunneldesk"}
    for path in domain_python_files():
        for root in imported_roots(path):
            assert root in allowed_self or not root.startswith(
                "tunneldesk"
            ) or root == "tunneldesk", f"{path.name}: impor tak terduga {root}"
