"""Smoke test frozen executable TunnelDesk (Task 3.1).

Dijalankan pada Windows runner SETELAH PyInstaller build (lihat
.github/workflows/package-windows.yml). Membuktikan **runtime** frozen,
bukan sekadar build sukses:

1. Executable dapat dijalankan (process alive ≥ SMOKE_SECONDS detik
   tanpa crash — modul utama termuat + Qt/PySide6 terinisialisasi).
2. Data pengguna masuk ke ``%APPDATA%\\TunnelDesk`` (instance.lock,
   A-11/A-13) — kebijakan lokasi data proyek dipatuhi.
3. Tidak ada file baru di direktori instalasi (tidak menulis ke dir
   install), dan tidak ada file ``*.py`` di hasil build (tidak butuh
   source Python) — executable dijalankan dari CWD terpisah.
4. Pindai artifact: tanpa file key/env dan tanpa string secret fixture
   (D-18 / AC-4).

Lulus = exit 0; gagal = pesan ``FAIL`` + exit bukan nol.
Windows-only: panggil hanya di sys.platform == "win32".
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SMOKE_SECONDS = 20.0
REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_APP = REPO_ROOT / "dist" / "TunnelDesk"
EXE = DIST_APP / "TunnelDesk.exe"

# Konsol Windows default cp1252 — label output memakai karakter non-ASCII
# (≥, —); paksa UTF-8 agar tidak UnicodeEncodeError di runner.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(label)


def snapshot_dir(root: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for path in root.rglob("*"):
        if path.is_file():
            result[str(path.relative_to(root)).lower()] = path.stat().st_size
    return result


def secret_markers() -> list[str]:
    """String secret dummy dari fixture F6 + pola kunci generik."""
    markers = [
        "DUMMY_ACCOUNT_TAG_",
        "DUMMY_TUNNEL_SECRET_",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN PRIVATE KEY",
        "BEGIN CERTIFICATE-----",
    ]
    fixture = REPO_ROOT / "tests" / "fixtures" / "F6" / "credentials-dummy.json"
    if fixture.exists():
        markers.extend(
            line.strip().strip('"{}[]:,')
            for line in fixture.read_text(encoding="utf-8").splitlines()
            if len(line.strip().strip('"{}[]:,')) >= 12
        )
    return [m for m in markers if m]


def scan_secrets() -> list[str]:
    """Pindai seluruh file artifact untuk marker secret/ekstensi sensitif."""
    findings: list[str] = []
    markers = secret_markers()
    for path in DIST_APP.rglob("*"):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix in {".key", ".pem", ".env", ".pfx", ".p12"}:
            findings.append(f"file sensitif: {path.name}")
            continue
        data = path.read_bytes()
        for marker in markers:
            if marker.encode("utf-8") in data:
                findings.append(f"string '{marker[:40]}' di {path.name}")
    return findings


def main() -> int:
    if sys.platform != "win32":
        print("FAIL — smoke test frozen hanya dijalankan di Windows")
        return 2

    # --- 0. Prasyarat --------------------------------------------------
    check("artifact ada", EXE.is_file(), str(EXE))
    if not EXE.is_file():
        return 1

    py_files = [str(p.relative_to(DIST_APP)) for p in DIST_APP.rglob("*.py")]
    check("tanpa file .py di hasil build", not py_files, ", ".join(py_files[:5]))

    # --- 1. Snapshot direktori instalasi -------------------------------
    before = snapshot_dir(DIST_APP)

    # --- 2. Lokasi data pengguna (A-11) --------------------------------
    appdata_tunnel = Path(os.environ["APPDATA"]) / "TunnelDesk"

    # --- 3. Jalankan frozen exe (CWD terpisah — bukan dist, bukan src) --
    cwd = Path(tempfile.mkdtemp(prefix="td-smoke-cwd-"))
    env = dict(os.environ)
    env["QT_QPA_PLATFORM"] = "offscreen"
    print(f"[INFO] menjalankan {EXE} (cwd={cwd}, QT_QPA_PLATFORM=offscreen)")
    proc = subprocess.Popen([str(EXE)], cwd=str(cwd), env=env)

    deadline = time.monotonic() + SMOKE_SECONDS
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(0.5)

    exited = proc.poll() is not None
    if exited:
        check(
            "frozen app hidup ≥ bebas crash saat startup",
            False,
            f"exit lebih awal (kode {proc.returncode}) sebelum {SMOKE_SECONDS:.0f}s",
        )
    else:
        check(
            "frozen app hidup ≥ bebas crash saat startup",
            True,
            f"alive setelah {SMOKE_SECONDS:.0f}s",
        )
        check("modul utama + Qt/PySide6 terinisialisasi", True, "loop Qt berjalan tanpa crash")

    # --- 4. Kebijakan lokasi data (A-11/A-13) ---------------------------
    check(
        "instance.lock di %APPDATA%\\TunnelDesk",
        (appdata_tunnel / "instance.lock").is_file(),
        "dibuat saat startup (A-11/A-13)",
    )
    check("data TIDAK ditulis ke dir instalasi", snapshot_dir(DIST_APP) == before)

    # --- 5. Hentikan proses --------------------------------------------
    if not exited:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # --- 6. Pindai keamanan artifact (AC-4) -----------------------------
    findings = scan_secrets()
    check("tanpa secret/key/env di artifact", not findings, "; ".join(findings[:8]))

    print()
    if failures:
        print(f"SMOKE TEST GAGAL ({len(failures)} temuan): {failures}")
        return 1
    print("SMOKE TEST LULUS — frozen runtime TunnelDesk memenuhi kriteria")
    return 0


if __name__ == "__main__":
    sys.exit(main())
