"""Locator executable `cloudflared` (E-5, tugas 2.1).

- Sumber pencarian: ``PATH`` (dari lingkungan, dapat diinjeksi untuk uji)
  dan lokasi umum per platform.
- Identifikasi versi: jalankan ``cloudflared --version`` melalui **port
  ProcessLauncher E-2** (argumen list, tanpa shell, dengan timeout) —
  D-18: hanya proses yang dilahirkan sendiri.
- Fail-safe: path tidak ada / tidak bisa dijalankan / timeout / output
  tidak dikenal → dicatat sebagai alasan, **tidak pernah exception** ke
  pemanggil.
"""

from __future__ import annotations

import os
from pathlib import Path

from tunneldesk.domain.tunnel.detection import (
    DetectionSource,
    ExecutableFinding,
    parse_version_output,
)
from tunneldesk.domain.tunnel.process_contracts import (
    ProcessLauncher,
    ProcessSpec,
)

__all__ = ["CloudflaredLocator", "common_cloudflared_dirs", "default_path_dirs"]

_EXECUTABLE_NAME = "cloudflared.exe" if os.name == "nt" else "cloudflared"
_VERSION_TIMEOUT_SECONDS = 5.0


def default_path_dirs() -> list[Path]:
    """Direktori dari variabel lingkungan PATH (urutan deklarasi)."""
    raw = os.environ.get("PATH", "")
    return [
        Path(part)
        for part in raw.split(os.pathsep)
        if part.strip()
    ]


def common_cloudflared_dirs() -> list[Path]:
    """Lokasi umum instalasi per platform (A-01: Windows utama; POSIX dev)."""
    home = Path.home()
    candidates: list[Path] = []
    if os.name == "nt":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        program_files_x86 = os.environ.get(
            "ProgramFiles(x86)", r"C:\Program Files (x86)"
        )
        local_appdata = os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local"))
        candidates += [
            Path(program_files) / "cloudflared",
            Path(program_files_x86) / "cloudflared",
            Path(local_appdata) / "cloudflared",
        ]
    else:
        candidates += [
            Path("/usr/local/bin"),
            Path("/opt/homebrew/bin"),
            Path("/usr/bin"),
            home / ".cloudflared" / "bin",
        ]
    return candidates


class CloudflaredLocator:
    """Pencari executable cloudflared — read-only, fail-safe.

    ``path_dirs`` dan ``common_dirs`` dapat diinjeksi untuk uji
    deterministik (tanpa bergantung pada sistem nyata).
    """

    def __init__(
        self,
        launcher: ProcessLauncher,
        path_dirs: list[Path] | None = None,
        common_dirs: list[Path] | None = None,
        version_timeout_seconds: float = _VERSION_TIMEOUT_SECONDS,
    ) -> None:
        self._launcher = launcher
        self._path_dirs = (
            path_dirs if path_dirs is not None else default_path_dirs()
        )
        self._common_dirs = (
            common_dirs if common_dirs is not None else common_cloudflared_dirs()
        )
        self._version_timeout = version_timeout_seconds

    def locate(self) -> tuple[ExecutableFinding, ...]:
        """Kembalikan temuan unik, urut prioritas sumber (PATH dulu)."""
        findings: list[ExecutableFinding] = []
        for directory, source in self._search_roots():
            candidate = directory / _EXECUTABLE_NAME
            if not candidate.is_file():
                continue
            version_info = self._probe_version(candidate)
            findings.append(
                ExecutableFinding(
                    path=candidate.resolve(),
                    source=source,
                    version=version_info["version"],
                    version_detail=version_info["version_detail"] or "",
                )
            )
        return self._dedupe(findings)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _search_roots(self) -> list[tuple[Path, DetectionSource]]:
        roots: list[tuple[Path, DetectionSource]] = []
        for directory in self._path_dirs:
            roots.append((directory, DetectionSource.PATH))
        for directory in self._common_dirs:
            roots.append((directory, DetectionSource.COMMON_LOCATION))
        return roots

    def _probe_version(self, executable: Path) -> dict[str, str | None]:
        """Jalankan ``--version`` dengan timeout; gagal → alasan, tanpa exception."""
        try:
            process = self._launcher.launch(
                ProcessSpec.from_sequence([str(executable), "--version"])
            )
        except OSError as exc:
            return {"version": None, "version_detail": f"tidak dapat dijalankan: {exc}"}
        try:
            exit_code = process.wait(self._version_timeout)
        except Exception:  # noqa: BLE001 — fail-safe kontrak deteksi
            return {"version": None, "version_detail": "probe versi gagal"}
        if exit_code is None:
            process.force_kill()
            return {
                "version": None,
                "version_detail": f"timeout setelah {self._version_timeout:g} dtk",
            }
        lines = process.output_lines()
        version = parse_version_output("\n".join(lines))
        if version is None:
            return {
                "version": None,
                "version_detail": f"output versi tidak dikenal (exit {exit_code})",
            }
        return {"version": version, "version_detail": ""}

    @staticmethod
    def _dedupe(
        findings: list[ExecutableFinding],
    ) -> tuple[ExecutableFinding, ...]:
        seen: set[Path] = set()
        unique: list[ExecutableFinding] = []
        for finding in findings:
            if finding.path not in seen:
                seen.add(finding.path)
                unique.append(finding)
        return tuple(unique)
