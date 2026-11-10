"""Uji string UI terpusat (Q-06) — semua kunci terisi dan tanpa duplikat."""

from __future__ import annotations

from tunneldesk.ui import strings


def test_semua_nilai_tidak_kosong() -> None:
    for key, value in strings.ID.items():
        assert value.strip(), f"teks kosong pada kunci {key}"


def test_tidak_ada_nilai_duplikat_pada_tombol() -> None:
    tombol = [v for k, v in strings.ID.items() if k.startswith("dash.btn_")]
    assert len(tombol) == len(set(tombol))


def test_placeholder_konsisten_dengan_format_args() -> None:
    # kunci dengan placeholder wajib bisa diformat
    strings.text("app.instance_running", pid=123)
    strings.text("dash.problem_crashed", code=1)
    strings.text("dash.problem_origin", detail="x")
    strings.text("err.operation_failed", detail="x")


def test_teks_indonesia() -> None:
    assert strings.text("dash.btn_start") == "Start"
    assert strings.text("menu.settings") == "Pengaturan"
