"""Wheel-ship-gate tests for oracle (v1.0 RELEASE).

These tests pin the v1.0 ship-gate contract: building a wheel + sdist,
installing the wheel into a fresh venv, exposing a working `oracle`
console script, importing all 6 public top-level modules, and printing
the correct version. They are gated by the `ship_gate` marker (set in
pyproject.toml) so they are excluded from the fast inner-loop but
included in the default `pytest -q` run (the v1.0 release gate).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DIST_NAME = "oracle-symexec"
EXPECTED_IMPORT_NAME = "oracle"
EXPECTED_VERSION = "1.0.0"
EXPECTED_WHEEL = f"dist/{EXPECTED_DIST_NAME.replace('-', '_')}-{EXPECTED_VERSION}-py3-none-any.whl"
EXPECTED_SDIST = f"dist/{EXPECTED_DIST_NAME.replace('-', '_')}-{EXPECTED_VERSION}.tar.gz"


def _project_python() -> str:
    """Return the absolute path to the project's venv Python."""
    venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    if not venv_python.exists():
        pytest.skip(f"project venv missing: {venv_python}")
    return str(venv_python)


@pytest.mark.ship_gate
def test_build_package_is_installed():
    """Precondition: `build` must be available in the project's venv for python -m build."""
    out = subprocess.run(
        [_project_python(), "-m", "build", "--help"],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, f"`python -m build --help` failed: {out.stderr}"
    assert "build" in out.stdout.lower()


@pytest.mark.ship_gate
def test_build_wheel_and_sdist():
    """`python -m build --wheel --sdist` must produce dist/oracle_symexec-1.0.0-{whl,tar.gz}."""
    dist = REPO_ROOT / "dist"
    if dist.exists():
        shutil.rmtree(dist)

    out = subprocess.run(
        [_project_python(), "-m", "build", "--wheel", "--sdist"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=300,
    )
    assert out.returncode == 0, f"build failed (exit {out.returncode}): {out.stderr}"

    wheel = REPO_ROOT / EXPECTED_WHEEL
    sdist = REPO_ROOT / EXPECTED_SDIST
    assert wheel.exists(), f"wheel not produced: {EXPECTED_WHEEL}"
    assert sdist.exists(), f"sdist not produced: {EXPECTED_SDIST}"
    assert wheel.stat().st_size > 50_000, f"wheel suspiciously small: {wheel.stat().st_size} bytes"
    assert sdist.stat().st_size > 50_000, f"sdist suspiciously small: {sdist.stat().st_size} bytes"


@pytest.mark.ship_gate
def test_fresh_venv_installs_wheel():
    """A fresh venv must install the wheel and the declared runtime deps."""
    wheel = REPO_ROOT / EXPECTED_WHEEL
    if not wheel.exists():
        pytest.skip(f"wheel not present (run test_build_wheel_and_sdist first): {EXPECTED_WHEEL}")

    with tempfile.TemporaryDirectory(prefix="oracle_ship_") as tmp:
        venv_dir = Path(tmp) / "fresh_venv"
        subprocess.run(
            [_project_python(), "-m", "venv", str(venv_dir)],
            check=True, timeout=120,
        )
        fresh_pip = venv_dir / "bin" / "pip"

        out = subprocess.run(
            [str(fresh_pip), "install", str(wheel), "--quiet"],
            capture_output=True, text=True, timeout=300,
        )
        assert out.returncode == 0, f"wheel install failed: {out.stderr}"

        deps = [
            "z3-solver>=4.12,<5",
            "evm-toolkit[solcx] @ git+https://github.com/bugsyhewitt/evm-toolkit",
        ]
        out = subprocess.run(
            [str(fresh_pip), "install", *deps],
            capture_output=True, text=True, timeout=600,
        )
        assert out.returncode == 0, f"deps install failed: {out.stderr}"

        oracle_bin = venv_dir / "bin" / "oracle"
        assert oracle_bin.exists(), "`oracle` console script missing from fresh venv"


@pytest.mark.ship_gate
def test_cli_version_from_fresh_venv():
    """`oracle --version` from the fresh venv must print exactly `oracle 1.0.0`."""
    wheel = REPO_ROOT / EXPECTED_WHEEL
    if not wheel.exists():
        pytest.skip(f"wheel not present (run test_build_wheel_and_sdist first): {EXPECTED_WHEEL}")

    with tempfile.TemporaryDirectory(prefix="oracle_ver_") as tmp:
        venv_dir = Path(tmp) / "fresh_venv"
        subprocess.run([_project_python(), "-m", "venv", str(venv_dir)], check=True, timeout=120)
        fresh_pip = venv_dir / "bin" / "pip"
        fresh_bin = venv_dir / "bin"

        subprocess.run([str(fresh_pip), "install", str(wheel), "--quiet"], check=True, timeout=300)
        subprocess.run(
            [str(fresh_pip), "install",
             "z3-solver>=4.12,<5",
             "evm-toolkit[solcx] @ git+https://github.com/bugsyhewitt/evm-toolkit"],
            check=True, timeout=600,
        )

        out = subprocess.run(
            [str(fresh_bin / "oracle"), "--version"],
            capture_output=True, text=True, timeout=30,
        )
        assert out.returncode == 0, f"oracle --version failed: {out.stderr}"
        assert out.stdout.strip() == f"oracle {EXPECTED_VERSION}", (
            f"expected 'oracle {EXPECTED_VERSION}', got {out.stdout.strip()!r}"
        )


@pytest.mark.ship_gate
def test_import_and_version_from_fresh_venv():
    """`import oracle; assert oracle.__version__ == '1.0.0'` must succeed in the fresh venv."""
    wheel = REPO_ROOT / EXPECTED_WHEEL
    if not wheel.exists():
        pytest.skip(f"wheel not present (run test_build_wheel_and_sdist first): {EXPECTED_WHEEL}")

    with tempfile.TemporaryDirectory(prefix="oracle_imp_") as tmp:
        venv_dir = Path(tmp) / "fresh_venv"
        subprocess.run([_project_python(), "-m", "venv", str(venv_dir)], check=True, timeout=120)
        fresh_pip = venv_dir / "bin" / "pip"
        fresh_py = venv_dir / "bin" / "python"

        subprocess.run([str(fresh_pip), "install", str(wheel), "--quiet"], check=True, timeout=300)
        subprocess.run(
            [str(fresh_pip), "install",
             "z3-solver>=4.12,<5",
             "evm-toolkit[solcx] @ git+https://github.com/bugsyhewitt/evm-toolkit"],
            check=True, timeout=600,
        )

        out = subprocess.run(
            [str(fresh_py), "-c",
             f"import {EXPECTED_IMPORT_NAME}; assert {EXPECTED_IMPORT_NAME}.__version__ == '{EXPECTED_VERSION}'"],
            capture_output=True, text=True, timeout=30,
        )
        assert out.returncode == 0, f"import/version check failed: {out.stderr}"


@pytest.mark.ship_gate
def test_all_public_modules_import_from_fresh_venv():
    """All 6 public top-level modules of oracle must import cleanly from the fresh venv."""
    wheel = REPO_ROOT / EXPECTED_WHEEL
    if not wheel.exists():
        pytest.skip(f"wheel not present (run test_build_wheel_and_sdist first): {EXPECTED_WHEEL}")

    public_modules = [
        "oracle",
        "oracle.analysis",
        "oracle.cli",
        "oracle.compiler",
        "oracle.laser",
        "oracle.report",
    ]
    with tempfile.TemporaryDirectory(prefix="oracle_mod_") as tmp:
        venv_dir = Path(tmp) / "fresh_venv"
        subprocess.run([_project_python(), "-m", "venv", str(venv_dir)], check=True, timeout=120)
        fresh_pip = venv_dir / "bin" / "pip"
        fresh_py = venv_dir / "bin" / "python"

        subprocess.run([str(fresh_pip), "install", str(wheel), "--quiet"], check=True, timeout=300)
        subprocess.run(
            [str(fresh_pip), "install",
             "z3-solver>=4.12,<5",
             "evm-toolkit[solcx] @ git+https://github.com/bugsyhewitt/evm-toolkit"],
            check=True, timeout=600,
        )

        out = subprocess.run(
            [str(fresh_py), "-c",
             f"import {', '.join(public_modules)}; print('ok')"],
            capture_output=True, text=True, timeout=30,
        )
        assert out.returncode == 0, f"module import failed: {out.stderr}"
        assert "ok" in out.stdout, f"expected 'ok' in stdout, got: {out.stdout!r}"
