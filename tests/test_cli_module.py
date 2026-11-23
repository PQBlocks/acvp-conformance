"""Unit tests importing pqblocks_acvp.cli directly (G3-IMPORT-SRC floor).

Product code must be exercised as an importable module, not only via
subprocess. Also carries the budget-feasibility check for the kill metric:
the CLI must start and parse arguments inside a bounded wall-clock budget,
otherwise the 'CI/CD pipeline integration success >=90%' kill metric in
VALUE-CASE.md §4 is unfalsifiable (a slow CLI fails CI integration).
"""
import os
import subprocess
import sys
import time

import pytest

from pqblocks_acvp import __version__
from pqblocks_acvp.cli import KNOWN_OUTPUT_FORMATS, KNOWN_VECTOR_SETS, main


def test_cli_module_importable():
    """Product module must be importable and expose main() + version."""
    assert callable(main)
    assert isinstance(__version__, str) and __version__.count(".") >= 1


def test_known_vector_sets_are_fips_algorithms():
    """Vector sets cover ML-KEM, ML-DSA, SLH-DSA families."""
    assert "ML-KEM-768" in KNOWN_VECTOR_SETS
    assert "ML-DSA-65" in KNOWN_VECTOR_SETS
    assert "SLH-DSA-SHA2-128s" in KNOWN_VECTOR_SETS


def test_known_output_formats_match_spec():
    """Output formats are exactly tap, json, tap+json per spec §3."""
    assert KNOWN_OUTPUT_FORMATS == ("tap", "json", "tap+json")


def test_cli_startup_within_budget():
    """Budget feasibility: --help responds in < 5s wall clock.

    Guards the kill metric 'CI/CD pipeline integration success >=90%'
    (VALUE-CASE.md §4): a CLI that takes pathological time to start breaks
    first-attempt CI integration.
    """
    _SRC = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = _SRC
    start = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-m", "pqblocks_acvp", "--help"],
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )
    elapsed = time.monotonic() - start
    assert result.returncode == 0, f"--help failed with code {result.returncode}"
    assert elapsed < 5.0, (
        f"CLI startup took {elapsed:.2f}s, exceeds 5s latency budget "
        f"(kill metric: CI/CD integration success)"
    )


def test_main_returns_zero_for_valid_args(capsys):
    """main() with fully valid args returns 0 exit code."""
    rc = main(
        [
            "--vectors", "ML-KEM-768",
            "--impl", "kyber_py.ml_kem_768",
            "--output", "json",
            "--seed", "7",
            "--timeout", "60",
            "--vector-revision", "1.0",
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert "Running ACVP KAT" in captured.out
    assert "ML-KEM-768" in captured.out


def test_main_rejects_bad_output(capsys):
    """E18 via direct main() call: SystemExit code 2 with exact message."""
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "--vectors", "ML-KEM-768",
                "--impl", "kyber_py.ml_kem_768",
                "--output", "xml",
            ]
        )
    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "invalid output format: xml" in captured.err


def test_main_rejects_bad_seed(capsys):
    """E19 via direct main() call: SystemExit code 2 with exact message."""
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "--vectors", "ML-KEM-768",
                "--impl", "kyber_py.ml_kem_768",
                "--seed", "abc",
            ]
        )
    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "seed must be an integer" in captured.err
