"""CLI argument parsing tests for pqblocks-acvp (subprocess-level).

Tests E17-E19 plus --help and --version via the real process entry point,
`python -m pqblocks_acvp`, so exit codes and stderr are observed exactly as
a CI job would see them.

These tests match the spec's exact error message requirements (E18, E19).
"""
import os
import subprocess
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


def _env_with_src():
    """Child environment with src/ on PYTHONPATH (src-layout product)."""
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = f"{_SRC}{os.pathsep}{existing}" if existing else _SRC
    return env


def _run(*args):
    """Run `python -m pqblocks_acvp <args>` in the product env."""
    return subprocess.run(
        [sys.executable, "-m", "pqblocks_acvp", *args],
        capture_output=True,
        text=True,
        env=_env_with_src(),
    )


def test_help_lists_all_flags():
    """E17: --help lists all required flags."""
    result = _run("--help")
    assert result.returncode == 0, f"--help failed with code {result.returncode}"
    help_text = result.stdout
    # All CLI flags from spec/spec.md §3 should appear in --help output
    required_flags = ["--vectors", "--impl", "--output", "--seed", "--timeout", "--vector-revision"]
    for flag in required_flags:
        assert flag in help_text, f"Missing flag {flag} in --help output"


def test_version_present():
    """E19-adjacent: --version is present and exits 0."""
    result = _run("--version")
    # --version should either exit 0 or print version and exit 0
    assert result.returncode == 0, f"--version failed with code {result.returncode}"


def test_missing_required_flags_exits_2():
    """E17: Missing required flags exits with code 2 and shows usage."""
    # Run with no args - should exit 2
    result = _run()
    assert result.returncode == 2, f"Expected exit 2 for missing flags, got {result.returncode}"
    # Usage message should mention required flags
    assert "usage" in result.stderr.lower() or "usage" in result.stdout.lower(), \
        "Expected usage message in stderr/stdout"


def test_invalid_output_format_exits_2():
    """E18: invalid --output value exits with code 2 and exact error message.

    Must provide --vectors and --impl first, then override --output.
    """
    result = _run(
        "--vectors", "ML-KEM-768",
        "--impl", "kyber_py.ml_kem_768",
        "--output", "xml",
    )
    assert result.returncode == 2, f"Expected exit 2 for invalid output, got {result.returncode}"
    assert "invalid output format: xml" in result.stderr, \
        f"Expected 'invalid output format: xml' error, got stderr={result.stderr}"


def test_non_integer_seed_exits_2():
    """E19: non-integer --seed exits with code 2 and exact error message.

    Must provide --vectors and --impl first, then override --seed.
    """
    result = _run(
        "--vectors", "ML-KEM-768",
        "--impl", "kyber_py.ml_kem_768",
        "--seed", "abc",
    )
    assert result.returncode == 2, f"Expected exit 2 for non-integer seed, got {result.returncode}"
    assert "seed must be an integer" in result.stderr, \
        f"Expected 'seed must be an integer' error, got stderr={result.stderr}"
