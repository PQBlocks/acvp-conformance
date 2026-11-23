"""CLI entry point for pqblocks-acvp.

Implements spec/spec.md §2 (CLI entry point) and §3 edge cases E17–E19.
"""
from __future__ import annotations

import argparse
import sys

from pqblocks_acvp import __version__

KNOWN_VECTOR_SETS = [
    "ML-KEM-768",
    "ML-KEM-512",
    "ML-KEM-1024",
    "ML-DSA-65",
    "ML-DSA-44",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHA2-256f",
]

KNOWN_OUTPUT_FORMATS = ("tap", "json", "tap+json")


def _create_parser() -> argparse.ArgumentParser:
    """Create the argument parser with all CLI flags."""
    parser = argparse.ArgumentParser(
        prog="pqblocks-acvp",
        description="ACVP KAT runner for FIPS 203/204/205 post-quantum "
        "cryptographic primitives",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--vectors",
        required=True,
        choices=KNOWN_VECTOR_SETS,
        help="Vector set name (ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s, ...)",
    )

    parser.add_argument(
        "--impl",
        required=True,
        help="Adapter import path (e.g., kyber_py.ml_kem_768, dilithium_py.ml_dsa_65, "
        "pqcrypto.ml_kem_768, oqs-python.ml_kem_768, mlkem.ml_kem_768)",
    )

    # --output / --seed parsed as raw strings; validated in main() to emit the
    # exact error messages mandated by spec edge cases E18 and E19.
    parser.add_argument(
        "--output",
        default="tap+json",
        help="Output format: tap | json | tap+json (default: tap+json)",
    )

    parser.add_argument(
        "--seed",
        default="42",
        help="Integer seed for deterministic RNG (default: 42)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=1000,
        help="Per-vector timeout in seconds (default: 1000)",
    )

    parser.add_argument(
        "--vector-revision",
        default="gen-val",
        help="ACVP-Server revision tag (default: gen-val)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"pqblocks-acvp {__version__}",
        help="Show version and exit",
    )

    return parser


def _validate_output(parser: argparse.ArgumentParser, value: str) -> str:
    """E18: reject unknown output formats with the spec-mandated message."""
    if value not in KNOWN_OUTPUT_FORMATS:
        parser.error(f"invalid output format: {value} (expected {'|'.join(KNOWN_OUTPUT_FORMATS)})")
    return value


def _validate_seed(parser: argparse.ArgumentParser, value: str) -> int:
    """E19: reject non-integer seeds with the spec-mandated message."""
    try:
        return int(value)
    except ValueError:
        parser.error("seed must be an integer")


def _run_legacy_conformance(argv: list[str]) -> int:
    import json
    from .parser import ACVPParser
    from .harness import ConformanceHarness
    from .adapters.reference import ReferencePQCAdapter
    from .adapters.pyca import PyCAAdapter
    from .adapters.go_bridge import GoBridgeAdapter
    from .adapters.liboqs import LibOQSAdapter
    from .compliance import ComplianceReporter
    from .runner import build_golden_session

    parser = argparse.ArgumentParser(description="pqblocks-acvp conformance harness")
    parser.add_argument("--corpus", type=str, help="Path to ACVP JSON vector file")
    parser.add_argument("--golden", action="store_true", help="Run golden test instances")
    parser.add_argument("--spdx", action="store_true", help="Print SPDX license manifest")
    parser.add_argument("--json", action="store_true", help="Output summary in JSON format")

    args = parser.parse_args(argv)

    if args.spdx:
        manifest = ComplianceReporter.generate_spdx_manifest()
        print(json.dumps(manifest, indent=2))
        return 0

    if args.corpus:
        session = ACVPParser.parse_file(args.corpus)
    else:
        session = build_golden_session()

    adapters = [ReferencePQCAdapter(), GoBridgeAdapter(), PyCAAdapter(), LibOQSAdapter()]
    harness = ConformanceHarness(adapters)
    reports = harness.run_session(session)

    if args.json:
        out = {k: v.summary_dict() for k, v in reports.items()}
        print(json.dumps(out, indent=2))
        return 0

    print("=" * 70)
    print("pqblocks-acvp Conformance Report (Denominator-Preserved)")
    print("=" * 70)
    print(f"Total Test Cases in Session: {session.total_test_cases}")
    print("-" * 70)
    print(f"{'Adapter':20} {'Attempted':10} {'Passed':8} {'DVR':8} {'Mismatch':9} {'Unsup':8} {'Err':8}")
    print("-" * 70)
    for name, rep in reports.items():
        print(f"{name:20} {rep.total_attempted:<10} {rep.passed:<8} {rep.documented_validation_rejections:<8} {rep.mismatches:<9} {rep.unsupported_operations:<8} {rep.adapter_errors:<8}")
    print("=" * 70)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point. Returns the process exit code."""
    raw_args = sys.argv[1:] if argv is None else argv
    if any(arg in raw_args for arg in ("--golden", "--spdx", "--corpus")):
        return _run_legacy_conformance(raw_args)

    parser = _create_parser()
    args = parser.parse_args(raw_args)

    args.output = _validate_output(parser, args.output)
    args.seed = _validate_seed(parser, args.seed)

    # Slice S1 scope: parsing only. Execution wiring arrives with S8.
    print(
        f"Running ACVP KAT: vectors={args.vectors}, impl={args.impl}, "
        f"output={args.output}, seed={args.seed}, timeout={args.timeout}, "
        f"vector_revision={args.vector_revision}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
