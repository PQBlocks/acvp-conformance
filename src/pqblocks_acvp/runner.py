"""CLI Runner and Entrypoint for pqblocks-acvp."""

import argparse
import json
import sys
from typing import List, Optional
from .parser import ACVPParser, ACVPTestSession, TestCase, TestGroup
from .harness import ConformanceHarness
from .adapters.reference import ReferencePQCAdapter
from .adapters.pyca import PyCAAdapter
from .adapters.go_bridge import GoBridgeAdapter
from .adapters.liboqs import LibOQSAdapter
from .compliance import ComplianceReporter


def build_golden_session() -> ACVPTestSession:
    """Build session containing the 4 golden instances defined in spec Section 6.1."""
    from .reference import MLKEMReferenceOracle

    # Real ML-KEM-768 encapsulation keys from KeyGen_internal(d, z) with fixed
    # seeds. The spec's original instances were repeated byte patterns
    # ("CDD40B1A" * 296), which are not valid encapsulation keys - FIPS 203
    # 7.2 requires rejecting them - and only "worked" against the former
    # simulated oracle.
    raw_cases = []
    for tcId, seed_byte, m in ((1, "01", "AA" * 32), (2, "02", "BB" * 32),
                               (3, "03", "CC" * 32), (4, "04", "DD" * 32)):
        ek, _dk = MLKEMReferenceOracle.keygen("ML-KEM-768", seed_byte * 32, seed_byte * 32)
        raw_cases.append((tcId, ek, m))

    test_cases = []
    for tcId, ek, m in raw_cases:
        c, k = MLKEMReferenceOracle.encapsulate("ML-KEM-768", ek, m)
        test_cases.append(
            TestCase(
                tcId=tcId,
                function="encapsulation",
                parameter_set="ML-KEM-768",
                inputs={"ek": ek, "m": m},
                expected={"c": c, "k": k},
            )
        )

    tg = TestGroup(
        tgId=1,
        algorithm="ML-KEM",
        mode="",
        parameter_set="ML-KEM-768",
        function="encapsulation",
        test_type="AFT",
        test_cases=test_cases,
    )
    return ACVPTestSession(vsId=42, algorithm="ML-KEM", groups=[tg])


def main(argv: Optional[List[str]] = None) -> int:
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
    elif args.golden or True:
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


if __name__ == "__main__":
    sys.exit(main())
