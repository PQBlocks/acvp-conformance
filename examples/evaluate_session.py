"""Example 1: Run ACVP test session and verify denominator preservation."""
from pqblocks_acvp.runner import build_golden_session
from pqblocks_acvp.harness import ConformanceHarness
from pqblocks_acvp.adapters.reference import ReferencePQCAdapter
from pqblocks_acvp.adapters.go_bridge import GoBridgeAdapter
from pqblocks_acvp.adapters.pyca import PyCAAdapter
from pqblocks_acvp.taxonomy import TaxonomyCategory


def main():
    session = build_golden_session()
    print(f"Loaded ACVP session: vsId={session.vsId}, algorithm={session.algorithm}, cases={session.total_test_cases}")

    adapters = [ReferencePQCAdapter(), GoBridgeAdapter(), PyCAAdapter()]
    harness = ConformanceHarness(adapters)
    reports = harness.run_session(session)

    ref_report = reports["Reference-FIPS-Oracle"]
    print(f"Reference adapter: {ref_report.passed} passed, {ref_report.documented_validation_rejections} DVR")
    assert ref_report.denominator_verified, "Denominator must be preserved"
    assert ref_report.total_attempted == session.total_test_cases, "All cases attempted"

    for name, rep in reports.items():
        assert rep.denominator_verified, f"Denominator violated for {name}"
        print(f"[{name}] attempted={rep.total_attempted} passed={rep.passed} unsupp={rep.unsupported_operations}")

    print("check passed: True")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
