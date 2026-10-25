"""Example 2: Implementing a custom PQC adapter with the 4-way error taxonomy."""
from typing import Any, Dict, Tuple
from pqblocks_acvp.adapters.base import BasePQCAdapter
from pqblocks_acvp.parser import TestCase, TestGroup, ACVPTestSession
from pqblocks_acvp.harness import ConformanceHarness
from pqblocks_acvp.taxonomy import TaxonomyCategory, TaxonomyClassifier


class DummyAgileAdapter(BasePQCAdapter):
    """A mock implementation adapter demonstrating error taxonomy classification."""

    def __init__(self):
        super().__init__("DummyAgileAdapter")

    def supports_algorithm(self, parameter_set: str, function: str) -> bool:
        return parameter_set == "ML-KEM-768"

    def execute_case(self, test_case: TestCase) -> Tuple[Dict[str, Any], bool, bool]:
        if test_case.parameter_set != "ML-KEM-768":
            return {}, False, True  # unsupported
        # If input is empty, reject it as invalid (Documented Validation Rejection)
        if not test_case.inputs.get("ek"):
            return {}, True, False
        # Valid test case: return dummy expected result
        return {"c": test_case.expected.get("c", ""), "k": test_case.expected.get("k", "")}, False, False


def main():
    tc_valid = TestCase(
        tcId=1,
        function="encapsulation",
        parameter_set="ML-KEM-768",
        inputs={"ek": "11" * 1184},
        expected={"c": "22" * 1088, "k": "33" * 32},
    )
    tc_malformed = TestCase(
        tcId=2,
        function="encapsulation",
        parameter_set="ML-KEM-768",
        inputs={"ek": ""},
        expected={"testPassed": False},
    )
    tc_unsupported = TestCase(
        tcId=3,
        function="encapsulation",
        parameter_set="ML-KEM-1024",
        inputs={"ek": "44" * 1568},
        expected={"c": "55" * 1568, "k": "66" * 32},
    )

    tg = TestGroup(
        tgId=1,
        algorithm="ML-KEM",
        mode="",
        parameter_set="ML-KEM-768",
        function="encapsulation",
        test_type="AFT",
        test_cases=[tc_valid, tc_malformed, tc_unsupported],
    )
    session = ACVPTestSession(vsId=100, algorithm="ML-KEM", groups=[tg])

    adapter = DummyAgileAdapter()
    harness = ConformanceHarness([adapter])
    reports = harness.run_session(session)

    rep = reports["DummyAgileAdapter"]
    print(f"Custom adapter attempted: {rep.total_attempted}, passed: {rep.passed}, "
          f"DVR: {rep.documented_validation_rejections}, unsupp: {rep.unsupported_operations}")

    assert rep.total_attempted == 3
    assert rep.passed == 1
    assert rep.documented_validation_rejections == 1
    assert rep.unsupported_operations == 1
    assert rep.denominator_verified

    print("check passed: True")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
