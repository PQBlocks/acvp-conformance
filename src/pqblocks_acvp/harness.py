"""Conformance Test Harness & Denominator Preserving Report Generator."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from .parser import ACVPTestSession, TestCase
from .adapters.base import BasePQCAdapter
from .taxonomy import ExecutionResult, TaxonomyCategory


@dataclass
class ConformanceReport:
    adapter_name: str
    total_attempted: int
    passed: int
    documented_validation_rejections: int
    unsupported_operations: int
    adapter_errors: int
    results: List[ExecutionResult] = field(default_factory=list)
    mismatches: int = 0          # answered, and disagrees with NIST

    @property
    def denominator_verified(self) -> bool:
        """All cases accounted for without denominator shrinkage."""
        return (
            self.total_attempted
            == (
                self.passed
                + self.documented_validation_rejections
                + self.unsupported_operations
                + self.adapter_errors
                + self.mismatches
            )
        )

    def summary_dict(self) -> Dict[str, Any]:
        return {
            "adapter": self.adapter_name,
            "total_attempted": self.total_attempted,
            "passed": self.passed,
            "documented_validation_rejections": self.documented_validation_rejections,
            "unsupported_operations": self.unsupported_operations,
            "adapter_errors": self.adapter_errors,
            "mismatches": self.mismatches,
            "pass_rate": (self.passed / self.total_attempted) if self.total_attempted > 0 else 0.0,
            "denominator_preserved": self.denominator_verified,
        }


class ConformanceHarness:
    def __init__(self, adapters: List[BasePQCAdapter]):
        self.adapters = {a.name: a for a in adapters}

    def run_session(self, session: ACVPTestSession, adapter_name: Optional[str] = None) -> Dict[str, ConformanceReport]:
        target_adapters = (
            [self.adapters[adapter_name]] if adapter_name and adapter_name in self.adapters else list(self.adapters.values())
        )
        reports = {}

        # Collect all test cases across all test groups
        all_cases: List[TestCase] = []
        for tg in session.groups:
            all_cases.extend(tg.test_cases)

        for adapter in target_adapters:
            passed = 0
            dvr = 0
            unsupported = 0
            adapter_errors = 0
            mismatches = 0
            results = []

            for case in all_cases:
                res = adapter.run(case)
                results.append(res)
                if res.category == TaxonomyCategory.PASS:
                    passed += 1
                elif res.category == TaxonomyCategory.DOCUMENTED_VALIDATION_REJECTION:
                    dvr += 1
                elif res.category == TaxonomyCategory.UNSUPPORTED_OPERATION:
                    unsupported += 1
                elif res.category == TaxonomyCategory.MISMATCH:
                    mismatches += 1
                elif res.category == TaxonomyCategory.ADAPTER_INVOCATION_ERROR:
                    adapter_errors += 1

            reports[adapter.name] = ConformanceReport(
                adapter_name=adapter.name,
                total_attempted=len(all_cases),
                passed=passed,
                documented_validation_rejections=dvr,
                unsupported_operations=unsupported,
                adapter_errors=adapter_errors,
                results=results,
                mismatches=mismatches,
            )

        return reports
