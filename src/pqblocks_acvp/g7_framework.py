"""Differential Re-execution Framework for Independent Verification."""

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple
from .parser import TestCase
from .adapters.base import BasePQCAdapter
from .taxonomy import TaxonomyCategory


@dataclass
class G7VerificationOutcome:
    sample_size: int
    total_cells: int
    matched: int
    mismatched: int
    agreement_rate: float
    passed: bool
    details: List[Dict[str, Any]]


class G7ReexecutionFramework:
    def __init__(self, primary_adapter: BasePQCAdapter, secondary_adapter: BasePQCAdapter):
        self.primary = primary_adapter
        self.secondary = secondary_adapter

    def verify_sample(
        self,
        test_cases: List[TestCase],
        sample_ratio: float = 0.10,
        seed: int = 42,
        agreement_threshold: float = 0.99,
    ) -> G7VerificationOutcome:
        """Independently re-execute at least 10% of test cells and check taxonomy agreement."""
        total = len(test_cases)
        if total == 0:
            return G7VerificationOutcome(
                sample_size=0,
                total_cells=0,
                matched=0,
                mismatched=0,
                agreement_rate=1.0,
                passed=True,
                details=[],
            )

        rng = random.Random(seed)
        sample_count = max(1, int(total * sample_ratio))
        sampled_cases = rng.sample(test_cases, sample_count)

        matched = 0
        mismatched = 0
        details = []

        for tc in sampled_cases:
            res_a = self.primary.run(tc)
            res_b = self.secondary.run(tc)

            is_match = res_a.category == res_b.category
            if is_match:
                matched += 1
            else:
                mismatched += 1

            details.append(
                {
                    "tcId": tc.tcId,
                    "parameter_set": tc.parameter_set,
                    "function": tc.function,
                    "primary_category": res_a.category.value,
                    "secondary_category": res_b.category.value,
                    "match": is_match,
                }
            )

        agreement = (matched / sample_count) if sample_count > 0 else 1.0
        passed = agreement >= agreement_threshold

        return G7VerificationOutcome(
            sample_size=sample_count,
            total_cells=total,
            matched=matched,
            mismatched=mismatched,
            agreement_rate=agreement,
            passed=passed,
            details=details,
        )
