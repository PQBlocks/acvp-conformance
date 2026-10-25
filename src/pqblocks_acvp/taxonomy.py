"""4-Way Taxonomy Classifier for PQC Conformance Validation."""

import enum
import hmac
from dataclasses import dataclass
from typing import Any, Dict, Optional


class TaxonomyCategory(str, enum.Enum):
    PASS = "pass"
    DOCUMENTED_VALIDATION_REJECTION = "documented-validation-rejection"
    UNSUPPORTED_OPERATION = "unsupported-operation"
    ADAPTER_INVOCATION_ERROR = "adapter/invocation error"
    # The implementation ANSWERED and the answer disagrees with NIST - the one
    # result a conformance tool exists to report. Until 2026-10-07 this fell
    # into PASS (testPassed was never compared) or "adapter error".
    MISMATCH = "mismatch"


@dataclass
class ExecutionResult:
    tcId: int
    category: TaxonomyCategory
    actual_output: Optional[Dict[str, Any]] = None
    expected_output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0

    @property
    def is_pass(self) -> bool:
        return self.category == TaxonomyCategory.PASS


class TaxonomyClassifier:
    @staticmethod
    def classify(
        actual: Optional[Dict[str, Any]],
        expected: Optional[Dict[str, Any]],
        exit_code: int = 0,
        error_msg: Optional[str] = None,
        unsupported: bool = False,
        validation_rejected: bool = False,
    ) -> TaxonomyCategory:
        """Classify execution result into exact 4-way taxonomy."""
        # 1. Unsupported operations (missing algorithm, unsupported parameter set)
        if unsupported or (error_msg and "unsupported" in error_msg.lower()):
            return TaxonomyCategory.UNSUPPORTED_OPERATION

        # 2. Adapter or invocation errors (segfaults, timeouts, exceptions)
        if exit_code != 0 or (error_msg and not validation_rejected):
            return TaxonomyCategory.ADAPTER_INVOCATION_ERROR

        # 3. Verdict tests (sigVer and friends): compare the verdict EXACTLY.
        if expected and "testPassed" in expected:
            if validation_rejected or (actual or {}).get("rejected") is True:
                got = False
            elif actual is not None and "testPassed" in actual:
                got = bool(actual["testPassed"])
            else:
                return TaxonomyCategory.ADAPTER_INVOCATION_ERROR
            if got != bool(expected["testPassed"]):
                return TaxonomyCategory.MISMATCH
            return TaxonomyCategory.PASS if got else TaxonomyCategory.DOCUMENTED_VALIDATION_REJECTION

        # 4. Value tests (keyGen/encap/decap): a rejection where NIST expects a value
        # is a disagreement, not a documented rejection.
        if validation_rejected:
            return TaxonomyCategory.MISMATCH if expected else TaxonomyCategory.DOCUMENTED_VALIDATION_REJECTION

        if actual is None or expected is None:
            return TaxonomyCategory.ADAPTER_INVOCATION_ERROR

        for k, exp_val in expected.items():
            if k == "resultsArray":
                continue
            act_val = actual.get(k)
            if act_val is None:
                return TaxonomyCategory.ADAPTER_INVOCATION_ERROR
            if isinstance(exp_val, str) and isinstance(act_val, str):
                if not hmac.compare_digest(exp_val.strip().lower(), act_val.strip().lower()):
                    return TaxonomyCategory.MISMATCH
            elif act_val != exp_val:
                return TaxonomyCategory.MISMATCH

        return TaxonomyCategory.PASS
