"""Abstract Base Adapter for PQC Implementations."""

import abc
import time
from typing import Any, Dict, Tuple
from ..parser import TestCase
from ..taxonomy import ExecutionResult, TaxonomyClassifier, TaxonomyCategory


class BasePQCAdapter(abc.ABC):
    def __init__(self, name: str):
        self.name = name

    @abc.abstractmethod
    def supports_algorithm(self, parameter_set: str, function: str) -> bool:
        """Return True if adapter supports the given parameter set and function."""
        pass

    @abc.abstractmethod
    def execute_case(self, test_case: TestCase) -> Tuple[Dict[str, Any], bool, bool]:
        """Execute test case.
        Returns:
            (actual_dict, validation_rejected, unsupported)
        """
        pass

    def run(self, test_case: TestCase, timeout_s: float = 5.0) -> ExecutionResult:
        """Run a single test case with taxonomy classification and timing."""
        if not self.supports_algorithm(test_case.parameter_set, test_case.function):
            return ExecutionResult(
                tcId=test_case.tcId,
                category=TaxonomyCategory.UNSUPPORTED_OPERATION,
                expected_output=test_case.expected,
                error_message=f"Algorithm/function {test_case.parameter_set}:{test_case.function} not supported by {self.name}",
            )

        t0 = time.perf_counter()
        exit_code = 0
        error_msg = None
        actual_output = None
        rejected = False
        unsupported = False

        try:
            actual_output, rejected, unsupported = self.execute_case(test_case)
        except NotImplementedError as e:
            unsupported = True
            error_msg = str(e)
        except ValueError as e:
            # Often validation rejection in crypto parsers
            rejected = True
            error_msg = str(e)
        except Exception as e:
            exit_code = 1
            error_msg = f"{type(e).__name__}: {str(e)}"

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        if elapsed_ms > (timeout_s * 1000.0):
            exit_code = 1
            error_msg = f"Timeout exceeded (> {timeout_s}s)"

        category = TaxonomyClassifier.classify(
            actual=actual_output,
            expected=test_case.expected,
            exit_code=exit_code,
            error_msg=error_msg,
            unsupported=unsupported,
            validation_rejected=rejected,
        )

        return ExecutionResult(
            tcId=test_case.tcId,
            category=category,
            actual_output=actual_output,
            expected_output=test_case.expected,
            error_message=error_msg,
            execution_time_ms=elapsed_ms,
        )
