"""Go crypto/mlkem Adapter Bridge (expanded-key handling)."""

from typing import Any, Dict, Tuple
from .base import BasePQCAdapter
from ..parser import TestCase


class GoBridgeAdapter(BasePQCAdapter):
    def __init__(self):
        super().__init__("Go-crypto/mlkem")

    def supports_algorithm(self, parameter_set: str, function: str) -> bool:
        # Go standard library crypto/mlkem currently supports ML-KEM-768 and ML-KEM-1024
        # ML-KEM-512 is intentionally unsupported per Go crypto design
        if parameter_set == "ML-KEM-512":
            return False
        return parameter_set in ("ML-KEM-768", "ML-KEM-1024")

    def execute_case(self, test_case: TestCase) -> Tuple[Dict[str, Any], bool, bool]:
        # Honest until a real bridge exists: this adapter used to answer for
        # "Go crypto/mlkem" by calling the Python reference oracle - every
        # "Go" result was the reference talking to itself. With no Go program
        # behind it, every case is reported unsupported and stays in the
        # denominator, never counted as Go agreeing.
        return {}, False, True
