"""liboqs C-API and Python Adapter."""

import contextlib
import sys
from typing import Any, Dict, Tuple
from .base import BasePQCAdapter
from ..parser import TestCase


class LibOQSAdapter(BasePQCAdapter):
    def __init__(self):
        super().__init__("liboqs")
        self._oqs = None
        try:
            # liboqs-python prints a banner to stdout on first import; keep --json output clean.
            with contextlib.redirect_stdout(sys.stderr):
                import oqs  # type: ignore
            self._oqs = oqs
        except ImportError:
            self._oqs = None

    def supports_algorithm(self, parameter_set: str, function: str) -> bool:
        return parameter_set in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87")

    def execute_case(self, test_case: TestCase) -> Tuple[Dict[str, Any], bool, bool]:
        if not self._oqs:
            # When liboqs C library is not on host, report unsupported operation
            return {}, False, True

        param = test_case.parameter_set
        fn = test_case.function.lower()
        inputs = test_case.inputs

        # liboqs canonical mechanism names use hyphens (e.g. ML-KEM-768)
        oqs_alg = param

        if "encap" in fn and "decap" not in fn:
            # liboqs-python encapsulates with its own randomness; an ACVP AFT
            # case fixes `m`, so a random encapsulation can never match and
            # was being reported as liboqs DISAGREEING. Unsupported, honestly.
            return {}, False, True

        elif "decap" in fn:
            dk_bytes = bytes.fromhex(inputs["dk"])
            c_bytes = bytes.fromhex(inputs["c"])
            with self._oqs.KeyEncapsulation(oqs_alg, secret_key=dk_bytes) as server:
                ss = server.decap_secret(c_bytes)
                return {"k": ss.hex().upper()}, False, False

        return {}, False, True
