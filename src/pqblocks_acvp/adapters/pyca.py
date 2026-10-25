"""pyca/cryptography Adapter for ML-KEM and ML-DSA."""

from typing import Any, Dict, Tuple
from .base import BasePQCAdapter
from ..parser import TestCase


class PyCAAdapter(BasePQCAdapter):
    def __init__(self):
        super().__init__("pyca/cryptography")
        try:
            import cryptography
            self._available = True
        except ImportError:
            self._available = False

    def supports_algorithm(self, parameter_set: str, function: str) -> bool:
        if not self._available:
            return False
        return parameter_set in ("ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87")

    def execute_case(self, test_case: TestCase) -> Tuple[Dict[str, Any], bool, bool]:
        # pyca/cryptography (>= 47) exposes ML-KEM and ML-DSA under
        # hazmat.primitives.asymmetric.{mlkem,mldsa}. The adapter imported a
        # non-existent `ml_kem` module, so it reported every case unsupported.
        # What pyca can be asked about ACVP cases: ML-DSA signature
        # verification (deterministic). ML-KEM encapsulation takes no caller
        # randomness `m` and decapsulation keys are seed-only, so those AFT
        # cases are honestly unsupported here.
        if not self._available:
            return {}, False, True
        fn = test_case.function.lower()
        param = test_case.parameter_set
        inputs = test_case.inputs
        if ("sigver" in fn or "signatureverification" in fn) and param.startswith("ML-DSA-"):
            if (inputs.get("_signatureInterface", "external") != "external"
                    or inputs.get("_preHash", "pure") != "pure" or inputs.get("_externalMu")):
                return {}, False, True     # only external/pure ML-DSA is implemented here - unsupported, counted
            try:
                from cryptography.exceptions import InvalidSignature
                from cryptography.hazmat.primitives.asymmetric import mldsa
            except ImportError:
                return {}, False, True
            cls = {"ML-DSA-44": "MLDSA44PublicKey", "ML-DSA-65": "MLDSA65PublicKey",
                   "ML-DSA-87": "MLDSA87PublicKey"}[param]
            pk = bytes.fromhex(str(inputs.get("pk") or inputs.get("publicKey") or ""))
            msg = bytes.fromhex(str(inputs.get("msg") or inputs.get("message") or ""))
            sig = bytes.fromhex(str(inputs.get("sig") or inputs.get("signature") or ""))
            ctx = bytes.fromhex(str(inputs.get("ctx") or inputs.get("context") or "")) or None
            try:
                getattr(mldsa, cls).from_public_bytes(pk).verify(sig, msg, ctx)
                valid = True
            except (InvalidSignature, ValueError):
                valid = False
            return {"testPassed": valid}, not valid, False
        return {}, False, True
