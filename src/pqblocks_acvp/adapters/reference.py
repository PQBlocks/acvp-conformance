"""Reference Adapter using Pure Python Reference Oracle."""

from typing import Any, Dict, Tuple
from .base import BasePQCAdapter
from ..parser import TestCase
from ..reference import MLKEMReferenceOracle, MLDSAReferenceOracle


class ReferencePQCAdapter(BasePQCAdapter):
    def __init__(self):
        super().__init__("Reference-FIPS-Oracle")

    def supports_algorithm(self, parameter_set: str, function: str) -> bool:
        if parameter_set.startswith("ML-KEM") and function in ("encapsulation", "decapsulation"):
            return True
        if parameter_set.startswith("ML-DSA") and function in ("signatureVerification",):
            return True
        return False

    def execute_case(self, test_case: TestCase) -> Tuple[Dict[str, Any], bool, bool]:
        fn = test_case.function.lower()
        param = test_case.parameter_set
        inputs = test_case.inputs

        if "encap" in fn:
            ek = inputs.get("ek") or inputs.get("publicKey")
            m = inputs.get("m", "")
            if not ek:
                raise ValueError("Missing public key (ek)")
            c, k = MLKEMReferenceOracle.encapsulate(param, ek, m)
            return {"c": c, "k": k}, False, False

        elif "decap" in fn:
            dk = inputs.get("dk") or inputs.get("privateKey")
            c = inputs.get("c") or inputs.get("cipherText")
            if not dk or not c:
                raise ValueError("Missing dk or c")
            k = MLKEMReferenceOracle.decapsulate(param, dk, c)
            return {"k": k}, False, False

        elif "sigver" in fn or "signatureverification" in fn:
            if (inputs.get("_signatureInterface", "external") != "external"
                    or inputs.get("_preHash", "pure") != "pure" or inputs.get("_externalMu")):
                return {}, False, True     # only external/pure ML-DSA is implemented here - unsupported, counted
            pk = str(inputs.get("pk") or inputs.get("publicKey") or "")
            msg = str(inputs.get("msg") or inputs.get("message") or "")
            sig = str(inputs.get("sig") or inputs.get("signature") or "")
            ctx = str(inputs.get("ctx") or inputs.get("context") or "")
            if not pk or not msg or not sig:
                raise ValueError("Missing pk, msg, or sig")
            valid = MLDSAReferenceOracle.verify(param, pk, msg, sig, ctx)
            return {"testPassed": valid}, not valid, False

        return {}, False, True
