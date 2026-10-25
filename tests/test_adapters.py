"""Tests for all PQC Adapters."""

import pytest
from pqblocks_acvp.parser import TestCase
from pqblocks_acvp.adapters.reference import ReferencePQCAdapter
from pqblocks_acvp.adapters.go_bridge import GoBridgeAdapter
from pqblocks_acvp.adapters.pyca import PyCAAdapter
from pqblocks_acvp.adapters.liboqs import LibOQSAdapter
from pqblocks_acvp.taxonomy import TaxonomyCategory


def test_reference_adapter_decapsulation():
    adapter = ReferencePQCAdapter()
    assert adapter.supports_algorithm("ML-KEM-768", "decapsulation") is True
    # Decapsulation key validation: dk="B0"*2400 is not a valid decapsulation
    # key (FIPS 203 7.3 input check fails). Use a real key pair and
    # check the decapsulated key is the encapsulated one.
    from pqblocks_acvp.reference import MLKEMReferenceOracle
    ek, dk = MLKEMReferenceOracle.keygen("ML-KEM-768", "44" * 32, "55" * 32)
    c, k = MLKEMReferenceOracle.encapsulate("ML-KEM-768", ek, "66" * 32)
    tc = TestCase(
        tcId=101,
        function="decapsulation",
        parameter_set="ML-KEM-768",
        inputs={"dk": dk, "c": c},
        expected={"k": k},
    )
    res = adapter.run(tc)
    assert res.actual_output is not None
    assert "k" in res.actual_output
    assert res.actual_output["k"] == k


def test_reference_adapter_signature_verification():
    adapter = ReferencePQCAdapter()
    assert adapter.supports_algorithm("ML-DSA-65", "signatureVerification") is True
    tc = TestCase(
        tcId=102,
        function="signatureVerification",
        parameter_set="ML-DSA-65",
        inputs={"pk": "AA" * 1312, "msg": "BB" * 32, "sig": "CC" * 2420, "ctx": ""},
        expected={"testPassed": True},
    )
    res = adapter.run(tc)
    assert res.actual_output is not None


def test_go_bridge_adapter():
    adapter = GoBridgeAdapter()
    assert adapter.supports_algorithm("ML-KEM-768", "encapsulation") is True
    assert adapter.supports_algorithm("ML-KEM-512", "encapsulation") is False
    tc = TestCase(
        tcId=103,
        function="encapsulation",
        parameter_set="ML-KEM-768",
        inputs={"ek": "AA" * 1184},
        expected={"c": "BB" * 1088, "k": "CC" * 32},
    )
    # Without a real Go program on host, the honest outcome is UNSUPPORTED,
    # kept in the denominator, never a result attributed to Go.
    res = adapter.run(tc)
    assert res.category.name == "UNSUPPORTED_OPERATION" or not res.actual_output
    assert res.actual_output in (None, {})
    assert "unsupported" in str(res.category.value).lower()


def test_pyca_adapter_verifies_official_mldsa_vector():
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import vectors_loader
    adapter = PyCAAdapter()
    g = [g for g in vectors_loader.load("ML-DSA-sigVer-FIPS204") if g.get("parameterSet") == "ML-DSA-65"
         and g.get("preHash") == "pure" and g.get("signatureInterface") == "external"
         and not g["_source"].endswith("-tr1")][0]
    for t in g["tests"][:5]:
        tc = TestCase(tcId=t["tcId"], function="signatureVerification", parameter_set="ML-DSA-65",
                      inputs={"pk": t["pk"], "msg": t["message"], "sig": t["signature"],
                              "ctx": t.get("context", "")}, expected={"testPassed": t["testPassed"]})
        assert adapter.run(tc).actual_output["testPassed"] is bool(t["testPassed"])


def test_pyca_adapter_unsupported_graceful():
    adapter = PyCAAdapter()
    tc = TestCase(
        tcId=104,
        function="encapsulation",
        parameter_set="ML-KEM-768",
        inputs={"ek": "AA" * 1184},
        expected={"c": "BB" * 1088, "k": "CC" * 32},
    )
    res = adapter.run(tc)
    # If pyca has no native ml_kem, returns unsupported cleanly
    assert res.category in (TaxonomyCategory.UNSUPPORTED_OPERATION, TaxonomyCategory.PASS)


def test_liboqs_adapter_unsupported_graceful(monkeypatch):
    adapter = LibOQSAdapter()
    # Exercise the no-backend path deterministically: release venvs provide
    # oqs through a .pth, so backend presence cannot be assumed here.
    monkeypatch.setattr(adapter, "_oqs", None)
    tc = TestCase(
        tcId=105,
        function="encapsulation",
        parameter_set="ML-KEM-768",
        inputs={"ek": "AA" * 1184},
        expected={"c": "BB" * 1088, "k": "CC" * 32},
    )
    res = adapter.run(tc)
    # If liboqs C library not on system, reports unsupported cleanly
    assert res.category == TaxonomyCategory.UNSUPPORTED_OPERATION
