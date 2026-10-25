"""Tests covering Edge-Case Ledger E01 through E16."""

import pytest
from pqblocks_acvp.parser import TestCase
from pqblocks_acvp.adapters.reference import ReferencePQCAdapter
from pqblocks_acvp.adapters.go_bridge import GoBridgeAdapter
from pqblocks_acvp.taxonomy import TaxonomyCategory, TaxonomyClassifier


def test_e01_empty_corpus():
    from pqblocks_acvp.parser import ACVPTestSession
    session = ACVPTestSession(vsId=1, algorithm="ML-KEM")
    assert session.total_test_cases == 0


def test_e04_key_format_mismatch():
    # E04: test with executing adapter
    adapter = ReferencePQCAdapter()
    tc = TestCase(
        tcId=4,
        function="decapsulation",
        parameter_set="ML-KEM-768",
        inputs={"dk": "", "c": "AA" * 1088},
        expected={"testPassed": False},   # malformed dk must be rejected, no NIST value exists
    )
    res = adapter.run(tc)
    assert res.category == TaxonomyCategory.DOCUMENTED_VALIDATION_REJECTION


def test_e05_parameter_mismatch_unsupported():
    adapter = GoBridgeAdapter()
    tc = TestCase(
        tcId=5,
        function="encapsulation",
        parameter_set="ML-KEM-512",  # Go bridge explicitly unsupported
        inputs={"ek": "AA" * 800},
        expected={"k": "BB" * 32},
    )
    res = adapter.run(tc)
    assert res.category == TaxonomyCategory.UNSUPPORTED_OPERATION


def test_e06_invalid_ciphertext_implicit_rejection():
    # FIPS 203 Alg 18: a ciphertext that does not re-encrypt yields the implicit
    # rejection key K_bar = J(z || c) = SHAKE256(z || c, 32), z = last 32 bytes of dk. Computed here from
    # the standard's formula - independent of the oracle under test.
    import hashlib
    from pqblocks_acvp.reference import MLKEMReferenceOracle
    _ek, dk_hex = MLKEMReferenceOracle.keygen("ML-KEM-768", "07" * 32, "08" * 32)
    c_hex = "00" * 1088
    k_bar = hashlib.shake_256(bytes.fromhex(dk_hex)[-32:] + bytes.fromhex(c_hex)).hexdigest(32).upper()
    adapter = ReferencePQCAdapter()
    tc = TestCase(
        tcId=6,
        function="decapsulation",
        parameter_set="ML-KEM-768",
        inputs={"dk": dk_hex, "c": c_hex},
        expected={"k": k_bar},
    )
    res = adapter.run(tc)
    assert res.category == TaxonomyCategory.PASS
    assert res.actual_output["k"].upper() == k_bar


def test_e13_zero_length_input():
    adapter = ReferencePQCAdapter()
    tc = TestCase(
        tcId=13,
        function="encapsulation",
        parameter_set="ML-KEM-768",
        inputs={"ek": ""},
        expected={"testPassed": False},   # empty ek must be rejected
    )
    res = adapter.run(tc)
    assert res.category == TaxonomyCategory.DOCUMENTED_VALIDATION_REJECTION


def test_e15_mldsa_context_mismatch():
    adapter = ReferencePQCAdapter()
    tc = TestCase(
        tcId=15,
        function="signatureVerification",
        parameter_set="ML-DSA-65",
        inputs={"pk": "AA" * 1312, "msg": "BB" * 32, "sig": "CC" * 2420, "ctx": "FF" * 300},  # Oversized ctx > 255
        expected={"testPassed": False},   # FIPS 204 requires |ctx| <= 255 - must be rejected
    )
    res = adapter.run(tc)
    assert res.category == TaxonomyCategory.DOCUMENTED_VALIDATION_REJECTION
