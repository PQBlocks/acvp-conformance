"""Tests for Tier 1 Reference Oracle."""

import pytest
from pqblocks_acvp.reference import MLKEMReferenceOracle, MLDSAReferenceOracle


def test_mlkem_encap_decap_roundtrip():
    # Real round trip: generate a key pair and verify the same K on both sides.
    ek_hex, dk_hex = MLKEMReferenceOracle.keygen("ML-KEM-768", "11" * 32, "22" * 32)
    c_hex, k_hex = MLKEMReferenceOracle.encapsulate("ML-KEM-768", ek_hex, "33" * 32)
    assert len(c_hex) == 1088 * 2
    assert len(k_hex) == 32 * 2

    k_decap = MLKEMReferenceOracle.decapsulate("ML-KEM-768", dk_hex, c_hex)
    assert len(k_decap) == 32 * 2
    assert k_decap == k_hex


def test_mlkem_decapsulation_rejects_inconsistent_dk():
    # FIPS 203 7.3: a dk whose embedded H(ek) does not match must be rejected
    _ek, dk_hex = MLKEMReferenceOracle.keygen("ML-KEM-768", "11" * 32, "22" * 32)
    bad = dk_hex[:-128] + "00" * 64          # corrupt H(ek) || z
    with pytest.raises(ValueError):
        MLKEMReferenceOracle.decapsulate("ML-KEM-768", bad, "A0" * 1088)


def test_mlkem_invalid_param_set():
    with pytest.raises(ValueError):
        MLKEMReferenceOracle.encapsulate("ML-KEM-999", "AA" * 100)


def test_mldsa_verify_basic():
    pk = "11" * 1312
    msg = "22" * 32
    sig = "33" * 2420
    # Basic structural check
    res = MLDSAReferenceOracle.verify("ML-DSA-65", pk, msg, sig)
    assert isinstance(res, bool)
