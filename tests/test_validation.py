#!/usr/bin/env python3
"""Test suite for S6 – Input validation (length checks per FIPS 203/204/205).

Tests:
- E4: wrong public key length → ValueError ("public key length X != Y for <set>")
- E5: wrong ciphertext length   → ValueError ("ciphertext length X != Y for <set>")
- E6: wrong signature length    → ValueError ("signature length X != Y for <set>")
- E7: wrong seed length         → ValueError ("seed length X != Y for <set>/keyGen")
- Valid vectors for every parameter set in brief §2.4 pass without raising.
"""

import pytest

from pqblocks_acvp.validation import validate_vector_fields


# ---------------------------------------------------------------------------
# Size tables (brief §2.4 + confirmed against cached ACVP corpus field sizes)
# ---------------------------------------------------------------------------

PK_SIZES = {
    "ML-KEM-512": 800,
    "ML-KEM-768": 1184,
    "ML-KEM-1024": 1568,
    "ML-DSA-44": 1312,
    "ML-DSA-65": 1952,
    "ML-DSA-87": 2592,
    "SLH-DSA-SHA2-128s": 32,
    "SLH-DSA-SHA2-128f": 32,
}
CT_SIZES = {
    "ML-KEM-512": 768,
    "ML-KEM-768": 1088,
    "ML-KEM-1024": 1568,
}
SIG_SIZES = {
    "ML-DSA-44": 2420,
    "ML-DSA-65": 3309,
    "ML-DSA-87": 4627,
    "SLH-DSA-SHA2-128s": 7856,
    "SLH-DSA-SHA2-128f": 17088,
}
SEED_SIZES = {
    "ML-KEM-512": 32,
    "ML-KEM-768": 32,
    "ML-KEM-1024": 32,
}

# The test-case field names used by each family (per ACVP corpus structure)
PK_FIELD = {
    "ML-KEM-512": "ek",
    "ML-KEM-768": "ek",
    "ML-KEM-1024": "ek",
    "ML-DSA-44": "pk",
    "ML-DSA-65": "pk",
    "ML-DSA-87": "pk",
    "SLH-DSA-SHA2-128s": "pk",
    "SLH-DSA-SHA2-128f": "pk",
}
CT_FIELD = {
    "ML-KEM-512": "c",
    "ML-KEM-768": "c",
    "ML-KEM-1024": "c",
}
SEED_FIELD = {
    "ML-KEM-512": "d",
    "ML-KEM-768": "d",
    "ML-KEM-1024": "d",
}
SIG_FIELD = {
    "ML-DSA-44": "signature",
    "ML-DSA-65": "signature",
    "ML-DSA-87": "signature",
    "SLH-DSA-SHA2-128s": "signature",
    "SLH-DSA-SHA2-128f": "signature",
}


# ---------------------------------------------------------------------------
# E4: wrong public key length
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("vector_set", list(PK_SIZES))
def test_E4_wrong_public_key_raises(vector_set):
    field = PK_FIELD[vector_set]
    good = PK_SIZES[vector_set]
    tc = {"tcId": 1, field: b"\x00" * (good + 1)}
    with pytest.raises(ValueError) as exc:
        validate_vector_fields(vector_set, {"parameterSet": vector_set}, tc)
    msg = str(exc.value).lower()
    assert "public key length" in msg
    assert str(good + 1) in msg
    assert str(good) in msg
    assert vector_set.split("-")[-1] in msg


@pytest.mark.parametrize("vector_set", list(PK_SIZES))
def test_E4_wrong_public_key_zero_raises(vector_set):
    field = PK_FIELD[vector_set]
    good = PK_SIZES[vector_set]
    tc = {"tcId": 1, field: b"\x00" * 0}
    with pytest.raises(ValueError) as exc:
        validate_vector_fields(vector_set, {"parameterSet": vector_set}, tc)
    assert "public key length" in str(exc.value).lower()


@pytest.mark.parametrize("vector_set", list(PK_SIZES))
def test_E4_good_public_key_passes(vector_set):
    field = PK_FIELD[vector_set]
    tc = {"tcId": 1, field: b"\x00" * PK_SIZES[vector_set]}
    validate_vector_fields(vector_set, {"parameterSet": vector_set}, tc)  # no raise


# ---------------------------------------------------------------------------
# E5: wrong ciphertext length
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("vector_set", list(CT_SIZES))
def test_E5_wrong_ciphertext_raises(vector_set):
    field = CT_FIELD[vector_set]
    good = CT_SIZES[vector_set]
    tc = {"tcId": 1, field: b"\x00" * (good - 1)}
    with pytest.raises(ValueError) as exc:
        validate_vector_fields(vector_set, {"parameterSet": vector_set}, tc)
    msg = str(exc.value).lower()
    assert "ciphertext length" in msg
    assert str(good - 1) in msg
    assert str(good) in msg


@pytest.mark.parametrize("vector_set", list(CT_SIZES))
def test_E5_good_ciphertext_passes(vector_set):
    field = CT_FIELD[vector_set]
    tc = {"tcId": 1, field: b"\x00" * CT_SIZES[vector_set]}
    validate_vector_fields(vector_set, {"parameterSet": vector_set}, tc)


# ---------------------------------------------------------------------------
# E6: wrong signature length
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("vector_set", list(SIG_SIZES))
def test_E6_wrong_signature_raises(vector_set):
    field = SIG_FIELD[vector_set]
    good = SIG_SIZES[vector_set]
    tc = {"tcId": 1, field: b"\x00" * (good - 1)}
    with pytest.raises(ValueError) as exc:
        validate_vector_fields(vector_set, {"parameterSet": vector_set}, tc)
    msg = str(exc.value).lower()
    assert "signature length" in msg
    assert str(good - 1) in msg
    assert str(good) in msg


@pytest.mark.parametrize("vector_set", list(SIG_SIZES))
def test_E6_good_signature_passes(vector_set):
    field = SIG_FIELD[vector_set]
    tc = {"tcId": 1, field: b"\x00" * SIG_SIZES[vector_set]}
    validate_vector_fields(vector_set, {"parameterSet": vector_set}, tc)


# ---------------------------------------------------------------------------
# E7: wrong seed length
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("vector_set", list(SEED_SIZES))
def test_E7_wrong_seed_raises(vector_set):
    field = SEED_FIELD[vector_set]
    good = SEED_SIZES[vector_set]
    tc = {"tcId": 1, field: b"\x00" * (good - 1)}
    with pytest.raises(ValueError) as exc:
        validate_vector_fields(vector_set, {"parameterSet": vector_set}, tc)
    msg = str(exc.value).lower()
    assert "seed length" in msg


@pytest.mark.parametrize("vector_set", list(SEED_SIZES))
def test_E7_good_seed_passes(vector_set):
    field = SEED_FIELD[vector_set]
    tc = {"tcId": 1, field: b"\x00" * SEED_SIZES[vector_set]}
    validate_vector_fields(vector_set, {"parameterSet": vector_set}, tc)


# ---------------------------------------------------------------------------
# Valid-vector smoke for every parameter set in brief §2.4
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "vector_set",
    [
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    ],
)
def test_valid_vectors_pass(vector_set):
    tc = {"tcId": 1}
    if vector_set in PK_FIELD:
        tc[PK_FIELD[vector_set]] = b"\x00" * PK_SIZES[vector_set]
    if vector_set in CT_FIELD:
        tc[CT_FIELD[vector_set]] = b"\x00" * CT_SIZES[vector_set]
    if vector_set in SEED_FIELD:
        tc[SEED_FIELD[vector_set]] = b"\x00" * SEED_SIZES[vector_set]
    if vector_set in SIG_FIELD:
        tc[SIG_FIELD[vector_set]] = b"\x00" * SIG_SIZES[vector_set]
    validate_vector_fields(vector_set, {"parameterSet": vector_set}, tc)


def test_validation_unknown_vector_set_raises():
    """Unknown vector set family is rejected loudly."""
    with pytest.raises(ValueError):
        validate_vector_fields("ML-KEM-999", {"parameterSet": "ML-KEM-999"}, {"tcId": 1})


def test_validation_missing_field_is_ok():
    """Absent fields that are not checked for this set are tolerated."""
    tc = {"tcId": 1}  # no fields at all
    validate_vector_fields("ML-KEM-768", {"parameterSet": "ML-KEM-768"}, tc)
