#!/usr/bin/env python3
"""
S6 – Input validation (length checks per FIPS 203/204/205).

Provides validate_vector_fields(vector_set, vector_group, test_case) -> None
Raises ValueError on length mismatch with exact expected vs actual sizes.
"""

from __future__ import annotations

# Expected byte sizes per parameter set (brief §2.4 + FIPS 203/204/205)
# ACVP vectors use hex strings; we measure in bytes = hex_len // 2

PK_SIZES = {
    "ML-KEM-512": 800,
    "ML-KEM-768": 1184,
    "ML-KEM-1024": 1568,
    "ML-DSA-44": 1312,
    "ML-DSA-65": 1952,
    "ML-DSA-87": 2592,
    "SLH-DSA-SHA2-128s": 32,
    "SLH-DSA-SHA2-128f": 32,
    "SLH-DSA-SHAKE-128s": 32,
    "SLH-DSA-SHAKE-128f": 32,
    "SLH-DSA-SHA2-192s": 48,
    "SLH-DSA-SHAKE-192s": 48,
    "SLH-DSA-SHA2-192f": 48,
    "SLH-DSA-SHAKE-192f": 48,
    "SLH-DSA-SHA2-256s": 64,
    "SLH-DSA-SHAKE-256s": 64,
    "SLH-DSA-SHA2-256f": 64,
    "SLH-DSA-SHAKE-256f": 64,
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
    "SLH-DSA-SHAKE-128s": 7856,
    "SLH-DSA-SHAKE-128f": 17088,
    "SLH-DSA-SHA2-192s": 16224,
    "SLH-DSA-SHAKE-192s": 16224,
    "SLH-DSA-SHA2-192f": 35616,
    "SLH-DSA-SHAKE-192f": 35616,
    "SLH-DSA-SHA2-256s": 17792,
    "SLH-DSA-SHAKE-256s": 17792,
    "SLH-DSA-SHA2-256f": 49856,
    "SLH-DSA-SHAKE-256f": 49856,
}

SEED_SIZES = {
    "ML-KEM-512": 32,
    "ML-KEM-768": 32,
    "ML-KEM-1024": 32,
}

# Field name used in ACVP test case for each parameter set
PK_FIELD = {
    "ML-KEM-512": "ek",
    "ML-KEM-768": "ek",
    "ML-KEM-1024": "ek",
    "ML-DSA-44": "pk",
    "ML-DSA-65": "pk",
    "ML-DSA-87": "pk",
    "SLH-DSA-SHA2-128s": "pk",
    "SLH-DSA-SHA2-128f": "pk",
    "SLH-DSA-SHAKE-128s": "pk",
    "SLH-DSA-SHAKE-128f": "pk",
    "SLH-DSA-SHA2-192s": "pk",
    "SLH-DSA-SHAKE-192s": "pk",
    "SLH-DSA-SHA2-192f": "pk",
    "SLH-DSA-SHAKE-192f": "pk",
    "SLH-DSA-SHA2-256s": "pk",
    "SLH-DSA-SHAKE-256s": "pk",
    "SLH-DSA-SHA2-256f": "pk",
    "SLH-DSA-SHAKE-256f": "pk",
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
    "SLH-DSA-SHAKE-128s": "signature",
    "SLH-DSA-SHAKE-128f": "signature",
    "SLH-DSA-SHA2-192s": "signature",
    "SLH-DSA-SHAKE-192s": "signature",
    "SLH-DSA-SHA2-192f": "signature",
    "SLH-DSA-SHAKE-192f": "signature",
    "SLH-DSA-SHA2-256s": "signature",
    "SLH-DSA-SHAKE-256s": "signature",
    "SLH-DSA-SHA2-256f": "signature",
    "SLH-DSA-SHAKE-256f": "signature",
}


# All parameter sets known to this validator (brief §2.4 size tables; every
# parameter set has a public key, so PK_SIZES is the complete registry).
KNOWN_PARAMETER_SETS = frozenset(PK_SIZES)

# Algorithm families recognized per the ACVP corpus layout.
KNOWN_FAMILIES = frozenset({"ML-KEM", "ML-DSA", "SLH-DSA"})


def _extract_bytes(tc: dict, field: str) -> bytes | None:
    """Extract field from test case as bytes (hex string → bytes)."""
    val = tc.get(field)
    if val is None:
        return None
    if isinstance(val, str):
        return bytes.fromhex(val)
    if isinstance(val, (bytes, bytearray)):
        return bytes(val)
    raise TypeError(f"Field {field!r} has unsupported type {type(val).__name__}")


def _check_length(actual: bytes | None, expected: int, what: str, vector_set: str) -> None:
    if actual is None:
        return  # field not present — we only validate fields that exist
    if len(actual) != expected:
        raise ValueError(
            f"{what} length {len(actual)} != {expected} for {vector_set}"
        )


def validate_vector_fields(
    vector_set: str,
    vector_group: dict,
    test_case: dict,
) -> None:
    """
    Validate ACVP test vector field lengths for a given parameter set.

    Args:
        vector_set: e.g. "ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s"
        vector_group: the ACVP test group dict (provides parameterSet confirmation)
        test_case: the ACVP test case dict (provides fields: pk, c, signature, d, etc.)

    Raises:
        ValueError: if any checked field has wrong length, with message:
            "public key length X != Y for ML-KEM-768"
            "ciphertext length X != Y for ML-KEM-768"
            "signature length X != Y for ML-DSA-65"
            "seed length X != Y for ML-KEM-768/keyGen"
        ValueError: if vector_set is not a known parameter set
            ("unknown vector set: ML-KEM-999").
    """
    # Reject unknown vector sets before any field check (E1-style guard).
    if vector_set not in KNOWN_PARAMETER_SETS:
        raise ValueError(f"unknown vector set: {vector_set}")

    # Confirm parameter set matches
    if vector_group.get("parameterSet") != vector_set:
        raise ValueError(f"vector_group parameterSet {vector_group.get('parameterSet')!r} != {vector_set!r}")

    # Public key check
    if vector_set in PK_FIELD:
        pk = _extract_bytes(test_case, PK_FIELD[vector_set])
        _check_length(pk, PK_SIZES[vector_set], "public key", vector_set)

    # Ciphertext check (ML-KEM encapDecap)
    if vector_set in CT_FIELD:
        ct = _extract_bytes(test_case, CT_FIELD[vector_set])
        _check_length(ct, CT_SIZES[vector_set], "ciphertext", vector_set)

    # Signature check (ML-DSA / SLH-DSA sigGen/sigVer)
    if vector_set in SIG_FIELD:
        sig = _extract_bytes(test_case, SIG_FIELD[vector_set])
        _check_length(sig, SIG_SIZES[vector_set], "signature", vector_set)

    # Seed check (ML-KEM keyGen)
    if vector_set in SEED_FIELD:
        seed = _extract_bytes(test_case, SEED_FIELD[vector_set])
        _check_length(seed, SEED_SIZES[vector_set], "seed", f"{vector_set}/keyGen")


__all__ = ["validate_vector_fields", "PK_SIZES", "CT_SIZES", "SIG_SIZES", "SEED_SIZES"]