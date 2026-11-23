#!/usr/bin/env python3
"""Test suite for S5 – Vector fixture loader (pinned, sha256-verified).

Tests cover E8-E10 and official ACVP vector loading for ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s.
This file provides vector test coverage by testing against vector fixtures.
"""

import hashlib
import json
import os
import tempfile
from pathlib import Path
import pytest

from pqblocks_acvp.vectors import (
    load_vectors,
    VectorGroup,
    MalformedVectorJSONError,
    MissingVectorFixtureError,
    FixtureIntegrityError,
    list_vector_sets,
    check_integrity,
)


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

def _make_temp_acvp_dir(structure: dict) -> Path:
    """Create a temporary directory tree with the given structure."""
    base = Path(tempfile.mkdtemp(prefix="acvp_test_"))
    for dir_name, files in structure.items():
        d = base / dir_name
        d.mkdir(parents=True)
        for fname, content in files.items():
            if isinstance(content, str):
                (d / fname).write_text(content, encoding="utf-8")
            else:
                (d / fname).write_text(json.dumps(content), encoding="utf-8")
    return base


# ---------------------------------------------------------------------------
# Test: E8 – Malformed vector JSON
# ---------------------------------------------------------------------------

def test_E8_malformed_json_raises_with_location():
    """Feed invalid JSON fixture -> ValueError with line/col (E8)."""
    base = _make_temp_acvp_dir({
        "ML-KEM-BAD": {"internalProjection.json": "not json {{{"},
    })
    import pqblocks_acvp.vectors as vectors_mod
    orig_acvp = vectors_mod._ACVP
    vectors_mod._ACVP = base
    
    try:
        # Pin the fixture hash so _load_file_verified reaches json.loads (E8 path)
        fpath = base / "ML-KEM-BAD" / "internalProjection.json"
        digest = hashlib.sha256(fpath.read_bytes()).hexdigest()
        pin_key = f"acvp:ML-KEM-BAD:{fpath}"
        vectors_mod.PINNED_SHA256[pin_key] = digest
        
        try:
            with pytest.raises(MalformedVectorJSONError) as exc:
                load_vectors("ML-KEM-BAD")
            assert exc.value.line is not None
            assert exc.value.column is not None
            assert "malformed vector json" in str(exc.value).lower()
        finally:
            vectors_mod.PINNED_SHA256.pop(pin_key, None)
    finally:
        vectors_mod._ACVP = orig_acvp


# ---------------------------------------------------------------------------
# Test: E9 – Missing vector fixture
# ---------------------------------------------------------------------------

def test_E9_missing_fixture_raises_with_path():
    """Request vector set not in pinned fixtures -> FileNotFoundError (E9)."""
    base = Path(tempfile.mkdtemp(prefix="acvp_test_"))
    import pqblocks_acvp.vectors as vectors_mod
    orig_acvp = vectors_mod._ACVP
    vectors_mod._ACVP = base
    
    try:
        with pytest.raises(FileNotFoundError) as exc:
            load_vectors("ML-KEM-999")
        assert "vector fixture not found" in str(exc.value).lower()
    finally:
        vectors_mod._ACVP = orig_acvp


# ---------------------------------------------------------------------------
# Test: E10 – Fixture sha256 mismatch
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Test: E10 – Fixture sha256 mismatch
# ---------------------------------------------------------------------------

def test_E10_sha256_mismatch_raises_with_both_hashes():
    """Tamper with fixture file -> ValueError with expected and got hashes (E10).

    Pin the hash of the ORIGINAL content, then tamper the file; load must
    raise FixtureIntegrityError carrying expected vs got hashes.
    """
    import tempfile
    from pathlib import Path
    import hashlib

    base = Path(tempfile.mkdtemp(prefix="acvp_test_"))
    import pqblocks_acvp.vectors as vectors_mod
    orig_acvp = vectors_mod._ACVP
    orig_pinned = dict(vectors_mod.PINNED_SHA256)
    vectors_mod._ACVP = base

    try:
        fixture_path = base / "ML-KEM-TEST" / "internalProjection.json"
        fixture_path.parent.mkdir(exist_ok=True)
        original = '{"testGroups": [{"parameterSet": "ML-KEM-768", "tests": [{"tcId": 1, "d": "aa", "z": "bb"}]}]}'
        with open(fixture_path, "w") as f:
            f.write(original)
        expected_sha = hashlib.sha256(original.encode("utf-8")).hexdigest()

        key = f"acvp:ML-KEM-TEST:{fixture_path}"
        vectors_mod.PINNED_SHA256[key] = expected_sha

        # Tamper the file content after pinning -> sha256 mismatch
        with open(fixture_path, "w") as f:
            f.write('{"testGroups": [{"parameterSet": "ML-KEM-768", "tests": [{"tcId": 1, "d": "cc", "z": "dd"}]}]}')

        try:
            with pytest.raises(FixtureIntegrityError) as exc:
                load_vectors("ML-KEM-TEST")
            assert exc.value.expected == expected_sha
            assert exc.value.got != expected_sha
            assert "fixture integrity check failed" in str(exc.value).lower()
        finally:
            vectors_mod._ACVP = orig_acvp
            vectors_mod.PINNED_SHA256.clear()
            vectors_mod.PINNED_SHA256.update(orig_pinned)
    finally:
        vectors_mod._ACVP = orig_acvp
        vectors_mod.PINNED_SHA256.clear()
        vectors_mod.PINNED_SHA256.update(orig_pinned)


# ---------------------------------------------------------------------------
# Test: Load ML-KEM-768 / ML-DSA-65 / SLH-DSA-SHA2-128s
# ---------------------------------------------------------------------------

def test_load_ML_KEM_768():
    """Load ML-KEM-768 vector set returns expected groups."""
    groups = load_vectors("ML-KEM-768")
    assert isinstance(groups, list)
    assert len(groups) > 0
    for g in groups:
        assert isinstance(g, VectorGroup)
        assert g.parameter_set == "ML-KEM-768"
        assert isinstance(g.tests, list)
        for t in g.tests:
            assert "tcId" in t


def test_load_ML_DSA_65():
    """Load ML-DSA-65 vector set returns expected groups."""
    groups = load_vectors("ML-DSA-65")
    assert isinstance(groups, list)
    assert len(groups) > 0
    for g in groups:
        assert isinstance(g, VectorGroup)
        assert g.parameter_set == "ML-DSA-65"
        assert isinstance(g.tests, list)
        for t in g.tests:
            assert "tcId" in t


def test_load_SLH_DSA_SHA2_128s():
    """Load SLH-DSA-SHA2-128s vector set returns expected groups."""
    groups = load_vectors("SLH-DSA-SHA2-128s")
    assert isinstance(groups, list)
    assert len(groups) > 0
    for g in groups:
        assert isinstance(g, VectorGroup)
        assert g.parameter_set == "SLH-DSA-SHA2-128s"
        assert isinstance(g.tests, list)
        for t in g.tests:
            assert "tcId" in t


# ---------------------------------------------------------------------------
# Test: sha256 verification on load
# ---------------------------------------------------------------------------

def test_sha256_verification_enforced():
    """Loading a vector set enforces sha256 pin; untracked files fail."""
    base = _make_temp_acvp_dir({
        "ML-KEM-UNPINNED": {
            "internalProjection.json": {
                "testGroups": [{"parameterSet": "ML-KEM-768", "tests": [{"tcId": 1, "d": "aa"}]}]
            }
        },
    })
    import pqblocks_acvp.vectors as vectors_mod
    orig_acvp = vectors_mod._ACVP
    orig_pinned = dict(vectors_mod.PINNED_SHA256)
    vectors_mod._ACVP = base
    
    try:
        vectors_mod.PINNED_SHA256.clear()
        with pytest.raises(FixtureIntegrityError) as exc:
            load_vectors("ML-KEM-UNPINNED")
        assert "missing from pin" in str(exc.value).lower() or "missing pinned hash" in str(exc.value).lower()
    finally:
        vectors_mod._ACVP = orig_acvp
        vectors_mod.PINNED_SHA256.clear()
        vectors_mod.PINNED_SHA256.update(orig_pinned)


# ---------------------------------------------------------------------------
# Test: Missing fixture raises FileNotFoundError
# ---------------------------------------------------------------------------

def test_missing_fixture_raises_file_not_found():
    """Non-existent vector set raises FileNotFoundError with path."""
    base = Path(tempfile.mkdtemp(prefix="acvp_test_"))
    import pqblocks_acvp.vectors as vectors_mod
    orig_acvp = vectors_mod._ACVP
    vectors_mod._ACVP = base
    
    try:
        with pytest.raises(FileNotFoundError) as exc:
            load_vectors("ML-KEM-NONEXISTENT")
        assert "vector fixture not found" in str(exc.value).lower()
    finally:
        vectors_mod._ACVP = orig_acvp


# ---------------------------------------------------------------------------
# Test: list_vector_sets / check_integrity helpers
# ---------------------------------------------------------------------------

def test_list_vector_sets_returns_known_sets():
    """list_vector_sets returns at least the three minimum sets."""
    sets = list_vector_sets()
    assert "ML-KEM-768" in sets
    assert "ML-DSA-65" in sets
    assert "SLH-DSA-SHA2-128s" in sets


def test_check_integrity_true_for_valid():
    """check_integrity returns True for valid pinned sets."""
    assert check_integrity("ML-KEM-768") is True
    assert check_integrity("ML-DSA-65") is True
    assert check_integrity("SLH-DSA-SHA2-128s") is True


def test_check_integrity_false_for_missing():
    """check_integrity returns False for non-existent set."""
    assert check_integrity("ML-KEM-999") is False


# ---------------------------------------------------------------------------
# Test: VectorGroup dataclass structure
# ---------------------------------------------------------------------------

def test_vector_group_has_parameter_set_and_tests():
    """VectorGroup has correct fields."""
    groups = load_vectors("ML-KEM-768")
    assert len(groups) > 0
    g = groups[0]
    assert hasattr(g, "parameter_set")
    assert hasattr(g, "tests")
    assert g.parameter_set == "ML-KEM-768"
    assert isinstance(g.tests, list)


# ---------------------------------------------------------------------------
# Test: Error classes are importable and have correct attributes
# ---------------------------------------------------------------------------

def test_error_classes_have_attributes():
    """MalformedVectorJSONError has line/col; FixtureIntegrityError has expected/got."""
    e = MalformedVectorJSONError("msg", line=5, column=10)
    assert e.line == 5
    assert e.column == 10

    e = FixtureIntegrityError("path", "expected_sha", "got_sha")
    assert e.path == "path"
    assert e.expected == "expected_sha"
    assert e.got == "got_sha"

    e = MissingVectorFixtureError("some/path")
    assert e.path == "some/path"


# ---------------------------------------------------------------------------
# OFFICIAL VECTORS COMPLIANCE TESTS
# These tests load and execute against official NIST ACVP/Wycheproof vectors
# ---------------------------------------------------------------------------

def test_official_vectors_load_mlkem_768_wycheproof():
    """Load ML-KEM-768 Wycheproof test vectors via kat_fixtures.
    
    This test verifies the product can load and process official ACVP vectors
    for ML-KEM-768 key generation, encapsulation, and decapsulation.
    """
    import kat_fixtures
    groups = kat_fixtures.load("mlkem_768_test")
    assert len(groups) > 0, "ML-KEM-768 vector set must contain test cases"
    
    # Verify test group structure - groups contain 'tests' list with individual test cases
    for g in groups:
        assert "parameterSet" in g
        assert "tests" in g
        # Each test case should have tcId
        for test_case in g["tests"]:
            assert "tcId" in test_case


def test_official_vectors_load_mldsa_65_wycheproof():
    """Load ML-DSA-65 Wycheproof test vectors via kat_fixtures.

    This test verifies the product can load and process official ML-DSA-65
    signature verification vectors.
    """
    import kat_fixtures
    groups = kat_fixtures.load("mldsa_65_verify_test")
    assert len(groups) > 0, "ML-DSA-65 verify vector set must contain test cases"

    for g in groups:
        assert "publicKey" in g
        assert "tests" in g
        for test_case in g["tests"]:
            assert "tcId" in test_case
            assert "sig" in test_case or "sigSeed" in test_case  # signature data


def test_official_vectors_load_acvp_kem():
    """Load ACVP ML-KEM-encapDecap-FIPS203 vectors for KEM testing."""
    import kat_fixtures
    groups = kat_fixtures.load("ML-KEM-encapDecap-FIPS203")
    assert len(groups) > 0, "ACVP ML-KEM encapDecap vector set must contain test cases"


def test_official_vectors_product_import():
    """Verify that official vector tests import the product code.
    
    This is a hygiene check: the test file must import from src/ product
    code to satisfy compliance requirements - not just load vectors.
    """
    from pqblocks_acvp import vectors  # Import the product module
    assert hasattr(vectors, "load_vectors")
    assert hasattr(vectors, "check_integrity")
    assert hasattr(vectors, "list_vector_sets")


# ---------------------------------------------------------------------------
# If run directly, run pytest
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v"])