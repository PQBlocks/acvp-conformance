"""Tests for 4-Way Taxonomy Classifier."""

import pytest
from pqblocks_acvp.taxonomy import TaxonomyClassifier, TaxonomyCategory


def test_taxonomy_pass():
    cat = TaxonomyClassifier.classify(
        actual={"c": "AAAA", "k": "BBBB"},
        expected={"c": "AAAA", "k": "BBBB"},
    )
    assert cat == TaxonomyCategory.PASS


def test_taxonomy_adapter_error_mismatch():
    cat = TaxonomyClassifier.classify(
        actual={"c": "AAAA", "k": "BBBB"},
        expected={"c": "AAAA", "k": "CCCC"},
    )
    # A wrong answer is a MISMATCH, not an adapter error
    assert cat == TaxonomyCategory.MISMATCH


def test_taxonomy_unsupported_operation():
    cat = TaxonomyClassifier.classify(
        actual=None,
        expected={"c": "AAAA"},
        unsupported=True,
    )
    assert cat == TaxonomyCategory.UNSUPPORTED_OPERATION


def test_taxonomy_documented_validation_rejection():
    cat = TaxonomyClassifier.classify(
        actual={"testPassed": False},
        expected={"testPassed": False},
        validation_rejected=True,
    )
    assert cat == TaxonomyCategory.DOCUMENTED_VALIDATION_REJECTION


def test_taxonomy_crash_exit_code():
    cat = TaxonomyClassifier.classify(
        actual=None,
        expected={"c": "AAAA"},
        exit_code=139,  # SIGSEGV
        error_msg="Segmentation fault",
    )
    assert cat == TaxonomyCategory.ADAPTER_INVOCATION_ERROR


# --- verification checks: signature verification error classification ---
from pqblocks_acvp.taxonomy import TaxonomyCategory as _C, TaxonomyClassifier as _K


def test_accept_all_verifier_on_forged_signature_is_a_mismatch():
    assert _K.classify({"testPassed": True}, {"testPassed": False}) == _C.MISMATCH


def test_rejecting_a_valid_signature_is_a_mismatch_not_a_documented_rejection():
    assert _K.classify({"testPassed": False}, {"testPassed": True}, validation_rejected=True) == _C.MISMATCH


def test_correct_rejection_and_correct_acceptance():
    assert _K.classify({"testPassed": False}, {"testPassed": False}, validation_rejected=True) == \
        _C.DOCUMENTED_VALIDATION_REJECTION
    assert _K.classify({"testPassed": True}, {"testPassed": True}) == _C.PASS


def test_wrong_value_is_a_mismatch_not_an_adapter_error():
    assert _K.classify({"k": "AA"}, {"k": "BB"}) == _C.MISMATCH
