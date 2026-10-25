"""The reference oracle against the published NIST ACVP corpus.

Everything this product reports is "implementation X agrees / disagrees with
the reference". The oracle itself is held to the official NIST test vectors here.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vectors_loader
import pytest

from pqblocks_acvp.reference import MLDSAReferenceOracle, MLKEMReferenceOracle


def _groups(name):
    return [g for g in vectors_loader.load(name) if not g["_source"].endswith("-tr1")]


def _cases(name, function):
    return [(g["parameterSet"], t) for g in _groups(name) if g.get("function") == function
            for t in g["tests"]]


@pytest.mark.parametrize("ps,t", _cases("ML-KEM-encapDecap-FIPS203", "encapsulation"))
def test_mlkem_encapsulation_matches_nist(ps, t):
    c, k = MLKEMReferenceOracle.encapsulate(ps, t["ek"], t["m"])
    assert (c.upper(), k.upper()) == (t["c"].upper(), t["k"].upper())


@pytest.mark.parametrize("ps,t", _cases("ML-KEM-encapDecap-FIPS203", "decapsulation"))
def test_mlkem_decapsulation_matches_nist(ps, t):
    assert MLKEMReferenceOracle.decapsulate(ps, t["dk"], t["c"]).upper() == t["k"].upper()


SIGVER_PURE = [(g["parameterSet"], t) for g in _groups("ML-DSA-sigVer-FIPS204")
               if g.get("signatureInterface") == "external" and g.get("preHash") == "pure"
               for t in g["tests"]]


@pytest.mark.parametrize("ps,t", SIGVER_PURE)
def test_mldsa_verify_matches_nist(ps, t):
    got = MLDSAReferenceOracle.verify(ps, t["pk"], t["message"], t["signature"], t.get("context", ""))
    assert got is bool(t["testPassed"]), t.get("reason")


def test_the_corpus_was_actually_used():
    # a parametrize over an empty list would pass silently
    assert len(_cases("ML-KEM-encapDecap-FIPS203", "encapsulation")) >= 60
    assert len(SIGVER_PURE) >= 30


def test_full_official_sigver_file_scores_without_mismatch():
    # review HIGH: internal/preHash groups were verified as pure and got wrong verdicts;
    # sigVer groups have no `function`, so the parser sent them down the KEM path
    import json
    from pqblocks_acvp.adapters.reference import ReferencePQCAdapter
    from pqblocks_acvp.harness import ConformanceHarness
    from pqblocks_acvp.parser import ACVPParser
    path = [s for k, n, s in vectors_loader.sets("ML-DSA-sigVer-FIPS204") if n == "ML-DSA-sigVer-FIPS204"][0]
    session = ACVPParser.parse_dict(json.load(open(path)))
    rep = list(ConformanceHarness([ReferencePQCAdapter()]).run_session(session).values())[0]
    assert rep.mismatches == 0 and rep.adapter_errors == 0
    assert rep.passed + rep.documented_validation_rejections >= 30
    assert rep.denominator_verified
