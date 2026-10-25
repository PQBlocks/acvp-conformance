"""Tests for ACVP JSON Parser."""

import pytest
from pqblocks_acvp.parser import ACVPParser, TestCase, TestGroup, ACVPTestSession


def test_parser_basic_dict():
    data = {
        "vsId": 42,
        "algorithm": "ML-KEM",
        "testGroups": [
            {
                "tgId": 1,
                "parameterSet": "ML-KEM-768",
                "function": "encapsulation",
                "testType": "AFT",
                "tests": [
                    {"tcId": 1, "ek": "AA" * 1184, "c": "BB" * 1088, "k": "CC" * 32},
                    {"tcId": 2, "ek": "DD" * 1184, "c": "EE" * 1088, "k": "FF" * 32},
                ],
            }
        ],
    }
    session = ACVPParser.parse_dict(data)
    assert session.vsId == 42
    assert session.total_test_cases == 2
    assert len(session.groups) == 1
    assert session.groups[0].test_cases[0].tcId == 1
    assert session.groups[0].test_cases[0].expected["c"] == "BB" * 1088


def test_parser_empty_corpus():
    data = {"vsId": 99, "algorithm": "ML-KEM", "testGroups": []}
    session = ACVPParser.parse_dict(data)
    assert session.total_test_cases == 0
    assert session.compute_sha256() is not None


def test_test_case_digest():
    tc = TestCase(
        tcId=1,
        function="encapsulation",
        parameter_set="ML-KEM-768",
        inputs={"ek": "1234"},
        expected={"k": "5678"},
    )
    d1 = tc.digest
    assert len(d1) == 64
    tc2 = TestCase(
        tcId=1,
        function="encapsulation",
        parameter_set="ML-KEM-768",
        inputs={"ek": "1234"},
        expected={"k": "5678"},
    )
    assert tc2.digest == d1
