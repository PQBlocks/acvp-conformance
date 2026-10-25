"""Tests for Golden Instances (GOLD-01 through GOLD-04)."""

import pytest
from pqblocks_acvp.runner import build_golden_session
from pqblocks_acvp.adapters.reference import ReferencePQCAdapter
from pqblocks_acvp.taxonomy import TaxonomyCategory


def test_golden_instances_execution():
    session = build_golden_session()
    assert session.total_test_cases == 4

    adapter = ReferencePQCAdapter()
    for tg in session.groups:
        for tc in tg.test_cases:
            res = adapter.run(tc)
            # Reference oracle runs deterministically on golden vectors
            assert res.actual_output is not None
            assert "c" in res.actual_output
            assert "k" in res.actual_output
            assert res.execution_time_ms >= 0.0
