"""Tests for Independent Re-execution Framework."""

import pytest
from pqblocks_acvp.runner import build_golden_session
from pqblocks_acvp.g7_framework import G7ReexecutionFramework
from pqblocks_acvp.adapters.reference import ReferencePQCAdapter
from pqblocks_acvp.adapters.go_bridge import GoBridgeAdapter


def test_g7_independent_reexecution():
    session = build_golden_session()
    cases = session.groups[0].test_cases

    framework = G7ReexecutionFramework(
        primary_adapter=ReferencePQCAdapter(),
        secondary_adapter=GoBridgeAdapter(),
    )

    # Sample 50% for test purposes
    outcome = framework.verify_sample(cases, sample_ratio=0.5, seed=42)
    assert outcome.total_cells == 4
    assert outcome.sample_size >= 1
    assert outcome.agreement_rate >= 0.0
    assert len(outcome.details) == outcome.sample_size
