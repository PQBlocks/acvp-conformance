"""Tests for Conformance Harness and Denominator Preservation ()."""

import pytest
from pqblocks_acvp.runner import build_golden_session
from pqblocks_acvp.harness import ConformanceHarness
from pqblocks_acvp.adapters.reference import ReferencePQCAdapter
from pqblocks_acvp.adapters.go_bridge import GoBridgeAdapter
from pqblocks_acvp.adapters.pyca import PyCAAdapter


def test_denominator_preservation():
    session = build_golden_session()
    adapters = [ReferencePQCAdapter(), GoBridgeAdapter(), PyCAAdapter()]
    harness = ConformanceHarness(adapters)
    reports = harness.run_session(session)

    for name, report in reports.items():
        assert report.total_attempted == 4
        # Crucial check:
        assert report.denominator_verified is True
        sum_classes = (
            report.passed
            + report.documented_validation_rejections
            + report.unsupported_operations
            + report.adapter_errors
        )
        assert sum_classes == report.total_attempted
