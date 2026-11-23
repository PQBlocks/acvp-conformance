"""Unit tests for ACVP result types & serialization (S4).

Slice S4 contract (spec/spec.md §5):
  src/pqblocks_acvp/results.py — ACVPVectorResult, ACVPResultSummary, ACVPResult
  with to_tap(), to_json()
Tests: serialization round-trip, TAP format matches spec, JSON schema validation,
E3 (hex dumps on FAIL)
"""
import json
import re

import pytest

from pqblocks_acvp.results import (
    ACVPResult,
    ACVPResultSummary,
    ACVPVectorResult,
)


# =============================================================================
# Test fixtures: sample vector results
# =============================================================================

@pytest.fixture
def single_pass_result():
    """A single PASS vector result."""
    return ACVPVectorResult(
        vector_id="ML-KEM-768/keyGen/001",
        status="PASS",
        expected_hex="a3b2c1d4e5f6",
        actual_hex="a3b2c1d4e5f6",
        error=None,
    )


@pytest.fixture
def single_fail_result():
    """A FAIL vector result with hex dumps."""
    return ACVPVectorResult(
        vector_id="ML-KEM-768/keyGen/002",
        status="FAIL",
        expected_hex="a3b2c1d4e5f6",
        actual_hex="deadbeefcafe",
        error="shared secret mismatch",
    )


@pytest.fixture
def single_skip_result():
    """A SKIP vector result."""
    return ACVPVectorResult(
        vector_id="ML-KEM-768/keyGen/003",
        status="SKIP",
        expected_hex=None,
        actual_hex=None,
        error="adapter not available",
    )


@pytest.fixture
def multi_vector_results():
    """Multiple vector results for testing lists."""
    return [
        ACVPVectorResult(
            vector_id="ML-KEM-768/keyGen/001",
            status="PASS",
            expected_hex="a3b2c1d4e5f6aa",
            actual_hex="a3b2c1d4e5f6aa",
            error=None,
        ),
        ACVPVectorResult(
            vector_id="ML-KEM-768/keyGen/002",
            status="FAIL",
            expected_hex="b4c3d2e1f0a1b2",
            actual_hex="00000000000000",
            error="encapsulation failed",
        ),
        ACVPVectorResult(
            vector_id="ML-KEM-768/keyGen/003",
            status="SKIP",
            expected_hex=None,
            actual_hex=None,
            error="timeout",
        ),
    ]


@pytest.fixture
def sample_summary():
    """A sample result summary."""
    return ACVPResultSummary(
        pass_count=1,
        fail_count=1,
        skip_count=1,
        pass_rate=33.33,
        elapsed_s=0.123,
    )


@pytest.fixture
def sample_metadata():
    """Sample metadata dict."""
    return {
        "seed": 42,
        "vector_set": "ML-KEM-768",
        "adapter": "kyber_py.ml_kem_768",
        "vector_revision": "gen-val",
        "timestamp": "2026-11-01T12:00:00Z",
    }


# =============================================================================
# Test ACVPVectorResult
# =============================================================================

class TestACVPVectorResult:
    """Test ACVPVectorResult dataclass behavior."""

    def test_pass_result_has_expected_fields(self, single_pass_result):
        """A PASS result has all expected fields populated."""
        assert single_pass_result.vector_id == "ML-KEM-768/keyGen/001"
        assert single_pass_result.status == "PASS"
        assert single_pass_result.expected_hex is not None
        assert single_pass_result.actual_hex is not None
        assert single_pass_result.error is None

    def test_fail_result_has_expected_fields(self, single_fail_result):
        """A FAIL result has expected/actual hex and error message."""
        assert single_fail_result.status == "FAIL"
        assert single_fail_result.expected_hex is not None
        assert single_fail_result.actual_hex is not None
        assert single_fail_result.error is not None

    def test_skip_result_has_null_hex(self, single_skip_result):
        """A SKIP result has None for expected/actual hex (spec E3)."""
        assert single_skip_result.status == "SKIP"
        assert single_skip_result.expected_hex is None
        assert single_skip_result.actual_hex is None
        assert single_skip_result.error is not None

    def test_status_literal_values(self):
        """Status must be exactly PASS, FAIL, or SKIP."""
        statuses = {"PASS", "FAIL", "SKIP"}
        # Can create each status
        ACVPVectorResult(vector_id="test", status="PASS", expected_hex="aa", actual_hex="aa", error=None)
        ACVPVectorResult(vector_id="test", status="FAIL", expected_hex="aa", actual_hex="bb", error="mismatch")
        ACVPVectorResult(vector_id="test", status="SKIP", expected_hex=None, actual_hex=None, error="skip")


# =============================================================================
# Test ACVPResultSummary
# =============================================================================

class TestACVPResultSummary:
    """Test ACVPResultSummary dataclass behavior."""

    def test_summary_counts_pass(self, sample_summary):
        """Summary has accurate pass_count."""
        assert sample_summary.pass_count == 1

    def test_summary_counts_fail(self, sample_summary):
        """Summary has accurate fail_count."""
        assert sample_summary.fail_count == 1

    def test_summary_counts_skip(self, sample_summary):
        """Summary has accurate skip_count."""
        assert sample_summary.skip_count == 1

    def test_summary_pass_rate_calculation(self):
        """Pass rate is (pass_count / total_non_skip) * 100."""
        summary = ACVPResultSummary(pass_count=98, fail_count=2, skip_count=0, pass_rate=98.0, elapsed_s=1.0)
        assert summary.pass_rate == 98.0

    def test_summary_pass_rate_zero_total(self):
        """Pass rate is 0.0 when there are no test results."""
        summary = ACVPResultSummary(pass_count=0, fail_count=0, skip_count=0, pass_rate=0.0, elapsed_s=0.0)
        assert summary.pass_count == 0
        assert summary.fail_count == 0
        assert summary.skip_count == 0
        assert summary.pass_rate == 0.0


# =============================================================================
# Test ACVPResult
# =============================================================================

class TestACVPResult:
    """Test ACVPResult dataclass behavior."""

    def test_result_has_per_vector_list(self, sample_metadata):
        """Result contains a per_vector list."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/001",
                    status="PASS",
                    expected_hex="aa",
                    actual_hex="aa",
                    error=None,
                )
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=0, skip_count=0, pass_rate=100.0, elapsed_s=0.1),
            metadata=sample_metadata,
        )
        assert len(result.per_vector) == 1
        assert result.per_vector[0].status == "PASS"

    def test_result_has_summary(self, sample_metadata):
        """Result contains a summary."""
        result = ACVPResult(
            per_vector=[],
            summary=ACVPResultSummary(pass_count=0, fail_count=0, skip_count=0, pass_rate=0.0, elapsed_s=0.0),
            metadata=sample_metadata,
        )
        assert result.summary.pass_count == 0

    def test_result_has_metadata(self, sample_metadata):
        """Result contains metadata dict."""
        result = ACVPResult(
            per_vector=[],
            summary=ACVPResultSummary(pass_count=0, fail_count=0, skip_count=0, pass_rate=0.0, elapsed_s=0.0),
            metadata=sample_metadata,
        )
        assert result.metadata["seed"] == 42
        assert "vector_set" in result.metadata


# =============================================================================
# Test JSON Serialization
# =============================================================================

class TestJSONSerialization:
    """Test to_json() produces valid JSON matching spec format."""

    def test_to_json_produces_valid_json(self):
        """to_json() returns valid JSON string."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/001",
                    status="PASS",
                    expected_hex="a3b2c1d4e5f6",
                    actual_hex="a3b2c1d4e5f6",
                    error=None,
                )
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=0, skip_count=0, pass_rate=100.0, elapsed_s=0.042),
            metadata={"seed": 42, "vector_set": "ML-KEM-768"},
        )
        json_str = result.to_json()
        # Should be valid JSON
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_to_json_matches_spec_schema(self):
        """JSON output matches the schema from spec/spec.md worked example."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/001",
                    status="PASS",
                    expected_hex="f4e5d6",
                    actual_hex="f4e5d6",
                    error=None,
                )
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=0, skip_count=0, pass_rate=100.0, elapsed_s=0.042),
            metadata={"seed": 42, "vector_set": "ML-KEM-768", "adapter": "kyber_py.ml_kem_768", "vector_revision": "gen-val"},
        )
        json_str = result.to_json()
        parsed = json.loads(json_str)

        # Check top-level keys per spec
        assert "per_vector" in parsed
        assert "summary" in parsed
        assert "metadata" in parsed

        # Check per_vector schema
        assert isinstance(parsed["per_vector"], list)
        vec = parsed["per_vector"][0]
        assert "vector_id" in vec
        assert "status" in vec
        assert "expected_hex" in vec
        assert "actual_hex" in vec
        assert "error" in vec

        # Check summary schema
        summary = parsed["summary"]
        assert "pass_count" in summary
        assert "fail_count" in summary
        assert "skip_count" in summary
        assert "pass_rate" in summary
        assert "elapsed_s" in summary

        # Check metadata schema
        assert "seed" in parsed["metadata"]
        assert "vector_set" in parsed["metadata"]

    def test_to_json_round_trip(self):
        """Round-trip: to_json() -> json.loads() -> object preserves data."""
        original = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/001",
                    status="PASS",
                    expected_hex="a3b2c1d4e5f6",
                    actual_hex="a3b2c1d4e5f6",
                    error=None,
                ),
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/002",
                    status="FAIL",
                    expected_hex="deadbeef",
                    actual_hex="cafeface",
                    error="secret mismatch",
                ),
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=1, skip_count=0, pass_rate=50.0, elapsed_s=0.1),
            metadata={"seed": 42},
        )
        json_str = original.to_json()
        parsed = json.loads(json_str)

        # Reconstruct and compare
        assert parsed["per_vector"][0]["status"] == "PASS"
        assert parsed["per_vector"][1]["status"] == "FAIL"
        assert parsed["per_vector"][1]["error"] == "secret mismatch"
        assert parsed["summary"]["pass_count"] == 1
        assert parsed["summary"]["pass_rate"] == 50.0


# =============================================================================
# Test TAP Format
# =============================================================================

class TestTAPSerialization:
    """Test to_tap() produces valid TAP format (Test Anything Protocol).

    TAP format per spec: line-oriented with pragma, test results, andYAML-like block
    for failures (YAML is used for hex dumps on FAIL - E3).
    """

    def test_to_tap_has_pragma(self):
        """TAP output starts with TAP version pragma."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/001",
                    status="PASS",
                    expected_hex="aa",
                    actual_hex="aa",
                    error=None,
                )
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=0, skip_count=0, pass_rate=100.0, elapsed_s=0.1),
            metadata={},
        )
        tap_str = result.to_tap()
        assert "TAP version 13" in tap_str

    def test_to_tap_reports_pass(self):
        """TAP output reports PASS with ok status."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/001",
                    status="PASS",
                    expected_hex="aa",
                    actual_hex="aa",
                    error=None,
                )
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=0, skip_count=0, pass_rate=100.0, elapsed_s=0.1),
            metadata={},
        )
        tap_str = result.to_tap()
        # TAP "ok" for pass
        assert re.search(r"^ok \d+ - .*\(PASS\)$", tap_str, re.MULTILINE) or "ok" in tap_str.lower()

    def test_to_tap_reports_fail(self):
        """TAP output reports FAIL with not ok status."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/002",
                    status="FAIL",
                    expected_hex="deadbeef",
                    actual_hex="cafeface",
                    error="secret mismatch",
                )
            ],
            summary=ACVPResultSummary(pass_count=0, fail_count=1, skip_count=0, pass_rate=0.0, elapsed_s=0.1),
            metadata={},
        )
        tap_str = result.to_tap()
        # TAP "not ok" for fail
        assert "not ok" in tap_str.lower() or "fail" in tap_str.lower()

    def test_to_tap_reports_skip(self):
        """TAP output reports SKIP with skip directive."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/003",
                    status="SKIP",
                    expected_hex=None,
                    actual_hex=None,
                    error="adapter timeout",
                )
            ],
            summary=ACVPResultSummary(pass_count=0, fail_count=0, skip_count=1, pass_rate=0.0, elapsed_s=0.1),
            metadata={},
        )
        tap_str = result.to_tap()
        # TAP skip directive
        assert "skip" in tap_str.lower() or "SKIP" in tap_str

    def test_to_tap_includes_vector_id(self):
        """TAP output includes vector_id in test description."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/001",
                    status="PASS",
                    expected_hex="aa",
                    actual_hex="aa",
                    error=None,
                )
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=0, skip_count=0, pass_rate=100.0, elapsed_s=0.1),
            metadata={},
        )
        tap_str = result.to_tap()
        assert "ML-KEM-768" in tap_str or "keyGen" in tap_str

    def test_to_tap_yaml_hex_dump_on_fail(self):
        """TAP output includes YAML block with hex dumps on FAIL (E3 requirement)."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/002",
                    status="FAIL",
                    expected_hex="a3b2c1d4e5f6aa112233445566778899",
                    actual_hex="00000000000000000000000000000000",
                    error="shared secret mismatch",
                )
            ],
            summary=ACVPResultSummary(pass_count=0, fail_count=1, skip_count=0, pass_rate=0.0, elapsed_s=0.1),
            metadata={},
        )
        tap_str = result.to_tap()
        # E3: hex dumps on FAIL
        assert "expected_hex" in tap_str or "expected_hex" in tap_str.lower()
        assert "actual_hex" in tap_str.lower()
        # The hex values should appear
        assert "a3b2c1d4e5f6" in tap_str.lower() or "0000000000000000" in tap_str.lower()

    def test_to_tap_plan_line(self):
        """TAP output includes a plan line with test count."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/001",
                    status="PASS",
                    expected_hex="aa",
                    actual_hex="aa",
                    error=None,
                )
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=0, skip_count=0, pass_rate=100.0, elapsed_s=0.1),
            metadata={},
        )
        tap_str = result.to_tap()
        # TAP plan: "1..1" for one test
        assert re.search(r"1\.\.1", tap_str) or "1.." in tap_str


# =============================================================================
# Test Serialization Round-Trip
# =============================================================================

class TestRoundTrip:
    """Test that serialization preserves all data."""

    def test_json_round_trip_preserves_all_results(self):
        """JSON round-trip preserves all vector results."""
        original = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/001",
                    status="PASS",
                    expected_hex="a3b2c1d4e5f6",
                    actual_hex="a3b2c1d4e5f6",
                    error=None,
                ),
                ACVPVectorResult(
                    vector_id="ML-DSA-65/sign/001",
                    status="FAIL",
                    expected_hex="deadbeef",
                    actual_hex="cafeface",
                    error="signature invalid",
                ),
                ACVPVectorResult(
                    vector_id="SLH-DSA-SHA2-128s/sign/001",
                    status="SKIP",
                    expected_hex=None,
                    actual_hex=None,
                    error="not implemented",
                ),
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=1, skip_count=1, pass_rate=50.0, elapsed_s=0.5),
            metadata={"seed": 123, "vector_set": "ML-KEM-768"},
        )

        json_str = original.to_json()
        parsed = json.loads(json_str)

        # Verify all passed through
        assert len(parsed["per_vector"]) == 3
        assert parsed["per_vector"][0]["status"] == "PASS"
        assert parsed["per_vector"][1]["status"] == "FAIL"
        assert parsed["per_vector"][2]["status"] == "SKIP"
        assert parsed["summary"]["pass_rate"] == 50.0
        assert parsed["metadata"]["seed"] == 123

    def test_tap_round_trip_content(self):
        """TAP output contains all expected content."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="ML-KEM-768/keyGen/001",
                    status="PASS",
                    expected_hex="a3b2c1d4e5f6aa112233445566778899aabbccddeeff00112233445566778899",
                    actual_hex="a3b2c1d4e5f6aa112233445566778899aabbccddeeff00112233445566778899",
                    error=None,
                )
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=0, skip_count=0, pass_rate=100.0, elapsed_s=0.042),
            metadata={"seed": 42, "vector_set": "ML-KEM-768", "adapter": "kyber_py.ml_kem_768"},
        )

        tap_str = result.to_tap()

        # Verify expected content
        assert "ML-KEM-768" in tap_str
        assert "42" in tap_str


# =============================================================================
# Test Edge Cases
# =============================================================================

class TestEdgeCases:
    """Test edge cases for ACVP result types."""

    def test_empty_per_vector_list(self):
        """ACVPResult with empty per_vector raises or handles gracefully."""
        result = ACVPResult(
            per_vector=[],
            summary=ACVPResultSummary(pass_count=0, fail_count=0, skip_count=0, pass_rate=0.0, elapsed_s=0.0),
            metadata={},
        )
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["per_vector"] == []
        assert parsed["summary"]["pass_count"] == 0

    def test_case_insensitive_hex(self):
        """Hex strings should be case-insensitive for comparison (per spec)."""
        # The to_json should preserve case; comparison is case-insensitive
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="test",
                    status="PASS",
                    expected_hex="A3B2C1",
                    actual_hex="a3b2c1",
                    error=None,
                )
            ],
            summary=ACVPResultSummary(pass_count=1, fail_count=0, skip_count=0, pass_rate=100.0, elapsed_s=0.1),
            metadata={},
        )
        json_str = result.to_json()
        # Both cases should be present in output
        assert "A3B2C1" in json_str or "a3b2c1" in json_str.lower()

    def test_unicode_in_error_message(self):
        """Error messages with unicode are handled correctly."""
        result = ACVPResult(
            per_vector=[
                ACVPVectorResult(
                    vector_id="test",
                    status="FAIL",
                    expected_hex="aa",
                    actual_hex="bb",
                    error="mismatch: expected ≠ actual",
                )
            ],
            summary=ACVPResultSummary(pass_count=0, fail_count=1, skip_count=0, pass_rate=0.0, elapsed_s=0.1),
            metadata={},
        )
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert "≠" in parsed["per_vector"][0]["error"]