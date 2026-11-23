"""ACVP result types & serialization (S4).

Slice S4 contract (spec/spec.md §5):
  ACVPVectorResult, ACVPResultSummary, ACVPResult with to_tap(), to_json()
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Literal


@dataclass
class ACVPVectorResult:
    """Result for a single ACVP test vector.

    Fields per spec/spec.md §1:
    - vector_id: e.g. "ML-KEM-768/keyGen/001"
    - status: PASS | FAIL | SKIP
    - expected_hex: expected output (hex), None for SKIP
    - actual_hex: actual output (hex), None for SKIP
    - error: error message if status == "FAIL" or "SKIP"
    """
    vector_id: str
    status: Literal["PASS", "FAIL", "SKIP"]
    expected_hex: str | None = None
    actual_hex: str | None = None
    error: str | None = None


@dataclass
class ACVPResultSummary:
    """Summary statistics for an ACVP run.

    Fields per spec/spec.md §1:
    - pass_count: number of PASS results
    - fail_count: number of FAIL results
    - skip_count: number of SKIP results
    - pass_rate: pass_count / (pass_count + fail_count) * 100
    - elapsed_s: total elapsed time in seconds
    """
    pass_count: int = 0
    fail_count: int = 0
    skip_count: int = 0
    pass_rate: float = 0.0
    elapsed_s: float = 0.0


@dataclass
class ACVPResult:
    """Complete ACVP KAT run result.

    Fields per spec/spec.md §1:
    - per_vector: list of ACVPVectorResult
    - summary: ACVPResultSummary
    - metadata: dict with seed, vector_set, adapter, vector_revision, timestamp
    """
    per_vector: list[ACVPVectorResult]
    summary: ACVPResultSummary
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to JSON string matching spec schema."""
        # Convert dataclasses to dicts
        data = {
            "per_vector": [asdict(v) for v in self.per_vector],
            "summary": asdict(self.summary),
            "metadata": self.metadata,
        }
        return json.dumps(data, separators=(",", ":"))

    def to_tap(self) -> str:
        """Serialize to TAP (Test Anything Protocol) format.

        TAP version 13 with:
        - Plan line (1..N)
        - Per-vector ok/not ok lines with description
        - YAML diagnostic blocks for FAIL with hex dumps (E3)
        - Metadata summary at end
        """
        lines = []
        n = len(self.per_vector)

        # TAP version pragma
        lines.append("TAP version 13")

        # Plan line
        lines.append(f"1..{n}")

        # Per-vector results
        for i, vec in enumerate(self.per_vector, 1):
            if vec.status == "PASS":
                lines.append(f"ok {i} - {vec.vector_id} (PASS)")
            elif vec.status == "FAIL":
                lines.append(f"not ok {i} - {vec.vector_id} (FAIL)")
                # YAML diagnostic block for hex dumps (E3)
                lines.append("  ---")
                if vec.expected_hex is not None:
                    lines.append(f"    expected_hex: {vec.expected_hex}")
                if vec.actual_hex is not None:
                    lines.append(f"    actual_hex: {vec.actual_hex}")
                if vec.error is not None:
                    # Escape YAML special chars in error
                    escaped_error = vec.error.replace(":", "\\:").replace("\n", "\\n")
                    lines.append(f"    error: {escaped_error}")
                lines.append("  ...")
            elif vec.status == "SKIP":
                lines.append(f"ok {i} - {vec.vector_id} (SKIP) # skip")
                if vec.error is not None:
                    lines.append("  ---")
                    escaped_error = vec.error.replace(":", "\\:").replace("\n", "\\n")
                    lines.append(f"    reason: {escaped_error}")
                    lines.append("  ...")

        # Metadata summary line
        seed = self.metadata.get("seed", "unknown")
        lines.append(f"# seed={seed}")

        return "\n".join(lines) + "\n"