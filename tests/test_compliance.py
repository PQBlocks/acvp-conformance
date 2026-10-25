"""Tests for SPDX 2.3 Compliance Reporter."""

from pqblocks_acvp.compliance import ComplianceReporter


def test_spdx_manifest_generation():
    manifest = ComplianceReporter.generate_spdx_manifest()
    assert manifest["spdxVersion"] == "SPDX-2.3"
    assert manifest["auditClean"] is True
    assert len(manifest["packages"]) >= 5
    names = [p["name"] for p in manifest["packages"]]
    assert "NIST-FIPS-203" in names
    assert "liboqs" in names
    assert "pyca/cryptography" in names
