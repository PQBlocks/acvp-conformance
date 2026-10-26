"""License and Compliance SPDX Reporter for PQC Libraries."""

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class LicenseEntry:
    component: str
    license_spdx: str
    provenance_url: str
    is_permissive: bool


class ComplianceReporter:
    KNOWN_COMPONENTS = [
        LicenseEntry("NIST-FIPS-203", "NIST-PD", "https://csrc.nist.gov/pubs/fips/203/final", True),
        LicenseEntry("NIST-FIPS-204", "NIST-PD", "https://csrc.nist.gov/pubs/fips/204/final", True),
        LicenseEntry("liboqs", "MIT", "https://github.com/open-quantum-safe/liboqs", True),
        LicenseEntry("pyca/cryptography", "Apache-2.0 OR BSD-3-Clause", "https://github.com/pyca/cryptography", True),
        LicenseEntry("Go-crypto", "BSD-3-Clause", "https://go.googlesource.com/crypto", True),
        LicenseEntry("Google-Wycheproof", "Apache-2.0", "https://github.com/google/wycheproof", True),
    ]

    @classmethod
    def generate_spdx_manifest(cls) -> Dict[str, Any]:
        """Generate SPDX 2.3 compliant license manifest."""
        packages = []
        all_permissive = True

        for entry in cls.KNOWN_COMPONENTS:
            if not entry.is_permissive:
                all_permissive = False
            packages.append(
                {
                    "name": entry.component,
                    "licenseConcluded": entry.license_spdx,
                    "downloadLocation": entry.provenance_url,
                    "licenseInfoFromFiles": [entry.license_spdx],
                    "copyrightText": "NOASSERTION",
                }
            )

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "documentName": "pqblocks-acvp-compliance",
            "packages": packages,
            "auditClean": all_permissive,
        }
