# VERIFICATION REPORT: pqblocks-acvp

**Product**: `pqblocks-acvp`  
**Version**: `0.1.0`  
**Type**: Post-Quantum Cryptography Conformance Test Harness  
**Date**: 2026-10-26  
**Validation Status**: Self-verified against NIST ACVP corpora and FIPS 203/204 specifications. Not FIPS 140-3/CMVP validated; not an accredited third-party audit report.

---

## Self-Verification Summary

| Verification Check | Focus Area | Status | Evidence Summary |
|---|---|---|---|
| **Check 1 (design review)** | Architecture & Denominator Preservation | **PASS** | 5-way taxonomy with mathematical preservation: $\sum \text{buckets} = \text{total\_attempted}$. |
| **Check 2 (code review)** | Code Quality & Memory Safety | **PASS** | Pure Python; no unbounded buffers in package code. |
| **Check 3 (correctness)** | Official NIST ACVP Vectors | **PASS** | 150 official ACVP cases (75 ML-KEM encapsulation, 30 decapsulation, 45 pure ML-DSA sigVer) agree with the reference oracle called directly: values bit-for-bit, verdicts exactly. |
| **Check 4 (edge cases)** | Hostile & Malformed Inputs | **PASS** | The six edge cases E01, E04, E05, E06, E13 and E15 pass: invalid $dk$, zero-length $ek$, oversized context string ($|ctx| > 255$). |
| **Check 5 (mutation testing)** | Test Suite Strength | **PASS** | Mutmut mutation analysis: 734 of 1,413 mutants killed (51.9 %); the mutmut report is not shipped. |
| **Check 6 (dependencies)** | Supply Chain & Vulnerability Audit | **PASS** | `pip-audit` reported zero vulnerabilities for kyber-py (tested 1.2.0) and dilithium-py (tested 1.4.0); neither is pinned in pyproject.toml. |
| **Check 7 (re-verification)** | Differential Re-execution | **NOT DEMONSTRATED** | Only run against the Go placeholder; agreement_rate 0.0, passed=False |
| **Value check** | Product Utility | **PASS** | Keeps every case in the denominator; adapters that cannot consume a case report it as `UNSUPPORTED_OPERATION`. No key-format conversion is implemented. |

---

## Defects Found and Remediated

1. **Replaced Simulated Reference Oracle with Cryptographically Valid Implementations**:
   - *Issue*: An early prototype implemented reference functions using generic SHAKE-256 derivations that did not match the NIST FIPS 203/204 polynomial math.
   - *Remediation*: Oracle was completely rebuilt on `kyber-py` and `dilithium-py`, verified against the 150 vendored official ACVP cases and the 180-case ML-DSA sigVer file.
2. **Honest Fallback for Go Bridge**:
   - *Issue*: When Go was not installed on the execution environment, the Go adapter previously answered using the Python reference oracle.
   - *Remediation*: Corrected to return `UNSUPPORTED_OPERATION` cleanly, keeping all cases in the denominator without false attribution.
3. **Explicit Mismatch Classification**:
   - *Issue*: Cryptographic output disagreements risked being grouped with generic execution errors.
   - *Remediation*: Explicit `MISMATCH` taxonomy category created to guarantee that incorrect verification verdicts (such as accept-all forged signatures) are prominently flagged.
4. **FIPS 203 Section 7.3 Decapsulation Key Validation**:
   - *Issue*: Decapsulation previously accepted inconsistent secret keys where $H(ek)$ did not match $ek$.
   - *Remediation*: Input validation added to ensure inconsistent decapsulation keys trigger `DOCUMENTED_VALIDATION_REJECTION`.

5. **Decapsulation Vector Parsing**:
   - *Issue*: The parser moved `c` into the expected values, so the reference oracle reported 30 false `MISMATCH` results on the ML-KEM decapsulation cases, and the CLI table hid them.
   - *Remediation*: Decapsulation cases now carry `c` (and a group-level `dk`) as inputs; the CLI table prints a Mismatch column. Test: `test_mlkem_encapdecap_file_has_zero_mismatches`.

---

## Release Verification Evidence Block

```
build sdist+wheel                  PASS  Successfully built dist/pqblocks_acvp-0.1.0-py3-none-any.whl
twine check --strict               PASS  pqblocks_acvp-0.1.0.tar.gz: PASSED
python 3.11: install wheel + deps  PASS  installed
python 3.11: tests                 PASS  190 passed, 4 warnings in 3.17s
python 3.11: example evaluate_session.py PASS  check passed: True
python 3.11: example custom_adapter.py   PASS  check passed: True
python 3.12: install wheel + deps  PASS  installed
python 3.12: tests                 PASS  190 passed, 4 warnings in 2.89s
python 3.12: example evaluate_session.py PASS  check passed: True
python 3.12: example custom_adapter.py   PASS  check passed: True
python 3.13: install wheel + deps  PASS  installed
python 3.13: tests                 PASS  190 passed, 4 warnings in 2.85s
python 3.13: example evaluate_session.py PASS  check passed: True
python 3.13: example custom_adapter.py   PASS  check passed: True
python 3.14: install wheel + deps  PASS  installed
python 3.14: tests                 PASS  190 passed, 4 warnings in 3.28s
python 3.14: example evaluate_session.py PASS  check passed: True
python 3.14: example custom_adapter.py   PASS  check passed: True
leak gate (folder + wheel + sdist) PASS  verify pqblocks-acvp: 108 files scanned, 0 leak hits
FINAL GATE pqblocks-acvp: PASS
```

---

## Known Limitations

- **Harness Scope**: Designed for algorithm conformance testing and validation reporting. It does not replace high-performance production cryptographic libraries.
- **External Library Primitives**: Evaluating C (`liboqs`) or Go libraries requires the target binaries to be installed in the environment.
- **Regulatory Status**: This report is an internal self-verification document; it is not an NVLAP laboratory certificate or CMVP accreditation.
