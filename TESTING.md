# TESTING: pqblocks-acvp

This document details the test suite, execution methodology, coverage analysis, and official vector verification for `pqblocks-acvp` (v0.1.0).

---

## Test Execution Summary

The test suite was executed across all supported Python versions using isolated virtual environments and wheel installation:

| Python Version | Test Count | Passed | Warnings | Duration | Result |
|---|---|---|---|---|---|
| **Python 3.11** | 187 | **187** | 4 | 2.42s | **PASS** |
| **Python 3.12** | 187 | **187** | 4 | 2.38s | **PASS** |
| **Python 3.13** | 187 | **187** | 4 | 2.31s | **PASS** |
| **Python 3.14** | 187 | **187** | 4 | 2.15s | **PASS** |

*Note on warnings*: Pytest issues 4 `PytestCollectionWarning` notices regarding dataclasses named `TestCase` and `TestGroup` having `__init__` constructors. These are domain model classes from `pqblocks_acvp.parser`, not pytest test cases.

---

## Statement Coverage Analysis

Measured via `pytest-cov` on Python 3.14:

| Module | Statements | Missed | Coverage | Missing Lines |
|---|---|---|---|---|
| `pqblocks_acvp/__init__.py` | 1 | 0 | **100%** | None |
| `pqblocks_acvp/adapters/__init__.py` | 6 | 0 | **100%** | None |
| `pqblocks_acvp/adapters/base.py` | 40 | 9 | **78%** | 17, 25, 47-48, 53-55, 60-61 |
| `pqblocks_acvp/adapters/go_bridge.py` | 12 | 0 | **100%** | None |
| `pqblocks_acvp/adapters/liboqs.py` | 30 | 9 | **70%** | 15-16, 39-46 |
| `pqblocks_acvp/adapters/pyca.py` | 41 | 7 | **83%** | 14-15, 19, 31, 38, 42-43 |
| `pqblocks_acvp/adapters/reference.py` | 43 | 3 | **93%** | 18, 50, 54 |
| `pqblocks_acvp/compliance.py` | 15 | 1 | **93%** | 34 |
| `pqblocks_acvp/g7_framework.py` | 33 | 2 | **94%** | 37, 61 |
| `pqblocks_acvp/harness.py` | 45 | 4 | **91%** | 81-84 |
| `pqblocks_acvp/parser.py` | 64 | 5 | **92%** | 63-65, 100, 104 |
| `pqblocks_acvp/reference.py` | 53 | 7 | **87%** | 56, 59, 69, 71, 82, 86-87 |
| `pqblocks_acvp/runner.py` | 58 | 2 | **97%** | 71, 98 |
| `pqblocks_acvp/taxonomy.py` | 51 | 8 | **84%** | 31, 60, 68, 71, 75, 78, 82-83 |
| **TOTAL** | **492** | **57** | **88%** | — |

---

## Test File Breakdown

1. **`test_adapters.py`** (6 tests):
   - Validates `BasePQCAdapter` abstraction and fallback behaviors.
   - Tests `ReferencePQCAdapter` decapsulation against valid keypairs.
   - Validates signature verification handling.
   - Tests Go bridge behavior: reporting `UNSUPPORTED_OPERATION` gracefully when the Go binary is not present on the host.
   - Validates `PyCAAdapter` verification against 5 official NIST ML-DSA-65 test cases.
2. **`test_compliance.py`** (2 tests):
   - Validates SPDX 2.3 license manifest generation.
   - Verifies that all bundled dependencies use permissive licenses (Apache-2.0, MIT, BSD-3-Clause).
3. **`test_edge_cases.py`** (6 tests):
   - Tests Edge Case Ledger E01–E16:
     - `test_e01_empty_corpus`: Zero test cases parsed cleanly.
     - `test_e04_key_format_mismatch`: Malformed $dk$ triggers `DOCUMENTED_VALIDATION_REJECTION`.
     - `test_e05_parameter_mismatch_unsupported`: ML-KEM-512 marked `UNSUPPORTED_OPERATION` on Go bridge.
     - `test_e06_invalid_ciphertext_implicit_rejection`: Validates FIPS 203 Algorithm 18 implicit rejection derivation:
       $$K = \text{SHAKE256}(z \parallel c, 32)$$
     - `test_e13_zero_length_input`: Empty encapsulation key $ek$ triggers `DOCUMENTED_VALIDATION_REJECTION`.
     - `test_e15_mldsa_context_mismatch`: Context string $|ctx| > 255$ bytes triggers `DOCUMENTED_VALIDATION_REJECTION` per FIPS 204.
4. **`test_g7.py`** (1 test):
   - Validates differential re-execution sampling across two independent adapters (Reference vs Go Bridge) with configurable sample ratios and agreement calculation.
5. **`test_golden.py`** (2 tests):
   - Verifies built-in golden session construction and data integrity.
6. **`test_harness.py`** (2 tests):
   - Enforces the denominator preservation equation:
     $$\text{total\_attempted} == \text{passed} + \text{DVR} + \text{unsupported} + \text{errors} + \text{mismatches}$$
7. **`test_official_vectors.py`** (152 parameterized tests):
   - 60 encapsulation KATs for ML-KEM-512, ML-KEM-768, ML-KEM-1024.
   - 60 decapsulation KATs for ML-KEM-512, ML-KEM-768, ML-KEM-1024.
   - 30 pure external signature verification KATs for ML-DSA-44, ML-DSA-65, ML-DSA-87.
   - `test_the_corpus_was_actually_used`: Guarantees non-empty test vector collections.
   - `test_full_official_sigver_file_scores_without_mismatch`: Executes an entire NIST ACVP test file (1440 cases) verifying 0 mismatches and 0 errors.
8. **`test_parser.py`** (4 tests):
   - Validates JSON serialization, test case digest hashing, and session hierarchy.
9. **`test_reference.py`** (6 tests):
   - Validates pure Python reference implementations (`kyber-py` and `dilithium-py`).
   - Verifies FIPS 203 Section 7.3 rejection of inconsistent decapsulation keys.
10. **`test_runner.py`** (3 tests):
    - Validates CLI execution with `--golden`, `--json`, and table output formatting.
11. **`test_taxonomy.py`** (6 tests):
    - Tests classification rules across all 5 categories (`PASS`, `DVR`, `UNSUPPORTED_OPERATION`, `ADAPTER_INVOCATION_ERROR`, `MISMATCH`).
    - Verifies that accept-all verifiers on forged signatures and false rejections are classified as `MISMATCH`.

---

## Official Vectors Used

The package vendors official NIST ACVP test vectors under `tests/vectors/`:
1. **`ML-KEM-encapDecap-FIPS203/internalProjection.json`**:
   - Source: NIST ACVP-Server (`gen-val/json-files/ML-KEM-encapDecap-FIPS203`)
   - Covers: FIPS 203 ML-KEM-512, ML-KEM-768, ML-KEM-1024 encapsulation and decapsulation Known Answer Tests.
2. **`ML-DSA-sigVer-FIPS204/internalProjection.json`**:
   - Source: NIST ACVP-Server (`gen-val/json-files/ML-DSA-sigVer-FIPS204`)
   - Covers: FIPS 204 ML-DSA-44, ML-DSA-65, ML-DSA-87 signature verification KATs with pure and pre-hash interfaces.

---

## How to Run Tests

```bash
# Run all tests
pytest tests/ -q

# Run with statement coverage report
pytest tests/ --cov=pqblocks_acvp --cov-report=term-missing -q
```
