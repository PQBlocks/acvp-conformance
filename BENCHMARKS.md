# BENCHMARKS: pqblocks-acvp

This document records the performance, correctness, and conformance verification results for `pqblocks-acvp` (v0.1.0).

---

## Benchmark Setup

- **Hardware**: Intel(R) Core(TM) i5-10300H CPU @ 2.50GHz (8 vCPUs), x86_64
- **OS**: Linux
- **Environment**: Python 3.11, 3.12, 3.13, 3.14 (fresh isolated virtual environments)
- **Dependencies**: `kyber-py==1.2.0`, `dilithium-py==1.4.0`, `cryptography>=47.0.0`
- **Official Corpora**: NIST ACVP-Server `gen-val/json-files` (`ML-KEM-encapDecap-FIPS203`, `ML-DSA-sigVer-FIPS204`)
- **Date**: 2026-10-25

---

## Conformance Results

### 1. Golden Session (Built-in Test Suite)

The golden session's expected values are computed by the reference oracle itself, so the Reference row is a self-consistency check, not a conformance result.

Evaluated over the standard 4-case golden validation session across all four adapter targets:

| Adapter | Total Attempted | Passed | Documented Validation Rejection (DVR) | Unsupported Operation | Adapter Errors | Mismatches | Pass Rate | Denominator Preserved |
|---|---|---|---|---|---|---|---|---|
| `Reference-FIPS-Oracle` | 4 | 4 | 0 | 0 | 0 | 0 | 100.0% | **True** |
| `Go-crypto/mlkem` (bridge) | 4 | 0 | 0 | 4 | 0 | 0 | 0.0% | **True** |
| `pyca/cryptography` | 4 | 0 | 0 | 4 | 0 | 0 | 0.0% | **True** |
| `liboqs` | 4 | 0 | 0 | 4 | 0 | 0 | 0.0% | **True** |

*Note*: In environments without Go or C liboqs installed, target adapters return `UNSUPPORTED_OPERATION` cleanly without crashing, and every case is preserved in the denominator ($0 + 0 + 4 + 0 + 0 = 4$).

### 2. Official NIST ACVP Corpus Results

Evaluated against official NIST ACVP test vectors in `tests/vectors/`:

| Standard | Test Vector Set | Cases Evaluated | Result | Classification |
|---|---|---|---|---|
| **FIPS 203** | `ML-KEM-encapDecap-FIPS203` (Encapsulation) | 75 | **75 passed, 0 failed** | `PASS` (bit-identical `c` and `k`) |
| **FIPS 203** | `ML-KEM-encapDecap-FIPS203` (Decapsulation) | 30 | **30 passed, 0 failed** | `PASS` (bit-identical shared key `k`) |
| **FIPS 204** | `ML-DSA-sigVer-FIPS204` (Pure External SigVer) | 45 | **45 passed, 0 failed** | `PASS` (verdict bit-identical with NIST) |
| **FIPS 204** | Full `ML-DSA-sigVer-FIPS204` file execution | 180 | 9 pass, 36 documented rejections, 135 unsupported internal/pre-hash cases | 0 mismatches, 0 adapter errors, denominator verified |

### 3. Execution Latency

- **Test Suite Runtime**: see the per-Python results in TESTING.md.
- Per-vector timings were not recorded in a shipped file.

---

## Losing Cases and Caveats

1. **Unequal Feature Coverage across Language Libraries**:
   - Go's standard library `crypto/mlkem` currently implements only ML-KEM-768 and ML-KEM-1024, omitting ML-KEM-512. In single-vendor reports, this often leads to dropping ML-KEM-512 cases. In `pqblocks-acvp`, all ML-KEM-512 test cases are accounted for as `UNSUPPORTED_OPERATION`.
2. **Deterministic vs Randomized Encapsulation**:
   - NIST ACVP Known Answer Tests (KATs) for encapsulation specify a fixed random seed `m`. Implementations that do not expose an internal RNG hook (such as standard `liboqs` Python bindings) cannot reproduce the deterministic ciphertext without modifying the C library. `pqblocks-acvp` records these as `UNSUPPORTED_OPERATION` rather than misclassifying them as a cryptographic failure.
3. **Invalid Decapsulation Keys and Implicit Rejection**:
   - FIPS 203 Section 7.3 specifies input validation on the decapsulation key $dk$, requiring rejection if the embedded public key hash $H(ek)$ does not match $ek$. The test suite verifies that malformed keys trigger `DOCUMENTED_VALIDATION_REJECTION` rather than returning an invented shared secret.

---

## How to Reproduce

Run the CLI golden session:
```bash
python -m pqblocks_acvp.runner --golden
```

Run the official NIST ACVP test suite:
```bash
pytest tests/test_official_vectors.py -q
```
