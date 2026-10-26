# USE CASES: pqblocks-acvp

This document outlines practical operational scenarios for `pqblocks-acvp`, complete with runnable Python snippets and expected outputs.

---

## Scenario 1: CI/CD Conformance Regression Gate

**Goal**: Automatically evaluate a cryptographic module in a continuous integration pipeline, failing the build if any test case produces an unexpected mismatch or if cases are dropped from the denominator.

```python
from pqblocks_acvp.runner import build_golden_session
from pqblocks_acvp.harness import ConformanceHarness
from pqblocks_acvp.adapters.reference import ReferencePQCAdapter

def test_ci_conformance_gate():
    session = build_golden_session()
    harness = ConformanceHarness([ReferencePQCAdapter()])
    reports = harness.run_session(session)

    rep = reports["Reference-FIPS-Oracle"]

    # Verify zero cryptographic mismatches
    assert rep.mismatches == 0, f"Found {rep.mismatches} mismatches"

    # Verify zero adapter crashes
    assert rep.adapter_errors == 0, f"Found {rep.adapter_errors} adapter errors"

    # Verify denominator integrity
    assert rep.denominator_verified, "Denominator preservation violated"

    print("CI Gate: Conformance passed cleanly.")

if __name__ == "__main__":
    test_ci_conformance_gate()
```

**Expected Output**:
```
CI Gate: Conformance passed cleanly.
```

---

## Scenario 2: Cross-Implementation Comparison without Favorable-Case Attrition

**Goal**: Compare multiple implementations (e.g., Python reference oracle vs `pyca/cryptography` vs `Go-crypto/mlkem`) against the same official ACVP test vector set without dropping unsupported cases.

```python
from pqblocks_acvp.parser import ACVPParser
from pqblocks_acvp.harness import ConformanceHarness
from pqblocks_acvp.adapters.reference import ReferencePQCAdapter
from pqblocks_acvp.adapters.go_bridge import GoBridgeAdapter
from pqblocks_acvp.adapters.pyca import PyCAAdapter

# Load test vectors
session = ACVPParser.parse_file("tests/vectors/ML-KEM-encapDecap-FIPS203/internalProjection.json")

# Evaluate across multiple runtimes
adapters = [ReferencePQCAdapter(), GoBridgeAdapter(), PyCAAdapter()]
harness = ConformanceHarness(adapters)
reports = harness.run_session(session)

print(f"{'Adapter':20} {'Attempted':10} {'Passed':8} {'Unsupported':12} {'Denominator OK':15}")
print("-" * 70)
for name, rep in reports.items():
    print(f"{name:20} {rep.total_attempted:<10} {rep.passed:<8} {rep.unsupported_operations:<12} {str(rep.denominator_verified):<15}")
```

**Expected Output**:
```
Adapter              Attempted  Passed   Unsupported  Denominator OK 
----------------------------------------------------------------------
Reference-FIPS-Oracle 165        105      60           True           
Go-crypto/mlkem      165        0        165          True           
pyca/cryptography    165        0        165          True           
```

The 60 unsupported Reference cases are the key-check functions (`encapsulationKeyCheck`, `decapsulationKeyCheck`), which the oracle does not run.

---

## Scenario 3: Validating FIPS 203 Section 7.3 Decapsulation Key Checks

**Goal**: Verify that an implementation correctly rejects decapsulation keys where the embedded public key hash does not match the actual public key.

```python
from pqblocks_acvp.reference import MLKEMReferenceOracle

# Generate a valid keypair
ek, dk = MLKEMReferenceOracle.keygen("ML-KEM-768", "11" * 32, "22" * 32)
c, k = MLKEMReferenceOracle.encapsulate("ML-KEM-768", ek, "33" * 32)

# Verify valid decapsulation succeeds
k_decap = MLKEMReferenceOracle.decapsulate("ML-KEM-768", dk, c)
assert k_decap == k

# Corrupt the embedded hash in dk (FIPS 203 Section 7.3 check)
dk_bytes = bytearray.fromhex(dk)
dk_bytes[-64] ^= 0xFF
corrupted_dk = dk_bytes.hex()

try:
    MLKEMReferenceOracle.decapsulate("ML-KEM-768", corrupted_dk, c)
    print("ERROR: Corrupted dk was accepted!")
except ValueError as e:
    print(f"PASS: Corrupted key rejected per FIPS 203 7.3: {e}")
```

**Expected Output**:
```
PASS: Corrupted key rejected per FIPS 203 7.3: hash check failed
```

---

## When to Use Something Else

- **High-Throughput Production Cryptography**: If your application needs to encrypt network packets or sign user tokens at high volume, use optimized C/Rust primitives such as `liboqs` or `cryptography`. `pqblocks-acvp` is a testing and audit harness, not a production encryption backend.
- **Full Client-Server ACVTS Protocol**: If you need to negotiate directly with NIST's Automated Cryptographic Validation Testing Server over HTTP/TLS (requesting vector sessions, uploading responses, managing server certificates), use `libacvp` (Cisco) or NIST's official ACVP client.
- **Legacy CAVP (FIPS 140-2) Validation**: For classical non-quantum algorithms (AES, SHA-2, RSA), use legacy CAVP test harnesses.
