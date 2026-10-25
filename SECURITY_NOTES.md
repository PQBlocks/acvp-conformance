# SECURITY NOTES: pqblocks-acvp

This document outlines the security architecture, threat model, operational boundaries, and security considerations for `pqblocks-acvp`.

---

## What It Protects and What It Does Not

### Protected
- **Conformance Integrity**: Enforces strict mathematical accounting ($\text{total} == \text{passed} + \text{DVR} + \text{unsupported} + \text{errors} + \text{mismatches}$) to prevent favorable-case attrition and cherry-picked pass rates.
- **Specification Compliance**: Verifies that implementations adhere strictly to NIST FIPS 203, FIPS 204, and FIPS 205 specifications, including implicit rejection mechanisms ($\bar{K} = \text{SHAKE256}(z \parallel c)$) and context length bounds ($|ctx| \le 255$).
- **Parser Robustness**: Safe, bounded parsing of untrusted NIST ACVP JSON vector files without code execution or unsafe deserialization.

### Not Protected
- **Production Secret Storage**: `pqblocks-acvp` is a test harness and algorithm validation engine. It is not designed to store, manage, or protect long-lived production cryptographic keys.
- **Side-Channel and Timing Resistance**: The bundled pure-Python reference oracles (`kyber-py`, `dilithium-py`) are structured for mathematical clarity and vector verification. Pure Python does not guarantee constant-time memory access or execution flow. It must not be deployed as an online cryptographic service where physical or cache side-channel attacks are in scope.

---

## Implementation Details

- **Reference Backend**: Built on pure-Python implementations of FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) via `kyber-py` and `dilithium-py`.
- **Foreign Function Interface (FFI)**: Adapter layers interfacing with external runtimes (Go bridge via subprocess/C-API, `liboqs` via dynamic linking, `pyca/cryptography` via Python bindings) handle boundary serialization and gracefully map runtime exceptions into structured taxonomy outcomes.
- **Random Number Generation**: Test vectors in Known Answer Tests (KATs) rely on deterministic input seeds specified by the standard ($d$, $z$, $m$). Random sampling for differential re-execution uses seeded pseudorandom generators (`random.Random(seed)`).
- **Zeroization**: Being implemented in Python, runtime memory management is handled by the Python runtime garbage collector. Sensitive test keys are not explicitly scrubbed from RAM.

---

## Hostile Input Handling

1. **Malformed Key Inputs**:
   - Encapsulation keys $ek$ and decapsulation keys $dk$ are validated against expected length constraints before processing (e.g. ML-KEM-768 $ek$ must be exactly 1,184 bytes; $dk$ must be 2,400 bytes). Malformed inputs trigger `DOCUMENTED_VALIDATION_REJECTION`.
2. **Context Strings in ML-DSA**:
   - In accordance with NIST FIPS 204 Section 5.4, context strings exceeding 255 bytes are rejected cleanly.
3. **Implicit Rejection Handling**:
   - Decapsulation of invalid or corrupted ciphertexts is verified against FIPS 203 Algorithm 18: the implementation must return the pseudorandom implicit rejection key derived from $z$ and $c$, rather than raising an unhandled exception or leaking information.

---

## Dependency Posture

- `kyber-py==1.2.0` (Apache-2.0 / MIT)
- `dilithium-py==1.4.0` (Apache-2.0 / MIT)
- Optional: `cryptography>=41.0.0` (Apache-2.0 / BSD)
All dependencies are audited via `pip-audit` with zero known vulnerabilities.
