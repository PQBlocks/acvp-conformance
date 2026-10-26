# Changelog

All notable changes to `pqblocks-acvp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-25

### Fixed
- Decapsulation vectors: the parser now keeps `c` (and a group-level `dk`, if present) as inputs; previously 30 decapsulation cases on `ML-KEM-encapDecap-FIPS203` were false `MISMATCH` results.
- The CLI text table now prints a Mismatch column.
- Removed the leftover FIPS 205 entry from the licence list and keywords.

### Added
- NIST ACVP JSON session, test group, and test case parser (`ACVPParser`).
- Cross-implementation conformance test harness with strict denominator preservation (`ConformanceHarness`).
- 5-way outcome taxonomy (`TaxonomyClassifier`, `TaxonomyCategory`).
- Pure Python reference oracles for FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) built on `kyber-py` and `dilithium-py`.
- Adapters: Python reference; Go placeholder (every case `UNSUPPORTED_OPERATION`, no Go code is called); `pyca/cryptography` (pure ML-DSA sigVer only); `liboqs` (ML-KEM decapsulation only).
- FIPS 203 Section 7.3 decapsulation key validation checks.
- Re-execution helper (`G7ReexecutionFramework`): samples cases and compares two adapters' outcome categories. It has only been run against the Go placeholder (agreement 0.0).
- `ComplianceReporter`: prints a fixed JSON list of reference components and their licences, shaped after SPDX 2.3. It is not a complete SPDX document and does not list the runtime dependencies kyber-py and dilithium-py.
- CLI runner supporting `--golden`, `--json`, `--corpus`, and `--spdx` modes.
