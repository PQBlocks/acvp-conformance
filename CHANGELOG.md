# Changelog

All notable changes to `pqblocks-acvp` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-25

### Added
- NIST ACVP JSON session, test group, and test case parser (`ACVPParser`).
- Cross-implementation conformance test harness with strict denominator preservation (`ConformanceHarness`).
- Standardized 4-way plus mismatch error taxonomy (`TaxonomyClassifier`, `TaxonomyCategory`).
- Pure Python reference oracles for FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) built on `kyber-py` and `dilithium-py`.
- Target implementation adapters for Python Reference, Go bridge, `pyca/cryptography`, and `liboqs`.
- FIPS 203 Section 7.3 decapsulation key validation checks.
- Differential verification re-execution framework with random sampling and agreement evaluation.
- SPDX 2.3 license compliance reporting (`ComplianceReporter`).
- CLI runner supporting `--golden`, `--json`, `--corpus`, and `--spdx` modes.
