# Changelog

All notable changes to kit are in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Every Ed25519 check uses one acceptance predicate (SPEC-SIGNING §1):
  canonical, non-small-order `A` and `R`, canonical `s`, and the cofactored
  equation. Commits, tags, attestations, write grants, URL tokens and auth
  envelopes all call `kit_core::sign::verify_ed25519`. Before, fetch used a
  batch check that accepted some torsion-padded signatures that `kit verify`
  rejected, and the transfer envelope test used the loose RFC 8032 check.

### Changed

- The verification equation is cofactored. A signature whose `R` or `A`
  carries a torsion component, which only the key holder can make, now
  verifies.
- Clone, pull and fetch check signatures with
  `kit_core::sign::verify_ed25519_batch`, which accepts exactly what the
  single check accepts. Its weights come fresh from the operating system.
  The `batch-verify` feature of `kit-core` and `kit_core::sign::verify_batch`
  are removed.

## [0.5.0] - 2026-10-28

### Added

- The `kit` command-line tool and the `kit-*` library crates.
- The `libkit` crate. It gives programs the same typed operations that the
  `kit` command runs: history, working tree, merge, rebase, remotes, grants,
  transfer, keys, attestation and git interop.
- The installer `install.sh`, served from `kit.storage`. It requires a cosign
  signature check by default.
- The release workflow `release.yml`. It signs each archive with cosign
  keyless signing, adds SLSA build provenance, and publishes a CycloneDX SBOM.
