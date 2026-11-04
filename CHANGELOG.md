# Changelog

All notable changes to kit are in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-11-04

### Security

- Every Ed25519 check uses one acceptance predicate (SPEC-SIGNING §1):
  canonical, non-small-order `A` and `R`, canonical `s`, and the cofactored
  equation. Commits, tags, attestations, write grants, URL tokens and auth
  envelopes all call `kit_core::sign::verify_ed25519`. Before, fetch used a
  batch check that accepted some torsion-padded signatures that `kit verify`
  rejected, and the transfer envelope test used the loose RFC 8032 check.
- Decoders bound every allocation and all decode work on hostile objects,
  packs, ignore files, refs and remote listings.
- Tree entry names reject `:` and the NTFS 8.3 aliases `kit~N` and `git~N`
  on every platform (SPEC-OBJECTS §4.1). A symlink target that escapes
  the working tree is refused.
- Git import checks object kinds, parents and hashes.
- Terminal control characters in remote text and messages are escaped.
- Signer PINs are wiped after use, and the signer process gets a limited
  environment.
- Release builds remap build paths, and CI checks that the release build
  reproduces.

### Added

- `kit_core::write_auth::inspect_headers` checks the header counts of a
  signed request (SPEC-TRANSPORT-CONNECT §7.1). It rejects a repeated
  envelope header and a missing one.
- `kit_core::write_auth::replay::classify_replay` and `storable_rejection`
  map a signed-write replay record to an outcome and decide which refusals
  a server may store.
- The `kit-wasm` crate wraps the byte-format and crypto paths of `kit-core`
  and `kit-attest` for the browser. It is not published to crates.io.
- A `libkit` usage guide and an example that `cargo test` builds.

### Changed

- The Commonware crates move to 2026.10.0. History roots (`history-mmr`)
  now bind the MMB family and bagging tags (SPEC-HISTORY-PROOF §2.3), so
  every root changes. Ancestry snapshots use format 2. A format 1 snapshot
  still loads with its root recomputed, and the next tip move rewrites it.
  Descriptors and proofs from an earlier kit do not verify against the new
  roots. `history::InclusionProof` aliases the 2026.10.0 proof type.
- Upstream Commonware 2026.10.0 assumes AVX2, BMI2 and ADX on x86-64
  (Intel Broadwell, AMD Zen or newer).
- The verification equation is cofactored. A signature whose `R` or `A`
  carries a torsion component, which only the key holder can make, now
  verifies.
- Clone, pull and fetch check signatures with
  `kit_core::sign::verify_ed25519_batch`, which accepts exactly what the
  single check accepts. Its weights come fresh from the operating system.
  The `batch-verify` feature of `kit-core` and `kit_core::sign::verify_batch`
  are removed.
- The disclosure proof variants are now `RangeProof::{Kdpb, Kdsp}` and
  `RangeProofKind::{Kdpb, Kdsp}`. The wire bytes do not change.
- `KitError` and `IgnoreError` have new variants for the new refusals.

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
