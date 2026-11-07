# Changelog

All notable changes to kit are in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `kit log -n N` from one revision streams the history while each commit
  has at most one followed parent, and stops after N commits. On one ext4
  disk with 1,000,000 linear commits, `kit log -n 20` went from about 8 s
  and 1.2 GB to about 4 ms and 8 MB, and the full log from about 8.2 s and
  1.2 GB to about 5.2 s and 415 MB. With `--first-parent` the whole walk
  streams. A history with a merge near the tip still reads every reachable
  commit before it prints. The output is unchanged.

### Fixed

- `kit log` and `kit rev-list` fail with an error that names the limit when
  a walk reaches more than 1,000,000 commits. They used to stop there and
  print the newest commits as if they were the whole history. The excluded
  side of a range (`A..B`, `A...B`) shares that limit; it used to stop
  silently at 10,000 commits, which let excluded commits through.
- `collect_ancestor_set`, `kit rebase` and `kit bisect` fail with an error
  that names the limit when an ancestor walk reaches 10,000 commits, and
  a rebase fails when the branch has more than 10,000 commits to replay.
  They used to stop there silently: a rebase could replay only the newest
  commits of a long branch, or replay commits its base already holds, and
  bisect could offer commits that are known good.
- `kit rebase` fails before it changes anything when a commit to replay
  or an ancestor of the base is missing, corrupt or not a commit. It used
  to end the walk there. It then dropped a missing commit of the branch
  and every commit below it, and after a missing commit in the base's
  history it replayed commits the base already holds.
- The excluded side of a `kit log` range (`A..B`, `A...B`) fails when one
  of its commits is missing, corrupt or not a commit. It used to skip such
  a commit, so the range printed ancestors of `A` that it leaves out. The
  error is `libkit::log::Error::ReadCommit` or `NotACommit`, as on the
  included side; the `WalkRangeBase` and `WalkMergeBase` variants are gone.
- `kit git format-patch A..B` fails before it writes a patch when an
  ancestor of `A` is missing, corrupt or not a commit. It used to skip such
  a commit, so the series held patches for ancestors of `A`.
- `kit bisect` fails when a commit of the range, or an ancestor of a good
  commit, is missing, corrupt or not a commit. The range walk used to end
  at such a commit and the good walk used to skip it, so bisect could miss
  candidates or offer commits that are known good.
- The two sides of a `kit log` range share one budget of 1,000,000
  commits, as the documentation says. Each side used to have its own, so
  a range could read up to twice the limit.
- `kit bisect` fails with an error that names the limit when a range has
  more than 10,000 candidates. Its candidate walk used to have no limit.
- `kit git format-patch` fails before it writes a patch when the two sides
  of its range would read more than 1,000,000 commits together, with an
  error that names the limit. Both walks used to have no limit.
- `kit blame --reverse` fails with an error that names the limit when the
  first-parent walk from the end of its range holds more than 1,000,000
  commits. It used to collect the whole chain with no limit.
- Blame caps its LCS comparison table at 64 MiB after trimming the common
  prefix. Larger comparisons use the bounded line diff search. Reassembly,
  line buffers, and attribution memory still grow with file size.
- Mutation testing of changed lines uses paths relative to the Rust workspace.

## [0.7.2] - 2026-11-06

### Security

- `PackReader::read` limits the bytes it decodes from a pack to 32,768 times
  the pack size, with a floor of 2 GiB and the old 16 GiB as the ceiling.
  Before, a pack of a few kilobytes could force 16 GiB of decompression.
  Real packs expand 2 to 4 times, and an honest pack of deltas of small files
  expands at most about 12,000 times.
- A zstd entry is checked against its claimed decompressed size before the
  reader reserves a buffer for it. The blocks of the frame must be able to
  decode to the claim. Before, a 15-byte entry could make the reader reserve
  1 GiB.

### Fixed

- The search of the line diff behind `diff`, `show`, `format-patch`, `add -p`
  and the text merge now uses about 64 MiB at most, whatever the input. It stops
  at 4096 line edits. Before, its memory grew with edits times lines, so
  rewriting a 1 MiB text file with 80-byte lines cost about 10 GiB. Output is
  unchanged up to the limit. Past it, a diff keeps the best alignment that the
  search reached and reports the rest as replaced, and a text merge reports a
  conflict. The line tables and output of a diff still grow with the file.
- The text merge reports a conflict for a single blob above the 1 MiB chunk
  threshold, the same as for a chunked file.

## [0.7.1] - 2026-11-04

### Added

- kit-wasm is published to npm as `@officialunofficial/kit-wasm`. The release
  workflow builds the package with `scripts/wasm-package.sh` and publishes it
  with npm trusted publishing.

## [0.7.0] - 2026-11-04

### Security

- The decoders of the range disclosure bundle, the pack list node and the
  closure manifest reserve memory for a list in proportion to the input,
  not to the declared length. Before, about 1 MB of input could reserve
  about 96 MB. Accepted and rejected inputs do not change.
- `PackDecodeCursor` no longer keeps a record for every frame of a pack. It
  held about 190 bytes for each 5-byte frame, so a 50 MB pack of empty frames
  pinned 1.9 GB before the first entry was decoded. The cursor now keeps its
  position and parses each frame when `resume` reaches it, and it keeps only
  the decompressed payload of a `0x03` or `0x04` frame, in a 24-byte slot. A
  pack of empty raw frames adds no allocation. `decode_entries_with` runs on
  the cursor and gets the same bound. Errors, their order and the wire format
  do not change.

### Added

- `PackEntries` implements `Clone`.

### Changed

- **Breaking:** a multi-leaf proof requires strictly ascending positions.
  The builders (`build_tree_entries_multi_proof`,
  `build_chunks_multi_proof`) and the verifiers (`verify_tree_entries_multi`,
  `verify_chunks_multi`) read the positions in input order and reject a
  position that is lower than the one before it with the new variant
  `MerkleError::UnsortedPosition`. Before, they sorted the positions. This
  matches the Commonware BMT, so both sides accept the same inputs.
  A position equal to the one before it is `DuplicatePosition`, and a repeat
  that is not adjacent is `UnsortedPosition`. The checks run in input order,
  so an input with more than one fault can report a different error than in
  0.6.0: on nine leaves, the verifiers give `DuplicatePosition(4)` for
  `[4, 4, 9]`, not `PositionOutOfRange(9)`. Proof bytes, roots and ids do
  not change (SPEC-MERKLE-OBJECTS §5.4).
- The `history-mmr` feature of `kit-core` builds the Commonware storage and
  cryptography crates without their `std` feature. The normal dependency graph
  of the feature drops from 364 to 135 crates. The deterministic runtime, the
  zstd 0.13 library, `blst` and an HTTP server crate no longer build with it.
  Roots, proofs and ids do not change.
- Commonware 2026.10.0 states AVX2, BMI2 and ADX as its supported x86-64
  floor and tests only at or above it. This corrects the 0.6.0 note on that
  floor. No Commonware code that kit builds checks for these features or needs
  them: their SIMD paths and the BLAKE3 code that kit uses detect the CPU
  features at run time. Kit sets no CPU floor of its own.

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
