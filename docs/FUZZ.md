# Fuzzing

kit ships a small number of **bounded property tests** that exercise the
binary parsers from adversarial inputs. They live in the `kit-fuzz`
crate at `rust/fuzz/` and run in two modes:

- `cd rust && cargo test --manifest-path fuzz/Cargo.toml` &mdash; plain unit-test
  harness over the target bodies; stable Rust, no extra tooling. CI runs
  this.
- `cd rust/fuzz && cargo +nightly fuzz run <target>` &mdash; libfuzzer-sys
  harness for coverage-guided runs. Same target bodies, same
  guardrails.

The property-test approach is deliberate: an earlier attempt that ran
inputs through a page-backed allocator ballooned to hundreds of GiB on a
pathological corpus. Everything in this document exists to prevent that
from recurring.

## What is fuzzed

| Target file                    | Target function             |
| ------------------------------ | --------------------------- |
| `fuzz_targets/delta.rs`        | `delta::decode`             |
| `fuzz_targets/pack.rs`         | `pack::PackReader::read`    |
| `fuzz_targets/tree.rs`         | `serialize::deserialize`    |
| `fuzz_targets/software_key_record.rs` | `EncryptedKeyRecord::decode` |
| `fuzz_targets/git_commit_parse.rs` | `kit-git-bridge gitparse::parse_commit` (untrusted upstream bytes, SPEC-GIT-IMPORT §2) |
| `fuzz_targets/git_tag_parse.rs` | `kit-git-bridge gitparse::parse_tag` |
| `fuzz_targets/git_tree_parse.rs` | `kit-git-bridge gitparse::parse_tree` plus `map_mode` |
| `fuzz_targets/rpc_decode.rs`   | `SignerFrame` / `SshFrame` wire decode (never panics) plus `Arbitrary`-driven encode/decode roundtrip |
| `fuzz_targets/ssh_session.rs`  | `kit_serve::serve_session` (arbitrary client bytes after a valid `Hello`; the session ends, every pack on disk hashes to its name, no temp file stays, nothing is written outside `packs/` and `refs/`) |
| `fuzz_targets/sparse_verify.rs` | `sparse::build_sparse` / `sparse::verify_sparse` (never panics on adversarial manifest/proof bytes) |
| `fuzz_targets/merkle_proof.rs` | `merkle::compute_{tree,chunked}_id` / `merkle::Proof::decode` / `merkle::verify_tree_entry` / `merkle::verify_chunk` (never panics; a freshly built proof verifies; adversarial proof bytes reject cleanly, whether at decode or at verify) |
| `fuzz_targets/merkle_packlist.rs` | `transfer::decode_packlist` / `transfer::encode_packlist` (never panics; a decoded node re-encodes and re-decodes to the same node) |
| `fuzz_targets/disclosure_decode.rs` | `verify::verify_disclosure` decode path (SPEC-DISCLOSURE) — never panics on adversarial bundle bytes, regardless of the commit id checked against; every `Vec`/`Proof` length is bounded before allocation |
| `fuzz_targets/verify_disclosure.rs` | `verify::verify_disclosure` / `verify::build_disclosure` (never panics; a freshly built bundle over a real `ObjectStore` fixture verifies; a mutated bundle rejects cleanly) |
| `fuzz_targets/span_decode.rs` | `verify::span::verify_disclosure_span` structural decode (never panics on arbitrary MKDS bytes; lengths and counts are checked before allocation) |
| `fuzz_targets/verify_span.rs` | `verify::span::{encode_span,verify_disclosure_span}` (a newly encoded committed span verifies; its mutated commit id rejects; arbitrary input never panics) |
| `fuzz_targets/pack_entries.rs` | `pack::PackEntries` (never panics on adversarial pack bytes; a pack `PackReader::read` accepts also parses as `PackEntries` with the same entry count) |
| `fuzz_targets/verify_closure.rs` | `verify::verify_closure` / `verify::verify_closure_packs` / `verify::verify_closure_manifest` / `verify::export_closure` (never panics; a freshly exported snapshot closure verifies; a mutated manifest rejects cleanly; raw adversarial bytes fed directly as pack buffers — whole and split into two — to `verify_closure_packs`/`verify_closure_manifest` never panic and any `Ok` report is internally consistent) |
| `fuzz_targets/envelope_decode.rs` | `kit_attest::envelope::decode` (every accepted input re-encodes to exactly itself) |
| `fuzz_targets/ref_wire_decode.rs` | `refs::decode_ref_wire` / `refs::parse_lowercase_hash` (an accepted hash survives an encode and decode round trip) |
| `fuzz_targets/index_decode.rs` | `index::deserialize` (an accepted index survives a serialize and deserialize round trip) |
| `fuzz_targets/history_order_decode.rs` | `TimestampDiscovery::decode` (every accepted input re-encodes to exactly itself) |
| `fuzz_targets/conflict_state_decode.rs` | `ops::conflict_state::deserialize_conflicts` (an accepted list survives a serialize and deserialize round trip) |
| `fuzz_targets/sparse_wire_decode.rs` | `sparse::decode_sparse_response` / `sparse::decode_sparse_cache` (never panics on any input) |
| `fuzz_targets/git_object_parse.rs` | `gitobj::GitObject::parse_raw` and the `kit-git-bridge` header, timestamp and person parsers (an accepted raw object re-renders to exactly the input) |
| `fuzz_targets/repo_identity_parse.rs` | The `repo_identity` namespace, repository and remote identity `parse` functions (an accepted value re-parses from its text form to the same text) |
| `fuzz_targets/commitment_parse.rs` | `write_auth::ContentCommitment::parse` (an accepted commitment displays as exactly the input text) |
| `fuzz_targets/ignore_parse.rs` | `ignore::parse` / `ops::restore::parse_sparse_patterns` (never panics on any text) |
| `fuzz_targets/grant_parse.rs` | `Grant::parse` / `SignedHeader::parse` (an accepted input re-encodes to exactly itself) |
| `fuzz_targets/epoch_visibility_parse.rs` | `EpochStatement::parse` / `VisibilityStatement::parse`, the stateless grant verifiers and the `webauthn-p256` blob and client data parsers |
| `fuzz_targets/config_parse.rs` | `config::apply_text` (a repository config never sets a user-scoped key) |
| `fuzz_targets/stash_list.rs` | `ops::stash::deserialize_list` (an accepted list re-encodes to exactly itself) |
| `fuzz_targets/bridge_map.rs` | The `kit-git-bridge` map and ref-state loaders (never panic on any file content) |
| `fuzz_targets/pack_cursor_decode.rs` | `pack::window::WindowCursor::from_bytes` (an accepted cursor re-encodes to exactly itself) |
| `fuzz_targets/chunked_blob_build.rs` | `worktree::chunked_blob_from_bytes` (the manifest records the input length) |

Targets that exercise crate-private parser surfaces should expose a minimal
`#[cfg(feature = "fuzzing")]` wrapper from that crate and enable the feature in
`rust/fuzz/Cargo.toml`, as `software_key_record` does for `kit-keystore`.

## Parser coverage

Every public function that decodes or parses bytes or text appears below.
Each one has a fuzz target, or a written reason why it has none.

| Parser | Fuzz target or reason |
| ------ | --------------------- |
| `kit_attest::envelope::decode` | `envelope_decode` |
| `kit_attest::grant` `Grant::parse`, `SignedHeader::parse`, `RepoScope` and `RefScope` `parse`, capability and visibility field `parse` | `grant_parse` |
| `kit_attest::grant` `EpochStatement::parse`, `VisibilityStatement::parse` | `epoch_visibility_parse` |
| `kit_attest::grant::webauthn` `WebAuthnAssertion::parse` | `epoch_visibility_parse` |
| `kit_attest::webauthn::decode_pae_b64_standard` | None. It is one call to the audited base64 decoder, and it has no parsing code of its own. |
| `kit_core::serialize::deserialize` | `tree` |
| `kit_core::delta::decode` | `delta` |
| `kit_core::pack` `PackReader::read`, `PackEntries` | `pack`, `pack_entries` |
| `kit_core::pack::window::WindowCursor::from_bytes` | `pack_cursor_decode` |
| `kit_core::merkle::Proof::decode` | `merkle_proof` |
| `kit_core::transfer::decode_packlist` | `merkle_packlist` |
| `kit_core::sparse::decode_sparse_response`, `decode_sparse_cache` | `sparse_wire_decode` |
| `kit_core::verify` closure manifest `decode` | `verify_closure` |
| `kit_core::refs::decode_ref_wire`, `parse_lowercase_hash` | `ref_wire_decode` |
| `kit_core::index::deserialize` | `index_decode` |
| `kit_core::history_order` `TimestampDiscovery::decode` | `history_order_decode` |
| `kit_core::ops::conflict_state::deserialize_conflicts` | `conflict_state_decode` |
| `kit_core::ops::stash::deserialize_list` | `stash_list` |
| `kit_core::repo_identity` every `parse` and `parse_bare_allowed` | `repo_identity_parse` |
| `kit_core::write_auth::ContentCommitment::parse` | `commitment_parse` |
| `kit_core::ignore::parse`, `ops::restore::parse_sparse_patterns` | `ignore_parse` |
| `kit_core::worktree::chunked_blob_from_bytes` | `chunked_blob_build` |
| `kit_git_bridge::gitparse` `parse_commit`, `parse_tag`, `parse_tree`, `parse_person` | `git_commit_parse`, `git_tag_parse`, `git_tree_parse`, `git_object_parse` |
| `kit_git_bridge::gitobj::GitObject::parse_raw`, `author::parse_timestamp`, `headers` `parse_identity`, `parse_hash`, `parse_signature` | `git_object_parse` |
| `kit_keystore` encrypted key record `decode` | `software_key_record` |
| `kit_storage::config` text parsing (`apply_text`) | `config_parse` |
| `kit_storage::config::parse_pipe_list` | None. It splits a user-written config value on `\|`. It does no other parsing. Unit tests cover it. |
| `kit_storage::grants::parse_relying_parties`, `grants::spec::parse_ttl`, `grants::cli::parse_timeout`, `grants::cli::parse_namespace` | None. They read command-line text that the user types, not bytes from a peer or a repository. Unit tests cover them. |
| `kit_storage::commands::attest_factory::parse_algorithm` | None. It matches a command-line word against a fixed list. Unit tests cover it. |
| `kit_storage::commands::trust_roots` `parse`, `hex_decode` | None. They read a trust file that the user owns. Unit tests cover them. |
| `kit_storage::clap_args::parse`, `term::parse` | None. They wrap the `clap` parser and the terminal setting. They read local arguments only. |
| `kit_transport_ssh::url::parse_kit_ssh_url` | None. It reads a URL that the user types. Unit tests cover it. |
| `kit_transport_s3::sigv4::parse_host` | None. It strips a scheme prefix from a configured endpoint. It does no other parsing. Unit tests cover it. |
| `kit_serve::serve_session` wire handling | `ssh_session`, `rpc_decode` |
| `kit-client` connect stream frame decoder (private) | None. It is not a public function. Unit tests in `connect/tests.rs` cover it. |

One surface has no fuzz target by design. `restore` resolves symlinks. Its
file-system side effects make it too easy to create symlink cycles. Revisit
it once a virtual file system exists to sandbox the target.

## Invariants per target

All targets share the same base invariants:

- No panic.
- No out-of-memory that is not an explicit `Vec::with_capacity`-caught
  allocation failure at the parser boundary.
- Every iteration completes in under 100 ms of wall-clock.

Target-specific invariants:

- **Packfile**: declared entry count plus declared entry lengths are
  bounds-checked against the actual input length *before* the parser
  allocates the entries vector. The most important regression case is
  "pack header claims count = 9 999 999, body is 0 bytes": the parser
  must reject before pre-allocating any large structure.
- **Tree**: every `TreeEntry.name` accepted by the parser is
  non-empty, contains no path separators and no NUL bytes, is not `.`
  or `..`, and is at most 255 bytes. Every mode is one of the defined
  enumerated values.
- **Delta**: a `COPY` instruction's `offset + length` stays within the
  base slice; a truncated `COPY` header or `INSERT` literal produces
  `DeltaCorrupt`; opcode `0x00` is always rejected.
- **MKDS span**: the decode target accepts arbitrary capped bytes without a
  panic. The verify target re-encodes the committed two-chunk fixture through
  the product encoder, verifies its 20-byte range, rejects a changed embedded
  commit id, then checks arbitrary capped bytes. The fixture and its derived
  bundles are fixed; libfuzzer mutates only the separate adversarial input.

## How to run

```sh
cd rust
cargo test --manifest-path fuzz/Cargo.toml
```

That runs the target bodies as ordinary unit tests with a seeded
PRNG &mdash; ~30 cases total, each wall-clock capped so a regression that
introduces an accidental loop aborts rather than hanging CI.

For coverage-guided runs (nightly toolchain required):

```sh
cd rust/fuzz
cargo +nightly fuzz run delta
cargo +nightly fuzz run pack
cargo +nightly fuzz run tree
cargo +nightly fuzz run software_key_record
cargo +nightly fuzz run rpc_decode
```

## In-process minifuzz (`rpc_decode` pilot)

The default in-process harness is a bespoke splitmix64 loop
(`run_iterated_unit` in `src/lib.rs`). The `rpc_decode` target's unit
test instead drives the shared body through
[`minifuzz`](https://docs.rs/commonware-invariants) &mdash; the same
in-process property-test harness upstream commonware uses for its own
in-tree tests. It is a mutational fuzzer (smarter than uniform-random
bytes) yet still a plain `#[test]` on stable, and on failure prints a
`MINIFUZZ_BRANCH = 0x...` token that replays the exact case via
`Builder::default().with_reproduce("0x...")`.

`commonware-invariants` is a **dev-dependency only** (pinned to the
commonware train fixed in `rust/Cargo.toml`, `2026.9.x` as of this revision); the libfuzzer binaries never link it. The
same six guardrails apply: `with_search_limit(MAX_ITER)` caps iterations,
`with_seed(RNG_SEED)` keeps the run deterministic, and the body still
truncates to `MAX_INPUT` and runs under the per-iteration wall-clock cap.
This is a pilot &mdash; the other targets stay on the splitmix loop until the
pattern proves out (`commonware-invariants` is alpha upstream).

## Guardrails (non-negotiable)

Every target body must satisfy all six:

1. **At most 100 iterations per invocation.**
2. **Every iteration's input is at most 64 KiB.**
3. **Bounded allocations.** Input cap (2) plus per-op output caps inside
   `kit-core` keep the worst-case heap under ~1 MiB per iteration:
   - `delta::decode` caps its initial `Vec::with_capacity` at
     `result_len.min(base.len() + 2 * stream.len())` so a 9-byte
     stream claiming `result_len = u32::MAX` cannot pre-allocate 4 GiB.
   - `pack::PackReader` enforces `MAX_ENTRIES = 10_000_000` and
     `MAX_PAYLOAD = 4 GiB` with count × entry-frame-length lower-bound
     checks against the input slice before any `Vec::with_capacity`.
   - `software_key_record` truncates each input to 64 KiB before calling
     `EncryptedKeyRecord::decode`. The decoder's cursor checks every
     length-prefixed field against the remaining input before copying, so
     allocation is bounded by bytes already present in the capped input rather
     than by untrusted declared lengths.
   - The harness adds defensive pre-checks
     (`claimed_result_len > MAX_INPUT * 4`,
     `claimed_entries > 100_000`) that short-circuit before calling
     into core, so the most pathological inputs don't even reach the
     parsers.
4. **Every iteration is timed; if it takes more than 100 ms the test
   aborts the remainder.** A slow iteration runs once more first. A busy
   machine can stall one call. Only two slow calls in a row fail the test.
5. **No `loop {}` or `while true {}` without a bounded iteration
   counter.**
6. **Seeded deterministic PRNG.** Inputs are synthesized from a fixed
   `u64` seed (`RNG_SEED`) so any failure reproduces exactly. Most targets
   use a splitmix64 PRNG (`run_iterated_unit`); the `rpc_decode` pilot
   drives the body through `minifuzz`, whose ChaCha8 sampler is seeded with
   the same constant via `with_seed` &mdash; also deterministic &mdash; plus a
   splitmix64 large-input sweep so the 8 KiB–64 KiB range stays covered
   (see the [In-process minifuzz](#in-process-minifuzz-rpc_decode-pilot)
   section).

## Known limitations

- PRNG-driven coverage is shallow &mdash; 100 iterations of random bytes
  will not find bugs that require deeply structured input. The fixed
  seed cases exist to cover the structurally interesting shapes
  (oversize counts, truncated headers, invalid modes, etc.) that
  random bytes rarely hit. Coverage-guided `cargo fuzz` runs fill in
  the rest.
- Fuzz outputs are only checked for "no panic, no runaway". This does not
  diff against a reference decoder.

## Adding a new target

Use this checklist before landing a new target:

- [ ] Pick a parser with a clear input → output contract.
- [ ] Add the target body to `rust/fuzz/src/lib.rs` as a `pub fn
      run_<name>(rng_seed: u64)` that enforces the six guardrails.
- [ ] Add a libfuzzer shim under `fuzz_targets/<name>.rs` calling the
      same body.
- [ ] Add a `#[test]` shim that invokes the body with fixed seeds.
- [ ] Add at least three hand-crafted fixed-seed cases: the happy path,
      one structural malformation, and one bounds-stress case
      (oversize-count / oversize-length style).

If you cannot satisfy the guardrails, do not land the target &mdash; leave
a note in this file explaining why it was deferred.
