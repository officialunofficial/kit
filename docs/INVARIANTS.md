# Invariants

This enforcement index summarizes properties of the kit repository. The
linked specs remain authoritative. These entries add code and regression-test
pointers. They are not a separate contract.

## Cached imports and gc agree on object retention

**Always:** gc's final age check and unlink exclude bulk refresh/write on the
same store. A cached import refreshes every object in its stored history
closure, including chunk leaves, once per run before publication; missing
cached objects refuse publication. The strict per-object grace bound remains
required for writers outside gc's worktree locks.

**Because:** a stale candidate read or a skipped cached descendant must not
turn a successful reuse into a dangling ref.

**If violated:** gc can delete an object after its writer refreshed it, or
prune an old descendant hidden behind a map-cache hit.

**Enforcement status:** shared/exclusive locks on the immutable format file,
`ObjectStore::prune_if_old`, `BulkWriter::reuse_object`, and import-run memoization.
Deterministic sweep interleaving, killed-sweeper restart, read-only reuse and
cached chunk-closure refresh regressions cover the boundaries. SPEC-GC states
the remaining zero-grace and long-import restrictions.

## Connect retries preserve identity and durable acknowledgements

**Always:** `kit-client` owns Connect encoding and decoding. The host selects
credentials, grants, admission helpers, retry scheduling, and receipt storage.
Ambiguous writes retain their authenticated identity until expiry. A durable
part receipt is stored before progress or the next part. Fresh clients reuse
acknowledged parts only when destination, signer, ticket, pack, and geometry
match. Signing and exchange time consume the same attempt budget.

**Because:** retrying a logical write must not duplicate mutation or charge,
and a process restart must not discard an acknowledged upload part.

**If violated:** a retry could execute a second write, reuse another upload's
receipt, resend durable parts, or exceed the operation deadline.

**Enforced by:** `ClientSource` write recovery and caller-owned `ClientSession`,
host request policy, `NativeHttp` budgets, both-backend push and policy tests,
the multipart process-kill test, and native streaming and response bound
tests. Session locks release before host callbacks; receipt observation precedes
successful ticket cleanup.

## Native connection reuse never replays a started request

**Always:** reads and signed writes reuse at most one idle HTTP connection per
origin for ten seconds on the same current-thread runtime. Automatic connection
recovery uses only hyper's recovered, untouched request, before writing starts;
signed headers, nonce, and buffered or streamed body remain identical. Failures
after writing starts return to caller-owned recovery. Partial responses and
cancellation do not make an incomplete exchange eligible for reuse.

**Because:** connection reuse removes repeated TLS handshakes, while only an
untouched request establishes that no mutation could have reached the server.

**If violated:** a pooled retry could duplicate a write, change its identity,
reuse an expired connection, or expose bytes from an interrupted response.

**Enforced by:** `NativeHttp`'s bounded idle pool, hyper's pre-start cancellation
retry, native connection reuse/idle expiration/post-write disconnect/streamed
idle-close/partial-response tests, and the real HTTPS CLI latency comparison.

## Git audit establishes correspondence without a signing key

**Always:** imported graph edges and translated unsigned fields are derived
from retained Git bytes and checked under the pinned public key. A head's
provenance claim must match its exact subject, ref, source and versions.

**Because:** valid signatures on unrelated twins do not authenticate a mutable
Git-to-kit mapping cache.

**If violated:** swapped mappings or unrelated attestations can pass an audit.

**Enforced by:** `rust/crates/kit-bin/tests/git_import_integration.rs` mapping
swap, unrelated attestation and private-key removal regressions; the full
45-test integration suite passes. Golden translated bytes remain unchanged.

## File equality survives valid representation changes

**Always:** different file object IDs compare by verified byte streams; modes
remain separate. Restaging identical content keeps the staged ID only when its
representation is valid for the new entry type; symlink targets use a single
Blob. Chunk failures remain errors, including after the first differing byte.

**Because:** an inline Blob, fixed-size manifest and CDC manifest may describe
the same bytes with different immutable object identities.

**If violated:** clean worktrees appear modified, restaging changes identity,
and merge or overwrite decisions depend on chunk boundaries. Retaining a chunked
file object for a symlink produces an index that cannot be committed.

**Enforced by:** core `worktree::blob::equality_tests`,
`ops::diff::tests::equal_content_different_chunk_layout_is_clean`, and
`rust/crates/kit-bin/tests/content_representation_integration.rs`. Comparison
holds at most one chunk per side plus manifests; rename fingerprints are
memoized for one diff and confirmed by byte comparison.

## Requested transport identities are checked before effects

**Always:** fetched packs and metadata match their requested keys. Sparse selections are
derived from canonical Tree witnesses verified against independently known IDs.

**Because:** internally valid content can still be a substituted response.

**If violated:** transports can publish unrequested objects or incomplete paths.

**Enforced by:** packmap substitution tests, core sparse
v2 mutation/completeness tests and `rust/tests/golden/sparse/response_v2.bin`.

## Every ref mutation participates in its lock protocol

**Always:** local Any, Missing, Match and deletion take the same full-ref guard.
The order is registry, worktrees, history, then ref mutation locks; peers within
a class use canonical order. File transport serializes all condition variants
within its separate transport lock domain.
Ref lock filenames use a fixed-length digest of the complete ref identity,
including its namespace, so valid long ref names remain writable.

**Because:** an unconditional writer can invalidate a conditional writer's
observation just as another CAS writer can.

**If violated:** reported successful updates lose writes or expose invalid
history publication states.

**Enforced by:** core refs and file-transport contention regressions, CLI
history lifecycle and publication retry tests, and core long-ref mutation and
lock-identity regressions.

## History evidence binds ancestry, generation and context

**Always:** a trusted proof describes the canonical first-parent chain for the
expected repository, ref, tip and generation. Pending durable intents pin both
previous and target tips as GC roots even without the history feature enabled.

**Because:** a mutation journal is not an ancestry proof, and publication spans
multiple durable files.

**If violated:** rewinds, resets, ABA or interrupted writes can issue misleading
proofs or let GC remove objects needed to recover.

**Enforced by:** `history/ancestry.rs` chain/context/generation and six-boundary
failure tests, and core GC intent-root tests. Current descriptors establish
local trust only; snapshots/reconstruction cost O(chain length), capped at one
million leaves. Only canonical ancestry snapshots are supported.

## Staging selections are durable; stat caches are disposable

**Always:** current index data preserves path, mode, staged object and deletion
intent. Only checksummed v3 is accepted. Unknown, empty or corrupt index data
stops operations that rely on staging, including GC; it is never converted or
rebuilt from working files.

**Because:** HEAD and the working file cannot reconstruct a partial selection.

**If violated:** recovery silently replaces staged A with working B or garbage
collect the only copy of staged content.

**Enforced by:** current index checksum/round-trip and unsupported-version
rejection tests, current golden fixtures, and GC no-sweep-on-corruption coverage.

## Pending verification preserves the advance identity

**Always:** a typed pending `AdvanceRefs` response causes a clamped poll, not
a retry-ladder step. Every attempt keeps the same nonce, timestamps and
signature while the envelope remains valid; before the next poll it is renewed
when less than 30 s of validity remains (or the unary timeout, if longer). An
ambiguous retry retains its identity until the envelope actually lapses.
Polling ends before the consumed ticket expires.

**Because:** a pending answer is never stored for replay, and the next attempt
must observe verification progress without changing the logical operation.

**If violated:** an advance can fail after the ordinary retry ladder, use an
expired signature, or keep polling after its ticket is invalid.

**Enforced by:** `ConnectTransport::advance_refs_with_deadline` and its pending
response, renewal and deadline tests. The caller's real ticket deadline is
not yet wired; until then the helper uses the seven-day maximum lifetime.

## External signer capabilities precede signing material

**Always:** the external signer returns compatible protocol, algorithm,
message-size and interaction capabilities before receiving SignRequest bytes.
The request uses a supported key form selected from that response, including
opaque handles for hardware signers with a configured default key.
All subprocess I/O retains frame and wall-clock bounds.

**Because:** advertising capabilities after signing cannot enforce them.

**If violated:** an incompatible signer can perform a request before rejection.

**Enforced by:** external signer no-sign-on-incompatible-handshake regressions,
opaque-handle request-frame and unsupported-key-form regressions, PIN/timeout
subprocess tests and the bundled file signer's end-to-end test.

## Single crypto-stack version across workspaces

**Always:** `ed25519-dalek` and `sha2` are pinned to the same
Cargo-semver-compatible version (for a `0.y.z` crate, `y` is the breaking
component; for `x.y.z` with `x >= 1`, `x` is) in every Cargo workspace that
declares them.

**Because:** several crates independently re-verify signatures/digests the
same byte-for-byte way another crate already does, and the golden-vector
tests (for example `kit-keystore`'s `*_matches_golden_vectors`) assert that
stays true. A
drifted major/breaking version of the same crypto crate across workspaces
can silently diverge in wire-visible behavior (ed25519-dalek 2->3 dropped
the `std` feature and moved error types to `core::error::Error`; a future
bump could change verification semantics) with nothing forcing every
workspace to move together.

**If violated:** nothing fails to compile — each workspace has its own
lockfile, so two incompatible versions of the same crypto crate can coexist
silently. A behavior difference between them (a stricter/laxer signature
check, a different digest padding) would only surface as a hard-to-trace
cross-service inconsistency, not a build error.

**Enforced by:** `scripts/check-crypto-stack-version.sh`, run by the
"Meta: crypto-stack version" workflow on any change to a `Cargo.toml`.

## A live `kit serve` is detectable by local worktree commands

**Always:** every live server process on a root holds a **shared** kernel
lock (`kit_core::repo_lock::acquire_shared`) on `<common_dir>/serve.lock`
for its entire lifetime: `kit serve <path>` (stdin SSH-frame, its only
mode) and any other server process that embeds the same filesystem layout. Every command that acquires `worktree.lock`
or `worktrees.lock` immediately probes that same `serve.lock`
non-blocking-exclusive (`kit_core::repo_lock::probe_exclusive`) and, if it
finds the lock busy, prints a warning to stderr naming the served root
before proceeding. Most commands do this through
`libkit::lock::acquire_worktree` / `libkit::lock::acquire_registry`; the
paths that take `worktree.lock` directly (the `fetch`/`pull` phases in
`remote_dispatch` and `status`'s index refresh) call the same
`libkit::lock::warn_if_served` probe (SPEC-CONCURRENCY §3.1). The one exclusive holder: at startup
`kit serve` tries `serve.lock` exclusively without waiting, and only
while it holds it (no other server is up) sweeps the temp files crashed
uploads left in `packs/` (`.<hex>.tmp.<pid>.<seq>`, at least an hour
old), then takes it shared as above.

**Because:** `kit-transport-file`'s only lock (`<root>/.kit/refs/.lock`)
serializes file-transport instances against *each other*, not against
local worktree mutation or `gc` (SPEC-CONCURRENCY §3.1). Running `kit
gc` or a worktree-mutating command directly against a root a live `kit
serve` is also operating on is unsupported and uncoordinated; without
this invariant, nothing distinguishes that misuse from an ordinary,
safe invocation, and the failure (a `gc` sweep racing a concurrent
push's object write, or a lost ref update) surfaces only as
after-the-fact corruption with no diagnostic pointing at the cause.

**If violated:** a `gc` can silently sweep objects a concurrent `kit
serve` client just uploaded, or a local commit/checkout can silently
lose a race against a client push — both without any warning ever
appearing, leaving an operator no reason to suspect the concurrent-serve
misconfiguration until data is already gone. This is detection only,
not coordination: a direct `kit push kit+file:///path` (bypassing
`kit serve`) and a `serve` that starts *during* an already-in-flight
local critical section both remain undetected — see SPEC-CONCURRENCY
§3.1 for the full statement of what this warning does and does not
cover. Detection does not make a concurrent `gc` safe: SPEC-GC
("Concurrent writers and the grace window") states the condition a
writer outside gc's lock set must meet, which a dedup hit on an old
unreachable object does not meet today.

**Enforced by:** `kit-bin/tests/serve_guard.rs`.

## Single commonware release train across every manifest and lockfile

**Always:** Commonware requirements use the same lower bound (`2026.10.0`)
across manifests. Committed lockfiles select the same release. A move to a
new release changes every manifest and lockfile in one commit.

**Because:** Cargo.lock holds the exact audited version. Commonware-backed kit
wire encodings must retain their pinned bytes when the resolved dependency
changes. A change of the lower bound makes each change of release a reviewed
change.

**If violated:** a compatible release can silently change kit bytes without an
encoder regression.

**Enforced by:** `scripts/check-crypto-stack-version.sh` audits the version
across manifests and committed lockfiles. `scripts/check-dependency-versions.py`
fails when a requirement is not a caret requirement whose lower bound equals the
version in Cargo.lock.

## Windows is not a build, test, or release target

**Always:** no workflow, action, crate manifest, or
installer targets Windows — no `windows-latest` / `pc-windows-msvc` CI
runner, no `backend-windows-credential` / `windows-credential` keystore
feature, no `install.ps1` or Scoop packaging, and no
`[target.'cfg(windows)'.dependencies]` stanza in any `Cargo.toml`.
`BackendKind` has no Windows Credential Manager variant.

**Because:** commonware-runtime 2026.9.0's storage-sync path calls
`libc::sync()` on every non-Linux target (`kit-core`'s
dev-dependencies pull it in) — `libc::sync()` does not exist on `x86_64-pc-windows-msvc`, so the
workspace and its test suite no longer build there. Maintaining a Windows
CI/release leg that cannot actually build or test the workspace would ship
an untested binary, so Windows was dropped as a supported target
rather than worked around. Windows users run kit under WSL, which uses
the Linux binary.

**If violated:** a reintroduced Windows CI leg goes red on every PR (the
workspace fails to build there); a reintroduced Windows release leg ships
a binary no test ever exercised; a reintroduced
`backend-windows-credential` feature reopens a semver-breaking
`BackendKind` variant on a published crate (`kit-keystore`) without the
required major bump.

**Enforced by:** `kit-keystore`'s `windows_credential_backend_name_is_not_recognized` test
(`crates/kit-keystore/src/lib.rs`) pins that `"windows-credential"` is an
unrecognized `BackendKind`/`KeyRef` backend string, not a fail-closed one.

## The default `kit` CLI is server-free

**Always:** the normal dependency graph of `kit-bin` with its default
features, on every target, contains no `axum`, `rusqlite` or `libsqlite3-sys`; it enables no hyper `server` feature, no
hyper-util `server*` feature and no connectrpc `server` or `axum` feature;
and it has `kit-serve` (the engine of `kit serve`), whose own graph has no
`tokio` and no `futures` package. `kit serve` builds no async runtime: it
runs the ssh session on the main thread, and its code names no tokio.
tokio itself is allowed: it is the runtime of the Connect and reqwest
*clients* in the default graph.

**Because:** the CLI is what every user installs (`cargo install
kit-bin`, the release archives). The HTTP server, the
`SQLite` metadata store and their dependencies belong outside the CLI. The
CLI serves only over ssh, through the small `kit-serve` crate. A server stack in the CLI
graph grows the published crate's supply chain, its build time and its
binary, and invites serving code paths the CLI was never reviewed for.

**If violated:** the published `kit` compiles an HTTP server, a C
`SQLite` build or a second async stack that no CLI command needs; the
release check (`scripts/check-release-artifact-features.sh`) then fails
only at release time, where this check fails at the PR.

**Enforced by:** `scripts/check-cli-baseline.sh` (a `cargo tree` model of
the graph plus a grep of `commands/serve/`), run by the
`cli-baseline` step of `cloudbuild/ci.yaml`. The release build's real compiler
artifacts are checked by `scripts/check-release-artifact-features.sh` against
`scripts/release/kit-packages.golden`.

## The zstd decoder accepts exactly one frame per entry

**Always:** a `0x03`/`0x04` entry's payload after `uncompressed_len` is
exactly one RFC 8878 Zstandard frame (SPEC-PACKFILE §3.3). The decoder
(`pack-zstd`) rejects a skippable or pre-RFC frame magic, a second
concatenated frame and any trailing byte, with `PackError::ZstdDecompress`.
It applies the §3.3 bomb guards: the claim is at most `MAX_RAW_OBJECT_SIZE`
before decoding, the output is bounded to the claim, and the decoded length
is checked against the claim. The decoder reserves output fallibly without
zero-filling the claim, and unpack charges the resident budget first. The
decode window is capped at 8 MiB independently of the claim. An
allocation-free preflight checks the frame window, the encoded block sizes,
the reserved descriptor bit and the reserved sequence-mode bits before the
decoder starts. A build without `pack-zstd` fails closed on a compressed
entry.

**Because:** a pack must mean the same objects on every build. A frame one
build accepts and another rejects splits pushes and fetches between them.

**If violated:** a runtime decodes bytes the spec forbids, such as a second
frame's content.

The hand-written frame parsing assembles header fields in `u64`, never
`usize`, so it behaves the same on 32-bit and 64-bit targets.

**Enforced by:** `kit_core::pack::zstd_tests` (`decoder_enforces_one_frame`,
`rejects_adversarial_frames`, `rejects_reserved_sequence_mode_bits`,
`enforces_window_and_block_limits` and
`rejects_oversized_literals_and_block_bodies`), plus
`golden_pack::pack_v2_fixtures::pack_v2_fixtures_decode` over
`rust/tests/golden/pack-v2/`.

## BMT inclusion-proof bytes and sibling selection match commonware exactly

**Always:** `kit_core::merkle::Proof`'s wire bytes (`u32 BE leaf_count ‖
varint(n) ‖ n × 32-byte digest`) and its level-major, self-duplicate- and
already-proven-sibling-omitting selection rule are byte-identical to
`commonware_storage::bmt::Proof` at the pinned `2026.10.0` train, for
single, range, and multi-leaf proofs alike — both directions: kit
decodes and accepts upstream's proof bytes, and upstream decodes and
accepts kit's.

**Because:** SPEC-MERKLE-OBJECTS §5.7 makes this byte-identity a
normative compatibility promise, so a commonware-based verifier (for
example, any other client) can decode and verify a kit proof with the
upstream type directly, applying only kit's outer type-domain wrap
(`wrap_id`) on top. kit cannot depend on `commonware-storage`'s `bmt`
module directly for this (it drags in `commonware-cryptography`'s
unconditional `blst` C dependency — see `merkle.rs`'s module docs), so the
construction is implemented in `kit-core` and the byte-identity claim has
no compiler to enforce it.

**If violated:** a proof kit produces would fail to decode, or would
decode but fail to verify, against an otherwise-correct commonware-based
verifier (and vice versa) — silently breaking cross-implementation
verification with no local test failure, since every kit-only
round-trip test would still pass.

**Enforced by:** `kit_core::merkle::tests::proofs_match_commonware`
(native-only, dev-dependency on `commonware-storage`/`commonware-cryptography`),
which builds many randomised trees and single/range/multi position sets,
asserts kit's encoded bytes equal upstream's `commonware_codec::Encode`
output, cross-decodes each side's bytes with the other's type, and
confirms both verifiers reject a mutated proof (flipped sibling byte,
dropped/added sibling, wrong `leaf_count`).

## Disclosure verification is against object ids only

**Always:** every check `kit_core::verify` performs — a path step, a
chunk, a byte range — is stated against an authenticated object id
(a commit id, a step's `child_id`, a `ChunkedBlob`/chunk id). A v2
bundle carries a bare inner root on each step and chunk header; that
field is wrap-checked against the trusted id (`domain_digest(TYPE_DOMAIN,
inner_root) == expected_id`) **before** it is used for anything, then
cross-checked against the proof fold. No verification step ever treats
a bare inner root, a caller-claimed path string, or an unauthenticated
length/offset as a trust anchor.

**Because:** an inner root is not type-distinct (SPEC-MERKLE-OBJECTS §2),
so accepting one directly would let a `Tree` proof pass for a
`ChunkedBlob` id or vice versa; and a caller-claimed path or offset that
was never itself checked against a proof is exactly the kind of
unauthenticated metadata a disclosure bundle exists to replace with a
proof.

**If violated:** a verifier could be tricked into accepting content at
the wrong path, or into reporting an offset/length nothing in the bundle
actually proves — silently, since the disclosed bytes themselves might
still be genuine content from *somewhere* in the repository, just not at
the claimed location.

**Enforced by:** `kit_core::verify::tests` (`verify_path_rejects_*`,
`verify_chunk_with_meta_bounds`, `commit_id_mismatch_is_rejected`) and
`rust/tests/golden/disclosure/`'s negative vectors (swapped steps, a
wrong-position proof, a forged `ChunkedBlob` meta pair) — SPEC-DISCLOSURE
§4 states this as a numbered MUST at every dispatch point.

## Declared disclosure inner roots wrap and match the proof fold

**Always:** for every v2 disclosure `Step` and chunk header,
`domain_digest(TYPE_DOMAIN, inner_root)` equals the parent Tree id or
ChunkedBlob leaf id, and the proof folds to exactly that declared
`inner_root`. Version byte `1` is rejected.

**Because:** a commonware-native verifier runs upstream
`verify_element_inclusion` / `verify_multi_inclusion` against the
declared root. Without wrap-check-first, a prover could substitute any
tree whose proof verifies against a forged root. Without the fold
cross-check, a bundle could declare a wrap-correct root while attaching
a proof built for a different tree.

**If violated:** an external verifier that trusted the field would
accept content from the wrong tree, or kit and a commonware-native
verifier would disagree on the same bundle.

**Enforced by:** `rust/crates/kit-core/tests/native_commonware_disclosure.rs`
(every accept golden verified with only bundle fields, upstream
`commonware_storage::bmt::Proof`, and `hash::domain_digest`; the three
v2 negatives fail at wrap or upstream verify) and
`rust/tests/golden/disclosure/neg_inner_root_forged.*`,
`neg_inner_root_fold_mismatch.*`, `neg_bundle_version_1.*`.

## Disclosed absolute offsets require a complete length-proof set

**Always:** `DisclosedPayload::Range::absolute_offset` is `Some(...)`
only when either the leaf is a plain `Blob` (nothing to sum) or the
disclosed chunk is index 0 (nothing precedes it), or `chunk_len_proofs`
verifiably covers exactly the index set `0..index` with no gaps and no
duplicates. Any other shape of `chunk_len_proofs` — a gap, a duplicate,
an index `>= index`, or one entry that fails to verify — is a typed
[`VerifyError::IncompleteLengthProofSet`], never a silent `None`. A
*non-empty* `chunk_len_proofs` on a chunk-index-0 range, or on a plain
`Blob` leaf, has nothing preceding it to describe and is rejected
outright as `VerifyError::UnexpectedLengthProofs`, never silently
ignored either.

**Because:** a partial or malformed length-proof set does not sum to a
value that means anything; treating it as "absent" (`None`) rather than
rejecting it outright would let a caller silently miss that an absolute
offset was *claimed but not actually provable*, rather than being told
plainly that the request failed. The chunk-0/plain-`Blob` case is the
same principle at its edge: an entry that describes nothing real is not
merely irrelevant, it is evidence of a malformed or lying builder.

**If violated:** an application relying on `absolute_offset` for, say,
byte-accurate DA-layer indexing could be handed a value derived from an
incomplete sum — or worse, silently receive `None` for a bundle that
*looked* like it was trying to prove one, masking a builder bug or a
malicious short-fill.

**Enforced by:** `kit_core::verify::tests::incomplete_length_proof_set_is_rejected`
and `rust/tests/golden/disclosure/neg_incomplete_length_proof_set.*`;
`kit_core::verify::tests::len_proofs_on_chunk0_are_rejected` and
`rust/tests/golden/disclosure/neg_len_proofs_on_chunk0.*` (SPEC-DISCLOSURE §4/§4.1).

## KDSP spans bind every chunk to one authenticated byte range

**Always:** an accepted KDSP container has one trusted commit, authenticated
path and leaf, a complete preceding length-proof set, and consecutive chunk
bundles. Its absolute boundaries come from verified canonical Blob content
lengths. The requested range starts in the first included chunk and ends in
the last, with no unnecessary last chunk. A malformed container returns its
first SPEC-DISCLOSURE §8.2 reason and no partial output bytes. A range-proof
builder checks untrusted boundary hints against the chunk bytes it reads and
does not read a chunk after the span.

**Because:** a chunk-size marker or unchecked hint is not a proof of a content
boundary, and combining individually valid bundles from different contexts
would not authenticate their concatenation as one requested range.

**If violated:** a caller can receive bytes at the wrong absolute offset or
from the wrong leaf, or accept an incomplete range as a valid disclosure.

**Enforced by:** `kit_core::verify::span` and its unit tests,
`rust/crates/kit-core/tests/golden_http_objects.rs` product/reference parity
and builder byte-identity checks
(SPEC-DISCLOSURE §8 and SPEC-HTTP-OBJECTS §5.2).

## Closure walks share one `children` function

**Always:** every reachability walk &mdash; store-backed
`reachable_objects` / `reachable_closure` / `reachable_snapshot`, the
store-less `verify_closure` BFS, the pull-based `verify_closure_streaming`
walk, push verification (`verify_push`), and push/fetch pack planning &mdash; takes
its edges from `ops::graph::children(obj, mode)`. The verifiers
(`verify_closure*` and `verify_push`) share one BFS, `verify::closure::walk`;
none keeps a walker of its own. Snapshot mode omits
commit/remix parents; history mode includes them; remix `sources` and
`Delta.base_hash` are never followed.

**Because:** a snapshot-vs-history disagreement, or a walker that
followed foreign remix sources, would let two "closures of the same
commit" disagree on the object set, so a DA-layer verifier and a push
could not be checking the same thing.

**If violated:** a history export verified in snapshot mode (or the
reverse) would silently drop or invent objects, and a verifier
walking a hand-rolled map would accept a different set than
`reachable_objects`.

**Enforced by:** `kit_core::ops::graph::tests::children_snapshot_omits_parents_history_includes_them`,
`reachable_snapshot_excludes_parent_commit`,
`kit_core::verify::closure::tests::history_on_snapshot_reports_parent_missing`
/ `snapshot_on_history_reports_parent_unreferenced`, and
`kit_core::verify::push::tests::history_vs_snapshot` /
`remix_sources_never_followed`.

## Streaming closure verification reads only reachable objects, each once

**Always:** `verify_closure_streaming` and `verify_push` queue and fetch each visited id at
most once (so repeated references do not grow the queue), fetch no id outside the selected snapshot/history closure, and drops an
object's bytes after extracting its child ids; it reports
`unreferenced_checked = false` because it cannot enumerate objects it never
requested.

**Because:** local closure verification must scale with the checked closure,
not with the size of the repository's unrelated object store, while a
duplicate or out-of-closure fetch would defeat the source's bounded,
pull-based contract.

**If violated:** a large local store can turn a small closure check into an
O(store-size) memory operation, or a buggy mode walk can silently inspect
foreign/unreachable objects and misrepresent what was verified.

**Enforced by:**
`kit_core::verify::closure::tests::streaming_fetches_each_reachable_object_once_and_only`,
which uses a counting source that panics on unknown ids and checks the exact
snapshot/history fetch sets, and
`kit_core::verify::push::tests::each_object_fetched_once_across_multiple_tips`
and `kit_core::verify::closure::tests::repeated_child_ids_are_queued_once`.

## Push verification and delta bases resolve only within the pushing repository

**Always:** `verify_push` reads objects only through the `ObjectSource` its
caller supplies, and stops only at ids the caller's `known` accepts; a
`known` id is neither fetched nor descended. A server supplies a source
limited to the pushing repository's members plus the pushed objects, and
`known` holds only for objects whose whole closure (in the walk's mode) was
already verified in that repository. Every fetched object is re-hashed, and
every commit, remix and tag has its signature checked
(`sign::verify_object_signature`), before any ref moves. Likewise a delta's
external base comes only from the `pack::DeltaBaseSource` the decoder is
given: the local `ObjectStore` on a client, the repository's membership on a
server, never a global content store. A source that does not have a base
and a source that may not serve it give the same `DeltaBaseMissing` error;
an unverified source's bytes are re-derived, so a wrong object is never
used as a base.

A `known` tip is skipped whole, including the commit/remix/tag type check
`verify_push` applies to every fetched tip. Callers MUST type-check known
tips themselves (from their index) before moving a ref to one.

`decode_entries_with` is bounded by the caller's `DecodeLimits`: every
`0x03`/`0x04` claim and every delta's declared result length is charged
before it is materialised, and every external base from the
`DeltaBaseSource` as it is fetched. An entry or external base stays
resident only until the last delta that names it; an external base's
charge is then credited back. The budget is per call: a server sizes it
from its isolate limit and decode concurrency. `PackReader::read` instead
uses the separate peak resident cap below. Compressed and delta claims
accumulate under `DecodeLimits`; resident reservations are released on
last use. `ObjectStore` base admission charges before allocation through
the provided `DeltaBaseSource` method; existing sources default to charging
the bytes returned by `base()`.

**Because:** repository isolation forbids existence oracles. If a push could close its
history, or resolve a delta, over objects held only by another repository or
the global store, the push's success would reveal that some other repository
holds those objects, and the repository would reference objects it never
held. A `known` that meant "exists somewhere" would skip verification of
content this repository never checked.

**If violated:** a pusher could probe for private content by pushing deltas
or commits over guessed ids, or land a ref whose history includes unverified,
unsigned or foreign objects.

**Enforced by:** `kit_core::verify::push::tests` (`frontier_stop` and
`known_tip_is_noop`, whose source panics on any fetch past the frontier;
`unsigned_commit_rejected`, `forged_tag_rejected`, `remix_signature_checked`,
`wrong_bytes_for_id_is_corrupt`) and `kit_core::pack::tests`
(`external_base_outside_source_is_delta_base_missing`,
`untrusted_source_returning_wrong_bytes_is_rejected`,
`decode_with_no_external_bases_matches_reader`,
`delta_bomb_is_rejected_before_any_delta_is_applied`,
`compressed_claims_are_charged_before_decompression`,
`external_bases_are_charged_against_the_budget`). The server-side wiring and
the cross-repository uniform-error conformance test belong to the server.

## Closure profile is raw-only

**Always:** a closure pack is SPEC-PACKFILE v1 with only `0x00` entries.
`PackWriter::new_raw_only` never compresses and rejects deltas.
`verify_closure_packs` treats any delta or compressed entry as
`VerifyError::ClosureProfileViolation` after a type scan that does not
decompress.

**Because:** a verifier can build `kit-core` with `default-features =
false` (no zstd). A compressed or delta pack would be unreadable there,
so the profile that such a verifier consumes has to be raw-only by
construction.

**If violated:** a native exporter could emit a v2 pack that a
verifier without zstd rejects (or, without the type scan, tries to decompress and
hits the `pack-zstd` stub), splitting the verifier kit into two
incompatible carriers. The type scan runs first, so a compressed entry is a profile violation,
not a decoded object.

**Enforced by:** `kit_core::pack::tests::raw_only_writer_emits_v1_raw_for_compressible_payload`,
`raw_only_writer_rejects_deltas`,
`kit_core::verify::closure::tests::delta_pack_is_profile_violation`,
and `rust/tests/golden/closure/neg_delta_entry.*` /
`neg_compressed_entry.*`, and
`golden_pack::pack_v2_fixtures::closure_profile_still_rejects_compressed_entries`
(every feature combination, including a frame corrupted past decoding).

## Windowed pack entries stay provisional until complete verification

**Always:** `pack::window` yields the same entry values as `PackEntries` when
resource limits do not bind, and returns `Done` only after framing, the trailer,
and any expected whole-pack id pass. Drivers discard all staged entries on
any error, including entries yielded before a checkpoint.

**Binding.** `Done` means every entry yielded across the whole run chain (the original run and every resume
through its cursors) is an entry, in order, of the one pack whose bytes hash to the verified pack id: the trailer,
and `expected_pack_id` when set. A cursor from pack A used on a source that yields different bytes for any
not-yet-verified range fails with `PackfileCorrupted`, never `Done`. The reader does not re-read ranges it has
already verified. **Keeping the source immutable across resumes is the caller's job**;
for example, an object-store adapter can pin range reads to one object version. A source whose already-verified prefix changed after verification can still
reach `Done`, but only with entries of the verified pack.

A `None` checkpoint means keep the previous cursor. After a boundary-state `None` (the trailer phase), resuming re-reads at most one window plus the trailer; after a mid-entry `None`, it re-reads every window the unfinished entry spans.

**Because:** a streaming trailer check occurs after entries have been delivered;
completed-window CVs and the incremental current-window prefix commitment bind the
entries staged across resumes without re-reading completed ranges.

The live prefix state has two fixed-size BLAKE3 hasher slots and a window-relative
length bounded by 64 MiB. Each checkpoint absorbs only newly consumed bytes;
repeated checkpoints finalize that state without rereading the prefix. Callers
that never checkpoint do no prefix hashing. An inline once-cell preserves
concurrent read-only checkpoint calls. Advancing the reader moves its cached
incremental state forward and clears the boundary cache. Cold resume
authenticates the prefix once and reconstructs this state. Only the existing
explicit subtree commitments and prefix digest enter the cursor encoding.

The opt-in one-pass reader keeps acquired windows through carried-frame decode.
Its exact-boundary cursor instead retains explicit subtree frontiers through
the acquired end, the collected trailer, and a commitment to the unconsumed
suffix. Cold resume requests that suffix from the entry boundary and verifies
it without hashing it into the frontiers again. Integrity-only drain checkpoints
resume at the acquired end. Both forms keep private hash-library memory out of
their encodings. Exact checkpoint creation charges suffix hashing as work;
decoder reservations use the next frame's actual wire geometry and scratch
requirement before allocation.

**If violated:** malformed packs or mismatched cursor/source pairs can publish
partially verified data.

**Enforced by:** `rust/crates/kit-core/src/pack/window/tests.rs` differential,
resume, cursor-binding, released-window, resource-budget, and trailer-split tests.
Caller staging rollback and
source immutability remain obligations of the caller; the core reader does not store objects.

## Cursor metadata preserves validation and private state

**Always:** `WindowCursor::metadata` applies the existing cursor geometry and
frontier validation before returning copied bindings through read-only accessors.
Inspection leaves cursor bytes unchanged and exposes no constructor or mutable
cursor state.

**Because:** outer checkpoints must bind opaque reader progress without copying
the cursor grammar or bypassing its validation.

**If violated:** callers could restore progress under mismatched source geometry
or mistake a metadata snapshot for source authentication.

**Enforced by:** cursor metadata boundary/round-trip, fixed-byte and invalid-state
regressions in `pack/window/tests.rs`, plus private-field compile-fail rustdoc
examples. Source binding and final reader verification remain required.

## Pack exclusions preserve surviving objects and delta bases

**Always:** a pack rewrite drops every excluded entry and rawifies a surviving
delta only when its direct base is excluded. Surviving bytes and entry order
are preserved; an unchanged pack keeps its original bytes. Rewrites use the
existing `DecodeLimits` charged-payload accounting; the caller supplies
repository-scoped bases.

**Because:** deleting a delta base otherwise makes retained objects undecodable;
transitive rawification adds size without improving decodability.

**If violated:** a takedown can corrupt unrelated objects or reveal external
object membership.

**Enforced by:** `pack::rewrite::tests` (128 property cases, chains of depth 1–5,
external bases, duplicates, compressed fixtures and budget/error checks).

## Client repository addressing and capabilities remain stable

**Always:** the Connect client validates the literal remote path without repairing
its spelling and sends the resulting identity on every RPC. Signed writes bind
that same value. A transport caches its first capability discovery outcome and
claims atomic advance only for a validated v2 advertisement with an explicit
true value. Ref hints never enter the signed canonical string.

**Because:** routing must agree with authentication, and a push must not reset a
packmap based on an unsupported or changing atomicity assumption.

**If violated:** a client can address an unintended repository or strand a head
behind a packmap reset that was not committed atomically.

**Enforced by:** Connect `client::tests::url_identity_table_preserves_literal_paths`,
`envelope::tests::parity`, `tests/v2_client.rs` discovery and paging regressions,
and CLI `tests/remote_dispatch_connect.rs` header capture.

## Pack unpack bounds owned payload residency

**Always:** unpack charges decompressed payloads, delta targets and cached store
bases before allocation against `max(2 × MAX_RAW_OBJECT_SIZE, 16 × pack_len)`.
Raw wire payloads stay borrowed; a base is released after its final delta use.
Decompression writes into reserved capacity without initializing the claimed
size first. Raw staging skips positions after its earliest permanent failure;
transient worker admission failures are retried strictly in pack order.
Framing arithmetic rejects out-of-bounds lengths.

**Because:** authenticated or malicious packs must not exhaust memory through
entry decompression or retained delta targets.

**If violated:** fetch, clone or pull can deny service.

**Enforced by:** `pack::tests` resident-peak, bomb, retention-equivalence and
maximum-wire-length regressions.

## Connect read authentication is scoped to one attempt

**Always:** a Connect client with a signer signs each repository read over
the exact HTTP request body, including streaming-request framing. Each retry
has fresh identity headers. Writes retain their logical-operation nonce, and
the grant header stays outside the signed canonical string. Discovery and
grant-epoch RPCs are never signed; grant-epoch RPCs carry no repository.

**Because:** read authentication selects the writer or private-reader view,
while replay protection applies only to writes. A grant is selected locally
and may change without changing the authenticated operation.

**If violated:** a private read can become anonymous, a retry can use an
expired identity, or a write can silently mint a new nonce.

**Enforced by:** the Connect procedure classification and envelope tests,
client retry tests, and `kit_core::write_auth::verify_headers` checks over
captured request bodies.

## Native HTTPS extra trust

**Always:** Native Connect HTTPS retains the compiled Mozilla roots and verifies
both the certificate chain and hostname. `KIT_SSL_CA_FILE` overrides the merged
`http.sslCAInfo` path; selected invalid files fail before any request dispatch.
**Because:** Extra local trust must authorize certificates explicitly without
silently downgrading verification or losing the normal public trust store.
**If violated:** A local trust option could admit an impersonated remote, or a
bad file could silently use another trust configuration.
**Enforcement:** `kit-transport-connect::tls::client_config` builds rustls with
augmented roots and its standard verifier. Real TLS Connect/streaming tests
cover trusted CA, hostname mismatch and default refusal; subprocess tests cover
selection and CLI config layering. Browser clients keep browser-managed trust.

## Timestamp-priority history traversal is bounded and exact

**Always:** the shared `TimestampDiscovery` reducer emits all-parent history in
decreasing canonical `Commit.timestamp`/`Remix.timestamp` order with
retained-discovery ties — never a hash tiebreak, never a topological gate. The
pending frontier never exceeds 256 verbatim slots and the emitted set never
exceeds 192 ids; crossing either bound fails the operation with no partial
state. Dedup goes live with the first revisitable emission (a
multi-local-parent node, or any emission while candidates remain pending) and
records every later emission; decoded is not emitted, and parent enqueue
completes before any snapshot. Seeding closes at the first completed emission
so a late seed cannot descend into the unrecorded linear prefix.

**Because:** server issuance/redemption and embedder page loops must produce
byte-identical pages from the same state without re-walking the emitted
prefix; a skipped ancestor or duplicate emission is a conformance break, and
unbounded seen state cannot travel in a bounded token.

**If violated:** pages could repeat or drop commits, drift between
implementations, or grow a continuation token without bound.

**Enforced by:** `kit-core::history_order` reference reducer and
[SPEC-HISTORY-ORDER](specs/SPEC-HISTORY-ORDER.md); fixture, page-boundary,
snapshot round-trip and explicit cap tests, plus proptest
split-vs-single-run equivalence.

## Native client headers and request budgets

**Always:** `NativeHttp` preserves supplied user-agent and gzip/identity-only
accept-encoding values, refuses unsupported or malformed negotiation before
connecting, and bounds each HTTP exchange through response receipt. Metadata
uses a 30-second default; UploadPack, UploadPart and DownloadPack use 300 seconds.
The two budgets can be configured independently.

**Because:** observer headers replace transport defaults, and metadata work
must not inherit a pack-transfer deadline.

**If violated:** host attempt policy could be silently replaced, unsupported
responses negotiated, or metadata connections held open for too long.

**Enforced by:** `kit-sync::NativeHttp::send_typed`, `request_headers`, and the
`native_http` header-preservation, negotiation-refusal and timeout tests.

## Complete ref listings retain bounded, strictly ordered state

**Always:** all three listing drivers use `kit_core::ref_listing::RefListing`.
Names increase strictly within and across pages, including empty intervening
pages. Each nonempty cursor is at most 4 KiB and appears once. Cursor history
retains only BLAKE3 digests. A listing accepts at most 100,000 pages and charges
names, ref entries, digest history, and the active cursor to 128 MiB. A caller's
lower page limit still applies. Invalid state fails before the page is retained.

**Because:** a remote server controls page contents and continuation tokens.
Empty pages must not bypass resource limits or cursor-cycle detection.

**If violated:** a remote can exhaust memory, loop a listing, or expose duplicate
or inconsistent refs to a caller.

**Enforced by:** the shared accumulator, `Client::list_refs` page validation,
core budget/page-cap tests, and `shared_listing_adversaries` in each driver.

## Fetch checkpoints follow verified tracking publication

**Always:** a native fetch checkpoint binds its remote branch to a repository
identity and origin, and records only a fully applied, verified packmap chain.
Fetch publishes the tracking ref durably before the checkpoint under the same
worktree lock. An unchanged remote tip and head download nothing. Every listed
tip still passes locked closure verification; new nodes retain digest and
signature checks.
Missing local objects trigger full-chain recovery before publication.

**Because:** immutable packmap nodes permit skipping verified ancestors, but
an unpublished or differently addressed checkpoint cannot establish local safety.

**If violated:** fetch could skip new content, fail to restore missing objects,
or publish an unverified branch after a crash or concurrent operation.

**Enforced by:** `kit-sync::fetch`, checksummed `checkpoint` records, bounded
`walk_pack_chain_until`, counting-source regressions on both backends, and crash,
concurrent-pull, identity-change, and signature-failure regressions.

## Sync source outcomes retain host scheduling evidence

**Always:** `RemoteSource` returns backend-neutral `SourceError`. Verification
and visibility waits, retry hints, payment challenges, signing failures, and raw
Connect code/message/details/status/headers survive the client adapter and
`SyncError::Source`. Classified core transport errors map explicitly. Sync
returns resumable outcomes without sleeping or retrying; refusal and transient
failure remain distinct. Observed signed clients compose without read callbacks.

**Because:** the host owns scheduling and admission policy, and deterministic
channel refusals must not become retryable connection failures.

**If violated:** hosts lose recovery evidence or retry terminal refusals, and
configured clients cannot be used through the sync adapter.

**Enforced by:** `kit-sync` source adapter tests for both backends, remote
metadata/overload tests, and `observed_signed_client_composes_as_source`.
CLI transport display parity and the existing CLI golden suites retain output
and exit-code behavior. No authorization, wire, or stored-format boundary moves.


## Client source writes keep policy and receipt durability in the host

**Always:** signed source writes use `kit-client` per-RPC calls. The host
selects grants on each signed envelope and schedules typed failures through
`WriteRecovery`. Ticket-consuming writes never run admission recovery. Each
part receipt finishes caller-owned durable `put` before progress or the next
part. Fresh instances recover the open ticket and reuse only matching receipts.

**Because:** wire ownership belongs to the protocol client, while credential
trust, helpers, scheduling, and filesystem durability depend on the caller.

**If violated:** policy could authorize the wrong request, or a restart could
resend an acknowledged part or advance refs without its upload commitment.

**Enforced by:** request-policy seam tests and both-backend native push tests,
including multipart interruption and receipt reuse across fresh instances.
