# kit specifications

The authoritative wire-format, on-disk, and subsystem specifications.
Each spec carries its own `status` (stable / normative / draft) in its
front matter.

[FORMAL.md](../FORMAL.md) maps spec clauses to the formal models and
proofs that check them, with each result's bounds.

- [SPEC-ATTESTATIONS](SPEC-ATTESTATIONS.md) &mdash; native attestations: in-toto v1 statements in DSSE envelopes.
- [SPEC-CONCURRENCY](SPEC-CONCURRENCY.md) &mdash; the total kit lock order across worktree, ref-history, and CAS locks.
- [SPEC-CONFIG-SECURITY](SPEC-CONFIG-SECURITY.md) &mdash; user-vs-repo config trust boundary and key classification rules.
- [SPEC-CONVENTIONS](SPEC-CONVENTIONS.md) &mdash; shared vocabulary (RFC 2119 keywords, status vocabulary, encoding notation) for the SPEC-*.md corpus.
- [SPEC-DELTA](SPEC-DELTA.md) &mdash; delta encoding for packfile objects.
- [SPEC-DISCLOSURE](SPEC-DISCLOSURE.md) &mdash; partial-disclosure bundle (path/chunk/byte-range proofs) and the closure profile (full disclosure against a commit id).
- [SPEC-EXTERNAL-SIGNER](SPEC-EXTERNAL-SIGNER.md) &mdash; subprocess protocol for out-of-process signers (HSM, TPM, WebAuthn, …).
- [SPEC-FASTCDC](SPEC-FASTCDC.md) &mdash; deterministic content-defined chunking for chunked blobs.
- [SPEC-GC](SPEC-GC.md) &mdash; garbage collection, object pruning, and recovery.
- [SPEC-GIT-BRIDGE](SPEC-GIT-BRIDGE.md) &mdash; kit→git export bridge (fork mode) and its verifiers.
- [SPEC-GIT-IMPORT](SPEC-GIT-IMPORT.md) &mdash; git→kit import bridge (one-way fork) and its verifiers.
- [SPEC-HISTORY-ORDER](SPEC-HISTORY-ORDER.md) &mdash; bounded timestamp/discovery all-parent traversal order and reducer snapshot format.
- [SPEC-HISTORY-PROOF](SPEC-HISTORY-PROOF.md) &mdash; MMB-based history proofs for light-client verification.
- [SPEC-HTTP-OBJECTS](SPEC-HTTP-OBJECTS.md) &mdash; HTTP object serving, published-view access, and disclosure proofs.
- [SPEC-INDEX](SPEC-INDEX.md) &mdash; repo-local staging-area index (advisory, not exchanged).
- [SPEC-KEYSTORE](SPEC-KEYSTORE.md) &mdash; key vault interface, backends, and `kit key` CLI surface.
- [SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md) &mdash; merkelized ChunkedBlob and Tree object hashing.
- [SPEC-OBJECTS](SPEC-OBJECTS.md) &mdash; on-disk object model and canonical serialization over BLAKE3 IDs.
- [SPEC-PACKFILE](SPEC-PACKFILE.md) &mdash; packfile wire format for object exchange.
- [SPEC-REFS](SPEC-REFS.md) &mdash; ref names, storage, and CAS update variants.
- [SPEC-RELEASE-THRESHOLD](SPEC-RELEASE-THRESHOLD.md) &mdash; BLS threshold signatures for release-party attestation.
- [SPEC-RPC](SPEC-RPC.md) &mdash; shared stdio protobuf framing for subprocess protocols.
- [SPEC-SIGNING](SPEC-SIGNING.md) &mdash; commit / remix / tag signing hashes and verification.
- [SPEC-SPARSE-CHECKOUT](SPEC-SPARSE-CHECKOUT.md) &mdash; verifiable server-side sparse checkout over HTTP/S3.
- [SPEC-TRANSPORT](SPEC-TRANSPORT.md) &mdash; seven-verb transport wire protocol (file, SSH, HTTP via SPEC-TRANSPORT-CONNECT, S3, memory).
- [SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md) &mdash; draft `kit.transport.v1` Connect service, the canonical remote protocol for `kit+https` remotes.
- [SPEC-WORKTREE](SPEC-WORKTREE.md) &mdash; linked working trees: common-dir/per-tree state split, discovery, and cross-worktree locking.
- [SPEC-WRITE-GRANTS](SPEC-WRITE-GRANTS.md) &mdash; draft owner-signed grants that let Ed25519 keys write to, or read from, a namespace's repositories.

## Specs kept outside this repository

Some specs cite SPEC-SERVER and SPEC-PRIMITIVE-EVIDENCE. These two specs
define the server side of the protocols. They are not part of this tree.
A citation of either spec names a rule that a server implementation must
follow. The client rules in this tree do not depend on the text of those
specs.
