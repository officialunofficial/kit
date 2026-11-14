# ARCHITECTURE &mdash; kit code map

Status: **Informative**. Audience: contributors and integrators who
need to find where something lives and how the pieces connect.

This document is the index. Normative shape lives in `SPEC-*.md`.

---

## 1. Workspace layout

The Rust workspace lives under `rust/`. Crate boundaries match
responsibility boundaries &mdash; there is no "common" or "utils" crate.

| Crate                          | Path                                  | Purpose                                                                |
|--------------------------------|---------------------------------------|------------------------------------------------------------------------|
| `kit-core`                    | `rust/crates/kit-core/`              | Object store, packs, refs, index, worktree, ignore, repo lock, ops, signing, protocol framing, `verify`/`verify::closure` (partial/full disclosure) |
| `kit-attest`                  | `rust/crates/kit-attest/`            | JCS canonical JSON, in-toto v1 Statement, DSSE envelope, signers, verifiers |
| `kit-keystore`                | `rust/crates/kit-keystore/`          | Key vault interface and backends (`specs/SPEC-KEYSTORE.md`)                  |
| `kit-git-bridge`              | `rust/crates/kit-git-bridge/`        | Git import/export bridge incl. fork mode (`specs/SPEC-GIT-BRIDGE.md`)        |
| `kit-rpc`                     | `rust/crates/kit-rpc/`               | Shared stdio framing for subprocess protocols (`specs/SPEC-RPC.md`)          |
| `kit-transport-memory`        | `rust/crates/kit-transport-memory/`  | In-process transport, used by tests                                    |
| `kit-transport-file`          | `rust/crates/kit-transport-file/`    | Local-filesystem transport; CAS under per-ref stripe locks, a create through `link(2)` |
| `kit-client`                  | `rust/crates/kit-client/`            | Runtime-independent async protocol client for kit servers: reads, signed writes and ticketed push, native and wasm |
| `kit-transport-connect`       | `rust/crates/kit-transport-connect/` | ConnectRPC client implementing `kit.transport.v1.TransportService` (`specs/SPEC-TRANSPORT-CONNECT.md`); the transport `kit-bin` actually constructs for `kit+https://` / `kit+http://` |
| `kit-transport-s3`            | `rust/crates/kit-transport-s3/`      | Hand-rolled SigV4 transport (S3-compatible conditional writes)           |
| `kit-transport-ssh`           | `rust/crates/kit-transport-ssh/`     | Spawns system `ssh(1)`; framed protocol over stdio                     |
| `kit-serve`                   | `rust/crates/kit-serve/`             | Self-host server: the `kit.rpc.v1.ssh` frame session over a repository on disk; `kit serve` is a thin wrapper |
| `kit-sync`                    | `rust/crates/kit-sync/`              | Native clone/fetch/pull for `.kit` repositories as a library: typed reports, no printing, no ambient config; `kit clone`/`fetch`/`pull` are thin wrappers over it |
| `libkit`                      | `rust/crates/libkit/`                | The facade crate for embedders. It re-exports `kit-core`, `kit-attest` and `kit-keystore` always. It re-exports `kit-sync` under the default feature `sync`. The features `git-bridge`, `transport-file`, `transport-ssh`, `transport-s3` and `transport-connect` add one crate each. The features `history-mmr` and `sparse-checkout` forward to `kit-core`. |
| `kit-bin`                     | `rust/crates/kit-bin/`               | The `kit` binary; thin glue over the library crates                   |
| `kit-wasm`                    | `rust/crates/kit-wasm/`              | WebAssembly bindings for the byte-format and crypto paths; published to npm as `@officialunofficial/kit-wasm`, not to crates.io |
| `kit-fuzz`                    | `rust/fuzz/`                          | cargo-fuzz harnesses (`docs/FUZZ.md`)                                  |
| `kit-sign-file`               | `rust/crates/kit-sign-file/`         | Reference external signer; protocol conformance baseline               |

The `libkit` crate does not re-export `kit-bin`, `kit-serve` or `kit-rpc`.
[`LIBKIT.md`](LIBKIT.md) is the usage guide.
`kit-bin` is the command line. `kit-serve` is the self-hosted server. `kit-rpc`
holds the wire framing for the signer and server protocols. `kit-client`,
`kit-transport-memory` and the test crates are not re-exported either.

The `kit-sign-file` crate is the only external signer that ships. It
communicates with `kit` over the protocol defined in
`specs/SPEC-EXTERNAL-SIGNER.md`.

### 1.1 Optional kit-core features

`kit-core` has two optional features. Both are off by default. Other
crates enable them through their own features. Kept code depends on both,
so the modules stay.

| Feature | Module | Lines | Kept code that needs it |
|---|---|---|---|
| `history-mmr` | `history.rs`, `history/ancestry.rs` | 2,641 | `refs.rs` and `refs/ancestry_state.rs` (ref-write journal), `kit-sync` `worktree.rs`, and in `kit-bin` the `branch`, `commit`, `reflog`, `reset` and `update-ref` commands. The `kit-formal-conformance` ref test and `docs/specs/SPEC-HISTORY-PROOF.md` also cite it. |
| `sparse-checkout` | `sparse.rs` | 536 | In `kit-bin`: `sparse_cache.rs`, the `--sparse` option of `clone` and `checkout`, and the `sparse_checkout_local` test. Also the `sparse-checkout` feature of `kit-transport-s3`, the `sparse_verify` fuzz target and the `layout.rs` witness cache directory. `docs/specs/SPEC-SPARSE-CHECKOUT.md` specifies the wire format. |

Removing one of these modules means removing every item in its row.
The spec text goes in the same change as the code.

### 1.2 Owner signature schemes

The grant owner schemes `secp256k1-eip191` and `webauthn-p256` stay.
The decision is to keep the code and the spec text together.

- `kit-attest` `eth.rs` (Keccak-256, EIP-191 digest, address derivation)
  is the base of both schemes and of the `0x` namespace address.
- `kit-attest` `grant/owner.rs` and `grant/webauthn.rs` verify the
  schemes. `kit-bin` `grants/owner.rs` signs with them.
- `kit grant`, `kit epoch` and `kit visibility` use them. `docs/CLI.md`
  and `docs/specs/SPEC-WRITE-GRANTS.md` section 4 describe them.
- The grant golden vectors and `scripts/golden/grants_ref.py` check them.

A removal has to take out all of these in one change, with the
`0x` namespace rule in `repo_identity`. No code is dead today, so the
spec text stays.

### 1.3 Size

Counts are lines of Rust (`wc -l`) in files that git tracks, per crate, as of
this writing. The Source column counts `src/`, including unit tests
that sit in the same file. The Tests column counts every other `.rs` file
in the crate, such as `tests/`. The Generated column counts the
checked-in generated code. The `kit-fuzz` row counts `rust/fuzz/`. The
`kit-benches` row counts `rust/benches/`. Rows sort by Total, largest first.
Each Total is Source plus Tests plus Generated.

| Crate | Source | Tests | Generated | Total |
|---|---:|---:|---:|---:|
| `kit-core` | 76,177 | 11,576 | 0 | 87,753 |
| `kit-bin` | 32,401 | 43,436 | 0 | 75,837 |
| `kit-rpc` | 985 | 175 | 50,438 | 51,598 |
| `libkit` | 25,660 | 7,226 | 0 | 32,886 |
| `kit-attest` | 12,899 | 6,409 | 0 | 19,308 |
| `kit-sync` | 12,871 | 4,579 | 0 | 17,450 |
| `kit-transport-connect` | 5,357 | 6,840 | 0 | 12,197 |
| `kit-client` | 6,582 | 3,105 | 0 | 9,687 |
| `kit-git-bridge` | 4,944 | 2,873 | 0 | 7,817 |
| `kit-keystore` | 6,210 | 219 | 0 | 6,429 |
| `kit-fuzz` | 4,003 | 1,225 | 0 | 5,228 |
| `kit-wasm` | 3,171 | 1,279 | 0 | 4,450 |
| `kit-serve` | 2,077 | 1,692 | 0 | 3,769 |
| `kit-transport-s3` | 2,153 | 1,513 | 0 | 3,666 |
| `kit-transport-file` | 3,527 | 0 | 0 | 3,527 |
| `kit-benches` | 1,347 | 1,725 | 0 | 3,072 |
| `kit-transport-ssh` | 2,207 | 0 | 0 | 2,207 |
| `kit-sign-file` | 445 | 421 | 0 | 866 |
| `kit-formal-conformance` | 10 | 722 | 0 | 732 |
| `kit-transport-memory` | 499 | 0 | 0 | 499 |
| `kit-test-util` | 156 | 0 | 0 | 156 |
| **All crates** | **203,681** | **95,015** | **50,438** | **349,134** |

Generated code is a documented exception to the rule against checked-in
generated output. The code generator needs `protoc`, and many hosts ship a `protoc` too old
for protobuf edition 2023. A normal build needs neither, because
`rust/crates/kit-rpc/generated/` stays in the tree. The
README in that directory gives the reason.
`scripts/check-generated-fresh.sh` regenerates the code and fails when the
checked-in copy differs. Only `kit-rpc` holds generated code.

### 1.4 What stays in the CLI

Four items stay in `kit-bin`. They are the `kit mcp`, `kit serve` and
`kit self` commands, and the `progress` module. `libkit` does not
re-export them.

| Item | Why it stays |
|---|---|
| `kit mcp` | It speaks a protocol on stdin and stdout. It runs each tool by starting this same binary, so it needs the CLI. The optional `mcp-v2` feature adds a network runtime. `libkit` stays free of it. |
| `kit serve` | It is a thin wrapper over `kit-serve`. It owns the process stdin, stdout and idle timer. An embedder that wants the server depends on `kit-serve` directly. |
| `kit self` | It replaces the running executable. It reads the installer receipt and calls `cosign`. A library has no executable to replace. |
| `progress` | It prints to the terminal. It is the CLI implementation of `Observer`. `libkit` exposes the `Observer` trait. The embedder supplies its own observer. |

Every other command is a thin layer over library code. Its logic moves
into `libkit` over time. The CLI keeps argument parsing, printing and
exit codes. The logic of `kit log`, `kit show`, `kit diff`, `kit blame`,
`kit branch`, `kit remote`, `kit worktree`, `kit mv`, `kit status`, `kit add`,
`kit commit`, `kit merge`, `kit rebase`, `kit key`, `kit attest`,
`kit verify-attest` and `kit git` is in `libkit::log`,
`libkit::diff`, `libkit::blame`, `libkit::branch`, `libkit::remote`, `libkit::linked`,
`libkit::mv`, `libkit::status`, `libkit::add`, `libkit::commit`,
`libkit::merge`, `libkit::rebase`, `libkit::keys`, `libkit::attest_signer`,
`libkit::attestation` and `libkit::git` already. The conflict
workflow of a paused operation is in `libkit::conflict`. The key code of
`kit commit`, `kit tag` and the other signing commands is in
`libkit::signer`. `libkit::merge` and `libkit::rebase` never load a key. The
command gives them a `libkit::signing::Signing`, and the library asks that
value for the key when it writes a commit. The plan of
`kit push` is in `libkit::push`. The transfer of `kit push`, `kit pull`,
`kit fetch` and `kit clone` is in `libkit::transfer`. It holds the transfer
operations, the one error type of a transfer, the reading of a remote URL, the
opening of a transport, the signer of a request envelope and the
credential-trust gate. The header checks, the field spellings, the grant store
and the grant choice of a Connect client are in `libkit::grants`. The owner
signing of `kit grant`, `kit epoch` and `kit visibility` stays in `kit-bin`.

Three parts of the transfer stay in `kit-bin`, in the `remote_dispatch`
module.

| Item | Why it stays |
|---|---|
| The assembly of a Connect transport | It connects the transport to the terminal progress, to the shutdown signal, to the admission helper process and to the warnings on stderr. These are the process of the CLI. `libkit::transfer` gives it the parts: the opener, the signer, the grant choice and the trust gate. |
| The cache of upload receipts | It writes its cleanup problems to stderr while an upload runs, and it has no caller to return them to. The path under the repository is a choice of the CLI. An embedder passes any `PartReceiptStore` to the transport. |
| The reading of `KIT_PACK_REBASELINE_DEPTH` | The library never reads the environment. The CLI reads the variable and passes the depth in `PushSettings`. |

Two decisions are proposals. They are not part of this release.

- **FFI and bindings.** This release ships none. The Rust API is not
  stable yet. A binding would freeze it too early.
- **Server through `libkit`.** `libkit` does not expose the server.
  The server holds write policy and a network surface. A library user
  can still depend on `kit-serve` by choice.

---

## 2. Data flow: object → pack → ref → transport

```
write path                                read path
==========                                =========

bytes                                     transport
  │                                         │
  ▼                                         ▼
chunker (FastCDC)                         pack reader
  │   SPEC-FASTCDC                          │   SPEC-PACKFILE
  ▼                                         ▼
object encoder                            object decoder + verify
  │   SPEC-OBJECTS §2 prologue              │   BLAKE3 verify on read
  ▼                                         ▼
content-addressed store                   refs
  │   .kit/objects/<dd>/<hex62>            │   SPEC-REFS
  ▼                                         ▼
pack writer                               worktree materialize
  │   SPEC-PACKFILE                          │   symlink containment
  ▼                                         ▼
transport                                 user
  └─── SPEC-TRANSPORT 7-verb wire ──────────┘
```

Every stage validates the previous stage's output. Decoders refuse
oversized allocations; the FastCDC chunker is fully deterministic
(frozen seed, SPEC-FASTCDC §3.1); object readers re-hash bytes before returning.

---

## 3. Merkle-root object identity

`Blob`, `Commit`, `Remix`, and `Tag` take their object ID from a flat
BLAKE3 digest of their canonical bytes. `Tree` and `ChunkedBlob` do
not: their ID is the domain-bound root of a Binary Merkle Tree (BMT)
built over their parts &mdash; one leaf per entry for a `Tree`, and a
metadata leaf plus one leaf per chunk for a `ChunkedBlob`. The
construction is normative in `docs/specs/SPEC-MERKLE-OBJECTS.md`; the
BMT code lives in `rust/crates/kit-core/src/merkle.rs`.

A flat digest names exact bytes and nothing more. Deriving the ID
from a Merkle root over the object's parts adds two properties.
Inclusion is provable: a caller holding one chunk of a `ChunkedBlob`,
or one entry of a `Tree`, can prove it belongs to the object without
fetching the rest. Completeness is structural: the store verifies
these two types on read by decoding, recomputing the root, and
comparing it to the ID, so "every child is present, unmodified, and
in order" falls out of the check that already runs on each read
&mdash; no trusted manifest involved. The root is also wrapped in a
per-type domain, so identical leaf streams &mdash; an empty `Tree`
and an empty `ChunkedBlob`, for example &mdash; never share an ID.

The guarantee composes up the object graph. A `Tree`'s entry leaves
bind the IDs of its children, a `Commit` binds its root tree, and
every ref resolves to a commit. Verifying a commit against its ID
therefore verifies every tree, entry, and chunk reachable from it.

`ObjectStore::open` enforces addressing consistency through the
`.kit/format` repository marker. `ObjectStore::init` writes the
marker with the value `bmt-v2`; `open` requires that same value and
rejects the repository with `IncompatibleRepoFormat` when the marker
is missing or different, rather than misreading objects under the
wrong addressing rule. The marker governs object identity. A change
to the identity of an object type moves the marker and that type's
`schema_version` together: the span-committed chunked blob is `bmt-v2`
and `schema_version` `0x02`.

**Verification.** The BMT inclusion proofs this section's identity
scheme makes possible are exposed as a first-class capability, not just
an internal read-time check: `kit_core::merkle`'s id-based proof
verifiers plus `kit_core::verify`/`verify::closure` (partial and full
disclosure against a commit id, for an external party with no repository
access &mdash; a DA provider, a light client, a browser) round out the
picture the diagram above starts. See `docs/VERIFY.md` for the
user-facing guide and `docs/specs/SPEC-MERKLE-OBJECTS.md` /
`docs/specs/SPEC-DISCLOSURE.md` for the normative wire formats and
verification algorithms.

---

## 4. Attestation flow

Attestations are a separate resource class from objects. A commit
without attestations and a commit with five are indistinguishable
at the commit layer.

```
predicate JSON  ── caller-supplied
       │
       ▼
in-toto v1 Statement   (subject = commit BLAKE3, predicateType = URI)
       │   SPEC-ATTESTATIONS §4.2
       ▼
JCS canonical bytes    (RFC 8785; kit-attest hand-rolled writer)
       │
       ▼
PAE("application/vnd.in-toto+json", payload)
       │   SPEC-ATTESTATIONS §2.1
       ▼
Signer ────► sig bytes        Signer is one of the two implemented paths:
       │                        - repo-key  (Ed25519, .kit/keys/default.key)
       │                        - external  (subprocess; SPEC-EXTERNAL-SIGNER)
       │
       │                      Roadmap, not implemented (`SigstoreSigner`
       │                      returns `Error::SigstoreNotImplemented`):
       │                        - sigstore-keyless (Fulcio/Rekor)
       ▼
DSSE envelope ─► JCS ─► BLAKE3 → attestation id
       │
       ▼
.kit/attestations/<commit-hex>/<att-id>.dsse
       │
       ▼
transport (OP_UPLOAD_ATTESTATION / DOWNLOAD / LIST)
```

`kit verify-attest` walks the envelope, dispatches each signature
to a verifier keyed on `keyid`, and consults trust roots from
`$XDG_CONFIG_HOME/kit/trust-roots.toml` (see
`THREAT-MODEL.md` §5).

---

## 5. External signer protocol

The contract is `docs/specs/SPEC-EXTERNAL-SIGNER.md` (Protocol v1, v1.1
adds optional WebAuthn wrapping). Shape:

```
kit attest ──► spawn binary at attest.external_signer_path
            ──► stdin:  one-line JSON {"pae_base64": …, "algorithm": …}
            ──► stdout: one-line JSON {"keyid": …, "sig_base64": …}
            ──► exit 0 on success
```

Argv comes from `attest.external_signer_args` (user-scoped config &mdash;
see `THREAT-MODEL.md` §4) or per-invocation flags. The `kit-sign-file` signer is the conformance baseline for this
contract.

---

## 6. Where to start reading

Pick the closest match.

### "I'm modifying the parser for an on-disk object."
Start at `rust/crates/kit-core/src/serialize.rs`, then read
`docs/specs/SPEC-OBJECTS.md`. Update the matching golden vector under
`rust/tests/golden/`. If you change the wire shape, version it.

### "I'm adding a new transport."
Start at `rust/crates/kit-core/src/protocol.rs` for the `Transport`
trait, then read `docs/specs/SPEC-TRANSPORT.md` for the verb set. Use
`kit-transport-memory` as the smallest implementation reference.

### "I'm adding a new signer algorithm or implementation."
For an in-tree algorithm, edit `kit-attest`'s `Algorithm` enum and
the verifier dispatch. For an out-of-tree signer (HSM, KMS, hardware
token), implement `docs/specs/SPEC-EXTERNAL-SIGNER.md` and ship a binary &mdash;
see `rust/crates/kit-sign-file/` for a minimal example.

### "I'm changing the wire format."
Bump the spec version in the relevant `docs/specs/SPEC-*.md`, write a
new golden vector alongside the old one, and gate the new shape
behind a version field. Do not delete the old vector until a major
release window.

### "I'm changing key handling, signing, or trust roots."
Read `docs/THREAT-MODEL.md` first. Crypto and key-handling changes
require a second reviewer per `CONTRIBUTING.md`, plus a CHANGELOG
entry under `### Security` and a note on which threat-model section
the change affects.

---

## 7. Cross-references

- `specs/SPEC-OBJECTS.md` &mdash; on-disk object format
- `specs/SPEC-MERKLE-OBJECTS.md` &mdash; `Tree`/`ChunkedBlob` BMT-root addressing
- `specs/SPEC-PACKFILE.md` &mdash; packfile wire format
- `specs/SPEC-DELTA.md` &mdash; delta encoding
- `specs/SPEC-FASTCDC.md` &mdash; content-defined chunking
- `specs/SPEC-REFS.md` &mdash; ref names, CAS variants
- `specs/SPEC-INDEX.md` &mdash; repo-local index
- `specs/SPEC-TRANSPORT.md` &mdash; seven-verb wire protocol
- `specs/SPEC-SIGNING.md` &mdash; commit / remix signing
- `specs/SPEC-ATTESTATIONS.md` &mdash; DSSE plus in-toto v1
- `specs/SPEC-EXTERNAL-SIGNER.md` &mdash; external signer subprocess protocol
- `SSH-SECURITY.md` &mdash; SSH trust model (informative)
- `THREAT-MODEL.md` &mdash; security boundaries (informative)
- `FUZZ.md` &mdash; fuzz harness conventions
