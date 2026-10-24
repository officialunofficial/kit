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
| `kit-transport-file`          | `rust/crates/kit-transport-file/`    | Local-filesystem transport, atomic CAS via `link(2)` on POSIX          |
| `kit-transport-connect`       | `rust/crates/kit-transport-connect/` | ConnectRPC client implementing `kit.transport.v1.TransportService` (`specs/SPEC-TRANSPORT-CONNECT.md`); the transport `kit-storage` actually constructs for `kit+https://` / `kit+http://` |
| `kit-transport-s3`            | `rust/crates/kit-transport-s3/`      | Hand-rolled SigV4 transport (S3-compatible conditional writes)           |
| `kit-transport-ssh`           | `rust/crates/kit-transport-ssh/`     | Spawns system `ssh(1)`; framed protocol over stdio                     |
| `kit-serve`                   | `rust/crates/kit-serve/`             | Self-host server: the `kit.rpc.v1.ssh` frame session over a repository on disk; `kit serve` is a thin wrapper |
| `kit-sync`                    | `rust/crates/kit-sync/`              | Native clone/fetch/pull for `.kit` repositories as a library: typed reports, no printing, no ambient config; `kit clone`/`fetch`/`pull` are thin wrappers over it |
| `kit-storage`                     | `rust/crates/kit-storage/`               | The `kit` binary; thin glue over the library crates                   |
| `kit-fuzz`                    | `rust/fuzz/`                          | cargo-fuzz harnesses (`docs/FUZZ.md`)                                  |
| `kit-sign-file` (contrib)     | `contrib/signers/kit-sign-file/`     | Reference external signer; protocol conformance baseline               |
| `kit-sign-se` (contrib)       | `contrib/signers/kit-sign-se/`       | Apple Secure Enclave signer (Swift / CryptoKit)                        |
| `kit-sign-tpm` (contrib)      | `contrib/signers/kit-sign-tpm/`      | TPM 2.0 P-256 signer (Linux/Windows)                                   |
| `kit-sign-ctap` (contrib)     | `contrib/signers/kit-sign-ctap/`     | FIDO2/WebAuthn roaming-authenticator signer                            |

The `contrib/signers/*` crates form a separate sibling Cargo
workspace under `contrib/signers/` &mdash; they are **not** members of the
`rust/` workspace.
They share package metadata, lint config, and dependency pins by
inheriting from `contrib/signers/Cargo.toml`, and they are not part of
the `kit` binary's link graph. They communicate over the protocol
defined in `specs/SPEC-EXTERNAL-SIGNER.md`.

### 1.1 Optional kit-core features

`kit-core` has two optional features. Both are off by default. Other
crates enable them through their own features. Kept code depends on both,
so the modules stay.

| Feature | Module | Lines | Kept code that needs it |
|---|---|---|---|
| `history-mmr` | `history.rs`, `history/ancestry.rs` | 2,478 | `refs.rs` and `refs/ancestry_state.rs` (ref-write journal), `kit-sync` `worktree.rs`, and in `kit-storage` the `branch`, `commit`, `reflog`, `reset` and `update-ref` commands. The `kit-formal-conformance` ref test and `docs/specs/SPEC-HISTORY-PROOF.md` also cite it. |
| `sparse-checkout` | `sparse.rs` | 537 | In `kit-storage`: `sparse_cache.rs`, the `--sparse` option of `clone` and `checkout`, and the `sparse_checkout_local` test. Also the `sparse-checkout` feature of `kit-transport-s3`, the `sparse_verify` fuzz target and the `layout.rs` witness cache directory. `docs/specs/SPEC-SPARSE-CHECKOUT.md` specifies the wire format. |

Removing one of these modules means removing every item in its row.
The spec text goes in the same change as the code.

The `pack-shards` feature and the `pack_shard` module are not part of
`kit`. Nothing kept depended on them.

#### Size of kit-core

The count is `find rust/crates/kit-core -name '*.rs' | xargs cat | wc -l`.
It covers `src`, `tests` and `examples`.

| Item | Lines |
|---|---|
| Imported tree | 81,981 |
| Net change in `src` and `tests` before this section | -850 |
| `pack_shard` module removed | -1,607 |
| `layout.rs` pack-shard directory removed | -25 |
| Now | 79,499 |

The migration plan sets a target of 77,357 lines. The plan reaches that
number by removing `pack_shard`, `history` and `sparse` (4,624 lines in
total). Here, `history` and `sparse` stay (3,015 lines). Without them the
count is 76,484, which is 873 lines under the plan. The other changes
above account for that difference.

### 1.2 Owner signature schemes

The grant owner schemes `secp256k1-eip191` and `webauthn-p256` stay.
The decision is to keep the code and the spec text together.

- `kit-attest` `eth.rs` (Keccak-256, EIP-191 digest, address derivation)
  is the base of both schemes and of the `0x` namespace address.
- `kit-attest` `grant/owner.rs` and `grant/webauthn.rs` verify the
  schemes. `kit-storage` `grants/owner.rs` signs with them.
- `kit grant`, `kit epoch` and `kit visibility` use them. `docs/CLI.md`
  and `docs/specs/SPEC-WRITE-GRANTS.md` section 4 describe them.
- The grant golden vectors and `scripts/golden/grants_ref.py` check them.

A removal has to take out all of these in one change, with the
`0x` namespace rule in `repo_identity`. No code is dead today, so the
spec text stays.

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
vendored BMT lives in `rust/crates/kit-core/src/merkle.rs`.

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
marker with the value `bmt-v1`; `open` requires that same value and
rejects the repository with `IncompatibleRepoFormat` when the marker
is missing or different, rather than misreading objects under the
wrong addressing rule. The marker governs object identity only: the
serialized wire format and the `schema_version` field are independent
of it.

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
see `THREAT-MODEL.md` §4) or per-invocation flags. Every reference
signer in `contrib/signers/` is a conformance test for this
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
see `contrib/signers/kit-sign-file/` for a minimal example.

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
