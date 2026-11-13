---
spec: SPEC-DISCLOSURE
version: 5
status: draft-normative
audience: implementers of a kit disclosure-bundle or closure-profile verifier (any language)
---

# SPEC-DISCLOSURE &mdash; partial-disclosure bundle and closure-profile verification

Status: **Draft, normative.** The wire format and verification algorithm
below are pinned by the golden vectors in §6, §7.6, and §8.3 and are not expected to
change incompatibly, but this document has not yet accumulated the
implementation experience SPEC-CONVENTIONS §2.1 reserves `stable` for.
Scope: proving that a single path, chunk, or byte range of a file belongs
to a specific kit commit id, with proof bytes on the order of a few KiB
regardless of repository size ("partial disclosure"), **and** proving that
a served object set is the full content that commit id commits to
("closure profile" / full disclosure, §7), and a multi-chunk range
container (KDSP, §8).

This spec covers the verifier kit. Out of scope, deliberately:
CLI commands and the docs guide.

## 1. Purpose and trust model

A **disclosure bundle** lets an untrusted party (a data-availability
provider, a light client, an auditor, a browser) hand a verifier three
things &mdash; a trusted commit id, an encoded bundle, and nothing else &mdash; and
receive back a [`Disclosed`](../../rust/crates/kit-core/src/verify.rs)
result whose `payload` bytes are **exactly** the content that commit id
commits to, at the path the bundle discloses.

A verified disclosure proves:

- **content &harr; commit id.** The disclosed bytes are reachable from
  `commit_id` via an unbroken chain of BLAKE3/BMT checks (§3).

A verified disclosure does **not** prove:

- **completeness.** That the disclosed path is the *only* thing under its
  parent, or that nothing else exists in the repository. A disclosure
  bundle carries a proof of *inclusion*, never of *exclusion* &mdash; see §9.
- **signer identity.** `signer`/`signature_valid` report whether the
  commit's (or remix's) embedded Ed25519 signature verifies against its
  embedded public key (SPEC-SIGNING §3). Binding that public key to a
  person, organization, or trust level is application policy, exactly as
  [`sign::verify_commit`](../../rust/crates/kit-core/src/sign.rs)
  already documents &mdash; this spec changes nothing about what a commit
  signature covers.

`absolute_offset` and chunk spans are the values the commit's manifest
commits to. A disclosure does not prove that manifest well-formed: that its
ends increase, end at `total_size`, and equal each chunk's length. Closure
verification (§7.4) and store admission prove that. Under an id whose manifest
is not well-formed, two disclosures can place different bytes at one offset.

## 2. The authentication chain

```
commit id
  = BLAKE3(commit bytes)                          <- verifier recomputes; reads tree_hash
tree_hash
  = wrap(Tree, BMT(entry leaves))                 <- SPEC-MERKLE-OBJECTS §2/§3.2
    one Step per path component: entry + <= log2(M) siblings
child_id (a Step's disclosed leaf)
  |- Blob            (SPEC-OBJECTS §3):  full canonical bytes, or a Bao
  |                   slice over them (content offset o -> canonical
  |                   offset o + 10)
  \- ChunkedBlob      (SPEC-OBJECTS §7): wrap(ChunkedBlob, BMT([meta, chunks...]))
                       chunk step = chunk leaf (span + chunk id) at position
                       (index + 1), via one multi-proof over {0, index + 1}
                       that also authenticates total_size/chunk_size
                       (SPEC-MERKLE-OBJECTS §3.1)
                       chunk bytes, or a Bao slice over the chunk's own
                       canonical bytes
```

Every layer verifies against the layer above and terminates at the
trusted commit id; nothing in this chain is ever compared against a bare
(pre-domain-wrap) BMT root (SPEC-MERKLE-OBJECTS §5.4).

## 3. Wire format

Encoded with `commonware-codec` conventions (SPEC-CONVENTIONS §3
generalizes; this corpus's specific convention, also used by
`transfer::PackListNode`, is: fixed integers **big-endian**, every length
an LEB128 **varint**, arrays raw, `Option<T>` as a bool discriminant
followed by `T` when present):

```
magic   = "KDPB"              (4 raw bytes)
version: u8 = 3
commit_id: [u8; 32]
commit_bytes: Vec<u8>          <= 4 MiB
steps: Vec<Step>               <= MAX_TREE_DEPTH (128), root first
  Step {
    name: Vec<u8> (1..=255)     entry name, SPEC-OBJECTS §4.1 rules
    mode: u8                    EntryMode (SPEC-OBJECTS §4)
    child_id: [u8; 32]
    inner_root: [u8; 32]        bare BMT root of the parent Tree
    position: u32                BMT position (= entry index) in the parent Tree
    proof: Proof (max_items = 1) SPEC-MERKLE-OBJECTS §5.1/§5.2
  }
payload_kind: u8
  0  Object { bytes: Vec<u8> <= MAX_RAW_OBJECT_SIZE }
  1  Chunk  { total_size: u64, chunk_size: u32, index: u32,
              start: u64, end: u64,
              inner_root: [u8; 32], proof: Proof (max_items = 2),
              bytes: Vec<u8> <= MAX_RAW_OBJECT_SIZE }
  2  Range  { chunk: Option<ChunkHdr>,
              offset_in_blob: u64, len: u64, slice: Vec<u8> }
     ChunkHdr { total_size: u64, chunk_size: u32, index: u32,
                start: u64, end: u64,
                inner_root: [u8; 32], chunk_id: [u8; 32],
                proof: Proof (max_items = 2) }
```

`start` and `end` are the chunk's span in the file, `[start, end)`
(SPEC-OBJECTS §7). They are big-endian `u64` like every fixed integer of the
bundle, after `index` and before `inner_root`. The leaf of the chunk is built
from them (SPEC-MERKLE-OBJECTS §3.1), so a wrong value fails the multi-proof.
`chunk_id` stays after `inner_root`.

`Step.inner_root` is the bare BMT root of the **parent** Tree this
step's proof is verified against (the tree whose id is the commit's
`tree_hash` for step 0, or the previous step's `child_id`).
`Chunk`/`ChunkHdr.inner_root` is the bare BMT root of the ChunkedBlob
whose id is the leaf id.

The whole bundle MUST be `<= MAX_BUNDLE_BYTES` (64 MiB), checked before
any decode work. Trailing bytes after the declared body MUST be
rejected. `version != 3`, an unrecognized `payload_kind`, and an
unrecognized `mode` byte are typed decode errors, never a bare "invalid".
A version byte of `2` is a typed `UnsupportedBundleVersion(2)` error, and so
is any other value (`1` included).

`Step` and `ChunkHdr`'s `proof` fields decode with
[`merkle::Proof::decode`](../../rust/crates/kit-core/src/merkle.rs)'s
`max_items` bound (SPEC-MERKLE-OBJECTS §5.2): 1 for a single-leaf proof,
2 for a multi-proof over `{0, position}` (§4.3). Every `Vec` read is
bounded with `read_range` before allocation (§5).

### 3.1 Why `ChunkHdr` carries an explicit `chunk_id`

A Bao `SliceDecoder` always requires its expected root hash **up front**
&mdash; it cannot recover an unknown root from the slice bytes themselves,
by construction (verified streaming's whole point is that the root is
already trusted before decoding starts). For the `Chunk` payload kind the
verifier can compute that hash itself, by hashing the disclosed `bytes`
directly (they *are* the chunk's canonical bytes). For the `Range`
payload kind on a `ChunkedBlob` leaf, only a byte range is disclosed &mdash;
the verifier never sees the chunk's full bytes to hash &mdash; so the
containing chunk's id MUST travel on the wire as its own field.
`ChunkHdr.chunk_id` is exactly the value [`verify_chunk_with_meta`](../../rust/crates/kit-core/src/verify.rs)'s
multi-proof authenticates against the leaf's `ChunkedBlob` id, so a
forged `chunk_id` simply fails to fold to that id (§4.3) &mdash; carrying it
explicitly costs nothing security-wise and closes an otherwise-unprovable
gap.

## 4. Verification algorithm

A conformant verifier, given a trusted `commit_id: Hash` and an encoded
`bundle: [u8]`:

1. **MUST** reject `bundle` outright if it exceeds `MAX_BUNDLE_BYTES`,
   before decoding anything.
2. **MUST** check the fixed 5-byte header (`"KDPB"` magic + version byte)
   before decoding the codec body; an unrecognized version is a typed
   error, not a fallback to another format.
3. **MUST** decode the codec body with every `Vec` bounded as in §3, and
   **MUST** reject any trailing bytes after the declared body.
4. **MUST** compare the bundle's embedded `commit_id` field against the
   externally trusted id the caller is verifying against, as a fast
   sanity check (a mismatch here is always also a hash mismatch at step
   5, but checking the field first avoids hashing a large `commit_bytes`
   for an obviously-wrong bundle).
5. **MUST** recompute `BLAKE3(commit_bytes)` and reject unless it equals
   the trusted `commit_id` &mdash; this is the one step that binds
   everything else to a value the caller did not have to fetch.
6. **MUST** decode `commit_bytes` and accept only `Commit` or `Remix`
   (SPEC-OBJECTS §5/§6); any other decoded type is a typed error. Take
   `tree_hash` from whichever it is.
7. **MUST** reject `steps.len() > MAX_TREE_DEPTH` (128, SPEC-OBJECTS'
   `store::MAX_TREE_DEPTH`).
8. For each `Step` at index `i` (root first):
   1. **MUST** validate `name` against SPEC-OBJECTS §4.1's entry-name
      rules ([`TreeEntry::validate_name`](../../rust/crates/kit-core/src/object.rs)) &mdash;
      an invalid name (trailing space, `.kit`, a reserved Windows device
      name, etc.) is rejected here, before its proof is even checked.
    2. **MUST** check `domain_digest(b"kit.tree\x00", inner_root) == expected_id`
       first, where `expected_id` is the previous step's `child_id` (step 0
       against `tree_hash` itself). A mismatch is a typed `InnerRootMismatch`.
       The field is never a second trust anchor (wrap-check-first,
       `docs/VERIFY.md` §5). **MUST** then require that the proof folds to
       exactly `inner_root`; a bundle whose proof folds to a different root
       than it declares is rejected even if the wrap of the declared root
       happens to match, and vice versa. **MUST** then wrap the folded
       value and compare to `expected_id` (SPEC-MERKLE-OBJECTS §5.4).
       A commonware-native verifier performs the wrap check itself and
       then runs upstream `bmt::Proof::verify_element_inclusion` against
       `inner_root` unmodified, needing no kit code beyond the public
       domain constants.
   3. **MUST** reject the whole bundle if `i` is not the last step and
      `mode != Tree` &mdash; every step but the last MUST descend into a
      directory.
9. The **authenticated path** is `steps.map(|s| (s.name, s.mode))`, and
   the **leaf id** is the last step's `child_id` (or `tree_hash` itself
   when `steps` is empty &mdash; disclosing the root tree). A verifier
   compares this authenticated path against whatever path string it
   asked for; **it MUST NOT trust a claimed path** carried any other way.
10. Dispatch on `payload_kind`. For `Chunk` and `Range` the leaf is blob
    data (a `ChunkedBlob`, or a plain `Blob` for a `Range` with `chunk =
    None`), so the verifier **MUST** reject the bundle, before it checks
    anything else in the payload, when the mode of the final step is
    `Tree` or when there is no step (the root tree). The mode of the final
    step is `Blob`, `Executable` or `Symlink` in every accepted case.
    - **`Object`**: **MUST** deserialize `bytes` and check its
      content-address (BLAKE3, or the BMT root for a `Tree`/`ChunkedBlob`
      &mdash; SPEC-MERKLE-OBJECTS §2) equals the leaf id. **MUST** then
      require the decoded type to match the mode of the final step: a
      `Tree` object for mode `Tree`, a `Blob` or `ChunkedBlob` object for
      every other mode. The root tree, which has no step, counts as mode
      `Tree`. Reject on a mismatch: without this check the authenticated
      path would report a blob under bytes that are a tree.
    - **`Chunk`**: runs the **chunked-leaf checks** below, with steps 1 to 6
      and 8's `Chunk` form. The chunk id is the BLAKE3 of `bytes` (its BLAKE3
      IS the chunk's Blob id, SPEC-OBJECTS §3).
    - **`Range`**, `chunk = None` (the leaf is a plain `Blob`): **MUST**
      reject `len == 0`. **MUST** verify a Bao slice proving `len` bytes
      at content offset `offset_in_blob` (Bao offset `offset_in_blob +
      10`, SPEC-OBJECTS §3's prologue) against the leaf id. `absolute_offset`
      is `offset_in_blob` itself &mdash; nothing further to prove. The
      result carries no span.
    - **`Range`**, `chunk = Some(hdr)` (the leaf is a `ChunkedBlob`):
      **MUST** reject `len == 0`, then run the chunked-leaf checks below on
      `hdr` (steps 1 to 5, 7 and 8), with `hdr.chunk_id` as the chunk id.

    **Chunked-leaf checks.** For a `Chunk` and a `Range` over a `ChunkedBlob`,
    the verifier holds `total_size`, `chunk_size`, `index`, `start`, `end`,
    `inner_root`, the chunk id and a multi-proof. It MUST run these in this
    order. Before step 1 it has checked the type of the leaf (§4 step 10),
    `len != 0` for a `Range`, and the wrap and declared-root check:
    **MUST** first check `domain_digest(b"kit.chunked\x00", inner_root) ==
    leaf_id`, else reject with `InnerRootMismatch`.

    1. **Leaf and multi-proof.** Build the chunk leaf from
       `(start, end, chunk id)` (SPEC-MERKLE-OBJECTS §3.1). **MUST** verify, in
       one multi-proof over BMT positions `{0, index + 1}` against the leaf
       id, that (a) the metadata leaf the verifier computes **itself** from
       `total_size`/`chunk_size` and (b) that chunk leaf at position
       `index + 1` both fold to exactly `inner_root`, which wraps to the leaf
       id (SPEC-MERKLE-OBJECTS §3.1, §5.5). The metadata leaf is **never**
       accepted as an externally supplied value at position 0 &mdash; only
       ever recomputed from the very fields being authenticated. A
       commonware-native verifier runs the wrap check and then upstream
       `bmt::Proof::verify_multi_inclusion` against `inner_root` unmodified.
       This step authenticates `leaf_count`.

    **Header check, after step 1 and before step 2.** The verifier never
    decodes the manifest, so it **MUST** apply the header check of
    SPEC-OBJECTS §7 to `total_size`, `chunk_size` and a chunk count of
    `leaf_count - 1`, and reject a layout it refuses
    (`ChunkedBlobTotalSizeInvalid`). `leaf_count` is trusted only once step 1
    has folded to the id.

    2. **Span.** `start < end <= total_size`, else `span outside the file`;
       and `end - start` is at most `MAX_RAW_OBJECT_SIZE - 10`, else `span
       above the object limit`.
    3. **First chunk.** `index == 0` exactly when `start == 0`, else `index 0
       and start 0 disagree`.
    4. **Last chunk.** `index + 1 == leaf_count - 1` exactly when
       `end == total_size`, else `last index and end == total_size disagree`.
    5. **Fixed layout.** For a fixed-size layout (`chunk_size` other than `0`
       and `0x8000_0002`), `start == index * chunk_size` and
       `end == min(start + chunk_size, total_size)`, else reject with
       `FixedChunkLength` (`a fixed-size chunk has the wrong span`). The
       arithmetic MUST be checked. A fixed layout is
       then proven regular twice: the manifest decoder requires each end to
       follow the formula (SPEC-OBJECTS §7), and the verifier checks the
       formula on the header fields alone.
    6. **`Chunk` bytes.** `bytes` MUST decode as a Blob under the strict rules
       of SPEC-OBJECTS §3 and §11 (its 10-byte prologue, no trailing byte), and its length field MUST equal `end - start`, else `blob
       length differs from the span`. `bytes` shorter than the prologue, or of
       another type, is rejected as `chunk bytes are not a blob`.
    7. **`Range` bytes.** `offset_in_blob + len <= end - start`, with checked
       arithmetic, else `range past the committed span`. **MUST** then verify a Bao slice proving
       `len` bytes at content offset `offset_in_blob` (Bao offset
       `offset_in_blob + 10`) against `hdr.chunk_id`. A `Range` is checked
       against the committed span only. A range that lies inside the span of a
       real chunk that is longer than its span verifies: bytes past the span
       cannot be disclosed, and a disclosure does not prove that spans equal
       real lengths (§1).
    8. **Absolute offset.** `absolute_offset = start + offset_in_blob`, a
       `u64`, **always present** for a `Range`. For a plain `Blob` it is
       `offset_in_blob`. `DisclosedPayload::Chunk` and `DisclosedPayload::Range`
       carry `start` and `end`; a `Range` over a plain `Blob` carries none.

    All arithmetic is checked. An overflow is rejected with the label of the
    step it occurs in: `index + 1` in step 1, `offset_in_blob + len` in
    step 7. The header check keeps the labels of SPEC-OBJECTS §7.

    Step 6 applies to a `Chunk` and step 7 to a `Range`. Steps 1 to 5 apply
    to both, and step 8 reports the absolute offset of a `Range`.

An offset proof is one multi-proof of about 46 siblings at any position,
about 1.5 KB plus the Bao slice. It does not grow with the chunk index.

## 5. Bounds

| Field | Bound | Rationale |
|---|---|---|
| whole bundle | `MAX_BUNDLE_BYTES` = 64 MiB | checked before any decode |
| `commit_bytes` | 4 MiB | comfortably above any real commit/remix |
| `steps` | `MAX_TREE_DEPTH` = 128 | SPEC-OBJECTS' existing tree-depth cap |
| `Step.name` | 1..=255 bytes | SPEC-OBJECTS §4.1 |
| `Object.bytes` / `Chunk.bytes` | `MAX_RAW_OBJECT_SIZE` = 1 GiB | the store's existing object-size cap |
| `Step`/`Chunk`/`ChunkHdr` proof siblings | `max_items * MAX_LEVELS` (32) | SPEC-MERKLE-OBJECTS §5.2, before any sibling is read |
| a chunk's span, `end - start` | `MAX_RAW_OBJECT_SIZE - 10` | a chunk is one Blob object (SPEC-OBJECTS §7) |

A malicious `leaf_count` inside any embedded `Proof` cannot force a large
allocation: sibling count is bounded by `max_items * MAX_LEVELS` before
any sibling digest is read (SPEC-MERKLE-OBJECTS §5.2), and `leaf_count`
itself is compared, never used to size an allocation.

## 6. Golden vectors

`rust/tests/golden/disclosure/` (SPEC-CONVENTIONS §5) carries the
authoritative pinned bytes: a deterministic fixture repo (fixed signer
seed, fixed timestamp, fixed file bytes; a large file of a fixed PRNG
stream so FastCDC yields several chunks), each `<name>.bin` disclosure
bundle paired with a `<name>.json` sidecar recording the commit id, the
requested path/selector, the expected `Disclosed` summary (path, leaf id,
payload kind, offsets, disclosed bytes' BLAKE3), and the expected
accept/reject outcome (with a reason for every reject). `MANIFEST.txt`
pins every vector's BLAKE3 digest.

Accept vectors: the root tree; a shallow file; a 3-level-nested file; an
executable-mode file; one chunk of a chunked file, for the first chunk, a
middle chunk and the last chunk, and a file of one chunk; a range inside a
chunk (its `absolute_offset` checked against the fixture's known plaintext
offset); a range covering a whole small blob (the first Bao block, and a
last partial block); the same chunk id at two indices; a range inside the
committed span of a real chunk that is longer than its span; and two
disclosures under an id whose spans overlap, which both verify and pin the
trust statement of §1. The last two are in
`scripts/golden/chunk_offsets_expected.json` (`long_chunk_range`, `overlap`),
which `golden_chunk_offsets.rs` checks, and the overlap also has the vectors
`chunk_overlap_first` and `chunk_overlap_second`.

Reject vectors: a non-`Tree` intermediate step mode; a step's proof
checked against the wrong parent (two steps swapped); an invalid entry
name (trailing space); a payload whose id does not equal the leaf id; a
`Chunk` payload with a forged `total_size`
(`neg_chunk_meta_forged_total_size`); a `Range` payload over a chunked
leaf with a forged `total_size` in its chunk header
(`neg_range_chunk_meta_forged_total_size`); a Bao slice at the wrong
offset; a zero-length range on a plain-`Blob` leaf
(`neg_zero_length_range`) and on a chunked leaf
(`neg_zero_length_range_chunked` &mdash; `len == 0` is checked before the
chunk header's wrap/fold checks, per §4); a wrong `start`; a wrong `end`;
index 0 with `start != 0`; a last chunk with `end != total_size`; a range
that passes the committed span although it lies inside the real chunk;
chunk bytes that are not a Blob; `steps.len() = 129`;
`version = 2` (`neg_bundle_version_2`) and `version = 4`; a declared inner
root that does not wrap to the parent id (`neg_inner_root_forged`); a
declared inner root that wraps correctly but whose proof was built for
a different tree (`neg_inner_root_fold_mismatch`); a trailing byte
after the declared body; `commit_bytes` that decode to a `Tag` (a
valid, signed object &mdash; just not one with a `tree_hash`); an `Object`
payload that is a tree under a final step of mode `Blob`
(`neg_blob_mode_names_tree`); and an `Object` payload that is a blob under
a final step of mode `Tree` (`neg_tree_mode_names_blob`); a `Chunk` payload
and a `Range` payload over a chunked blob under a final step of mode `Tree`
(`neg_tree_mode_chunk_payload`, `neg_tree_mode_range_chunked`); and a
`Range` payload over a plain blob under a final step of mode `Tree`
(`neg_tree_mode_range_blob`). Accept
sidecars record `step_inner_roots_hex` and `chunk_inner_root_hex`.

`rust/crates/kit-core/tests/golden_disclosure.rs` reads only the
committed files, runs `verify::verify_disclosure`, and compares the
result against each sidecar; it never calls the fixture generator.

## 7. Closure profile (full disclosure)

Purpose: given a trusted commit (or remix, or tag) id and a set of
object bytes &mdash; optionally wrapped in raw-only v1 packs plus a
convenience manifest &mdash; a verifier checks that every object reachable
from that id is present and re-hashes to the id it was supplied under.
This is full disclosure against a commit id, for a DA provider, a light
client, or an auditor. The root id is the **only** trust anchor. The
manifest is an index of pack hashes; it does not authenticate the
objects.

### 7.1 Modes and `children`

Two walk modes, because the on-chain anchor is per commit:

| Mode | Byte | What is included |
|---|---|---|
| snapshot (default) | `0` | the root object and its tree closure (trees, blobs, chunked-blob manifests, chunks); tag &rarr; target; remix &rarr; tree. Parents are referenced but not included. |
| history | `1` | today's `reachable_objects` semantics: every ancestor, identical to what push/fetch ship |

`children(obj, mode)` is the single source of truth for "what does this
object reference":

- `Commit`: `tree_hash`, plus `parents` only in history.
- `Remix`: `tree_hash`, plus `parents` only in history; never `sources`
  (foreign-repo pointers, SPEC-OBJECTS §6).
- `Tree`: every entry `object_hash`.
- `ChunkedBlob`: every chunk.
- `Tag`: `target`.
- `Blob` / `Delta`: none (`Delta.base_hash` is not followed).

Each reference also states which object types its target may have:

| Reference | Target type |
|---|---|
| tree entry of mode `Tree` | `Tree` |
| tree entry of mode `Blob`, `Executable` or `Symlink` | `Blob` or `ChunkedBlob` |
| chunk of a `ChunkedBlob` | `Blob` |
| `tree_hash` of a `Commit` or a `Remix` | `Tree` |
| `target` of a `Tag` | the type in the tag's `target_type` (SPEC-OBJECTS §6a) |
| `parents` of a `Commit` or a `Remix` | not restricted here |

The root, when present, MUST deserialize as a `Commit`, `Remix`, or
`Tag`. A typed error is raised otherwise.

### 7.2 Raw-only pack rule

A closure pack is a [SPEC-PACKFILE](SPEC-PACKFILE.md) v1 pack of `0x00`
(raw) entries only. The writer MUST NOT compress and MUST NOT emit
deltas. This is so a wasm verifier, which is built without `pack-zstd`,
can consume the profile: `0x03`/`0x04` entries error in that build via
the existing stub, and a delta would require a store to resolve.

A verifier that sees a delta entry or a compressed entry MUST fail with
a profile-violation error naming the pack index and entry index. It MUST
NOT decompress in order to decide this &mdash; scan entry types first.

### 7.3 Manifest bytes

Encoded with commonware-codec conventions (fixed integers big-endian,
lengths LEB128 varint, arrays raw), matching §3:

```
magic "KCLM"            (4 raw bytes)
version: u8 = 1
root: [u8; 32]
mode: u8                0 = snapshot, 1 = history
packs: Vec<[u8; 32]>    pack_key of each pack, in order; length <= 65_536
```

Decoders MUST reject trailing bytes, an unknown version, and an unknown
mode. `pack_key` is BLAKE3 of the entire pack including its trailer
(SPEC-PACKFILE §7).

The manifest is a convenience index. The root id remains the only trust
anchor: a verifier that already has the packs MAY call the pack-set
entry point directly and ignore the manifest.

### 7.4 Verifier MUSTs

1. Re-hash every supplied object (`deserialize` then `id_from_object`).
   In the store-less map path, bytes that fail to deserialize are not an
   object and no id derives from them: they are `unreferenced` under the
   BLAKE3 of those bytes, never `corrupt`, so they do not fail
   completeness. A bit-flipped object that still deserializes
   is content-addressed under a *different* id and surfaces as `missing`
   (the referenced id) plus `unreferenced` (the supplied one), not
   `corrupt`. A verifier that fetches by id MAY report a hash mismatch as
   `corrupt` under the requested id; this is the useful classification when
   a store returns bytes from the requested object slot.
2. Walk from the root with `children(obj, mode)` over the resulting
   `id → bytes` map or pull-based source (BFS, visited set). The map walk
   is store-less; a pull-based source fetches only requested ids.
3. Anything referenced and absent is `missing`. Anything supplied and
   never visited is `unreferenced` when the verifier can enumerate the
   supplied set. Completeness fails on `missing` or `corrupt`;
   `unreferenced` is reported, not an error &mdash; a DA provider MAY serve
   a superset. A report that cannot enumerate the supplied set MUST set
   `unreferenced_checked` to `false` and leave `unreferenced` empty.
4. The root itself missing is `missing = [root]`, `verified = 0`.
5. Delta or compressed pack entries are a profile violation (§7.2).
6. The verifier MUST be given the trusted root by its caller and MUST
   reject a manifest whose `root` differs; the manifest is a locator,
   never a trust anchor.
7. Manifest pack hashes MUST equal `pack_key` of the supplied packs, in
   order, and the counts MUST match.
8. Object count MUST NOT exceed SPEC-PACKFILE `MAX_ENTRIES`
   (10,000,000). Pack payload sum and entry count reuse SPEC-PACKFILE
   caps. Tree depth, tree entries, chunks, and parents reuse
   `store::MAX_TREE_DEPTH`, `serialize::MAX_TREE_ENTRIES`,
   `serialize::MAX_CHUNKS`, `serialize::MAX_PARENTS`.
9. The objects MUST fit together as a checkout. A reached object whose
   type is not allowed by a reference to it (§7.1) is `corrupt` under its
   id, and the verifier does not descend into it. An id that two references
   require to have types that no object has (for example a `Tree` entry and
   a `Blob` entry naming one id) is `corrupt`, even when it is also
   `missing`.
10. Each chunk of a `ChunkedBlob` MUST hold exactly the length of its span.
    The length of a chunk is the length of its `Blob` data, and its span is
    `end - start` from the manifest (SPEC-OBJECTS §7). The rule is the same for
    both layouts, and each chunk is checked on its own, so no sum is checked:
    the manifest decoder already made the spans contiguous and the last end
    `total_size`. A chunk that was read and whose length differs from its span
    makes the `ChunkedBlob` `corrupt` under its id, even when another chunk of
    the same manifest is missing; that chunk is still reported `missing`. When
    several chunks differ, the lowest index is the one reported. A chunk that
    is missing or not a `Blob` is not measured; it is already incomplete or
    `corrupt` by item 9. A chunk listed twice under two different spans is
    measured against each span.

### 7.5 Bounds

| Bound | Value | Applied to |
|---|---|---|
| pack entries | 10,000,000 | each pack, and the supplied object set |
| pack payload sum | 4 GiB | each pack (SPEC-PACKFILE §5) |
| raw object size | 1 GiB | each object (store cap) |
| manifest packs | 65,536 | `packs` vector |
| tree depth | 128 | inherited from object decode |
| tree entries | 1,000,000 | inherited from object decode |
| chunks | 8,388,608 | inherited from object decode |
| parents | 1,000 | inherited from object decode |

### 7.6 Vectors

`rust/tests/golden/closure/` pins the bytes. The vectors use their own
small fixture repo. Its `chunked.bin` is a 36 KiB file split by FastCDC
into more than one chunk. The fixture stores the ChunkedBlob directly, so
the vectors stay under 1 MiB in total. Accept vectors: `snapshot`
(fixture head commit), `history` (a second commit so history &ne;
snapshot; the parent's tree objects are present only in history),
`tag_root` (tag &rarr; commit, snapshot). Sidecars record the root, mode,
pack hashes, expected `verified` count, and the sorted id list.

Reject / incomplete vectors: missing chunk; a damaged blob (its magic byte
flipped, so the referenced id is `missing` and the damaged bytes are
`unreferenced`); a tree entry of mode `Tree` that names a blob
(`neg_tree_mode_names_blob`); a tree entry of mode `Blob` that names a tree
(`neg_blob_mode_names_tree`); a chunk id that names a tree
(`neg_chunk_names_non_blob`); a commit or a remix whose `tree_hash` names a
blob (`neg_commit_tree_names_blob`, `neg_remix_tree_names_blob`); a tag
that records `target_type` `Commit` but names a tree (`neg_tag_target_type`);
chunks whose lengths are swapped but sum correctly
(`neg_chunk_lengths_swapped`); a fixed-size layout of `chunk_size` 6 whose chunks
hold 5 and 7 bytes (`neg_fixed_chunk_length`); a `Tree` entry and a `Blob`
entry that name one absent id (`neg_conflicting_edges_to_missing`);
unreferenced extra (still
complete); `unreferenced_undecodable_extra`, bytes that decode to no object
(unreferenced, still complete); a delta entry; a compressed entry; a manifest
pack-hash mismatch; the wrong root id; a manifest whose `root` differs
from the caller's trusted root; manifest version 2; a trailing byte on
the manifest.

`rust/crates/kit-core/tests/golden_closure.rs` reads only the committed
files.

`scripts/golden/closure_ref.py` is an independent check in Python. It shares
no code with the Rust crates. It decodes the manifest and the packs, derives
every object id, walks the closure from the trusted root, and compares the
result with each sidecar.

## 8. Multi-chunk span container (KDSP v2)

KDSP proves a content range crossing chunk boundaries of one ChunkedBlob.
It wraps unchanged KDPB v3 Chunk bundles, rather than introducing a payload
kind. External tools MUST be able to encode and verify KDSP from this section
and §3&ndash;§5 alone. [SPEC-HTTP-OBJECTS](SPEC-HTTP-OBJECTS.md) selects this
representation by query.

### 8.1 Encoding and bounds

Fixed-width integers are big-endian; vector lengths are unsigned LEB128
varints as in §3 (minimal encoding, bounded to u32 for vector lengths).
Arrays are raw bytes. No padding is inserted.

```text
magic: [4] = "KDSP"
version: u8 = 2
commit_id: [32]
offset: u64                 absolute content offset
len: u64                    content length, not inclusive endpoint
chunks: Vec<Vec<u8>>         encoded KDPB v3 Chunk bundles
```

There is no anchor. Each Chunk bundle proves its own span (`start`, `end`), so
the container needs no separate proof of where the first chunk begins. The
chunk vector MUST contain 2&ndash;1,000,000 bundles, with consecutive indices
`first..last` in ascending order, inclusive: for every adjacent pair,
`index[i+1] = index[i] + 1`. Each contains the full canonical Blob bytes,
including its prologue and length field.

A decoder MUST reject an encoded container larger than 64 MiB before
any decoding or allocation. It MUST bound each vector length by the
remaining input and 64 MiB, and chunk count to at most 1,000,000, before
allocation. The verifier classifies a zero or one chunk count under §8.2.
This bundle cap belongs to the span container. It is not the chunk cap
of SPEC-OBJECTS §7 (8,388,608), and it stays at 1,000,000. Each bundle
carries a commit, its steps, a proof and a chunk Blob, so a container
within 64 MiB holds far fewer bundles than either cap.
The decoder MUST reject trailing bytes, unknown magic or version,
truncated fields, and invalid varints. A deployment SHOULD also cap
requested content, for example at 8 MiB; this service cap is separate
from format validity.

A KDSP of version 1, or one that wraps KDPB v2 bundles, is not accepted:
version 1 is `span_version`, and a v2 bundle is `span_inner_invalid`.

### 8.2 Verification and reject reasons

The caller supplies a trusted commit id; the embedded id MUST equal it.
The verifier MUST perform the following checks in order and return a
distinct reason for the first failed check. Reason labels below are the
language-independent golden contract, not implementation type names.

| Check | Reject reason |
|---|---|
| Total encoded size at most 64 MiB | `span_too_large` |
| Magic equals KDSP | `span_magic` |
| Version equals 2 | `span_version` |
| Fields and bounded vectors decode completely, including chunk count at most 1,000,000 | `span_encoding` |
| No trailing bytes | `span_trailing_bytes` |
| Embedded commit equals caller's trusted commit | `span_commit` |
| Nonzero len and checked offset + len | `span_range_arithmetic` |
| At least two chunk bundles | `span_chunk_count` |
| Every chunk bundle verifies under §4 against commit_id (a bundle that is a bad Blob fails here) | `span_inner_invalid` |
| Every chunk payload is Chunk | `span_chunk_selector` |
| Every bundle shares authenticated path and leaf id | `span_leaf_context` |
| Every bundle shares total_size, chunk_size, and chunk inner root | `span_chunk_context` |
| Chunk indices are first..last, consecutive and in order (`index[i+1] = index[i] + 1`) | `span_chunk_order` |
| For every adjacent pair, `end[i] == start[i+1]` | `span_chunk_chain` |
| `start_first <= offset < end_first`, and `offset + len <= end_last` | `span_range_outside` |
| The requested end exceeds the start of the last chunk (`offset + len > start_last`), so the last chunk is needed | `span_last_unneeded` |

The span of each chunk is the one its leaf commits (§4 step 2 and the
multi-proof of step 1), so the boundaries are authenticated and the container
carries nothing else to prove. `span_chunk_context` is
a defence-in-depth check: the authenticated chunk proofs make that failure
unreachable once the earlier checks pass. It remains a distinct reject reason
for an independent verifier that receives inconsistent decoded proof data.
Checked arithmetic MUST be used throughout.

On success the verifier MUST strip each Blob's canonical header,
concatenate its content in order, and return the slice
`[offset - start_first, offset + len - start_first)`. It MUST also return
the authenticated path, leaf id, trusted commit id, absolute offset (`offset`),
and signature verification result under §4's trust model. A claimed path
outside the verified bundles is not evidence. The caller MUST compare
that authenticated path and range against its request.

### 8.3 Vectors and version history

[`rust/tests/golden/http-objects/`](../../rust/tests/golden/http-objects/)
pins accept containers starting at both zero and nonzero chunk indices,
and rejects for gaps, duplicates, a chain that breaks (`end[i] != start[i+1]`),
wrong selectors, mixed commits, mismatched leaves, ranges outside the span,
an unnecessary last chunk, magic/version errors, trailing bytes,
truncation, a non-minimal varint, a varint above `u32::MAX`, a chunk count
of 1,000,001, a span of KDPB v2 bundles, a KDPB supplied in place of a KDSP, and oversize input.
Large reject bodies use sidecar byte-range copy and patch
recipes over the accepted containers; each recipe reconstructs exact bytes
before verification.
The oversize vector uses a pinned small seed plus a sidecar expansion
recipe to construct 64 MiB + 1 bytes without checking in a large zero file.
The bad-varint vectors splice the malformed prefix over the real first
bundle length inside an otherwise complete valid container, and the
chunk-count vector is zero-filled to one empty vector per declared chunk, so a
lenient reader fails for a different reason and only the 1,000,000 cap rejects
it. Each reject sidecar names the exact reason in §8.2.

Document version 5 changes KDPB to wire version 3 and KDSP to wire version 2.
A KDPB v2 bundle is a typed `UnsupportedBundleVersion(2)` error.

## 9. Later (out of scope for this document)

- **Non-membership.** `payload_kind 3` is reserved for a future proof
  that a name is *absent* from a `Tree` (a range proof over the two
  lex-adjacent entries). Not
  implemented here.

## 10. Invariants

| Mutation | Detected because |
|---|---|
| a span mixes commits, leaves, metadata, or nonconsecutive chunks | the checks and distinct reject reasons in §8.2 |
| a span claims incorrect boundaries | each chunk's committed span in its leaf, and the chain rule `end[i] == start[i+1]` (§8.2) |
| any disclosed byte tampered | the Bao slice / BLAKE3 check against the authenticated id fails |
| a step's `(name, mode, child_id)` tampered | that step's inclusion proof no longer folds to the expected parent id |
| declared inner root does not wrap to the parent id | wrap-check-first (`domain_digest(TYPE_DOMAIN, inner_root) == expected_id`) fails with `InnerRootMismatch` |
| proof fold does not equal the declared inner root | rejected even if the wrap of the declared root happens to match |
| step order/parent tampered (steps swapped) | each step verifies against the *previous* step's `child_id`, not an independent root |
| a non-final step's mode misreported as non-`Tree` | rejected outright (§4 step 8.3), before its proof is even checked |
| `ChunkedBlob` `total_size`/`chunk_size` forged | the multi-proof's metadata leaf (computed by the verifier, never accepted as input) no longer folds to the leaf id |
| a `Range` payload's offset/length claim tampered | the Bao slice fails to verify at the claimed offset |
| a chunk's `start` or `end` tampered | the chunk leaf changes, so the multi-proof no longer folds (§4 step 1) |
| a first chunk that does not start at 0, a last chunk that does not end at `total_size`, a fixed-size chunk off its span | §4 steps 3, 4 and 5 |
| chunk bytes whose length differs from the span | §4 step 6 for a `Chunk`; §7.4 item 10 for a closure |
| a manifest whose spans overlap or leave gaps | not proven by a disclosure (§1); refused by the manifest decoder and by closure verification (§7.4) |
| oversize bundle / proof sibling count | bounded before any decode allocation (§5) |
| checked against a bare inner root instead of the object id | every check here goes through the id-based `merkle::verify_*` (SPEC-MERKLE-OBJECTS §5.4) |
| a claimed path not matching what was actually authenticated | callers compare the returned authenticated `path`, never a path string the bundle merely asserts |
| a closure object omitted | the walk from the root reports it in `missing`; completeness fails |
| a closure object's bytes tampered | map verification reports a deserialize failure as `corrupt` and a still-deserializable bit flip as `missing` plus `unreferenced`; a verifier that fetches by id MAY report a hash mismatch as `corrupt` under the requested id |
| a delta or compressed pack in a closure | profile violation, before any decompress |
| a closure manifest pack hash swapped | `pack_key` mismatch against the supplied pack |
| a closure verified against the wrong root | the requested root is `missing`; the supplied set is `unreferenced` |
| a closure manifest whose `root` differs from the caller's trusted root | typed `ClosureRootMismatch`; the manifest is a locator, never a trust anchor |

## Cross-references

- [SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md) §2 (identity), §3.1/§3.2
  (leaf schemes, chunk spans), §5 (inclusion proofs, wire bytes,
  verification-against-id rule).
- [SPEC-OBJECTS](SPEC-OBJECTS.md) §3 (Blob), §4 (Tree, entry-name rules),
  §6 (Remix sources), §6a (Tag), §7 (ChunkedBlob).
- [SPEC-PACKFILE](SPEC-PACKFILE.md) &mdash; v1 raw (`0x00`) packs are the
  closure-profile carrier.
- [SPEC-SIGNING](SPEC-SIGNING.md) §3 (what a commit signature covers).
