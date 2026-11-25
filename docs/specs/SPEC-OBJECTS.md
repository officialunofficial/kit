---
spec: SPEC-OBJECTS
version: 1
status: stable
audience: implementers of compatible tools producing or consuming kit on-disk objects
---

# SPEC-OBJECTS &mdash; kit v1 on-disk object format

Status: **Normative** for kit v1.
Scope: `.kit/objects/` content and the byte layout of every object type.
Endianness: **little-endian** throughout. All hashes are 32-byte BLAKE3.

This document defines the on-disk object byte layout and the identity /
remix object model. External tools MUST be able to produce and consume
these bytes with only this document.

---

## 1. Object types

```
ObjectType (u8)         name
0x01                    blob
0x02                    tree
0x03                    commit
0x04                    remix
0x05                    chunked_blob
0x06                    delta
0x07                    tag            (annotated / signed tag; new in v1)
```

`0x01`–`0x06` are unchanged in v1. `0x07` (tag) is additive: it appends
a new storable object type and does NOT alter the layout, signing bytes,
or hashes of any pre-existing type, so all earlier golden vectors remain
valid. Readers MUST accept `0x01..=0x07`.

`delta` objects are **pack-only**. They MUST NOT appear in the object store
and MUST NOT be served by `downloadObject`-style APIs. Deltas are resolved
during pack unpacking into a materialized base type (`blob`, `tree`,
`commit`, etc.).

---

## 2. V1 prologue &mdash; every object

Every stored object begins with:

```
offset  size  field              value
0       1     object_type        one of 0x01..0x07 (see §1)
1       4     magic              ASCII "KOB1" = 0x4B 0x4F 0x42 0x31
5       1     schema_version     0x01, or 0x02 for object_type 0x05 (chunked_blob)
6       …     body               type-specific (see §3-§8)
```

The prologue applies to **all seven object types**. Rationale:

1. Without a version byte, any field addition silently shifts every
   hash.
2. Partial prologue (commit and remix only) leaves four object types
   unversioned and makes readers branch on type before they can detect a
   future format change. All-types prologue lets the prologue itself be
   the single branching point.
3. Cost: 5 bytes per object. Negligible against the 33-byte minimum
   overhead a stored blob already carries.

Readers MUST reject any of:
- `object_type` not in `0x01..0x07` → `InvalidObjectType`
- `magic` != `"KOB1"` → `InvalidMagic`
- `schema_version` other than the version of the object's type →
  `UnsupportedObjectVersion`. The version of `chunked_blob` (`0x05`) is
  `0x02`. The version of every other type is `0x01`.

A reader parses `object_type` first and then compares `schema_version` with
that type's version. The commit signing bytes (SPEC-SIGNING §3) copy the
commit prologue, so they keep `0x01`.

There is no v0. kit does not read kit-era bytes.

---

## 3. Blob (`0x01`)

```
[prologue 6]
[u32 LE len]
[len bytes data]
```

No interpretation of `data`. `len = 0` is valid (empty blob). Upper bound
is enforced at the storage layer: the object store rejects objects
> 1 GiB. A pack entry independently caps at the packfile total limit
(see SPEC-PACKFILE).

---

## 4. Tree (`0x02`)

```
[prologue 6]
[u32 LE entry_count]                      0..=1_000_000
repeat entry_count:
    [u32 LE name_len]                     1..=255
    [name_len bytes name]                 UTF-8 (see §4.1)
    [u8 mode]                             see §4.2
    [32 bytes object_hash]
```

`entry_count > 1_000_000` → `TooManyEntries`.

**Identity:** a `Tree`'s object id is its Binary Merkle Tree root over the
entry leaves (one leaf per `(name, mode, object_hash)` triple, in the
canonical lex order), NOT `BLAKE3` of these bytes. The byte layout is
unchanged. See [SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md) §3.2.

### 4.1 Entry name rules

Normative:

- `name_len` ∈ `[1, 255]`. Zero-length name is illegal.
- Forbidden bytes **anywhere** in name: `0x00`, `/` (`0x2F`), `\` (`0x5C`),
  `:` (`0x3A`). NTFS reads `:` as an alternate data stream or drive marker
  (`.kit::$INDEX_ALLOCATION`, `C:x`).
- Forbidden exact names: `"."`, `".."`.
- Forbidden trailing characters: `.` (`0x2E`) and SPACE (`0x20`). Windows
  silently strips these, which would alias one entry onto another of the
  same bare name. Applies to the last byte of `name` only &mdash; interior
  dots and spaces are accepted.
- Forbidden case-insensitively: the bare names `.kit` and `.git`. ASCII
  case-folding only; names containing non-ASCII bytes are not folded
  (they remain constrained by every other rule above). This is a
  Git CVE-2021-21300 family defense.
- Forbidden case-insensitively: `kit~N` and `git~N`, where N is one or more
  ASCII digits. These are the NTFS 8.3 short names of `.kit` and `.git`.
- Forbidden Windows reserved device names, case-insensitively, with or
  without an extension: `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`,
  `LPT1`-`LPT9`. Comparison is against the stem (the bytes before the
  first `.`). `COM0` and `LPT0` are NOT reserved.
- No further Unicode validation performed. Implementations SHOULD reject
  input that is not well-formed UTF-8 but MAY pass it through byte-for-byte.

Violations of any rule above → `InvalidEntryName`.

Additionally, entries within a single tree MUST be sorted
lexicographically (byte-wise ascending) by `name` with no duplicates.
Readers MUST reject unsorted trees with `InvalidEntryOrder`. This is
load-bearing: tree hashes are only reproducible across implementations
when ordering is canonical.

### 4.2 Entry mode

```
0x01    blob         regular file content
0x02    tree         subdirectory
0x03    symlink      symbolic link; object_hash points to a blob whose
                     data is the link target path
0x04    executable   regular file, executable bit set (POSIX 0o755)
```

Mode `0x04` marks an executable file. Writers MUST emit `0x04` for any
file with the POSIX executable bit set at staging time. Non-POSIX hosts
MAY round-trip `0x04` bytes opaquely.

Any other mode byte → `InvalidEntryMode`.

A staging or checkout tool MUST reject a symlink target that is empty,
starts with `/`, contains a `..` segment, or contains NUL, `\` or `:`.
The rule is the same on every platform, so a tree valid on one host is
valid on all hosts.

### 4.3 Rename detection

kit detects **exact** renames: because every blob is named by its BLAKE3
content id, a deletion and an addition that share an object id are the same
bytes at two paths &mdash; an exact move (git's `similarity index 100%`), found
by an O(n) hash match with no heuristic and no false positives. `status`
and `diff` render these as `R` by default (`--no-renames` opts out),
scoped per diff as git does.

**Not yet detected:** rename-with-edits (similarity < 100%) and copy
detection (`-C`). Those require git's content-similarity scoring; kit's
chunked/merkle blobs give a natural shared-chunk similarity signal, so they
are a tractable follow-up rather than a structural gap. `merge` still
treats all moves as (delete, add) pairs. This differs from git.

---

## 5. Commit (`0x03`)

```
[prologue 6]
[32 bytes tree_hash]
[u32 LE parent_count]                     0..=1_000
repeat parent_count:
    [32 bytes parent_hash]
[Identity author]                         see §9
[u32 LE message_len]
[message_len bytes message]               UTF-8 by convention (see below), NOT null-terminated
[u64 LE timestamp]                        seconds since Unix epoch
[32 bytes signer]                         Ed25519 public key
[32 bytes message_hash]                   may be zero (see §5.1)
[32 bytes content_digest]                 may be zero (see §5.1)
[64 bytes signature]                      Ed25519, see SPEC-SIGNING
```

Message bytes are UTF-8 **by convention**: writers SHOULD emit UTF-8,
but readers MUST NOT reject non-UTF-8 message bytes (load-bearing for
histories imported from systems with non-UTF-8 encodings).

### 5.1 `message_hash`/`content_digest`

These remain **core fields** on `Commit` but are
**NOT part of the commit signing bytes** (see SPEC-SIGNING §3). They are
optional off-chain annotation slots for downstream consumers. Core
stores them because:
1. They are 32 bytes each and carry a stable meaning regardless of any
   consumer.
2. Stripping them from core would require a sidecar file per commit and
   break in-place round-trip.

Writers with no annotation to record MUST emit them as `0x00`*32 (zero
hash). Readers MUST NOT reject a commit because they are zero.

### 5.2 Root commits

`parent_count = 0` is valid and denotes a root commit.
`parent_count > 1_000` → `TooManyParents`.

---

## 6. Remix (`0x04`)

```
[prologue 6]
[32 bytes tree_hash]
[u32 LE parent_count]                     0..=1_000
repeat parent_count:
    [32 bytes parent_hash]
[u32 LE source_count]                     0..=10_000
repeat source_count:
    [32 bytes upstream_id]                was project_id in kit
    [32 bytes commit_hash]
[Identity author]                         see §9
[u32 LE message_len]
[message_len bytes message]
[u64 LE timestamp]                        widened from u32 (see §5)
[32 bytes signer]                         Ed25519 public key
[64 bytes signature]                      Ed25519, see SPEC-SIGNING
```

Naming: the 32-byte source identifier is called `upstream_id` in v1 (the
byte layout is unchanged &mdash; the name transition is cosmetic).

### 6.1 Source sort invariant

Sources MUST be sorted lexicographically by `(upstream_id, commit_hash)`,
primary key `upstream_id`. Duplicate `(upstream_id, commit_hash)` pairs
are illegal. Readers reject unsorted sources with `InvalidSourceOrder`.

`RemixSource` is **opaque in core**: `upstream_id` is 32 bytes of caller-
chosen content. Typical values include `BLAKE3(repo_url)` or any other
32-byte identifier that uniquely names the upstream. Core never
interprets it.

---

## 6a. Tag (`0x07`)

An **annotated / signed tag** object. Lightweight tags are
*not* objects &mdash; they are a bare `refs/tags/<name>` ref pointing straight
at a commit (see SPEC-REFS). A tag object is created only by
`kit tag -a` (annotated) or `kit tag -s` (signed); in both cases the
`refs/tags/<name>` ref points at the **tag object hash**, and the tag
object's `target` field points at the tagged object.

```
[prologue 6]                              object_type=0x07
[32 bytes target]                         hash of the tagged object
[u8 target_type]                          ObjectType of target (0x01..=0x05, 0x07; NOT 0x06 delta)
[u32 LE name_len]                         1..=4096
[name_len bytes name]                     short tag name (for example "v1.0.0"); no \0/\\
[Identity tagger]                         see §9
[u32 LE message_len]
[message_len bytes message]               UTF-8, NOT null-terminated; may be empty
[u64 LE timestamp]                        seconds since Unix epoch
[32 bytes signer]                         Ed25519 public key
[64 bytes signature]                      Ed25519 over the tag signing bytes (SPEC-SIGNING §4a)
```

Rules:

- `target_type` MUST be a storable object type. `0x06` (delta) is
  pack-only and rejected with `TagTargetTypeInvalid`. Recording the
  target type lets a verifier display the tag without fetching the
  target.
- `name` is the **short** ref name, not a full `refs/tags/...` path.
  Empty, over 4096 bytes, or containing `\0`/`/`/`\\` →
  `TagNameInvalid`. The full ref-name grammar (SPEC-REFS) is enforced at
  ref-write time; the object layer enforces only this floor so the wire
  form is unambiguous.
- An **annotated, unsigned** tag carries an all-zero `signature`
  (`0x00`×64). A verifier MUST treat an all-zero signature as
  "unsigned" &mdash; it does not verify as a valid Ed25519 signature, so
  `kit verify` on an unsigned annotated tag fails the signature check.
- A **signed** tag's `signature` is `Ed25519.sign(signer_seed,
  tag_signing_hash)` (SPEC-SIGNING §4a). `signer` is the verification
  key; `tagger` is an independent attribution claim (same separation as
  commit `author` vs `signer`, SPEC-SIGNING §6).

The tag object is content-addressed like every other object; its hash is
`BLAKE3(serialized tag bytes)`.

---

## 7. Chunked blob (`0x05`)

```
[prologue 6]                              schema_version 0x02 for this type
[u64 LE total_size]
[u32 LE chunk_size]                       default marker, fixed size, or chunker profile ID
[u32 LE chunk_count]                      0..=8_388_608
repeat chunk_count:
    [32 bytes chunk_hash]                 each chunk stored as its own blob
    [u64 LE end_offset]                   offset one past the chunk's last byte
```

The object is `22 + 40 * chunk_count` bytes. Entry `i` starts at byte
`22 + 40 * i`. Entries are interleaved, so a writer appends as it cuts and a
reader finds the chunk of a byte offset by binary search over fixed-width
entries.

The **span** of chunk `i` is `[start_i, end_i)`, with `start_0 = 0` and
`start_i = end_{i-1}`. The span is the byte range the chunk holds in the
file. The manifest commits it: a chunk's blob MUST hold exactly `end_i -
start_i` bytes of content.

The `chunk_size` field identifies the layout:

| Value | Meaning |
|---|---|
| `0` | FastCDC v1, the default (SPEC-FASTCDC) |
| `1..=0x7FFF_FFFF` | Fixed size in bytes |
| `0x8000_0000..=0xFFFF_FFFF` | Chunker profile ID. `0x8000_0002` names FastCDC v2 (SPEC-FASTCDC §11). Readers MUST refuse all other IDs in this range. |

FastCDC v1 and v2 are content-defined layouts. In a fixed-size layout, each
chunk except the last is exactly the stated size. The last holds between
1 and that many bytes.

**Header check.** The header alone (`total_size`, `chunk_size`, `chunk_count`)
MUST satisfy all of these. This is the check a disclosure verifier runs
without the entries (SPEC-DISCLOSURE §4). Each rule has its own label:

- `total_size` is at most 128 GiB (137,438,953,472), else `total_size above
  the file limit`.
- `chunk_size` names a supported layout, else `UnknownChunkerProfile`
  (`unknown chunker profile`).
- `chunk_count` is `0` only when `total_size` is `0`, else `total_size
  without chunks`.
- when the layout is content-defined and `chunk_count` is above `0`,
  `total_size` is at least `chunk_count`, else `total_size below
  chunk_count`.
- when the layout is fixed-size and `chunk_count` is above `0`, `total_size`
  is above `(chunk_count - 1) * chunk_size` and at most
  `chunk_count * chunk_size`, else `total_size outside the fixed-size layout`.

The decoder and the id fold check the chunk count cap, the 128 GiB cap and
the chunker profile before processing entries. The entry checks enforce the
remaining layout rules. The disclosure verifier runs the whole header check
on `leaf_count - 1`.

**Entry check.** One function checks each entry. The decoder and the id fold
(SPEC-MERKLE-OBJECTS §1.2) both run it, so both refuse at the same entry with
the same label. For entry `i` with `end_{-1} = 0`, in this order:

1. `end_i > end_{i-1}`, else `end not increasing`.
2. `end_i - end_{i-1}` is at most `MAX_RAW_OBJECT_SIZE - 10` (1 GiB less the
   10-byte Blob prologue), else `chunk length above the object limit`.
3. `end_i <= total_size`, else `end above total_size`.
4. In a fixed-size layout, `end_i == min((i + 1) * chunk_size, total_size)`,
   else `fixed layout end`. The arithmetic MUST be checked.

**Decoding.** A reader MUST run these checks in this order. Each has its own
error and its own label. An object shorter than the 22-byte header is
refused first, as `truncated`. All arithmetic in the decoder, the fold and
the verifier MUST be checked; an overflow is refused with the label of the
step it occurs in.

1. `chunk_count` is at most 8,388,608, else `TooManyChunks` (`too many
   chunks`).
2. The object is exactly `22 + 40 * chunk_count` bytes, else `manifest
   length`. This check comes before any allocation, so a short body under a
   large `chunk_count` allocates nothing.
3. `total_size` is at most 128 GiB, else `total_size above the file limit`.
   Then `chunk_size` names a supported layout, else `UnknownChunkerProfile`
   (`unknown chunker profile`). This check also applies to empty manifests.
4. Each entry passes the entry check.
5. The last end equals `total_size`. With no entries, `total_size` is `0`.
   Check 4 already refuses an end above `total_size`, so this check refuses a
   last end below it (`last end below total_size`) and a manifest with no
   entries and a non-zero `total_size` (`total_size without chunks`).

These checks imply every rule of the header check. The header check stays as
its own check for a verifier that holds no entries.

An entry with `end_0 = 0` refuses as `end not increasing`. A fixed-size layout
whose last end is off by one refuses as `fixed layout end`.

A `schema_version` other than `0x02` is `UnsupportedObjectVersion` (§2),
refused when the prologue is read, before `truncated` and the checks above.

Reassembly: concatenate each `chunk_hash` blob's contents in order. A reader
MUST check each chunk's content length against its span, not only the
concatenated length. The concatenated length then equals `total_size`.

Readers MUST NOT size a buffer from `total_size`. Readers MUST stop writing
when the running byte count passes `total_size`.

Writers MUST refuse to encode a manifest that a reader rejects, and MUST pass
each chunk's length when they build one. A manifest is otherwise stored under
an id no reader can decode.

The 128 GiB bound is the largest file kit stores. The chunk cap, 8,388,608,
is that bound cut at the 16 KiB FastCDC minimum chunk size (SPEC-FASTCDC).
The largest manifest is `22 + 40 * 8,388,608` = 335,544,342 bytes, under the
1 GiB object cap. A reader that holds a whole file in memory, such as a text
diff, blame or a git export, MAY refuse a file above its own smaller limit. It
refuses with a typed error and before it reads a chunk. kit's limit for such
readers is 1 GiB.

File-content equality MUST be independent of the chosen valid Blob or
ChunkedBlob representation. Equal object IDs permit a fast path; otherwise
comparisons MUST verify the referenced objects and compare the full ordered
byte stream, bounded by the manifest and one chunk per side. A missing chunk,
wrong-type chunk or chunk whose length differs from its span is an error even
if an earlier byte already differed. Mode equality is a separate condition.
Derived raw content hashes may index rename candidates, but MUST NOT replace
object IDs; candidate matches are confirmed by byte comparison.

Status, diff, staging, merge decisions and overwrite protection use this
content contract. Restaging equal bytes preserves the previous staged object
ID. Writer chunking policy does not invalidate an otherwise conforming object.

**Identity:** a `ChunkedBlob`'s object id is its Binary Merkle Tree root
(leaves = a metadata leaf binding `total_size`/`chunk_size`, then one leaf
per chunk binding its span and its id), NOT `BLAKE3` of these manifest bytes.
The byte layout above is unchanged by this; only the byte→id function
differs. See [SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md) §3.1. Because the
leaves commit the spans, a disclosure proves a chunk's byte offsets with one
proof of logarithmic size (SPEC-DISCLOSURE).

---

## 8. Delta (`0x06`)

Pack-only. See SPEC-DELTA for the instruction format and SPEC-PACKFILE
for framing. The on-disk layout (if ever serialized alone, which
implementations SHOULD NOT do) is:

```
[prologue 6]
[32 bytes base_hash]
[u32 LE result_size]
[u32 LE instr_len]
[instr_len bytes instructions]
```

---

## 9. Identity &mdash; tagged union

```
[u8 kind]
[u16 LE len]
[len bytes payload]
```

Kinds:

```
0x01    ed25519         len MUST be 32; payload = raw 32-byte Ed25519 public key
0x02    did_key         len >= 1;       payload = UTF-8 `did:key:...` string, minus the scheme prefix
                                        (that is, the multibase-encoded key material, starting with 'z')
0x03    opaque          len >= 1;       payload = arbitrary bytes defined by adapter
```

Rules:

- `len = 0` is **illegal** for every kind → `InvalidIdentity`.
- `len > 4096` → `IdentityTooLarge`.
- Unknown `kind` → `UnknownIdentityKind`.
- Two identities compare equal iff `kind` and `payload` bytes are
  byte-equal. No case-folding, no canonicalization.

Identity serialization is used in **both** the on-wire serialized commit
and the signing bytes (see SPEC-SIGNING). The bytes are identical in both
contexts. This means the identity length is variable at signing time,
which is why the `len` field is always explicit.

---

## 10. Storage

A loose object lives at `.kit/objects/<dd>/<rrrrrrrrr...r>`, where
`<dd>` is the lowercase hex first byte of its id and `<r...>` is the
remaining 62 hex digits. A packed object lives in a raw frame indexed by
the same id under `.kit/objects/pack/` (common directory for linked
worktrees). See [SPEC-PACKFILE §3.1.1](SPEC-PACKFILE.md#311-local-packs).

The object id is type-dependent: a `Tree` (`0x02`) or `ChunkedBlob`
(`0x05`) is addressed by its Binary Merkle Tree root
([SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md)). Every other storable type
uses `BLAKE3(object bytes)`. The 1 GiB serialized-size cap applies to
both locations.

### Repository marker

The common directory MUST contain a `format` file. A new store starts
with the packed marker. A store made by an earlier kit that no later kit
has written to keeps the legacy marker `bmt-v2` (canonical bytes
`bmt-v2\n`) and is loose-only.
The bytes after the canonical prefix `bmt-v2\n` are a required set of
ASCII capability letters. Each letter occurs once. A reader MUST refuse
the store with `IncompatibleRepoFormat` and tell the user to update kit
if the set contains a letter the reader does not know. `P` is the only
currently defined letter. It requires support for the raw local pack
and its index, including the full range of storable objects. The current
packed marker is exactly `bmt-v2\nP` with no final newline.
Bound marker reads. Accept exactly three byte strings and no others:
`bmt-v2\n` (the legacy marker, a loose store), `bmt-v2\n\0` (a lost
activation, which opens as a loose store) and `bmt-v2\nP` (a packed
store). Refuse every other byte string, including whitespace around the
legacy value, and an absent marker, with `IncompatibleRepoFormat`. A
legacy reader refuses the packed form. Readers check the marker under the
shared lock and enable local-pack discovery only with `P`.

A writer of objects tries activation once per store handle, before its
first write and before it takes a shared prune guard. That covers a
staged batch at its first staged write, a single object write, a bulk
write session at its first write and a fetch before its guard. A read, a
ref write and an open do not activate. Creating a store writes the packed
marker: write the bytes `bmt-v2\nP` to a temporary file in the common
directory, sync it, rename it to `format`, then sync the directory.
Under the exclusive `format`
try-lock, validate the marker. For the canonical legacy marker or the
exact zero-tail form, write only the ASCII byte `P` at offset 7 with a
positional write through the locked handle, then sync the file. Preserve
the seven-byte prefix and the inode, including on error. If the
try-lock is busy, or the marker cannot be opened for writing because
of permissions or a read-only filesystem, use loose writes and leave the
marker as it is; the handle does not try again. Any other failure is
an error.
Lock details are in [SPEC-CONCURRENCY §3.4](SPEC-CONCURRENCY.md#34-object-refresh-versus-local-gc).

An interrupted activation can leave the canonical legacy marker, the
eight-byte marker with a zero tail, or the packed marker. Readers need
only the shared lock in each case. A publisher must sync and validate
the packed marker before publishing any pack, including on retry after
an uncertain sync. Once activated durably, the packed marker is
permanent even when no local packs remain. Upgrade all clients sharing
the common directory and drain sessions opened by legacy clients before
activation. The packed marker fences subsequent legacy opens, so a
legacy kit refuses a repository that a later kit created or wrote to.

### Object lookup

Every logical object accessor uses the same location lookup. This includes
full and allocator-backed reads, restore and sparse fan-out, verification
and closure walks, headers and types, cached children, presence, reuse,
and serialized size. Push uses logical headers and sizes for planning,
split limits, and delta budgeting. The packed serialized size is the raw
payload length. Physical loose-file metadata remains available for a
loose-file sweep.

With `P` set, a reader checks the versions of each live pair before
using its layout. A pair whose pack header and index carry the same unknown
version was written by a newer kit: that is `IncompatibleRepoFormat`, with an
instruction to update kit, and it stops lookup and repair. One file with an
unknown version while the other differs is damage to that pair, not a newer
format: the reader records it, names the pair, skips it as for any other
damage, and keeps reading the other pairs. See
[SPEC-PACKFILE §3.1.1](SPEC-PACKFILE.md#311-local-packs).

Try known published packs, then the loose path. Skip an unusable index
when looking for another copy. On a miss, including a stale location that
disappears or cannot be opened because its deletion is pending, refresh
pack discovery and retry before reporting absence. A refresh in a store
opened with the legacy marker MUST reread the marker under a shared
`format` lock and enable pack discovery if `P` has appeared. If no copy is
found and an unusable pair might have held the id, return an integrity
error that names the pair. The refresh MUST work when directory mtime
is unchanged. A lookup used only to avoid a redundant write MAY
skip the refresh on a miss if that miss causes a verified copy to be
written. Resolve short ids and enumerate objects over both locations.
Refresh discovery before reporting a short id missing or unique, and
count copies of the same id once.

A verified read checks canonical object bytes and recomputes the
type-dependent id. If a copy fails verification, try the other locations,
including the refreshed set. Return `HashMismatch` if the available
copies have mismatching ids and no verified copy exists. An unresolved
integrity or I/O error MUST remain distinct from a confirmed missing
object. Header and size probes keep their existing verification contract
and stay within the selected frame. The closure verifier can obtain a
bad copy for diagnosis if no copy verifies, preserving its mismatch
classification. A presence or size probe alone never proves integrity.

### 10.1 Durability

Object writes MUST be atomic with respect to readers. A loose object
becomes visible at its final path by renaming a staged file. A packed
object becomes visible through its complete pair. In both cases:

> An object's bytes MUST be durable before it becomes visible. Refs,
> the staging index, and recovery state MUST only name objects whose
> bytes and usable locations are durable.

Implementations MAY amortize flushes across a multi-object command.
Batched mode stages files, makes contents durable before renaming them,
then flushes the touched directories. Per-object flushing remains a
conforming schedule. Batched mode's directory flushes carry the dirent
ordering on metadata-journaling filesystems in ordered-data mode.
Deployments on filesystems without that property SHOULD use per-object mode.

For each local pair, the publisher MUST enforce this order. Hold the
shared `format` guard or its exclusive lock from staging through the
final directory flush. This prevents the orphan sweep from removing
files of a live publisher.

1. Ensure the marker with `P` is durable. Sync
   the common directory before publishing, including on retry after an
   uncertain directory sync.
   Create `objects/pack/` if needed and make its entry durable in
   `objects/` before acknowledging the pair.
2. Stage and verify the sealed pack and its index in
   `objects/pack/.<nonce>.tmp.pack` and `objects/pack/.<nonce>.tmp.idx`.
   The nonce consists of 32 lowercase hex digits. Make both files'
   contents durable before publishing either name.
3. Publish the final pack name, then the final index name. The pack name
   MUST survive any crash that leaves the index name from this publish.
   Flush the pack name first if the filesystem gives no such ordering
   guarantee. Flush `objects/pack/` before acknowledging the pair. A concurrent
   publisher can reuse an existing pair of the same key only after verifying
   both members and confirming the names still resolve. Add the published
   pair to the publisher's lookup view.
4. Persist completed remote-pack records after all their object
   locations are durable. Publish refs only over durable objects and
   after the checks in [SPEC-TRANSPORT](SPEC-TRANSPORT.md#pack-chain-fetch).

A writer that found its object already visible MUST make its location
durable before referencing it. Flush the loose shard or the pack
directory and, if needed, the directory containing the pack directory.
When another process can retire the selected location, follow the
guard and re-resolution rules in SPEC-CONCURRENCY §3.4. A per-object write
that creates a loose shard directory also flushes `objects/`, which holds the
new directory entry.

Local batched and per-object writes look in loose storage and in their
discovered pack catalog. They MAY accept a loose file or packed frame of
the exact serialized length without reading the object body. Fetch writes
every object in its window.

A local batched write (`kit add`, `kit add -u`, `kit commit -a`,
`kit stash`) in a store with capability `P` writes each chunk of a chunked
file it must store into a local pack of its own, in file order. Past the
first 64 small files of a batch whose blob the store did not already hold, it
also packs each small file, a plain blob of at most 16,384 serialized bytes,
into that pack. A file whose blob the store already holds does not count. It stores everything
else loose. The batch seals its open pack at 64 MiB of
payload or 65,536 entries, and when it commits. Before it renames a loose
manifest, tree or commit, it publishes the pack, so no such object is
visible before the packed chunks it names. A pack's layout is checked
against the writer's records when it is published, and an index entry or
ref is written only after the batch's last pack is published. Per-object writes, loose stores, and a
writer that cannot activate the marker keep every chunk loose.

**Writer limit on entries.** Every writer of local packs seals a pack before
it would hold more than 65,536 entries. The `kit add` batch above, a fetch
publication window ([SPEC-TRANSPORT](SPEC-TRANSPORT.md#pack-chain-fetch)) and
a gc output ([SPEC-GC](SPEC-GC.md)) share this limit, and they share the
payload limit of 64 MiB of serialized bytes, with one exception: gc gives one
object that alone passes 64 MiB an output pack of its own. These limits are
writer policy and bound the locators, batch paths and index workspace of one
pack. A reader accepts any pack within the format caps of 10,000,000 entries
and 4 GiB of payload ([SPEC-PACKFILE](SPEC-PACKFILE.md) §5 and §3.1.1), so a
pack from a writer with other limits stays readable.

Before pack publication, a crash can leave staged files. Between
renames it can leave a pack with no index. Before the final directory
flush, the pack name or the complete pair can survive a power loss.
Normal discovery ignores a lone member. A surviving complete pair can serve reads after normal
validation. Once the directory flush succeeds, a crash before the
applied record leaves the pair available for lookup and the remote pack
eligible for replay. After the record is durable, a restart can reuse
the completed remote pack even if no ref was published. These cases
leave existing refs intact. See [SPEC-GC](SPEC-GC.md#local-pack-maintenance)
for orphan handling, repair, and retirement ordering.

---

## 11. Trailing-byte rule

Every object deserialiser MUST verify that after parsing the declared
layout there are zero remaining bytes. Extra bytes → `TrailingData`.
This prevents trivial amplification and prologue-replay attacks.

---

## 12. Version history

| Version | Released | Changes                                                          |
|---------|----------|------------------------------------------------------------------|
| `0x01`  | v1.0     | First kit format. See §2 for prologue.                          |
| `0x02`  |          | `chunked_blob` only: 40-byte entries that carry end offsets (§7). |
| marker `P` | 0.10 | Repository marker capability `P` (`bmt-v2\nP`): raw local packs and their index (§10). A reader that does not know `P` refuses the store. This reader accepts exactly the three marker byte strings of §10. |
| local add packs chunks and small files | 0.10.x | A batched write packs the chunks of a chunked file and the small files past the first 64 new ones of the batch into local packs, as §10.1 says. It is a writer policy. It changes no byte of a pack, an index or an object, and needs no marker beyond `P`. |

A new store starts with the packed marker, and a later kit's first object write activates an older loose store, so kit 0.9 and older refuse a repository that this version created or wrote to.

A later marker capability is another letter after the `bmt-v2\n` prefix, and a reader that does not know it refuses the store.

`schema_version` is per object type. It is `0x02` for `chunked_blob`
(`0x05`) and `0x01` for every other type. A version bump is reserved for
changes that alter an existing type's layout: the end offsets in each
`chunked_blob` entry are such a change. An old reader gets
`UnsupportedObjectVersion` for a new manifest, not a length error.

Adding the `tag` object type (`0x07`) is an **additive object-type allocation
within v1**: it introduces a new `object_type` byte and a new body layout but
changes no existing type's bytes, so `schema_version` is NOT bumped and every
pre-tag golden vector is unaffected.

Merkle object addressing (`Tree`/`ChunkedBlob` keyed by BMT root,
[SPEC-MERKLE-OBJECTS](SPEC-MERKLE-OBJECTS.md)) leaves every type's **bytes**
unchanged. The `bmt-v2` addressing marker (§10) guards these ids,
including the leaves of §7 that commit chunk spans. Activating local
packs leaves existing loose object bytes and ids in place.

Future versions MUST increment `schema_version` and MUST preserve the
`"KOB1"` magic prefix. The magic byte string is normative &mdash; readers are
allowed to route on `magic` before consulting `schema_version`, enabling
multi-version readers.

---

## 13. Test vectors (implementer MUST produce)

1. **Empty blob id**: `Blob` is a flat type (§10) &mdash; its id is
   `BLAKE3(prologue{0x01,KOB1,0x01} ‖ u32(0))`, a 10-byte total input.
   Record the resulting hex digest.
2. **Empty tree id**: `Tree` is a **merkelized** type (§10 /
   SPEC-MERKLE-OBJECTS) &mdash; its id is the domain-wrapped Merkle root over
   its (empty) entry set, **not** `BLAKE3` of the serialized prologue
   bytes. The empty tree's id is pinned as a real, common object:

   ```
   b29117ce9b3d66ba98cd0a57145400f0bf6fff8b5c27c4552d80a38446f27ef7
   ```

   (`kit-core::merkle::TREE_EMPTY_ID`; the empty BMT root is
   `H(leaf_count ‖ H(""))`, not `H(0 ‖ 0)` &mdash; see SPEC-MERKLE-OBJECTS §4.)
3. **Canonical single-file tree**: one entry `{name="README.md",
   mode=0x01, object_hash=<id of §13.1>}`. Record the serialized bytes,
   and separately record the object's id computed per the merkelized
   rule (§10 / SPEC-MERKLE-OBJECTS) &mdash; the two are different values; do
   not conflate "the serialized bytes' flat BLAKE3" with "the object id"
   for this type.
4. **Identity round-trip**: encode `Identity{kind=0x01, len=32,
   payload=[0xAA; 32]}` → must be exactly 35 bytes.
5. **Root commit with zero message_hash/content_digest and Ed25519
   identity**: serialize and record signing bytes hex +
   cross-domain-verification-negative hex.
6. **Remix with two sources (identical upstream_id, distinct
   commit_hash)**: verify sort orders by secondary key.
7. **ChunkedBlob with `chunk_size=0` and 3 chunks**: verify prologue
   present and length=6+8+4+4+40*3=142. `ChunkedBlob` is also
   **merkelized** (§10 / SPEC-MERKLE-OBJECTS): its id is the
   domain-wrapped Merkle root over its chunk leaves plus the metadata
   leaf, not a flat `BLAKE3` of these 142 bytes. Record both the
   serialized bytes and the merkelized id separately.
8. **Annotated tag** (`target_type=0x03`, ed25519 tagger, non-empty
   message, all-zero signature): `Tag` is a flat type &mdash; record
   serialized bytes + `BLAKE3` of those bytes as the id.
9. **Signed tag** (same shape, signed with seed `[0x07;32]` over the
   `kit.tag\0` domain &mdash; a permanent domain separator per
   SPEC-CONVENTIONS §4): record serialized bytes, the canonical tag
   signing bytes, the signing hash, and the 64-byte Ed25519 signature.
10. **Tree entry inclusion proof**: a single-leaf BMT inclusion proof
    (SPEC-MERKLE-OBJECTS §5) for the `tree_single_file` object of §13.3,
    at position 0. Record the encoded proof bytes and the object id it
    verifies against.
11. **ChunkedBlob chunk inclusion proof**: a single-leaf BMT inclusion
    proof (SPEC-MERKLE-OBJECTS §5) for a chunk of the `chunked_blob_cs0_3chunks`
    object of §13.7. Record the encoded proof bytes, the proven chunk's
    position (chunk index + 1, per SPEC-MERKLE-OBJECTS §3.1/§5.5), and
    the object id it verifies against.
12. **ChunkedBlob bounds** (§7): the header check accepts a FastCDC header of
    2 chunks with `total_size` 128 GiB and refuses one with 128 GiB + 1. A
    header that declares 8,388,608 chunks passes the count check, and one
    that declares 8,388,609 fails `TooManyChunks` before any chunk id is
    read. A header that declares 8,388,608 chunks with a short body fails
    `manifest length` before any allocation.
13. **ChunkedBlob manifests**: the manifest bytes and id for 0, 1, 2, 3 and
    5 chunks, content-defined and fixed-size, and the leaf digest of §3.1 of
    SPEC-MERKLE-OBJECTS with asymmetric maximum values, so a big-endian or
    swapped implementation fails. A one-chunk fixed layout with
    `chunk_size = 0x7FFF_FFFF` is accepted. Refused manifests name the first
    failing check. They include unknown profiles `0x8000_0000`,
    `0x8000_0001`, `0x8000_0003` and `0xFFFF_FFFF`, an end that does not
    increase, `end_0 = 0`, a last end that is not `total_size`, a chunk longer
    than `MAX_RAW_OBJECT_SIZE - 10`, a fixed-size end off by one, `22 + 40n ±
    1` bytes, a count above the cap with a short body, type `0x05` with
    `schema_version` `0x01`, and another type with `schema_version` `0x02`.

Vectors 1–7 are under `rust/tests/golden/objects/`, tag vectors 8–9
under `rust/tests/golden/tags/`, and proof vectors 10–11 under
`rust/tests/golden/proofs/` (SPEC-MERKLE-OBJECTS §5.6). Each set ships a
`MANIFEST.txt` and per-vector `.json` sidecar carrying the BLAKE3 digest.
Vectors 12 and 13 are checked by `scripts/golden/objects_ref.py`, the unit
tests in `rust/crates/kit-core/src/serialize.rs` and the Rust tests that read
`scripts/golden/chunk_offsets_expected.json`.

### Mixed local-pack conformance vector

The golden vector is `local_pack_mixed` under `rust/tests/golden/`. A
test-only writer produces a raw pack and index containing a chunk, a
manifest and a tree each larger than 16 KiB, and a whole-file blob.
Include the packed repository marker, a byte-identical loose copy of one
packed object, and an unknown sidecar. Record the expected object ids,
sizes, pack key, and index bytes. Verify the fixture through the store
accessors and independently check its encoding. A writer change that
uses capability `P` MUST test that the first released reader supporting
`P` reads the new writer's output.

---

## 14. Invariants

Properties that MUST hold for every conformant reader/writer, and the
mechanism that enforces or detects each:

| Invariant | Enforced by |
|---|---|
| Every stored object is one of the seven known types under `"KOB1"` and the `schema_version` of its type (`0x02` for `chunked_blob`, `0x01` otherwise) | prologue rejection: `InvalidObjectType`/`InvalidMagic`/`UnsupportedObjectVersion` (§2) |
| An object's bytes always match its id | read-time recomputation under the type-dependent id rule → `HashMismatch`; for merkelized types this also proves the child set present and correctly ordered (§10) |
| No stored object exceeds 1 GiB | storage-layer rejection (§3, §10) |
| An object encodes exactly its declared layout, nothing more | trailing-byte rule → `TrailingData` (§11) |
| Tree entries are canonical: lex-sorted byte-wise, no duplicates | reader rejection `InvalidEntryOrder` (§4) |
| Tree entry names cannot alias, escape, or shadow repo metadata | name grammar → `InvalidEntryName` (§4.1); mode whitelist → `InvalidEntryMode` (§4.2) |
| Remix sources are canonical and duplicate-free | `(upstream_id, commit_hash)` sort → `InvalidSourceOrder` (§6.1) |
| Collection counts are bounded | `TooManyEntries` ≤ 1 000 000 (§4); `TooManyParents` ≤ 1 000 (§5.2); `source_count` ≤ 10 000 (§6); `TooManyChunks` ≤ 8 388 608 (§7) |
| Identity payloads are non-empty, bounded, and of known kind | `InvalidIdentity`/`IdentityTooLarge`/`UnknownIdentityKind` (§9) |
| A tag targets only a storable object, with an unambiguous name | `target_type` whitelist → `TagTargetTypeInvalid`; name floor → `TagNameInvalid` (§6a) |
| Delta objects never appear in the object store | pack-only rule (§1, §8) |
| A `ChunkedBlob` names a supported layout | `0` names FastCDC v1, positive values below `0x8000_0000` are fixed sizes, and `0x8000_0002` is the only recognized profile ID in the reserved range (§7) |
| A `ChunkedBlob`'s spans are increasing, end at `total_size`, and follow the fixed layout | the decode checks (§7) |
| Every chunk of a `ChunkedBlob` holds exactly the length of its span, and the content is exactly `total_size` bytes | per-chunk length check at reassembly (§7) |
| A merkle-addressing reader never mis-reads a store without the marker | mandatory `bmt-v2` addressing marker and recognized required capabilities → `IncompatibleRepoFormat` (§10, §12) |
| A visible object is durable; refs/index/log entries reference only durable objects | durable staged bytes, atomic publication, and directory flush before reference publication (§10.1) |

These are format-level guarantees. Signature guarantees are specified in
SPEC-SIGNING; per-object tamper evidence for merkelized types in
SPEC-MERKLE-OBJECTS §6.
