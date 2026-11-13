---
spec: SPEC-FASTCDC
version: 2
status: stable
audience: implementers of compatible chunkers; anyone reproducing chunked_blob hashes across producers
---

# SPEC-FASTCDC &mdash; kit v1 content-defined chunking

Status: **Normative** for kit v1 (content-defined chunking of large
files). §11 (FastCDC v2) is **draft**: it is specified and implemented,
and no writer uses it by default.
Scope: gear table derivation, chunking parameters, and the determinism
contract that makes chunked_blob hashes stable across producers.

The gear seed is fixed, so chunking is deterministic.

---

## 1. Purpose

For files larger than a fixed threshold, kit uses FastCDC (Fast
Content-Defined Chunking) to cut the file at content-defined
boundaries, store each chunk as its own blob, and reference them from
a `chunked_blob` object (SPEC-OBJECTS §7).

This lets edits near the end of a large file reuse most of the
prior version's chunks, which is critical for dedup across pack
transfers (see SPEC-PACKFILE §3.2 delta vs. SPEC-OBJECTS §7 chunked
dedup &mdash; these are complementary layers).

---

The 1 MiB writer threshold and the boundary rules here govern newly produced
objects. They do not impose a unique representation on existing file contents:
a large inline Blob or another valid chunk layout remains readable. File
comparison follows SPEC-OBJECTS §7 and preserves an existing staged identity
when bytes are unchanged.

## 2. Determinism contract

Chunk boundaries, and therefore `chunked_blob` hashes, are **fully
determined by**:

1. The input file bytes.
2. The gear table seed (§3).
3. The chunking parameters `(min_size, avg_size, max_size)` (§4).
4. The mask derivation (§5).

**Any change to any of (2), (3), or (4) breaks chunk boundary
reproducibility.** The chunk hashes change, and blob-level dedup
across the change boundary fails for every large file.

This is why (2) through (4) are specified as normative constants in v1
and can only be changed through a format-version bump.

A manifest names the chunker that cut it in its `chunk_size` field
(§6): `0` for FastCDC v1, `0x8000_0002` for FastCDC v2 (§11). The
contract above holds per chunker. The same bytes cut by two chunkers
give two different `chunked_blob` ids.

---

## 3. Gear table seed

The gear table is 256 `u64` entries, derived from a splitmix64 initial
state seeded with a 7-byte ASCII literal. kit does **not** use the
gear table from the FastCDC paper (Xia et al., USENIX ATC '16); the
table is kit-specific and produced by the procedure below.

```
state = 0x004B495446434443        # ASCII "KITFCDC" interpreted as big-endian u64
for each of 256 entries:
    state = state +% 0x9e3779b97f4a7c15              # wrapping add (splitmix64 gamma)
    z = state
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9        # wrapping mul
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb
    z = z ^ (z >> 31)
    table[i] = z
```

The reference Rust implementation lives in
`kit-core::chunker::build_gear_table` and uses a `std::sync::OnceLock`
to memoise the 2 KiB table on first use. The exported constant `SEED`
is the same `0x004B_4954_4643_4443` value.

### 3.1 Seed decision (v1)

The seed ASCII is **`"KITFCDC"`**, frozen for the lifetime of v1.
The seed is not user-visible. It is 7 bytes, read as a big-endian `u64`
with one leading zero byte.

The seed sets the chunk boundaries, so every chunked blob id depends on
it. An implementation MUST NOT change it.

Future format versions that want to change chunking MUST bump the
format version. A future reader that
needs to chunk for a different chunk-family MAY use a different seed
and namespace the result accordingly, but v1 does NOT provide a
mechanism for this.

---

## 4. Chunking parameters

Hard-coded defaults (applied whenever the worktree takes the chunked
path):

```
min_size =  16 * 1024   =   16 KiB
avg_size =  64 * 1024   =   64 KiB
max_size = 256 * 1024   =  256 KiB
```

Normative constraint: `avg_size` MUST be a power of two (the mask
derivation in §5 uses `log2(avg_size)`); `min_size < avg_size <
max_size` MUST hold strictly. kit's v1 constants satisfy "all three
are powers of two", but the format only requires this of `avg_size`.

Files of size ≤ `min_size` are NOT chunked &mdash; `cut` returns the full
input length, so the caller stores the file as a single `blob`. The
threshold for taking the chunked path is an implementer choice; in
kit-core the worktree picks `CHUNK_THRESHOLD = 1 MiB`
(`worktree::CHUNK_THRESHOLD`). v1 specifies only that **once a file
is chunked**, the parameters above MUST be used.

Implementation status: end-to-end wiring is in place across the
hashing, staging, commit, and read-back paths.

`worktree::store_file_object` decides the object representation of a
file held in memory: at or below `CHUNK_THRESHOLD` it writes a single
`Blob`; above it, it splits with `FastCdc::v1`, stores each chunk as its
own `Blob`, and writes a `ChunkedBlob` manifest (with `chunk_size = 0`,
FastCDC v1) whose hash lands in the parent tree. `worktree::hash_file`
applies the same rule to a file on disk and streams a file above the
threshold through the same chunker, so a given file produces the same
object/hash regardless of the path that computes it:

- `worktree::{hash_file, build_tree}` &mdash; diff, status, tree, and the
  `rm`/`checkout` dirty-checks;
- `kit add` (`add_one` / `stage_tracked`) &mdash; staging into the
  index;
- `worktree::build_tree_from_index` &mdash; the commit/index tree build now
  accepts a `ChunkedBlob` under a regular-file (Blob/Executable) entry,
  so committing a > 1 MiB file no longer fails with a "non-blob object"
  error.

Read-back is symmetric: `worktree::read_blob` reassembles a `Blob` or
`ChunkedBlob` into the full byte stream, and backs `kit cat`,
`kit diff`, and worktree restore (`kit checkout`). `kit cat` on a
`ChunkedBlob` hash streams the reassembled content rather than an object
placeholder.

The byte-level chunk boundaries are pinned by the goldens in §8; the
worktree round-trip is covered by
`worktree::tests::large_file_becomes_chunked_blob`, the index-path
acceptance by `worktree::tests::from_index_accepts_chunked_blob_for_file_entry`,
and the full add → commit → status/diff/rm → checkout → cat round-trip
by the `chunked_blob_roundtrip` unit test in `kit-core::serialize`.

---

## 5. Mask derivation and cut algorithm

Mask derivation:

```
bits   = log2(avg_size)
mask   = (1 << bits) - 1
mask_s = mask | (mask << 1)      # stricter: fewer boundaries
mask_l = mask >> 1                # looser: more boundaries
```

For `avg_size = 64 KiB = 2^16`, `bits = 16`:

```
mask   = 0x0000_FFFF
mask_s = 0x0001_FFFF
mask_l = 0x0000_7FFF
```

Cut algorithm (normative):

```
cut(data) -> length:
    if len(data) <= min_size: return len(data)
    hash = 0
    # Strict region: min_size .. avg_size
    for i in min_size .. min(avg_size, len(data)):
        hash = (hash << 1) +% gear_table[data[i]]
        if (hash & mask_s) == 0: return i
    # Loose region: avg_size .. max_size
    for i in avg_size .. min(max_size, len(data)):
        hash = (hash << 1) +% gear_table[data[i]]
        if (hash & mask_l) == 0: return i
    # Forced cut at max_size
    return min(max_size, len(data))
```

The result `length` is the number of bytes in the first chunk. The
caller consumes those bytes, then calls `cut` again on the remainder.
The iteration continues until all bytes are consumed.

Implementation note (informative): a run of one byte value `c` drives
`hash` to the fixed point `-gear_table[c]` (wrapping), because
`(-g << 1) +% g == -g`. Once `hash` equals that value after a byte `c`,
each further `c` leaves `hash` and the mask test unchanged, so an
implementation MAY jump to the end of the run, stopping at the
strict/loose switch and at `max_size`. The cut points do not change.
kit-core does this, so runs of zero bytes cut at memory speed.

---

## 6. Chunked_blob composition

See SPEC-OBJECTS §7 for the container. Key points for chunking:

- `total_size` = sum of all chunk byte lengths = file size.
- `chunk_size` names the chunker, not a size: **0** for FastCDC v1,
  **`0x8000_0002`** for FastCDC v2 (§11.2). Any other value is a
  fixed-size manifest (SPEC-OBJECTS §7).
- `chunks` = ordered list of chunk BLAKE3 hashes.
- Each chunk is itself stored as a `blob` object (SPEC-OBJECTS §3)
  under its content hash.

A reader reassembles the file by concatenating `chunks[0].data ||
chunks[1].data || ... || chunks[n-1].data` and verifying the length
equals `total_size`.

---

## 7. Cross-implementation validation

Any two conformant implementations chunking the same file with the
same (seed, parameters, mask) MUST produce:

- The same number of chunks.
- The same chunk boundaries (byte offsets).
- The same chunk hashes.
- The same `chunked_blob` object hash.

Conformance tests SHOULD include at least one 10 MiB pseudo-random
file and one 10 MiB highly-repetitive file, asserting byte-identical
chunk lists across platforms.

---

## 8. Test vectors

The vectors below are exercised by
`rust/crates/kit-core/tests/golden_pack.rs` (boundaries on disk under
`rust/tests/golden/fastcdc/`) plus the unit tests in
`rust/crates/kit-core/src/chunker.rs::tests`.

1. **Gear table hash**: `gear_table_digest()` returns
   `BLAKE3` of the 256 `u64` entries little-endian-encoded
   (2 048 bytes total). Any implementation that derives the same table
   for seed `"KITFCDC"` will produce the same digest. Stability is
   asserted by `gear_table_digest_is_stable`; the table is also checked
   to be all-unique and non-zero by `gear_table_is_unique_and_nonzero`.
2. **Small file fits in single chunk**: short input → `cut` returns
   `data.len()` immediately. No `chunked_blob` produced
   (`small_input_is_single_chunk`).
3. **`min_size`-or-smaller is single chunk**: `data.len() <= min_size`
   → `cut` returns `data.len()` (`cut_at_exactly_min_size_returns_full`).
4. **Pseudo-random 1 MiB file**, splitmix64 stream from seed
   `0xA5A5_F00D_DEAD_BEEF`: chunk boundary offsets are pinned in
   `rust/tests/golden/fastcdc/fastcdc_boundaries_1mib.bin`
   (`fastcdc_boundaries_1mib_match_golden`).
5. **Pseudo-random 256 KiB file**, splitmix64 stream from seed
   `0xCAFE_BABE_1234_5678`: pinned in
   `rust/tests/golden/fastcdc/fastcdc_boundaries_256k.bin`
   (`fastcdc_boundaries_256k_match_golden`).
6. **Repetitive buffer**: all-zero data with a tiny chunker exercises
   the forced-cut-at-`max_size` path
   (`cut_forces_boundary_at_max_size`).
7. **Boundary stability under a 1-byte insert**: insert one byte at
   32 KiB into a 64 KiB pseudo-random file; ≤ 3 chunks differ
   (`boundary_stability_single_byte_insert`). The shifted-chunks
   identity test is subsumed by this regression.
8. **Iterator total covers the input**: chunk lengths sum to the
   input length (`fastcdc_iterator_total_equals_input_length`).
9. **Different `avg_size` yields different boundaries**: a chunker
   with `(8K, 32K, 128K)` does not produce the v1 boundaries
   (`different_avg_size_yields_different_boundaries`).
10. **Seed misuse detector**: if an implementation is accidentally
    built with any seed other than `"KITFCDC"`, the gear-table-hash
    pin and the boundary goldens both fail loudly at test time.
11. **Runs stream, v1**: 1 MiB made of 393 216 zero bytes, then 262 144
    bytes of the splitmix64 stream from seed `0x0052_554E_5300_0001`,
    then 131 072 bytes of `0xA5`, then 262 144 bytes of the splitmix64
    stream from seed `0x0052_554E_5300_0002`. It covers forced cuts
    inside a run and runs that end inside a chunk. Pinned in
    `fastcdc_boundaries_runs.bin`.
12. **FastCDC v2 boundaries** (§11) of the streams of vectors 4 and 5:
    `fastcdc_v2_boundaries_1mib.bin` and
    `fastcdc_v2_boundaries_256k.bin`.
13. **FastCDC v2 boundaries** of the runs stream of vector 11:
    `fastcdc_v2_boundaries_runs.bin`. They differ from vector 11.
14. **FastCDC v2 manifest**: the `chunked_blob` (SPEC-OBJECTS §7) that
    FastCDC v2 gives for 2 MiB of the splitmix64 stream from seed
    `0x4B49_5446_4344_4332`, with `chunk_size = 0x8000_0002`, in
    `fastcdc_v2_manifest_2mib.bin`. Its object id
    (SPEC-MERKLE-OBJECTS §3.1) is the
    `fastcdc_v2_manifest_2mib_object_id` line of `MANIFEST.txt`.

Vectors 11 to 14 are checked by `fastcdc_runs_and_v2_boundaries_match_golden`
and `fastcdc_v2_manifest_matches_golden`. `scripts/golden/objects_ref.py`
checks vectors 1, 4, 5 and 11 to 14 independently: it derives the gear
table, both mask sets, the boundaries, the chunk ids, the manifest bytes
and the manifest id from this document and SPEC-OBJECTS alone.

---

## 9. Future work (non-v1)

- Per-file-type tuning (for example, larger `avg_size` for media files) is
  out of scope.
- A sliding-window gear hash implementation variant would produce
  different boundaries; not a v1 alternative.

---

## 10. Invariants

| Invariant | Enforced by |
|---|---|
| Chunk boundaries &mdash; and therefore `chunked_blob` hashes &mdash; are a pure function of the input bytes | frozen seed (§3), parameters (§4), and mask derivation (§5); any change requires a format-version bump (§2) |
| Every implementation derives the identical gear table | the `"KITFCDC"` + splitmix64 procedure (§3); gear-table digest pin and uniqueness/non-zero checks (§8 vector 1) |
| `avg_size` is a power of two; `min_size < avg_size < max_size` holds strictly | normative parameter constraint (§4) |
| Input of ≤ `min_size` bytes is a single chunk, never a `chunked_blob` | `cut` returns the full input length (§4, §5) |
| No chunk exceeds `max_size` | forced cut at `max_size` (§5) |
| Chunk lengths sum to the input length; `total_size` equals the file size | iterative consumption until all bytes are cut (§5); reassembly length check against `total_size` (§6); pinned by §8 vector 8 |
| Content-defined manifests are distinguishable from fixed-size ones | `chunk_size` is `0` or `0x8000_0002` (§6; SPEC-OBJECTS §7) |
| Any two conformant chunkers agree on chunk count, byte offsets, chunk hashes, and manifest hash | cross-implementation contract (§7); boundary goldens (§8 vectors 4–5) |
| A build with the wrong seed or parameters cannot ship silently | gear-table-hash pin and boundary goldens fail loudly at test time (§8 vectors 9–10) |
| A manifest says which chunker cut it | `chunk_size` is `0` for v1 and `0x8000_0002` for v2 (§6, §11.2) |
| No writer produces v2 manifests unless its caller asks | §11.3; the default store path is v1 |

---

## 11. FastCDC v2 (draft)

FastCDC v2 is a second content-defined chunker. It keeps the gear table
(§3), the sizes (§4: 16, 64 and 256 KiB) and the cut loop (§5), and
replaces the two masks. Its manifests are a format change: the same
bytes get a different `chunked_blob` id. Readers need no change to
reassemble them (§11.4).

### 11.1 Spread masks

The v1 masks test the low 15 to 17 bits of the hash. Bit `p` of the
hash depends only on the last `p + 1` bytes, so v1 cut decisions see
only the last 15 to 17 bytes. On text with a repeating structure, such
as logs, source code and tar headers, that window repeats, few positions
cut, and many chunks run to the forced cut at `max_size`.

v2 spreads the mask bits over bits 16 to 47, so each decision depends
on the last 48 bytes, and it uses normalization level 2: the strict
mask has two more bits than `log2(avg_size)` and the loose mask two
fewer (v1 uses one).

```
spread(n) = OR over k in 0 .. n-1 of  1 << (16 + floor((2k + 1) * 32 / (2n)))
bits      = log2(avg_size)                    # 16
mask_s    = spread(bits + 2)                  # 18 one-bits
mask_l    = spread(bits - 2)                  # 14 one-bits
```

For the v2 sizes:

```
mask_s = 0x0000_AB55_AB55_0000
mask_l = 0x0000_552A_552A_0000
```

The cut loop is §5 with these masks. The implementation note of §5
about runs of one byte value applies unchanged.

### 11.2 Chunker id

A v2 manifest is a `chunked_blob` (SPEC-OBJECTS §7) with
`chunk_size = 0x8000_0002`. A reader of an earlier revision reads the
value as a fixed chunk size of about 2 GiB, above its 1 GiB file limit.
It accepts such a manifest only with at most one chunk, and that
manifest keeps its bytes and id under this revision. It refuses a v2
manifest of two or more chunks at decode time.

### 11.3 Selecting a chunker

A writer MUST cut with FastCDC v1 and write `chunk_size = 0` unless its
caller asks for v2. Repositories written before this revision therefore
read and write byte-identically. kit-core exposes v2 only through
explicit calls (`Chunker::FastCdcV2`, `store_file_object_with`,
`chunked_blob_from_bytes_with`). No command line flag or configuration
key selects it yet. Making v2 a default is a separate format decision.

### 11.4 Reading

Readers reassemble a v2 manifest exactly as a v1 manifest: concatenate
the chunks and check `total_size`. File-content equality does not depend
on the chunker: SPEC-OBJECTS §7 requires a full byte comparison when two
ids differ, so a v1 and a v2 object of the same bytes are equal content.

### 11.5 Git bridge

The git bridge reconstructs chunked blobs by re-chunking with FastCDC
v1 (SPEC-GIT-BRIDGE §4, §9). It refuses a v2 manifest as non-canonical,
so a v2 object is never exported in a form that would not round-trip.

### 11.6 Measured comparison (informative)

`cargo bench -p kit-benches --bench chunker_dedup` cuts six generated
workloads, each a pair of versions A and B built from fixed splitmix64
seeds. "New bytes" are the bytes of B in chunks that A does not have.

| Workload | v1 new bytes | v2 new bytes | v1 dedup | v2 dedup | v1 / v2 chunks of A | v1 / v2 forced cuts |
|---|---:|---:|---:|---:|---:|---:|
| 32 MiB random, 50 one-byte inserts | 5 217 900 | 3 720 253 | 84.45% | 88.91% | 393 / 451 | 0.3% / 0.0% |
| 32 MiB random, 4 000 8-byte overwrites | 8 543 555 | 8 415 903 | 74.54% | 74.92% | 409 / 450 | 0.0% / 0.0% |
| 32 MiB log, 200 lines edited, 2 MiB appended | 16 536 317 | 13 050 635 | 53.62% | 63.39% | 288 / 445 | 3.8% / 0.0% |
| 32 MiB source, 300 lines inserted | 26 000 415 | 16 549 715 | 22.54% | 50.69% | 238 / 450 | 12.2% / 0.0% |
| 48 MiB tar of text files, 40 files edited | 6 605 792 | 3 991 429 | 87.00% | 92.15% | 388 / 674 | 8.0% / 0.0% |
| 64 MiB sparse image, 1% of 4 KiB blocks rewritten | 27 812 140 | 21 887 031 | 58.56% | 67.39% | 438 / 579 | 17.1% / 3.6% |

v2 stores fewer new bytes on all six. Its mean chunk is close to the
64 KiB target on every workload; v1 chunks of text average 116 to
141 KiB because so many run to `max_size`. The cost is more chunk
objects: 15% more on random bytes and up to 89% more on text. Cutting
speed is the same on random bytes and about 10% lower on the sparse
image.

