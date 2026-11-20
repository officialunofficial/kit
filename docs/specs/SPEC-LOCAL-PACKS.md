---
spec: SPEC-LOCAL-PACKS
version: 1
status: draft
audience: implementers of the object store, write batches and gc
---

# SPEC-LOCAL-PACKS &mdash; local pack segments in the object store

Status: **Draft**. Describes the prototype on branch
`claude/project-thread-pwtq6s`. Nothing here is normative until the open
decisions in §9 are made. See SPEC-CONVENTIONS §2 for the status
vocabulary and its RFC 2119 keywords.

## 1. Why this spec exists

Writing one loose file per object (SPEC-OBJECTS §10) costs most of a
`kit add` or `kit clone` of many objects: every object pays a create, a
close, a reopen for its write barrier and a rename. A local pack segment
holds many objects in one file, found through a sorted index, so a batch
pays those costs once. Loose objects stay as they are; a store may hold
both.

This is a local storage layout. It is never exchanged; transfers keep
using SPEC-PACKFILE.

## 2. Layout

A segment is two files in `.kit/objects/packs/`:

- `<name>.pack` holds object bytes back to back, with no framing.
- `<name>.idx` lists where each object sits in the pack.

`<name>` is the lowercase hex BLAKE3 of the index bytes (64 characters).
A reader MUST ignore any file in `packs/` whose name is not
`<64 hex>.idx` or `<64 hex>.pack`, except as §7 allows gc to remove it.

The `packs` directory name is not two hex digits, so loose-shard
enumeration never visits it.

## 3. Index format

All integers are little-endian.

```
offset  size        field
0       8           magic       "KITLPX01"
8       4           count       u32, number of entries
12      8           pack_len    u64, exact length of the .pack file
20      count × 44  entries     id (32), offset (u64), len (u32)
…       32          trailer     BLAKE3 of every byte before it
```

A reader MUST refuse an index, and treat none of its objects as present,
when any of these holds:

1. The file is larger than 256 MiB. This is checked before reading.
2. The length is not exactly `20 + 44 × count + 32`.
3. The magic differs.
4. The trailer differs from the BLAKE3 of the preceding bytes.
5. Entry ids are not strictly ascending. This also rules out duplicates.
6. For any entry, `offset + len` overflows or exceeds `pack_len`, or
   `len` exceeds the object size cap (SPEC-OBJECTS, 1 GiB).
7. The `.pack` file's length is not exactly `pack_len`.

A writer MUST produce exactly this encoding. An accepted index therefore
re-encodes to the same bytes (fuzz target `pack_index_decode`).

The bytes at `[offset, offset + len)` are the object's serialized bytes
(SPEC-OBJECTS), the same bytes a loose file would hold.

## 4. Reads

A lookup checks the loose path first, then the loaded segments by binary
search. When both miss, the reader reloads the segment list if the
`packs/` directory changed, and then MUST look again whether or not its
own reload found anything new: another thread may have loaded the segment
in between.

Every read recomputes the object id from the bytes (SPEC-OBJECTS §10),
exactly as for a loose object. A damaged segment fails that check per
object with `HashMismatch`. The index trailer is not a substitute for it.

## 5. Writes

A write batch (`WriteBatch`) writes its first 64 new objects as loose
files and appends every later one to a segment. Objects already present,
loose or packed, are not written again.

The segment becomes visible in this order. Each step MUST complete before
the next starts:

1. Make sure the format file carries the packs feature (§6).
2. Append each object's bytes to a pack temp file in `packs/`. Writeback
   of the pack MAY start early, every 32 MiB in the prototype.
3. Write the index to a temp file in `packs/`.
4. Make both temp files durable, together with every loose object of the
   batch, under the batch's flush schedule.
5. Rename the pack temp to `<name>.pack`.
6. Rename the index temp to `<name>.idx`. **This is the visibility
   point.**
7. Flush the `packs/` directory, then the batch's final device flush.

So a visible packed object is a durable one, the same rule SPEC-OBJECTS
§10.1 sets for loose objects. Refs and the staging index are written only
after the batch commits, unchanged.

A crash before step 6 leaves temp files or a pack with no index. Neither
is visible, and gc removes both once they are older than the grace window
(§7).

## 6. Format marker

The format file `.kit/format` holds `bmt-v2` (SPEC-OBJECTS §10). Before
the first segment of a store is created, the writer adds the line
`packs-v1` and makes the file durable:

```
bmt-v2
packs-v1
```

A kit that predates segments compares the whole trimmed file with
`bmt-v2`, so it refuses the repository with `IncompatibleRepoFormat`
instead of reporting packed objects missing. A repository that never
creates a segment keeps the one-line marker and stays readable by older
kit.

The format file is the anchor of the store's prune lock (SPEC-GC) and
MUST NOT be replaced, so the line is written in place after the first
line. A reader:

- MUST accept `bmt-v2` alone, or followed by `packs-v1`, with or without
  trailing newlines.
- MUST ignore a last line with no newline that is a strict prefix of
  `packs-v1`. That is an interrupted write. It is safe to ignore because no
  segment is visible before the write completes, and the next writer
  completes it.
- MUST refuse any other full line.

## 7. gc and repack

Marking is unchanged: it reads packed objects through the store like
loose ones. After the loose sweep, gc visits each segment.

The objects of a segment share its pack's mtime, so the grace window
applies to the segment as a whole. gc leaves a segment unchanged when
none of its objects is unreachable, when its pack is younger than the
grace window, or when its index cannot be loaded. Otherwise it repacks
that segment:

1. Copy each live object into a new segment, checking its id first. A
   damaged object stops gc with an error and the old segment stays.
   When no object is live, no new segment is written.
2. Publish the new segment with steps 5 to 7 of §5, after making both of
   its files durable.
3. Take the exclusive lock on the format file without waiting
   (SPEC-GC). If that fails, because a fetch holds the prune guard, keep
   the old segment.
4. Check that the old pack is still older than the grace window. Remove
   its index, then its pack, then flush `packs/`.

At every step each live object is visible in at least one durable
segment. A crash before step 4 leaves duplicate bytes. A crash within it
leaves a pack with no index.

Last, gc removes from `packs/` the temp files and the packs with no index
that are older than the grace window. It uses the same locked age check
as loose temp files, so a writer between its two renames (§5 steps 5 and
6) is never touched.

Nothing refreshes a pack's mtime on a dedup hit. A write batch dedups
only under `worktree.lock`, which gc holds through mark and sweep
(SPEC-CONCURRENCY). The bulk writer used by git import, which runs
outside that lock, checks for a loose file only and writes a loose copy
when it finds none.

This replaces SPEC-GC's statement that "the store keeps objects as loose
files because gc removes single objects".

## 8. Invariants and tests

| Invariant | Test |
| --- | --- |
| A packed object is visible only after its bytes are durable | `pack_segment_is_durable_before_its_index_is_visible` (recording syncer) |
| A dropped batch leaves no segment | `dropped_batch_leaves_no_pack_segment` |
| A damaged segment fails the hash check per object | `damaged_segment_fails_the_hash_check` |
| Concurrent first lookups all find their objects | `concurrent_first_reads_of_a_segment_all_find_their_objects` |
| The index parser refuses every malformed input in §3 | unit tests in `store::packs`, fuzz target `pack_index_decode` |
| An older kit refuses a repository with segments | `the_first_segment_marks_the_format_so_an_older_kit_refuses_the_repo` |
| An interrupted marker write neither breaks open nor sticks | `an_interrupted_marker_write_is_ignored_then_completed` |
| gc never drops a live packed object, even after a crash at any repack step | `a_crash_at_any_repack_step_loses_nothing_and_the_next_gc_recovers` |
| gc respects the grace window and the prune guard | `gc_keeps_a_segment_younger_than_the_grace_window_whole`, `gc_keeps_the_old_segment_while_a_writer_holds_the_prune_guard` |

## 9. Open decisions

- Whether to adopt local packs at all.
- Whether packs are on by default for large batches or opt-in first. The
  prototype turns them off with `KIT_PROTO_PACKS=0`; a shipped version
  would use a config setting.
- Whether to keep this minimal layout or store SPEC-PACKFILE entries so
  that local packs double as transport packs.
