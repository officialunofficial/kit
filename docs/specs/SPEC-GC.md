---
spec: SPEC-GC
version: 1
status: stable-normative
audience: implementers of gc/recovery and reviewers of object pruning
---

# SPEC-GC &mdash; garbage-collection retention roots and recovery

Status: **Normative** for kit v1; **implemented** (see below). See
SPEC-CONVENTIONS §2 for the maturity/bindingness status vocabulary this
frontmatter uses. Concurrency: see SPEC-CONCURRENCY (this document no
longer states its own lock model). The recovery model &mdash; retention
roots + live closure (`ops::gc`), the recovery log + retention
policy (`ops::recovery`), and the producers (amend/reset/rebase record
the superseded tip) &mdash; **and the `kit gc` command itself** are all
shipped. `kit gc` runs `recovery::expire` → `ops::gc::run_gc`
(the mark, then prune `store ∖ live`, skipping objects within the
grace window) under the locks SPEC-CONCURRENCY §4 assigns to `gc`
(the worktree registry lock, then every registered tree's per-tree
lock &mdash; no separate lock guards the recovery-log expire step; the
per-tree locks gc already holds are what serializes it, see §3.2).

## Why this spec exists

Normal object-store writes append data, so unreachable
objects accumulate (notably the commits superseded by `commit --amend`,
`reset`, and `rebase`). `kit gc` reclaims them. Pruning is
safe **only** against a complete, exact retention root set: anything
reachable from a root is live; everything else is reclaimable. An
incomplete root set means deleting a live object &mdash; silent corruption.
This spec pins that root set so gc has one normative definition to honor.

Gc can reclaim a loose object individually. Gc reclaims packed objects
by retiring whole packs. A pack that also holds live objects is first
copied: its surviving entries go to new packs, and the old pair is
retired. The mark, including chunk type checks, uses the shared object
lookup (SPEC-OBJECTS §10). See
[local pack maintenance](#local-pack-maintenance).

## Retention roots

`ops::gc::collect_roots(kit_dir)` returns the complete set. A root is an
object hash that must be kept along with its full reachable closure. The
all-zero hash (an unset ref / `ORIG_HEAD`) is excluded.

| Source | On-disk | Roots contributed |
|--------|---------|-------------------|
| HEAD | `.kit/HEAD` | current tip (covers a detached HEAD) |
| Branches | `.kit/refs/heads/*` | each branch tip |
| Tags | `.kit/refs/tags/*` | each tag target |
| Remote-tracking | `.kit/refs/remotes/<remote>/*` | each remote ref |
| Staging index | `.kit/index` | each entry's `object_hash` (staged-but-uncommitted content) |
| Stash | `.kit/stash` | each entry's `commit_hash` + `parent_hash` |
| Previous detached HEAD | `.kit/PREVIOUS_HEAD` | the saved detached commit |
| Reset/op backup | `.kit/ORIG_HEAD` | the saved pre-op HEAD |
| Pull restore in progress | `.kit/PULL_HEAD` | target commit and pre-pull tree |
| Merge in progress | `.kit/MERGE_HEAD` (+`ORIG_HEAD`) | `merge_head`, `orig_head` |
| Cherry-pick in progress | `.kit/CHERRY_PICK_HEAD` (+`ORIG_HEAD`) | `cherry_pick_head`, `orig_head` |
| Revert in progress | `.kit/REVERT_HEAD` (+`ORIG_HEAD`) | `revert_head`, `orig_head` |
| Rebase in progress | `.kit/rebase-apply/{orig-head,onto,todo,done}` | `orig_head`, `onto`, every `todo` + `done` commit |
| Bisect in progress | `.kit/bisect` | `orig_head`, the bad commit, every good and skipped commit |
| Operation result tree | `.kit/KIT_OP_RESULT` and `.kit/rebase-apply/KIT_OP_RESULT` | the tree a merge, cherry-pick, revert or rebase wrote, until the operation ends |
| Conflict sidecar | `.kit/kit-conflicts` and `.kit/rebase-apply/kit-conflicts` | each record's `base`/`ours`/`theirs` blob (when present) |
| Attestations | `.kit/attestations/<commit-hex>/<att-id>.dsse` | each subject directory with a regular envelope file, as a soft root |
| Pending history publication | `.kit/history-v1/branches/<ref-key>/transaction` | previous and target ref values; strict parse even without `history-mmr` |
| Recovery log | `.kit/recovery-log` | each superseded commit (until expired) |

An envelope file has a 64-hex id followed by `.dsse`. GC uses the filename
and file type to identify it. An empty subject directory contributes no
root. The sweep removes such a directory after the grace window under the
same worktree locks. A dry run leaves directories in place. The sweep
leaves a directory containing any file or subdirectory in place.

A present empty, corrupt, oversized or unsupported staging index MUST abort GC
before sweeping. An absent index alone means no staging roots. Only the current
index format is supported (SPEC-INDEX).

The live keep-set is the reachable closure over those roots, held in two
parts: the gc mark returns a `LiveSet` of
`objects` and `chunks`. Walk semantics match `reachable_objects`
(commits/remixes → tree + parents, trees → entries, tags → target;
blobs/deltas are leaves), with one difference: the walk queues no chunk of a
chunked blob.

- `objects` holds the commits, trees, tags, remixes, manifests and blobs that
  the walk reaches other than as a chunk. It is capped at `MAX_REACHABLE`
  (10,000,000), and no chunk counts toward the cap.
- `chunks` holds the ids that reached manifests list, sorted, without
  duplicates and disjoint from `objects`. It is capped at 134,217,728
  distinct ids, which is 4 GiB of ids. The id buffer is checked at a
  compaction, so it can hold about twice that before the error. Each chunk
  MUST be a blob, since a chunk is a leaf and gc cannot tell what
  an object of another kind reaches. An object of another kind that a manifest
  lists, and that the walk reaches no other way, is an error, not a chunk. A manifest that another manifest lists
  as a chunk and that is also reached as a file is an object, and its own
  chunks are live.
- An object is live when it is in `objects` or in `chunks`.

Before a packed blob can end a walk, gc verifies its canonical bytes
and id. A bad locator cannot hide the edges of a tree or manifest.
For an id reached only as a chunk, gc checks the blob prologue and frame
length of a packed copy and does not hash it. Such an id is live because a
manifest lists it, whatever its copy holds, and the walk follows no edge from
it. So a wrong locator or a damaged payload for a chunk passes the mark. It
can also stop the mark with `ChunkNotBlob` when the locator names another
kind of object, even though a good loose copy exists. Every step of gc that
deletes or replaces a copy in reliance on a packed copy verifies that copy:
loose-duplicate removal, the body check before retirement, and copy-then-retire,
which hashes each covering copy and re-derives the id of each survivor it
copies. The local
writer's reuse of a packed copy by id and length does not, as before. An
integrity scan reports a bad packed copy. An id that the walk also reaches as
a file, and an id that the soft-root classification reaches as a node, stays
fully verified. Loose leaf probes read the object type as before.

The walk keeps the chunk ids in a buffer that it sorts and deduplicates
whenever the buffer would grow past the larger of twice its length after the
last compaction and 1,048,576 ids, so the buffer stays near twice the number
of distinct chunks whatever the number of manifests.

## Fail-closed requirement

`collect_roots` returns an error if **any** source cannot be read, and
`gc` MUST abort on that error rather than prune against a partial root
set. In particular:

- Refs are walked **strictly** (not via the lenient `refs::list_*`): an
  unreadable file, undecodable content, or a ref tree deeper than the
  walk depth cap is an error, never a silent skip. (Dot-prefixed
  atomic-write temp files are ignored.)
- A root or referenced object missing from the store during the closure
  walk (`StoreError::ObjectNotFound`) propagates. One kind of root is the
  exception: attested subjects, the result tree of an operation in progress and the commits of a
  bisect are named by a state file alone, and an older gc may have pruned
  them, or a part of what they reach. When the store lacks such an object, or
  an object that the closure of such a root reaches, gc skips the root, lists
  the state file (or attestation subject directory) in `GcReport::skipped_state_files` and `kit gc` warns with
  its path. An object that a ref or any other root reaches is never skipped.
  The objects that a skipped root would have kept are live only if another
  root reaches them.
- If the walk reaches [`MAX_REACHABLE`] objects, the mark returns
  `GcRootsError::Truncated` &mdash; beyond the cap the "unreachable" verdict is
  unsound, so gc must abort rather than prune. Push planning fails
  closed the same way: the push walk counts the commits the remote holds, the
  commits it lacks and the objects the walk keeps toward a cap of 10,000,000,
  counts no chunk, and returns `OperationLimitExceeded` at the cap, so a push
  whose walk reaches it fails before it publishes a pack. The walk never
  returns a partial plan. A held commit that this store cannot read ends its
  path and only makes the push send more.
- If the distinct chunk ids pass their cap, the mark returns
  `GcRootsError::TooManyChunks`. A manifest that lists an object that is not
  a blob gives `GcRootsError::ChunkNotBlob`, which names the
  manifest and the chunk. A chunk missing from the store is
  `StoreError::ObjectNotFound`.
- The whole mark, every chunk type read included, ends before gc lists or
  deletes any object. Every error returns before a delete.
- The sweep lists one `objects/<2 hex>/` directory at a time, tests each
  object against the `LiveSet` and applies the age rules, so it never holds
  the id of every loose object. The dry run and the real run visit the same
  candidates.

Gc first runs one ordinary union mark across all hard and soft roots. When
all closures are present, that mark is the entire walk. Only an
`ObjectNotFound` error starts the shared completeness fallback; other errors
abort. Soft-root completeness is then memoized across all hard and soft roots. During
classification, gc reads each distinct metadata object and checks each
distinct chunk once, propagating missing-closure results to dependent roots.
It discards edge lists after each postorder verdict and retains only the
verdicts. Then it releases that cache and runs one ordinary union mark over
the hard roots and complete soft roots. Neither pass walks shared history
separately for every root. The existing distinct-object and distinct-chunk
caps apply; repeated tree entries or chunk references add no new edge cap.
A cap or a non-missing read error aborts before deletion. A missing soft
root or descendant is skipped and reported.

## Recovery log

Commits superseded by `commit --amend`, `reset`, or `rebase` remain recoverable
through the **recovery log** (`.kit/recovery-log`, `ops::recovery`). Each rewrite
appends the superseded tip (`<unix_ts>\t<op>\t<64-hex>\t<branch>`), every
logged hash is a GC root (clock-free, strict/fail-closed parse), and
`recovery::expire(now, policy)` drops entries past the retention policy
(default: younger than 90 days **or** among the most recent 50) so they
stop pinning objects. A gc run expires first, then computes roots.

`record` is durable &mdash; it `fsync`s the log file and its parent directory
before returning &mdash; so a crash cannot leave a ref rewrite persisted while
its recovery entry is lost. `record` and `expire` are **not** internally
synchronized: `ops::recovery`'s own concurrency note requires callers to
hold "the repo lock" &mdash; in practice each producer's per-tree
`worktree.lock` (see SPEC-CONCURRENCY §3.2). gc's "expire → collect
roots → prune" sequence runs under the full lock set SPEC-CONCURRENCY §4
assigns to `gc` &mdash; every registered tree's `worktree.lock`, a superset of
any single producer's one tree &mdash; so a producer append can never race an
`expire` rewrite and vanish, without either side needing a distinct,
dedicated recovery-log lock.

**Status:** complete. The recovery log and its producers
are implemented &mdash; `commit --amend`, `reset`, and `rebase` each
record the superseded tip (op tokens `amend`/`reset`/`rebase`) before
moving the ref, and `stash pop` records the popped commit (op token
`stash-pop`) before restoring the worktree and dropping the manifest
entry &mdash; each per the lock set SPEC-CONCURRENCY §4 assigns to that
command &mdash; and the **`kit gc` command** consumes them: under
gc's lock set (SPEC-CONCURRENCY §4) it expires the recovery log,
computes the mark, then prunes `store ∖ live`, keeping unreachable
objects younger than the grace window (default 14 days; `--grace-secs 0`
prunes all, `--dry-run` previews).

Versioned ancestry snapshots (`history-v1`) are described in SPEC-HISTORY-PROOF.
Archived generation snapshots are evidence, not additional retention roots.
Only unfinished publication intents add roots; this lets recovery rebuild the
complete target ancestry even when its ref had not yet become visible.

## Concurrent writers and the grace window

gc's lock set (SPEC-CONCURRENCY §4) excludes every writer that holds a
`worktree.lock` or `worktrees.lock` for the span from its first object
write to its ref, index or recovery-log publication. Such a writer
publishes either before gc collects its roots or after gc's sweep ends.
Writers outside that lock set are not excluded, and for them the grace
window is the only protection. The one such writer into the object store
gc sweeps is the import phase of `kit git import`/`fetch`/`pull`, which
writes objects and then tags and remote-tracking refs under
`git-<remote>.lock` only (SPEC-CONCURRENCY §4).

A native `kit fetch`, `kit pull` and `kit clone` also write objects with no
`worktree.lock` held, for hours on a large repository, and take the lock
only to publish a remote-tracking ref. Grace does not protect their
objects, because an object the fetch reuses keeps its old `mtime`. A fetch
is protected by a prune guard instead: it holds the shared kernel lock on
the `format` file (below) from before it reads its record of applied packs
until after its last ref publish. While any guard is held, the sweep's final
check cannot take the exclusive lock, so it keeps every candidate at any
grace, including zero. The guard stops only the delete step. It protects a
fetch from a gc that holds the worktree locks of SPEC-CONCURRENCY §4 from its
mark through its sweep, so the mark sees the ref the fetch publishes. A fetch
that dies releases the guard with its process. The objects of a dead fetch are
then ordinary unreachable objects, and a later fetch repairs the store if a gc
pruned any of them (SPEC-TRANSPORT, "Pack-chain fetch").

A native `kit push` holds the same guard from before it plans until after
its last remote-tracking ref write, and writes each of those refs under
`worktree.lock`. A gc during the push therefore cannot prune the tip of a
tracking ref the push writes, even when the local branch is deleted first.

A local batch that writes the chunks of a large file, or small files past
the first 64 new ones of the batch (`kit add`,
`kit stash`) publishes the packs it fills, at 64 MiB, at commit, and at a
checkpoint that stages a manifest, tree or commit, before any ref or index
names their objects. It holds `worktree.lock` from its
first write to its index or ref write, so gc's mark either sees the
result or sweeps before the first write, as for loose objects. The batch
holds a prune guard while it publishes packs. A pack that no index
names, left by a crash or an aborted add, is a wholly dead pack, and
the sweep retires it after grace. That grace protects the packs of a batch
from a step that does not hold every `worktree.lock`, such as the sweep of
leftover files.

A push through the file transport (`kit push kit+file://...`) or one
received by `kit serve` or a layout server is not such a writer. It stores
packs as `<root>/packs/<hex>` and refs as `<root>/<name>` under the
transport root, while gc sweeps only the local store in
`<common_dir>/objects` and takes roots only from `<common_dir>`. The two
are disjoint, so gc cannot delete a pushed object, and a pushed ref is not
a gc root.

`kit gc` reads its clock once, as `now`, after it takes its locks and
before it expires the recovery log and computes the mark. Its sweep
deletes an unreachable object when `now - mtime >= grace`, where `mtime`
is the object file's on-disk modification time, and keeps any object
whose `mtime` cannot be read (`ops::gc::run_gc`). An implementation MUST
read `now` no later than the start of the mark; the safety condition
below depends on it.

**Reference-server behavior.** Bulk writes refresh the on-disk `mtime`
of byte-equal existing objects, rewriting on a failed refresh. Git import
also refreshes the full stored history closure on a translation-map hit,
including chunks that have no separate map entry. Successful writes and
cached reuse are memoized across every ref in one import run: each cached
object is refreshed at most once, without re-hashing its contents. Missing
objects or malformed cached reference metadata abort import before ref publication. Native
`ObjectStore::write` and `WriteBatch` callers still rely on gc's worktree
locks and do not need an mtime refresh.

The sweep's preliminary metadata read is advisory. Its final age check and
unlink hold an exclusive kernel lock on the existing common-dir
`format` inode. Bulk writes and cached reuse hold the corresponding shared
lock across their presence check, refresh and any rewrite, and a fetch
holds it for its whole run. If refresh wins, the final check sees the new
mtime; if unlink wins, a later write recreates the object and cached reuse
refuses the missing object. Lock contention or uncertain metadata keeps the
candidate. No process ever blocks on the exclusive lock: the sweep only tries
it. The lock order is specified by SPEC-CONCURRENCY.

A writer that dies leaves its `.kit.tmp.*` file in the object's shard
directory. The sweep also recognizes `.<name>.tmp.*` files left by older
writers. It removes a temp file once its modification time is at least
`grace` old, through the same final check as an
object: under the exclusive lock of `format`, kept on contention, on uncertain
metadata or when the file is younger. A fetch or a bulk write that is alive
holds the shared lock, and any other writer holds a worktree lock that gc
holds, so the sweep never removes the temp file of a live writer. The loose sweep
touches no other file in the shard directories.

Loose objects are unlinked in place during a sweep.
A crash before unlink leaves the object there, and the kernel releases the
lock. A subsequent open can read it and a subsequent gc applies the same
root and age checks. A crash after unlink has removed only an old,
unreachable candidate; a lost directory update may retain that candidate,
which is safe. No trash namespace or persistent sweep journal is needed.

**Safety condition (normative).** Let a writer that does not hold gc's
locks publish a ref at instant `T`. The publication cannot lose an object
to any gc run, whether that run's mark precedes `T` or follows it, when
every object the publication makes newly reachable (not reachable from
roots that stay unchanged during the gc run) is present at `T` with

```text
T - mtime < grace
```

using the on-disk `mtime` of the object file or its pack. This holds because a gc whose
mark precedes the publication read `now <= T`, so it keeps every such
object, and a gc whose mark follows the publication sees the new ref as a
root. The bound is tight: with `T - mtime <= grace` instead, a gc can
delete an object at the boundary (the model's `mutBoundedLax` mutant and
`boundaryLossTest`). Consequences:

- A writer outside gc's lock set MUST NOT rely on the duration of its own
  write-to-publish window to meet this condition, because a skipped
  object keeps its old `mtime`. The condition is met by
  a write-to-publish window shorter than `grace` only when every object
  the writer relies on had its `mtime` set within that window.
- `--grace-secs 0` is never safe against a concurrent writer outside gc's
  lock set.
- Git import refreshes every object it makes newly reachable, including
  map-cache hits and their stored closure. Concurrent gc is safe when the
  time from each object's write or first reuse to publication is strictly
  shorter than `grace`, with a coherent filesystem clock. The split
  metadata-read/unlink race is excluded by the format-file lock.
- Operators MUST exclude concurrent gc when using zero grace or when an
  import can exceed that per-object interval (including a stalled import).
  Once-per-run refresh does not renew the grace window during a long run.
  Clock rollback or timestamp precision that violates the strict on-disk
  bound also falls outside this guarantee.

## Local pack maintenance

A published local pack has both final names and a valid index
([SPEC-PACKFILE §3.1.1](SPEC-PACKFILE.md#311-local-packs)). A scan
recognizes only the final name forms of SPEC-PACKFILE §3.1.1 and the
staged-file names of [SPEC-OBJECTS §10.1](SPEC-OBJECTS.md#101-durability),
and considers only regular files in those forms. Readers and integrity scans ignore unknown files. Gc
leaves them untouched. An optional sidecar cannot determine discovery,
object identity, reachability, or retention.

A pack's age comes from the on-disk mtime of its `.pack` file.
A writer that reuses and refreshes an object refreshes the file
containing the selected copy under the shared `format` guard. The
index's mtime and the pack key convey no age. Under the exclusive
`format` try-lock, the orphan sweep rechecks name, counterpart,
file identity, and age. Keep a candidate on contention or uncertain,
changed, or young metadata. Recognized staging files and lone final
members are eligible after grace. A pair with a damaged index is an
integrity error, even if every requested object has a loose copy.
Gc aborts before sweeping on such an error. Enumeration skips a lone
member, but existing hard-root closure checks still fail if any
required object has no readable copy.

Gc rewrites and merges local packs by copy-then-retire. After the
retention mark, gc classifies every published pair that the wholly dead
retirement below does not take. A pair whose live entries all have a
verified copy in a pair that stays, and whose unreachable entries are all
past grace, is retired without a copy. A pair past grace
whose dead bytes, plus the bytes of live entries held by a pair that
stays, reach a quarter of its payload is rewritten. Pairs smaller than
16 MiB of payload and 16,384 entries are merged when at least eight exist.
These thresholds are policy, not format.

An input entry survives in two cases. An unreachable entry survives while
its input pack is within grace, whatever other copies exist. A live entry
survives when no pair that stays holds a verified copy of its id. Coverage
never removes an unreachable entry inside grace, and it never shortens
grace: a copy of an unreachable entry has the age of its new pack. A pair
that stays is one that is neither a wholly dead candidate nor an input of
the same run. Gc copies each survivor into a new pack, verifying the
copied object's canonical encoding and id against the index. It closes an
output before it would pass 64 MiB of payload or 65,536 entries; one
object larger than the payload cap gets an output of its own. Gc never
relies on a copy in a pair it retires in the same run, or on a loose copy.
A covering copy in a pair that stays is read and verified before gc
relies on it. An entry that cannot be read or verified keeps its input in
place. An input key also used as an output key stays in place.

Gc publishes every output durably (SPEC-OBJECTS §10.1) under the shared
`format` guard and reopens each output index. It then releases the guard
before retiring any input. Under the exclusive `format` try-lock, before
the first input unlink, gc checks that both members of every output and
covering pair are present under their final names with unchanged stamps. It
then flushes those files, the pack directory and the objects directory.
A missed try-lock retires nothing. The outputs stay as duplicates, and
the next run takes them as coverage for the live entries. It copies again
only the entries that coverage may not drop. If the copy itself fails, gc
keeps every input, reports the error, and goes on with the rest of the run.

Gc also retires a pack when every verified entry is unreachable and the
pack has passed grace. Gc records the pack's mtime after the retention mark
and before acquiring the exclusive `format` try-lock. Under the lock, it
rescans the pack directory and keeps any pair whose identity or pack mtime
changed. Live packs, and mixed packs that copy-then-retire does not
select, stay in place. If a candidate's body
fails integrity verification, gc reports the damage, keeps the pair,
and continues collecting other eligible objects.

Retirement takes the exclusive `format` try-lock once per batch of at most
32 items and 256 MiB of pack and index files: pack pairs, copy inputs and
leftovers together. A batch always takes at least one item, so a pack larger
than 256 MiB retires alone. Each batch is a
complete retirement as described here: it rechecks its own items, makes what
they rely on durable, unlinks the pack names, flushes, unlinks the indexes
and flushes, then releases the lock, so a writer that waits for the lock waits
for one batch. The two caps are policy. The target is a hold of about 50 ms
or less for the work that scales with size: 32 packs of 64 MiB took 150 ms
and more on the reference VM, and 256 MiB (four packs of 64 MiB) took a
median of 11 to 19 ms. A stalled flush on a busy disk can still stretch one
hold to a few hundred ms, which no size cap bounds. A failed try in any
batch ends the run with the earlier batches done. `kit gc` then prints one
line to standard error that says retirement stopped and how many packs it
retired; the exit code does not change, and the next run retires the rest. A crash between batches leaves only pairs and
inputs that the next run reconsiders; an input whose survivors have an output
is then covered by it and retires without a copy. No input relies on a pair
that the same run retires, whichever batch takes it.

Retirement after a copy takes the same try-lock and rechecks input
identity and the file stamps of every output and covering pair it relies
on, and durable coverage by the verified replacement packs.
Keep an input when its replacements cannot be read independently of it.
In either case, remove the pack name first.
Make all such removals durable in the pack directory before removing
their index names. Flush the directory after those index unlinks.
Directory syncs can cover a batch of removals under the same lock.
A crash before the first directory flush leaves either a complete input
pair or a lone index. After that flush, the retired pack name cannot
reappear through an index rebuild. A reader with a stale location can
rediscover the replacements.

Gc also drops a loose duplicate, including one left by a push, after
verifying a durable packed copy of the same id. It rechecks the loose
candidate and replacement under the exclusive `format` try-lock. Keep
a loose copy still within grace when the packed copy is older. A
duplicate can be reachable because the operation leaves a verified,
usable copy. Gc keeps the loose copy when
verification or durability is uncertain. This rule does not relax the
mark or age checks for deleting the last copy of an object.

### Dry run

`kit gc -n` uses the same retention mark and integrity checks as a
real run. It reports serialized payload bytes by physical copy:
unreachable bytes in wholly dead packs, unreachable bytes in packs
with both live and dead entries, and unreachable bytes old enough to
pass grace. It also reports the live payload bytes in mixed packs
with eligible dead bytes as the predicted survivor writes for
rewriting those packs. These estimates exclude framing and index
overhead. It also reports the pairs it would rewrite, merge or retire as
covered, and the survivor bytes it would copy. The sweep reclaims whole
eligible packs. The dry run changes no files.

### Automatic maintenance

A native fetch or pull that applied at least one pack or pruned a
remote-tracking ref runs one maintenance step after its last ref publish.
It first releases its prune guard and every `worktree.lock`. It reports
the original command result even if maintenance fails or is interrupted.
Set `gc.auto = false` or disable the embedder's option to skip the step.

A `kit commit` runs the same step after it has published the commit, printed
its output and released `worktree.lock`, because a repository that never
fetches would otherwise never run it: each `kit add` of a large file or of
more than 64 new small files leaves one pack pair. The commit's exit code and
standard output are unchanged; the step's only output is its maintenance line
on standard error, which `--quiet` and `gc.auto = false` suppress. `kit add`
alone does not run the step. It stages work that a commit follows, and the
commit is where a version is published and the next step is due, so the add
loop pays nothing. A commit in a repository whose `gc-auto` stamp does not exist and that holds fewer than 32 pairs does nothing and creates no file, so the `.kit` layout of a small repository is unchanged. The commit installs no signal handler for the step, so an
interrupt during it ends the process with the usual interrupt status after
the commit is durable. A step that is not due costs one lock try on the stamp, a
read of it and a listing of the pack directory.

The step only tries locks. It stops at the first miss. It tries the
exclusive lock of `<common_dir>/gc-auto` first. The holder rewrites that
file in place with the last attempt's time and outcome and the pair count
at the last complete collection. An empty stamp means the step has never
run, so it is due as soon as the listing shows 32 published pairs. An
unreadable stamp is rewritten and the step stops.
The stamp is advisory and never authorizes deletion.

**Sweep.** List `objects/pack/` by name to count published pairs and
find recognized staging files and lone final members. Apply the manual
orphan rule above at the default grace. Under the exclusive `format`
try-lock, recheck the candidate's name, counterpart, file identity and
age. Keep the manual sweep's directory flush before unlinking the
leftovers and its second flush after the unlinks. The sweep reads no object
and takes no `format` lock unless it finds an eligible leftover. A
publisher holds the shared guard from staging through its final flush.
A fetch or push that requests the shared guard during the sweep can
wait for the rest of the exclusive hold, including the recheck,
unlinks and both directory flushes. The sweep remains effective if the
collection that follows stops without retiring any pack.

**Collection.** The listing must show at least 32 published pairs, or the
stamp must record a step that made progress (below). The stamp allows a new
collection 7 days after a complete collection or an error, 1 hour after a
lock miss, changed roots, a step that made progress or a step that ran out
of budget before it verified one wholly dead pack, or 30 days after any
other attempt that ran out of budget before it retired anything. A
complete collection is also due again, whatever its age, once the listing
shows at least 32 more published pairs than the stamp's pair count at that
collection, so a repository that never fetches merges its small packs
again after every 32 new pairs and not once a week. These intervals and the
growth step are policy.

A step *made progress* when it retired or rewrote at least one pack and left
planned work for the next step: wholly dead packs it had no time to verify,
or copy inputs that did not fit in its one output pack. The step then stamps
`progress`, which is due after an hour and ignores the 32-pair floor, because
a store that a step brings under the floor can still hold garbage that the
next step plans to remove. A lock miss or changed roots right after a
step of progress keeps the `progress` stamp, so the retry is due in the same
hour and still ignores the floor. A step that left work but retired nothing
keeps the interval of its own outcome, so work that cannot be done never
repeats every hour. A store under the floor with no stamp of progress is left
alone until a manual `kit gc`: its garbage is bounded by the size of fewer
than 32 packs, and the step costs a mark of the whole history.

1. Read `now` and collect retention roots without the worktree locks.
2. Mark the roots under a wall-clock budget of 5 seconds that also covers
   retirement planning, coverage verification and the copy. A missing
   object or skipped soft root stops collection.
3. Plan retirement at the default grace. Validate the indexes, account
   for each entry against the mark, and record each wholly dead pair past
   grace with its file stamps. Verify the body of those pairs oldest first.
   The budget is checked before each pack and never inside one, so a pack
   that has started is read to its end. When the budget ends, the packs
   verified so far stay planned and the rest wait for the next step; the
   step then skips the copy and, once it has retired at least one of them,
   reports `progress`. If it ended before one pack was verified, nothing is
   planned: the step reports `over_budget` and stamps `progress`, due in an
   hour, because it had wholly dead packs past grace in view. A mark or
   listing that ran out of budget before any dead pack was seen reports
   `over_budget` with the 30-day interval. If the budget ends inside the last
   wholly dead pack, every pack verified stays planned, and the copy
   planning that follows defers only the copy. If
   every verified pack fails its recheck before retirement, the step
   reports `over_budget` and keeps the 7-day interval of a finished step. A damaged pair or cancellation ends collection
   before retirement. Then plan
   copy-then-retire as `kit gc` does (see "Local pack maintenance"), but
   keep only the inputs whose survivors fit in one output pack: at most
   64 MiB of payload and 65,536 entries, inputs that copy nothing first,
   then the smallest. With no candidate and no input, record a complete
   collection and stop. A budget that expires in this copy planning, in the
   verification or in the copy, or an I/O error such as a full disk there,
   defers only the copy: the wholly dead pairs planned above still retire
   (steps 5 to 7), as they do without a copy. The collection reports
   `over_budget` or `failed`, and the stamp keeps the 7-day interval of a
   complete collection, not the 30 days of a step that ran out of budget
   before it retired anything: the step did retire the wholly dead pairs, and
   a longer wait would postpone the retirement that a step without a copy
   did every week. If no pair is left to retire after a budget deferral,
   the interval is the same. Interruption and damage still stop the step.
4. Copy. Verify each covering copy that an input relies on, copy the
   survivors into one output pack and publish it durably under the shared
   `format` guard, which the step takes after planning and releases before
   the next step. The copy reads pack bodies, so it runs before any
   worktree lock. The budget can stop it before the publication, which then
   publishes nothing and leaves no staging file. An unreadable input
   frame, a frame that is not the object its index row names, or a covering
   copy that fails verification stops collection with nothing published and
   no pair retired: the automatic step never repairs or works around
   damage, and it does not keep a damaged input and go on as `kit gc`
   does. Once the output is published the budget no longer applies.
5. Try `worktrees.lock`, then every registered tree's `worktree.lock`
   in the order of SPEC-CONCURRENCY §4.
6. Read the roots again. If the hard set or the soft list differs, stop.
   An unreadable root also stops collection before retirement.
7. Retire the planned pairs and the copy inputs under the exclusive
   `format` try-lock, in batches (see "Local pack maintenance"). Apply the
   stamp recheck and removal order above. Release the locks.

A lock miss or changed roots after the output was published leaves it beside
its inputs. Those inputs are then covered by the output, and the next step
retires them without copying.

The mark depends on immutable objects and the retention roots. The
second root read holds every lock that manual gc takes, so a locked
writer cannot publish between that read and retirement. Fetch and push
hold a prune guard until they publish under a worktree lock. A git
import refreshes the mtime of the selected copy, and the pre-mark
`now` preserves the grace condition. The collection reads root files
and rechecks names and metadata under the locks. It reads no object
or pack body while holding them.

Automatic maintenance never expires the recovery log, prunes loose
objects or their temporary files, sweeps the spool, rebuilds an index,
or invalidates fetch records. Collection stops on an
integrity error without retiring a pair or repairing anything. A
completed orphan sweep stands. An interruption during retirement can
leave a lone index. The orphan rule removes it on a later sweep. A
torn stamp can only cause a new attempt.

### Integrity checks and repair

Fsck verifies the index and pack against each other, including the
whole-file key, trailer, frame layout, canonical object bytes, and
type-dependent ids. In repair mode, fsck MUST rebuild a bad index
beside a verified pack. Under the exclusive `format` try-lock, recheck
the same pack is still present, scan and verify it independently of
the old index, and make its name durable before publishing a staged
replacement index under SPEC-OBJECTS §10.1. If the pack changed, restart
validation. A lone index is a crash leftover and cannot be rebuilt.
Ordinary repair leaves a lone pack invisible. Gc handles recognized
leftovers after grace.

If the payload cannot be verified, report the damage. Invalidate the
affected applied-pack records and fetch shortcuts, conservatively
clearing them when their coverage is unknown, so refetch can obtain
verified copies. Use the exclusive `format` try-lock and the
fetch-shortcut invalidation rules in SPEC-TRANSPORT §1.2 to exclude fetch
while clearing records. An integrity repair does not advance refs or
create applied-pack records. A fetch that verifies and stages the exact
same pack key can replace a damaged member with the staged copy. It makes
the pack name durable before publishing the index. Unresolved corruption
remains an error.


## Invariants

| Invariant | Enforced by |
|---|---|
| No live object loses its last copy | loose pruning uses the complete retention mark. Loose duplicate removal and copy-then-retire require verified, durable coverage by a copy that is not retired in the same run. Gc can also retire packs of unreachable entries ("Local pack maintenance") |
| Automatic collection retires only what `kit gc` would retire at the default grace | Accept an unlocked mark only if the roots read under gc's full lock set equal the marked roots. See "Automatic maintenance". |
| gc never prunes against a partial root set | `collect_roots` errors if **any** source is unreadable &mdash; strict ref walk, no lenient skips &mdash; and gc MUST abort on that error ("Fail-closed requirement") |
| gc never prunes on an unsound "unreachable" verdict | a closure hitting `MAX_REACHABLE` returns `GcRootsError::Truncated`; gc aborts ("Fail-closed requirement") |
| A missing root or referenced object aborts gc | `StoreError::ObjectNotFound` propagates from the closure walk ("Fail-closed requirement") |
| gc counts no chunk toward the object cap | `LiveSet` holds chunks apart from `objects`; only `objects` is capped at `MAX_REACHABLE` ("Retention roots") |
| A chunk that is not a blob aborts gc | the mark reads the type of each distinct chunk and returns `GcRootsError::ChunkNotBlob` before the sweep lists an object ("Fail-closed requirement") |
| gc holds neither every loose object nor an uncompacted chunk buffer | the sweep lists one `objects/<2 hex>/` directory at a time, and the chunk ids are compacted before the buffer grows past its threshold ("Retention roots") |
| A superseded tip stays recoverable until the retention policy expires it | amend/reset/rebase/stash-pop append to `.kit/recovery-log` before moving the ref or dropping the stash entry; every logged hash is a root ("Recovery log") |
| A crash cannot persist a ref rewrite while losing its recovery entry | `record` fsyncs the log file and its parent directory before returning ("Recovery log") |
| A producer append cannot race an `expire` rewrite and vanish | callers hold the repo lock; gc runs expire → collect roots → prune under the same lock ("Recovery log") |
| Recently-orphaned objects survive a gc run | unreachable objects younger than the grace window (default 14 days) are skipped ("Status") |
| A writer outside gc's lock set never publishes a dangling ref | when every newly reachable object has an on-disk `mtime` strictly within `grace` of publication; import refreshes writes and complete cached closures, and the final sweep check is excluded from refresh ("Concurrent writers and the grace window") |
| An unset ref never pins an object | the all-zero hash is excluded from roots ("Retention roots") |

The load-bearing rule is the fail-closed requirement: every guarantee
above degrades to "gc aborts" rather than "gc guesses" whenever any
input cannot be read completely.
