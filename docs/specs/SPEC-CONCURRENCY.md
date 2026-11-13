---
spec: SPEC-CONCURRENCY
version: 2
status: draft-normative
audience: implementers of any lock-taking kit-core/kit-bin code path; reviewers of concurrency-sensitive changes
---

# SPEC-CONCURRENCY &mdash; the total kit lock order

Status: **Normative** for lock naming, location, and acquisition order.
**Draft** because §3.1 documents an open coordination gap this document
does not resolve. See SPEC-CONVENTIONS §2 for what draft/normative mean.

Scope: this document is the single owner of the total lock order across
*every* lock any kit process takes &mdash; repo-local locks defined in
SPEC-WORKTREE §4.3, the ref-history locks defined in `kit-core::refs`,
and the file transport's ref locks defined in SPEC-REFS §5.1.1. Any
other `SPEC-*.md` document that mentions a lock cross-references this
one rather than restating the order; this document does not restate
those other documents' non-locking content.

---

## 1. Why this document exists

Nearly a dozen `SPEC-*.md` documents each independently described a
slice of kit's locking model, using inconsistent names for the same
lock and never stating the total acquisition order a multi-lock caller
must follow. That let deadlock-shaped bugs (two processes taking the
same two locks in opposite order) hide in the gap between documents.
This spec is the one place that total order lives; every other
document points here.

## 2. Lock inventory

| Lock | Location | Scope | Guards | Defined in |
|---|---|---|---|---|
| `worktree.lock` | each tree's state dir | per-tree | that tree's worktree/index read-modify-write | SPEC-WORKTREE §4.3 |
| `worktrees.lock` | common dir | per-repo | linked-worktree registry mutations, branch-checked-out-elsewhere guard + HEAD write | SPEC-WORKTREE §4.3 |
| `refs-history-<branch>.lock` | common dir, keyed on the branch name | per-branch | ancestry intent + ref + descriptor publication for one branch (`kit_core::refs::history_lock_name`) | §3.2, §3.3 (this document) |
| `refs-<ref>.lock` | common dir, keyed on the full ref path | per-ref | every direct on-disk ref mutation: Any, Missing, Match, delete, tags, remote refs and batch writes (`kit_core::refs::cas_lock_name`) | SPEC-REFS §5.1 |
| `<root>/.kit/refs/.lock` | transport root | per-repo, **local to the file transport only** | held shared by a single-ref write and by a two-ref advance of existing refs, and exclusive by a multi-file step and by a two-ref advance that creates a ref; the exclusive hold excludes every file-transport write (`kit-transport-file`'s `RefLock`) | SPEC-REFS §5.1.1, §3.1 (this document) |
| `<root>/.kit/refs/refs-<hh>.lock` | transport root, keyed on the first byte of the BLAKE3 digest of the full ref name | per-stripe (256), **local to the file transport only** | a single-ref write's Any, Missing and Match critical section, and the checks and writes of a two-ref advance of existing refs | SPEC-REFS §5.1.1 |
| `git-<remote>.lock` | common dir, keyed on the git bridge remote name | per-bridge-state | one `kit git import`/`fetch`/`pull` import phase or `kit git export` against that remote's bridge state dir (`kit-bin`'s `git_import::import_into`, `git::export`) | §4 (this document) |
| shared/exclusive `format` handle | existing immutable common-dir `format` file | per-repo; short object-store critical section, except a fetch's guard, which lasts the whole fetch | shared during a bulk write or cached reuse and during format validation, and for the whole run of a fetch (the prune guard); exclusive, try-only, during gc's final age check and unlink | SPEC-GC, §3.4 (this document) |
| `git-import-key.lock` | common dir | per-repo | first-time generation of the shared git-import signing key (`git_import::load_or_create_import_key`) | §4 (this document) |
| `serve.lock` | common dir | per-repo, **detection only, not a critical-section lock** | held **shared** for its whole lifetime by every live server process on the root: `kit serve` (stdin SSH-frame, its only mode) and any layout server, meaning a server that embeds the `.kit` filesystem layout (which also holds `server.lock` exclusively, so one layout server serves a root at a time); taken exclusive without waiting by a starting `kit serve` only to sweep crashed uploads' temp files; probed non-blocking-exclusive by `worktree.lock`/`worktrees.lock` acquisition to warn when a root is concurrently served | §3.1 (this document) |

The recovery log (`.kit/recovery-log`) has **no dedicated lock** &mdash; see
§3.2.

In the schematic names above, `<ref>` MUST be the lowercase hexadecimal BLAKE3
digest of the full UTF-8 ref path relative to the common directory, such as
`refs/heads/main`. `<branch>` MUST be the same digest for `refs/heads/` followed
by the branch name. This bounds each filename independently of ref length and
keeps namespaces distinct. History and mutation locks retain separate prefixes.
Version 2 deliberately replaces escaped ref names with these digest names;
only the current lock naming contract is supported.

## 3. Cross-subsystem interactions

### 3.1 File-transport CAS vs. local worktree operations (detected, not coordinated)

The file transport's locks (`<root>/.kit/refs/.lock` and
`<root>/.kit/refs/refs-<hh>.lock`, SPEC-REFS §5.1.1) serialize file-transport
Any, Missing and Match writes to one ref against other file-transport
instances pointed at the same root.
Direct local ref mutations instead share the full-ref
`<common_dir>/refs-<ref>.lock`, including unconditional writes and deletes.
Each domain therefore prevents its own unconditional writer from bypassing a
concurrent conditional write. The two domains use different lock files:
the file transport does not acquire the local full-ref lock, `worktree.lock`,
`worktrees.lock`, or `refs-history-<branch>.lock`.

The cross-domain gap remains: local `kit commit`/`checkout`/`gc` against a
directory simultaneously served by `kit serve` or a layout server is not coordinated with the
transport. When the served root is the repository's common dir (`.kit`),
the transport's `<root>/refs/...` files are the local refs, so a local ref
mutation can race a client CAS. When the served root is any other directory
the two sets of refs are separate files. In either layout a GC sweep cannot
delete a pushed object: pushes store packs under `<root>/packs/`, which gc
neither sweeps nor roots (SPEC-GC "Concurrent writers and the grace
window"). The supported file-transport deployment is a
bare/shared remote that a worktree-owning process does not also mutate directly.
Local worktree commands against a live `kit serve` or layout-server root remain unsupported.

**The server now detects this case instead of staying silent**, without closing
it: every live server process on the root &mdash; `kit serve <path>`
(stdin SSH-frame, its only mode) and any layout server (a server
that embeds the `.kit` filesystem layout) &mdash; holds a **shared**
kernel lock (`std::fs::File::lock_shared`, never exclusive &mdash;
SPEC-TRANSPORT documents multiple concurrent `serve` processes against
one root, e.g. one per SSH forced-command connection, as a supported
deployment, so `serve` instances must not exclude each other) on
`serve.lock` (in the common dir) for its whole lifetime. A layout server
also holds `server.lock` (in the common dir) **exclusively**, so one
layout server serves a root at a time; it shares `serve.lock` with any
`kit serve` processes on the same root. The one exclusive hold: at
startup `kit serve` tries `serve.lock` exclusively, without waiting, and
only while it holds it (so no other server is up) sweeps the temp files
crashed uploads left in `packs/`, then drops it and takes the shared lock;
if the lock is busy it skips the sweep. `worktree.lock`
and `worktrees.lock` acquisition (`libkit::lock::acquire_worktree`
and `libkit::lock::acquire_registry`) each follow up with a
non-blocking exclusive probe of that same `serve.lock`
(`kit_core::repo_lock::probe_exclusive`); when the probe finds it busy
(i.e. at least one `serve` is alive), the command prints a warning to
stderr and proceeds anyway &mdash; it does not refuse or block. The paths that
take `worktree.lock` without the helper call the same probe directly
(`libkit::lock::warn_if_served`) right after acquiring it: the per-branch
publish step of `fetch`/`pull` and the fast-forward phase of
`pull` (`kit_sync::fetch` and `remote_dispatch::pull_all_with`), and
`status`'s opportunistic index refresh. So every command that takes
`worktree.lock` or `worktrees.lock` emits the warning: the
worktree-mutating commands, `gc` (which takes both), `tag` (create),
`attest`, `fetch`/`pull`, `clean`, and the fast-forward of `kit git
pull`. Paths that take neither lock do not, including `push`, `tag -d`,
and the import phase of `kit git import`/`fetch`/`pull` and `kit git
export`, which hold only `git-<remote>.lock` (§4's per-command table).

Residual gaps this warning does **not** close:

- A push made directly against the file transport (`kit push
  kit+file:///path`, bypassing `kit serve` entirely) is not detected
  &mdash; nothing takes `serve.lock` on that path.
- Detection is one-directional: a `kit serve` that starts *during* a
  local command's already-in-flight critical section is not itself
  warned, since `serve` does not probe the worktree locks.

### 3.2 Recovery-log `record`/`expire` synchronization

`ops::recovery::record` and `ops::recovery::expire` are not internally
synchronized (see that module's own concurrency note) and have no
dedicated lock of their own. Correctness instead relies on lock
**superset** containment:

- Every producer (`commit --amend`, `reset`, `rebase`, `stash pop`)
  calls `record` while already holding *its own tree's* `worktree.lock`
  &mdash; the same lock it took for the read-modify-write the recovery entry
  is about.
- `kit gc` calls `expire` while holding `worktrees.lock` **and every
  registered tree's `worktree.lock`** (SPEC-WORKTREE §4.3's holder
  list) &mdash; a strict superset of any single producer's one lock.

Because gc's lock set always contains whichever single `worktree.lock`
a producer would be holding, a producer's `record` append and gc's
`expire` rewrite can never interleave &mdash; without a separate recovery-log
lock being necessary. `ops::recovery`'s module doc calls this "the repo
lock" generically rather than naming a specific lock file, precisely
because the guarantee comes from lock containment, not from a
dedicated primitive.

### 3.3 First-parent history publication

The history-enabled CLI uses `refs::update_ref_with_ancestry`, taking the
branch history lock and then its full-ref mutation lock before reading state.
Initial ancestry construction, multi-commit fast-forward, generation selection,
intent persistence, ref publication and descriptor publication all run within
these guards. Snapshot readers take the same pair, and reject pending intent.
Guarded internal ref primitives MUST NOT reacquire the held mutation lock.

Pending intent retains both its old and target ref as GC roots, even in a build
without `history-mmr`; all raw mutation paths reject stepping over that intent.
The exact durable state machine and generation semantics are
SPEC-HISTORY-PROOF §4. The low-level event-journal APIs do not establish first-parent
ancestry.

### 3.4 Object refresh versus local gc

The common-dir `format` file is immutable after initialization and MUST NOT
be replaced or unlinked while the repository is in use. Independently opened
handles take shared locks for bulk writes, cached reuse and format validation.
Gc takes a nonblocking exclusive lock for each final age-check/unlink;
contention keeps the object. No object changes namespace while this lock is
held, so process death requires no persistent sweep recovery.

No process ever blocks on the exclusive format lock. Gc takes it with a
non-blocking try, and keeps the object when the try fails. A process that
waited for it would wait as long as the longest shared holder, and a fetch
holds the shared lock for hours.

A fetch takes the shared lock as a prune guard before it reads its record of
applied packs, and holds it until after its last remote-tracking ref publish.
While a guard is held, gc keeps every candidate at any grace, so the objects
a fetch has written and no ref names yet survive (SPEC-GC, "Concurrent
writers and the grace window"). The guard relies on a local filesystem, as
every lock here does. On Linux NFS a shared `flock` can vanish when another
handle to the file closes.

The shared lock is innermost for a bulk write: acquire it after any registry,
worktree, git-remote, history or ref locks already held. Its holder MUST NOT
acquire another repository lock. Bulk commit does not hold it while
publishing refs. The prune guard is the one exception. A fetch holds it and
then takes `worktree.lock`, and the ref locks below it, to publish a ref.
This inverts the order above and cannot deadlock. The guard is a shared lock,
so it never waits for another shared holder. The one process that holds
`worktree.lock` and wants the exclusive format lock is gc, and it only tries
the exclusive lock and moves on, so a fetch that waits for gc's
`worktree.lock` while holding the guard waits for gc to finish, not for a
lock gc is waiting on. The existing local-filesystem locking assumptions
apply.

## 4. Global lock order and per-command lock sets

A process that takes more than one lock from §2 MUST acquire them in
this order:

```
worktrees.lock  ≺  per-tree worktree.lock(s)  ≺  refs-history-<branch>.lock(s)  ≺  refs-<ref>.lock(s)
```

All direct local mutations of a full ref path MUST hold its `refs-<ref>.lock`, including
unconditional writes and deletes. An Any condition removes the value
precondition, never the serialization requirement. The lock is nested inside
history guards by history-aware writers; guarded internal primitives MUST NOT
reacquire it. Multiple locks within a class MUST be acquired in canonical
order before proceeding to the next class: main worktree first then registry
IDs, branch names lexicographically, and full ref paths lexicographically.
Current rename operations publish individual refs; this order does not promise
an atomic multi-ref transaction.

The git bridge locks nest only with the ref class of this chain:
`git-<remote>.lock` ≺ `git-import-key.lock` ≺ `refs-<ref>.lock`(s). A
process MUST NOT acquire either bridge lock while it holds `worktrees.lock`,
a `worktree.lock`, a `refs-history-<branch>.lock`, or a `refs-<ref>.lock`. `kit git pull`
releases `git-<remote>.lock` when its import phase returns, before its
fast-forward acquires `worktree.lock`.

The short-lived shared/exclusive `format` lock (§3.4) is innermost in
both chains. Holders acquire no further repository locks; gc never waits
for its exclusive acquisition. Per-command sets below omit this implicit
object-store lock.

The file transport's locks serialize every write condition to one ref within
that transport. A process takes the repo lock before the stripe lock, and a
holder of the exclusive repo lock takes no stripe lock (SPEC-REFS §5.1.1). A
two-ref advance of two existing refs takes both refs' stripe locks in
ascending stripe order under the shared repo lock; one that creates a ref
holds the repo lock exclusive instead. Readers take none of these locks, so
a reader can see an advance's new packmap with the old head; the push
driver's reset rule for that case is in SPEC-TRANSPORT §7.2. The file transport's locks
are not composed with the local chain above; the served-root/local-worktree
deployment restriction in §3.1 still applies.

`serve.lock` is a lifetime detection guard, excluded from this acquisition
chain. A server holds it shared while handling requests, including requests
that take the file transport's ref locks. A local command only probes
it non-blocking from inside its `worktree.lock`/`worktrees.lock` critical
section and immediately releases a successful probe. Neither path waits for
exclusive ownership of `serve.lock`, so detection introduces no blocking
lock-order dependency. The per-command sets below omit these implicit probes
(see §3.1).

Per-command lock sets (extends SPEC-WORKTREE §4.3's holder list with
the history lock):

| Command/path | Lock set, in acquisition order |
|---|---|
| `add`, `commit`, `merge`, `checkout`, `rebase`, `cherry-pick`, `revert`, `reset`, `restore`, `rm`, `mv`, `stash`, `sparse-checkout`, `update-ref` | this tree's `worktree.lock`, then (if the command moves a branch ref and history-mmr is enabled) that branch's `refs-history-<branch>.lock`, then the full ref's mutation lock |
| `checkout`/`switch` (branch-checked-out-elsewhere guard), `branch -d`/`-m` | `worktrees.lock`, then (branch-moving forms) `refs-history-<branch>.lock`, then the full-ref mutation lock |
| `worktree add` | `worktrees.lock` (guard re-verified after acquiring), then the new tree's `worktree.lock` |
| `worktree remove` | `worktrees.lock`, then the condemned tree's `worktree.lock` |
| `gc` | `worktrees.lock` first (freezes the worktree set), then every registered tree's `worktree.lock`, deterministic order (main tree first, then registry ids ascending) |
| `clean` | this tree's `worktree.lock` |
| `status` (opportunistic index refresh) | this tree's `worktree.lock`, tried with a 10 ms timeout; on contention the refresh is skipped |
| `tag <name>` (lightweight and annotated create) | this tree's `worktree.lock`, held across the target re-check (and, for an annotated tag, the tag-object write) and the ref publish, then the tag ref's `refs-<ref>.lock` (`tag.rs`). `tag -d` takes only the tag ref's `refs-<ref>.lock` |
| `attest` | this tree's `worktree.lock`, held across the subject re-check and the attestation write, after signing (`attest.rs`); no ref lock |
| `fetch`, and the fetch phase of `pull` | the shared `format` lock (the prune guard) for the whole fetch, taken first. Per remote branch: download, unpack and record the packs with no `worktree.lock` held, then this tree's `worktree.lock` around the remote-tracking ref publish and its checkpoint, then that ref's `refs-<ref>.lock`; released before the next branch (`kit_sync::fetch::fetch_objects_inner`). The wait for `worktree.lock` has no deadline, reports once that it waits, and ends on an interrupt. A retry after a concurrent re-baseline downloads again with no lock held |
| `pull` (fast-forward phase) | this tree's `worktree.lock` across the restore-safety check, the branch write and the worktree restore, then (history-mmr) `refs-history-<branch>.lock`, then the branch's `refs-<ref>.lock` (`remote_dispatch::pull_all_with`) |
| `push` | no `worktree.lock`; each remote-tracking ref write takes its `refs-<ref>.lock` |
| `kit git import`/`fetch`/`pull` (import phase) | `git-<remote>.lock`, then (first import only) `git-import-key.lock`, then per written tag or remote-tracking ref its `refs-<ref>.lock`; no `worktree.lock` (`git_import::import_into`) |
| `kit git export` | `git-<remote>.lock` only; it reads local refs and writes no local ref (`git::export`) |
| `kit git pull` (fast-forward phase), after the import phase released `git-<remote>.lock` | this tree's `worktree.lock`, then (history-mmr) `refs-history-<branch>.lock`, then the branch's `refs-<ref>.lock` (`git_import::fast_forward_current`) |

A process that violates this order and blocks on two locks acquired in
opposite order by two racing processes normally time out independently
(`repo_lock`'s default 5s timeout) rather than deadlock indefinitely &mdash;
the format-file shared lock has no timeout. Processes SHOULD NOT rely on
lock timeouts as a substitute for correct
ordering; a timed-out multi-lock command leaves its already-acquired
locks released (RAII drop) but may leave mid-sequence on-disk state
requiring the caller to retry.
