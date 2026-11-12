# Changelog

All notable changes to kit are in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SyncOptions::max_staged_bytes` sets the most bytes a fetch stages without
  the repository lock. It defaults to 64 GiB. `kit` has no flag for it.
- The S3 transport offers a repository cursor (SPEC-TRANSPORT §6.8). It is a
  digest of the key, `ETag` and `LastModified` of every object under `refs/`,
  read from the listing alone, so it needs no new object and no change to a
  writer. A fetch of an unchanged `kit+s3://` remote takes one request for up
  to 1,000 refs, and one more for each further 1,000. It took one listing and
  one read per ref, and a packmap read per branch, before. A store that
  returns no `ETag` or `LastModified` offers no cursor, and the fetch works as
  before.
- `kit worktree move [-f] <path> <new-path>`, `lock [--reason <text>] <path>`,
  `unlock <path>` and `repair [<path>...]`. A locked tree is refused by
  `remove` and `move` unless `-f` is given twice, and `prune` keeps it.
  `worktree list` shows the lock. A locked tree has an optional `locked` file
  in its state directory. No existing file changes.
- `kit stash push [-m <message>]` is another name for `kit stash save`.
- `kit pull --no-ff` fetches, then merges the fetched branch and always writes
  a merge commit, even when a fast-forward is possible. A conflict leaves the
  state of `merge`. It does not combine with `--all` or `--rebase`.
  `libkit::merge::Request` has a `no_ff` field.
- `kit pull --rebase` fetches with the usual signature checks, then replays
  the current branch onto the fetched branch through the code of `rebase`. A
  conflict leaves the state of `rebase`, and `--continue`, `--skip` and
  `--abort` finish it. It does not combine with `--all`.
- `kit rebase --onto <newbase> <upstream> [<branch>]` replays the commits of
  `<upstream>..<branch>` onto `<newbase>`. `<branch>` is a local branch and
  defaults to the current branch. `--continue`, `--skip` and `--abort` work
  after a conflict. The replayed commits are signed as in any rebase.
  `libkit::rebase::Request` has `upstream` and `branch` fields, and
  `libkit::rebase::Error::NoSuchBranch` reports a missing branch.
- `log --graph` draws the commit graph in the left margin with `*`, `|`, `/`
  and `\`, for the default and the `--oneline` format. It draws an edge only
  to a parent that the output shows. It is a usage error together with `-p`,
  `--stat` or `--format=json`, and an error for a history with more than 1024
  open branches.
- `log --decorate` prints the refs that name a commit after its id, as
  `(HEAD -> main, tag: v1, origin/main)`. It reads the refs once and prints
  each name with control characters escaped. It is a usage error together
  with `--format=json`.
- `log --all` starts the walk at `HEAD`, every local branch, every
  remote-tracking ref and every tag. A commit shows once. The flag is a usage
  error together with a revision or a range. `libkit::log::Query::all` selects
  it, and `libkit::log::ref_tips` lists the refs.
- `commit --allow-empty` is accepted. It makes a first commit with an empty
  tree when nothing is staged. A commit that has a parent never needed it.
- `checkout -- <path>...` restores the paths from the index. It runs
  `restore <path>...`, so it refuses a file with unstaged edits, and `-f`
  (`--force`) overrides the refusal.
- `checkout <rev> -- <path>...` restores the paths from `<rev>` into the index
  and the working tree. It refuses a file with unstaged edits, and `-f`
  overrides the refusal.
- `init <dir>` creates `<dir>`, nested levels included, and initialises it. It
  refuses a `<dir>` that is a symlink, a dangling one included, or a file.
  `init -q` (`--quiet`) drops the success line and never an error. `init` in
  an existing repository stays an error.
- `show-ref <pattern>...` keeps the refs that a pattern names: the full ref
  name, or its trailing path components. `main` keeps `refs/heads/main` and
  not `refs/heads/domain`. Several patterns give the union, and an empty
  pattern is a usage error. `show-ref` exits `1` with no output when nothing
  matches.
- `rev-parse --verify <rev>` takes exactly one revision, or `<rev>:<path>`,
  and prints its full ID. The object must exist in the store. Any other input
  prints nothing on stdout and exits `1`, or `64` when the count of
  revisions is not one. `-q` (`--quiet`) drops the message. It does not
  combine with `--abbrev-ref` or `--show-toplevel`.
- `add -n` (`--dry-run`) prints `add '<path>'` for each file that a real add
  would stage or update, and `remove '<path>'` for each deletion that `-A`
  would record. It writes no index and no object. It excludes `-p` and `-u`.
  `libkit::add::Request` has a `dry_run` field.
- `kit revert -m <parent-number> <merge>` reverts a merge commit relative to
  the chosen parent. `kit-core` takes the parent as the `mainline`
  argument of `ops::revert::revert`. A merge without `-m`, a number out of
  range and `-m` on a commit that is not a merge are errors.
- `kit branch -u <remote>/<branch> [<branch>]` (`--set-upstream-to`) records
  the upstream of a branch in the repo config, and `--unset-upstream` removes
  it. The remote-tracking ref must exist. `libkit::branch::set_upstream` and
  `unset_upstream` do the work.
- `rev-list` takes `-n <n>` and `--max-count=<n>`, which keep the first `<n>`
  commits, and a range `A..B` or `A...B` in place of a revision. It reads the
  range as `log` does.
- `log -p` (`--patch`) and `log --stat` follow each commit with its diff against
  its first parent, in the text of `show`. A root commit is diffed against
  an empty tree. The flags exclude each other and `--format=json`.
- `show`, `cat-file` and `rev-parse` take `<rev>:<path>`, the object at
  `<path>` in the tree of `<rev>`. `libkit::revspec::resolve_object`
  resolves it. The path is relative, has at most 4096 bytes and has no
  empty, `.` or `..` component. A missing path, a path through a file and a
  malformed path are errors.
- `kit push <remote> <src>:<dst>` pushes the local branch `<src>` to the
  remote branch `<dst>` on the path of a plain push, so the lease and the
  non-fast-forward check apply. Each side is a branch name or a
  `refs/heads/<name>` ref. A refspec push records an upstream only with `-u`.
  kit rejects a wildcard, a leading `+`, an empty `<src>` and a ref outside
  `refs/heads/`. `libkit::push::parse_refspec` and `plan_refspec` back it.
- `kit fetch --prune` (`-p`) deletes the remote-tracking refs of branches the
  remote lost (SPEC-TRANSPORT §1.3). It runs only after a complete, verified
  fetch, re-reads each candidate from the remote, and never deletes a local
  branch or a tag. `SyncOptions::prune` and `FetchReport::branches_pruned`
  carry it; `libkit::transfer::fetch_with_source` takes a `prune` argument.
- `kit branch -r` lists the remote-tracking branches as `<remote>/<branch>`,
  and `kit branch -a` lists the local branches and then the tracking branches
  as `remotes/<remote>/<branch>`. `libkit::branch::Query::scope` selects them,
  and `libkit::branch::Branch` has a `remote` field.

### Changed

- A fetch no longer fails when its packs pass the staging budget. It stages
  packs without the lock while they fit, then takes the lock and downloads,
  checks, applies and records each later pack before the next. A clone of a
  file larger than the budget works, and the staged bytes never pass it. A
  failure part way leaves the applied packs recorded; the next fetch skips
  them.
- The closure check before a fetch publishes a ref reads each chunk's type
  and no longer counts chunks toward its 10,000,000-object cap. A repository
  of many large files can be fetched. `gc` and push still count every chunk.

### Fixed

- Push planning fails when its closure walk reaches the 10,000,000-object
  cap. `reachable_closure`, `reachable_objects` and `reachable_snapshot`
  return `OperationLimitExceeded` there instead of a cut set, so a push no
  longer sends a pack without the objects past the cut and then moves the
  branch.
- The disclosure verifier checks fixed-size chunk lengths. In a fixed-size
  `ChunkedBlob` every chunk but the last must hold exactly `chunk_size` bytes,
  and the last the rest of `total_size` (SPEC-OBJECTS §7), but the manifest
  binds no chunk lengths. A disclosed whole chunk and every length proof of a
  fixed-size layout must now have the length the layout requires, or
  verification fails with `VerifyError::FixedChunkLength`. A disclosed chunk
  or range of a `ChunkedBlob` must also have a `total_size` that its layout
  can produce, by the same rules as decoding a manifest. An absolute offset
  still comes only from length proofs, for every layout.
- `kit verify-proof` exits `65` (`DATAERR`) when the commit's embedded
  signature does not verify, with or without trust roots. It used to print
  `ok: ... (INVALID signature)` and exit `0` unless trust roots were loaded.
  It now prints `bad:` instead of `ok:`, and writes no `--payload-out` file.
  The report still shows what the bundle disclosed.
- The closure verifier now checks that the objects fit together as a
  checkout. A tree entry of mode `Tree` must name a tree. An entry of mode
  `Blob`, `Executable` or `Symlink` must name a blob or a chunked blob. A
  chunk must name a blob. The chunk lengths of a chunked blob must add up to
  its `total_size`, and in a fixed-size layout each chunk must hold the
  length the layout requires. A mismatch is `corrupt`. Before, a set with such objects
  was complete. Bytes that decode to no object are now `unreferenced`
  instead of `corrupt`, so an extra object that does not decode no longer
  makes a map-based or pack-based verdict incomplete.
- Disclosure verification now checks that an `Object` payload has the type
  that the mode of the final step names: a tree for mode `Tree`, a blob or a
  chunked blob for every other mode. Before, a step of mode `Blob` could name
  a tree and return that tree's bytes under a path that reports a blob.
  `verify::VerifyError` has a `PayloadTypeMismatch` variant.
- The closure verifier now also checks the type of the tree of a commit or a
  remix, which must be a tree, and of the target of a tag, which must have the
  type that the tag records. A mismatch is `corrupt`.
- Disclosure verification now rejects a `Chunk` or `Range` payload when the
  final step has mode `Tree`, or when there is no step. Both payloads are blob
  data, so the final step must name a blob, an executable or a symlink.
- `kit stash` removed ignored files from the working tree and did not save
  them, so `stash pop` could not bring them back. A stash now removes only
  the paths it saved. It refuses, before it changes anything, when HEAD needs
  a path that an ignored file holds. The clean sweep of a restore keeps
  ignored files below a directory that the target lacks, and keeps that
  directory. The restore safety check no longer refuses an untracked
  directory that only holds a target path or only holds ignored files.

## [0.8.0] - 2026-11-10

### Added

- `find_merge_base_strict` and `is_ancestor_strict` in kit-core read every
  commit they walk. On a healthy store they give the answers of
  `find_merge_base` and `is_ancestor`; where a commit is missing, corrupt
  or not a commit they fail with an `AncestorError` that names it, and a
  walk that would read more than 1,000,000 commits on either side fails
  with an error that names the limit. `find_merge_base` and `is_ancestor`
  keep ending a path at a missing object, for push and its shallow
  boundaries.
- `Transport::supports_serialized_advance` and
  `RemoteSource::supports_serialized_advance`: whether a two-ref advance is
  serialized for writers. Both default to the atomic-advance capability.
- Transports can offer a repository cursor, an opaque value that changes
  whenever a ref changes (SPEC-TRANSPORT §1.2). A fetch whose remote cursor
  equals the one its last complete fetch saw, with its remote-tracking refs
  and their tip objects as that fetch left them, makes no other request.
  `FetchReport::remote_unchanged` reports it. The memory transport offers a
  cursor. The file transport offers one on Linux: it keeps a write count in
  each stripe lock file and also reads the times of the ref directories, so
  that a write by kit 0.7.3 or earlier, which keeps no count, changes the
  cursor too (SPEC-REFS §5.1.2). It offers none while a ref directory was
  modified in the last 2 s. On one ext4 disk, a fetch of an unchanged
  `kit+file://` remote with 10,000 branches takes one request and about
  23 ms; it took 20,001 requests before. The SSH transport offers the cursor
  of the repository that `kit serve` serves, through a new `ReadRepoCursor`
  request (SPEC-TRANSPORT §4.2.2). A fetch of an unchanged `kit+ssh://`
  remote takes that one request, and the 4,999-branch limit of a session does
  not apply to it. A client that talks to an older server, and an older client
  that talks to this server, work as before. The S3 and Connect transports
  offer no cursor, and neither does the file transport, or `kit serve` over
  it, on other systems: a fetch there works as before.
- FastCDC v2 (SPEC-FASTCDC §11, draft): spread masks at normalization
  level 2 over the v1 gear table and sizes. A v2 manifest carries
  `chunk_size = 0x8000_0002`. kit-core exposes it through
  `Chunker::FastCdcV2`, `store_file_object_with` and
  `chunked_blob_from_bytes_with`. No writer uses it by default, so
  existing repositories read and write byte-identically. The git bridge
  refuses v2 manifests.

### Changed

- **Breaking:** `kit_transport_file::temp_path` is private. `create_temp`
  replaces it: it creates the temporary file next to a destination with
  `create_new`, takes the next name when one is taken, and returns the path
  and the open file. A caller of `temp_path` that created the file itself
  calls `create_temp`.
- **Breaking:** `RestoreError` in kit-core is `#[non_exhaustive]` and has a
  new `File` variant that carries the path of the file that failed. The
  function `restore_temp_sibling` is gone. `is_restore_temp_name` replaces
  it and takes a name only, because a restore temporary name no longer
  contains the name of the file it replaces. Code that matches
  `RestoreError` needs a wildcard arm.
- **Breaking:** `BisectError`, `RebaseError` and `BlameError` in kit-core
  are `#[non_exhaustive]`, and each has a `History` variant that carries
  the `AncestorError` of a history walk. A commit that cannot be read
  gives `AncestorError::Unreadable` with its id, a parent that is not a
  commit gives `AncestorError::NotACommit` with its id, and a walk over
  its cap gives `AncestorError::Limit` naming the limit. This covers the
  range and good walks of bisect, the replay and base walks of rebase, the
  first-parent chain of `kit blame --reverse` and the ancestry walk of the
  copy tie-break of blame. An object whose bytes match its id but do not
  decode now fails with an error that names it. Code that matches these
  enums needs a wildcard arm.
- **Breaking:** `libkit::log::Error` no longer has the `WalkRangeBase` and
  `WalkMergeBase` variants. No walk returned them: a commit that cannot be
  read gives `ReadCommit`, and an object that is not a commit gives
  `NotACommit`.
- `kit log -n N` from one revision streams the history while each commit
  has at most one followed parent, and stops after N commits. On one ext4
  disk with 1,000,000 linear commits, `kit log -n 20` went from about 8 s
  and 1.2 GB to about 4 ms and 8 MB, and the full log from about 8.2 s and
  1.2 GB to about 5.2 s and 415 MB. With `--first-parent` the whole walk
  streams. A history with a merge near the tip still reads every reachable
  commit before it prints. The output is unchanged.
- The file transport and `kit serve` lock each ref instead of the whole root.
  A ref write holds the repo lock shared and the lock of the one of 256
  stripes that the ref maps to, so writes to refs in different stripes no
  longer wait for one another (SPEC-REFS §5.1.1). Measured with single-ref
  compare-and-swap writes on one 4-CPU VM with an ext4 disk, 32 writers to 32
  refs in one root went from about 1,100 to about 2,500 writes per second; 32
  writers in separate roots on the same disk reached about 7,000, so the limit
  is inside one root. Writes to one ref still serialize, and `FileTransport::with_ref_lock` still excludes
  every ref write. `FileTransport::with_ref_lock_for` is the single-ref
  entry point.
- Batched object writes, such as `kit add`, start each object's write
  barrier on a background pool as soon as the object is staged. Before, every
  barrier waited for commit. The device wait now overlaps chunking and
  hashing. Objects still become visible only after the batch's full flush.
- FastCDC cuts chunks on up to 8 threads. The boundaries are byte-identical
  to the single-threaded chunker, so the object format does not change.
- The file transport advances a branch head and its packmap under the locks
  of both refs (SPEC-REFS §5.1.1). It checks both conditions before it
  writes either, so a conflict changes nothing, and it puts the packmap back
  when the head write fails. An advance that creates a ref holds the repo
  lock exclusive, so a clash with a ref created at the same time is reported
  as `InvalidRef` and leaves nothing behind. The file transport still offers
  no atomic advance: a reader can see the new packmap with the old head.
- A push that would grow a packmap chain past the re-baseline depth (64 by
  default, `KIT_PACK_REBASELINE_DEPTH`) replaces the chain with one node
  that lists every pack of the chain and then its own (SPEC-TRANSPORT §7.2).
  It uploads only its own packs, and a fetch into an existing clone downloads
  only the new ones. Before, such a push to a Connect server uploaded the
  full closure of the tip again and every clone downloaded it again, and a
  chain on any other transport grew by one node with each push. The node
  holds everything the chain held, so every transport and every head
  condition allows it. A node lists at most 1,024 packs: a chain that holds
  more keeps appending. A fresh clone downloads every pack of the branch.
  With the `fetch-grow` row of the multi-writer benchmark, the largest
  upload of one push among 1,000 pushes of a 1 KiB change went from 740,447
  bytes to 32,120 bytes, and a clone after them from 41 packs and 84 requests
  to 1,001 packs and 1,044 requests (docs/PERFORMANCE.md).
- The file transport reports `Transport::supports_serialized_advance`: its
  advance is serialized for writers, but a reader, or a crash, can see the
  new packmap with the old head. Force pushes over `kit+file://` take the
  guarded force driver, which plans again when another writer replaces the
  chain its plan read.
- The FastCDC cutter jumps over runs of one byte value, such as the zero
  blocks of a sparse image, once the rolling hash reaches its fixed point.
  The cut points do not change.
- `kit checkout`, `pull`, `merge`, `rebase`, `revert`, `cherry-pick` and
  `worktree add` record the stat cache of each file they write in the index.
  The next command no longer re-hashes those files, so the safety check of a
  second checkout and the first `status` after a checkout skip reading them.
  kit-core exposes this as `restore_tree_to_worktree_observed`.
- An ignore check of one path, such as `kit add <path>` and the restore
  safety check, slices each ancestor directory out of the path instead of
  building a new string for it.
- The S3 transport reads the refs of a listing with at most 16 requests in
  flight, not one after another. Against a local server that delays each
  read by 5 ms, a listing of 1,000 refs went from about 6.4 s to about
  0.4 s. The request count and the result do not change: refs come back in
  name order, a 404 skips the ref, and any other failure fails the listing
  (SPEC-TRANSPORT §6).

### Fixed

- Branch and remote names up to the file system limit work for create, fetch
  and clone. Ref, index and file-transport writes name their temporary file
  `.kit.tmp.<pid>.<seq>`, which does not contain the name of the file it
  replaces. Before, a ref name segment of 236 bytes or more failed with
  `ENAMETOOLONG`, so one such branch on a remote made every `kit fetch` and
  `kit clone` of it fail. `kit serve` sweeps crashed uploads by the new name.
- File-transport writes never follow or truncate an existing temporary file,
  and do not leave one behind. A write creates its temporary file exclusively
  and takes the next name when one is taken, so a link planted at a temporary
  name can no longer redirect a push to another file. A write that fails
  after it created the temporary file removes it.
- Restore writes a file through a temporary name of fixed length,
  `.kit-restore-tmp.<pid>.<counter>`, so a file name of up to 255 bytes
  checks out, clones and pulls. Before, a name of 240 bytes or more failed
  because its temporary name passed the file system limit. A restore never
  opens, follows or removes a file that already has a temporary name; it
  takes the next counter value. Pull recovery sweeps an untracked regular
  file with that name shape, and the rule no longer needs a tracked sibling.
- A restore I/O error names the file, as a path relative to the restore root.
- A restore that fails while it writes a file, sets its mode or renames it
  into place removes the temporary file it created. Before, a failed
  checkout, pull or stash left a `.kit-restore-tmp.<pid>.<counter>` file or
  symlink in the worktree, which `kit status` listed and `kit add` staged.
  A killed restore still leaves one for pull recovery to sweep.
- `kit log` and `kit rev-list` fail with an error that names the limit when
  a walk reaches more than 1,000,000 commits. They used to stop there and
  print the newest commits as if they were the whole history. The excluded
  side of a range (`A..B`, `A...B`) shares that limit; it used to stop
  silently at 10,000 commits, which let excluded commits through.
- `collect_ancestor_set`, `kit rebase` and `kit bisect` fail with an error
  that names the limit when an ancestor walk reaches 10,000 commits, and
  a rebase fails when the branch has more than 10,000 commits to replay.
  They used to stop there silently: a rebase could replay only the newest
  commits of a long branch, or replay commits its base already holds, and
  bisect could offer commits that are known good.
- `kit rebase` fails before it changes anything when a commit to replay
  or an ancestor of the base is missing, corrupt or not a commit. It used
  to end the walk there. It then dropped a missing commit of the branch
  and every commit below it, and after a missing commit in the base's
  history it replayed commits the base already holds.
- The excluded side of a `kit log` range (`A..B`, `A...B`) fails when one
  of its commits is missing, corrupt or not a commit. It used to skip such
  a commit, so the range printed ancestors of `A` that it leaves out. The
  error is `libkit::log::Error::ReadCommit` or `NotACommit`, as on the
  included side.
- `kit git format-patch A..B` fails before it writes a patch when an
  ancestor of `A` is missing, corrupt or not a commit. It used to skip such
  a commit, so the series held patches for ancestors of `A`.
- `kit bisect` fails when a commit of the range, or an ancestor of a good
  commit, is missing, corrupt or not a commit. The range walk used to end
  at such a commit and the good walk used to skip it, so bisect could miss
  candidates or offer commits that are known good.
- `kit merge-base`, `kit merge-base --is-ancestor`, `kit merge`,
  `kit diff A...B`, `kit diff --merge-base`, the ancestry filters of
  `kit branch`, the fast-forward check of `kit pull` and of the git bridge
  pull, and the copy tie-break of `kit blame` read every commit of their
  merge base or ancestry walk. A commit that is missing, corrupt or not a
  commit used to end the walk there: `kit merge-base` printed no base or a
  wrong one, `--is-ancestor` answered "no" with exit 1, and `kit merge`
  and `kit diff` could use a wrong base. They now fail with an error that
  names the commit: `kit merge-base`, `kit merge`, `kit diff` and
  `kit branch` exit 65, print nothing on stdout, and change nothing.
  `libkit::merge::Error::History`, `libkit::diff::Error::History` and
  `libkit::branch::Error::History` carry the error. Push keeps the lenient
  walks.
- The two sides of a `kit log` range share one budget of 1,000,000
  commits, as the documentation says. Each side used to have its own, so
  a range could read up to twice the limit.
- `kit bisect` fails with an error that names the limit when a range has
  more than 10,000 candidates. Its candidate walk used to have no limit.
- `kit git format-patch` fails before it writes a patch when the two sides
  of its range would read more than 1,000,000 commits together, with an
  error that names the limit. Both walks used to have no limit.
- `kit blame --reverse` fails with an error that names the limit when the
  first-parent walk from the end of its range holds more than 1,000,000
  commits. It used to collect the whole chain with no limit.
- The file transport and `kit serve` report a ref absent when a ref file
  sits above its name (`refs/heads/a` for `refs/heads/a/b`) or a directory
  of other refs sits at it. Before, the read failed with a `Not a
  directory` or `Is a directory` I/O error. A listing under a prefix that
  names a ref file is empty instead of an error. Other read failures are
  still errors.
- `kit serve` names its limit when a session sends more than 10,000 frames,
  and SPEC-TRANSPORT §4.4 states what fits: over ssh an unchanged fetch costs
  one frame plus at least two per branch, so one session fetches at most
  4,999 branches.
- An S3 `list_refs` fails when it cannot read a listed ref. Before, a ref
  whose read returned an error status such as 403 or 500, or a body that is
  not a canonical ref wire, was left out of the listing, so a fetch treated
  the branch as absent. A ref that returns 404 is still left out: it was
  deleted after the page was listed.
- `kit push` and `kit push --force-with-lease` fail as a non-fast-forward,
  before they upload anything, when the remote head they read differs from
  their lease. They used to plan against that head and condition the head
  write on the lease. If the head then moved back to the lease while another
  push reset the packmap chain, the push could land a head whose chain lacks
  objects it needs, and fetches and clones of the branch then failed with a
  missing object. This affected every remote. A push whose earlier attempt
  already landed still succeeds and writes nothing (SPEC-TRANSPORT §7).
  Because push reads the head before its first upload, a push without write
  permission whose history does not fast-forward the branch now fails as a
  non-fast-forward.
- A failed save no longer wedges a paused rebase. Each state file is staged
  in a synced temporary file and replaced whole, and the files are staged
  before any is replaced, so a full disk leaves the previous state intact.
  Before, a save could leave `head-name`, `orig-head`, `todo` or `actions`
  empty, and `kit rebase --continue`, `--abort` and a new rebase all failed
  until `.kit/rebase-apply` was removed by hand. A rebase whose first save
  fails removes the empty state directory it created. `read_state` also
  rejects an empty `head-name` as invalid state.
- `kit trust add` and `kit trust remove` no longer empty the trust catalog
  when a write fails. They write a synced temporary file and replace the
  catalog whole. The catalog keeps its permissions, and a catalog that is a
  symlink, dangling or not, stays a symlink.

## [0.7.3] - 2026-11-08

### Fixed

- An interrupted pull resumes its worktree restore on the next pull. Recovery
  refuses to overwrite local work and reports when it completes the pull.
- Blame caps its LCS comparison table at 64 MiB after trimming the common
  prefix. Larger comparisons use the bounded line diff search. Reassembly,
  line buffers, and attribution memory still grow with file size.
- Mutation testing of changed lines uses paths relative to the Rust workspace.
- Apple release archives build on macos-26.

## [0.7.2] - 2026-11-06

### Security

- `PackReader::read` limits the bytes it decodes from a pack to 32,768 times
  the pack size, with a floor of 2 GiB and the old 16 GiB as the ceiling.
  Before, a pack of a few kilobytes could force 16 GiB of decompression.
  Real packs expand 2 to 4 times, and an honest pack of deltas of small files
  expands at most about 12,000 times.
- A zstd entry is checked against its claimed decompressed size before the
  reader reserves a buffer for it. The blocks of the frame must be able to
  decode to the claim. Before, a 15-byte entry could make the reader reserve
  1 GiB.

### Fixed

- The search of the line diff behind `diff`, `show`, `format-patch`, `add -p`
  and the text merge now uses about 64 MiB at most, whatever the input. It stops
  at 4096 line edits. Before, its memory grew with edits times lines, so
  rewriting a 1 MiB text file with 80-byte lines cost about 10 GiB. Output is
  unchanged up to the limit. Past it, a diff keeps the best alignment that the
  search reached and reports the rest as replaced, and a text merge reports a
  conflict. The line tables and output of a diff still grow with the file.
- The text merge reports a conflict for a single blob above the 1 MiB chunk
  threshold, the same as for a chunked file.

## [0.7.1] - 2026-11-04

### Added

- kit-wasm is published to npm as `@officialunofficial/kit-wasm`. The release
  workflow builds the package with `scripts/wasm-package.sh` and publishes it
  with npm trusted publishing.

## [0.7.0] - 2026-11-04

### Security

- The decoders of the range disclosure bundle, the pack list node and the
  closure manifest reserve memory for a list in proportion to the input,
  not to the declared length. Before, about 1 MB of input could reserve
  about 96 MB. Accepted and rejected inputs do not change.
- `PackDecodeCursor` no longer keeps a record for every frame of a pack. It
  held about 190 bytes for each 5-byte frame, so a 50 MB pack of empty frames
  pinned 1.9 GB before the first entry was decoded. The cursor now keeps its
  position and parses each frame when `resume` reaches it, and it keeps only
  the decompressed payload of a `0x03` or `0x04` frame, in a 24-byte slot. A
  pack of empty raw frames adds no allocation. `decode_entries_with` runs on
  the cursor and gets the same bound. Errors, their order and the wire format
  do not change.

### Added

- `PackEntries` implements `Clone`.

### Changed

- **Breaking:** a multi-leaf proof requires strictly ascending positions.
  The builders (`build_tree_entries_multi_proof`,
  `build_chunks_multi_proof`) and the verifiers (`verify_tree_entries_multi`,
  `verify_chunks_multi`) read the positions in input order and reject a
  position that is lower than the one before it with the new variant
  `MerkleError::UnsortedPosition`. Before, they sorted the positions. This
  matches the Commonware BMT, so both sides accept the same inputs.
  A position equal to the one before it is `DuplicatePosition`, and a repeat
  that is not adjacent is `UnsortedPosition`. The checks run in input order,
  so an input with more than one fault can report a different error than in
  0.6.0: on nine leaves, the verifiers give `DuplicatePosition(4)` for
  `[4, 4, 9]`, not `PositionOutOfRange(9)`. Proof bytes, roots and ids do
  not change (SPEC-MERKLE-OBJECTS §5.4).
- The `history-mmr` feature of `kit-core` builds the Commonware storage and
  cryptography crates without their `std` feature. The normal dependency graph
  of the feature drops from 364 to 135 crates. The deterministic runtime, the
  zstd 0.13 library, `blst` and an HTTP server crate no longer build with it.
  Roots, proofs and ids do not change.
- Commonware 2026.10.0 states AVX2, BMI2 and ADX as its supported x86-64
  floor and tests only at or above it. This corrects the 0.6.0 note on that
  floor. No Commonware code that kit builds checks for these features or needs
  them: their SIMD paths and the BLAKE3 code that kit uses detect the CPU
  features at run time. Kit sets no CPU floor of its own.

## [0.6.0] - 2026-11-04

### Security

- Every Ed25519 check uses one acceptance predicate (SPEC-SIGNING §1):
  canonical, non-small-order `A` and `R`, canonical `s`, and the cofactored
  equation. Commits, tags, attestations, write grants, URL tokens and auth
  envelopes all call `kit_core::sign::verify_ed25519`. Before, fetch used a
  batch check that accepted some torsion-padded signatures that `kit verify`
  rejected, and the transfer envelope test used the loose RFC 8032 check.
- Decoders bound every allocation and all decode work on hostile objects,
  packs, ignore files, refs and remote listings.
- Tree entry names reject `:` and the NTFS 8.3 aliases `kit~N` and `git~N`
  on every platform (SPEC-OBJECTS §4.1). A symlink target that escapes
  the working tree is refused.
- Git import checks object kinds, parents and hashes.
- Terminal control characters in remote text and messages are escaped.
- Signer PINs are wiped after use, and the signer process gets a limited
  environment.
- Release builds remap build paths, and CI checks that the release build
  reproduces.

### Added

- `kit_core::write_auth::inspect_headers` checks the header counts of a
  signed request (SPEC-TRANSPORT-CONNECT §7.1). It rejects a repeated
  envelope header and a missing one.
- `kit_core::write_auth::replay::classify_replay` and `storable_rejection`
  map a signed-write replay record to an outcome and decide which refusals
  a server may store.
- The `kit-wasm` crate wraps the byte-format and crypto paths of `kit-core`
  and `kit-attest` for the browser. It is not published to crates.io.
- A `libkit` usage guide and an example that `cargo test` builds.

### Changed

- The Commonware crates move to 2026.10.0. History roots (`history-mmr`)
  now bind the MMB family and bagging tags (SPEC-HISTORY-PROOF §2.3), so
  every root changes. Ancestry snapshots use format 2. A format 1 snapshot
  still loads with its root recomputed, and the next tip move rewrites it.
  Descriptors and proofs from an earlier kit do not verify against the new
  roots. `history::InclusionProof` aliases the 2026.10.0 proof type.
- Upstream Commonware 2026.10.0 assumes AVX2, BMI2 and ADX on x86-64
  (Intel Broadwell, AMD Zen or newer).
- The verification equation is cofactored. A signature whose `R` or `A`
  carries a torsion component, which only the key holder can make, now
  verifies.
- Clone, pull and fetch check signatures with
  `kit_core::sign::verify_ed25519_batch`, which accepts exactly what the
  single check accepts. Its weights come fresh from the operating system.
  The `batch-verify` feature of `kit-core` and `kit_core::sign::verify_batch`
  are removed.
- The disclosure proof variants are now `RangeProof::{Kdpb, Kdsp}` and
  `RangeProofKind::{Kdpb, Kdsp}`. The wire bytes do not change.
- `KitError` and `IgnoreError` have new variants for the new refusals.

## [0.5.0] - 2026-10-28

### Added

- The `kit` command-line tool and the `kit-*` library crates.
- The `libkit` crate. It gives programs the same typed operations that the
  `kit` command runs: history, working tree, merge, rebase, remotes, grants,
  transfer, keys, attestation and git interop.
- The installer `install.sh`, served from `kit.storage`. It requires a cosign
  signature check by default.
- The release workflow `release.yml`. It signs each archive with cosign
  keyless signing, adds SLSA build provenance, and publishes a CycloneDX SBOM.
