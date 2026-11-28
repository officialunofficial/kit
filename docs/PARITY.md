# kit and Git parity

This file defines what "usable like Git" means for kit. It states the scope,
the non-goals, the machine-output contract and the documented divergences.
The per-command matrix is on [kit.storage/parity](https://kit.storage/parity).
It gives each command the status `parity`, `divergent` or `non-goal`.

## Scope

kit targets **CLI behavior parity** with Git. A command and flag that a person
or an agent types in Git behaves the same way in kit, unless this file lists
a divergence. kit keeps its own properties:

- BLAKE3 content addressing.
- A signature on every commit.
- Guards against data loss.

kit does **not** target on-disk or wire interoperability with Git
repositories. kit objects are BLAKE3 objects. A BLAKE3 object store cannot
share bytes with the SHA-1 object store of Git.

The `kit git` commands are the one exception. They translate objects between
the two stores. `kit git export` writes a deterministic Git mirror
([`SPEC-GIT-BRIDGE`](specs/SPEC-GIT-BRIDGE.md)). `kit git import` writes a
signed downstream fork of a Git remote
([`SPEC-GIT-IMPORT`](specs/SPEC-GIT-IMPORT.md)). Both commands translate every
object. Neither shares bytes between the stores. Two-way sync is a non-goal.

## Inherent divergences

These divergences stay while kit uses BLAKE3.

- **Hash length.** kit object IDs have 64 hex characters. Git object IDs have
  40. A Git hash never resolves in kit. A short prefix of a kit ID resolves,
  for example `kit cat-file -t f9f9951d`.
- **Repository directory.** kit stores its state in `.kit/`, not `.git/`. kit
  does not detect a repository by `.git/`.
- **Default remote name.** The default remote of kit is `default`, not
  `origin`. Its tracking refs live under `refs/remotes/default/`.
- **Remote URLs.** A kit remote URL starts with `kit+<scheme>://`. Plain
  `https://` and plain paths are errors. The one exception is a path to a
  closure export's `MANIFEST.mkcl`, which `clone` and `fetch` read as
  `kit+closure://`.

## Non-goals

- Submodules and subtrees.
- Hooks, including `core.hooksPath`.
- The full refspec grammar. `push` takes `<src>:<dst>` and a lone `<branch>` for branches,
  a lone tag name or `refs/tags/<t>` for one tag, and nothing else: no
  wildcard, no leading `+`, no renamed tag and no other ref. `push --delete`
  takes one branch or tag, never an empty `<src>`.
- Git wire protocol v2 and smart-HTTP negotiation.
- `git notes`.
- Shallow clone. `clone --depth` is a usage error, and a clone holds the full
  history. A design is in draft ([SPEC-SHALLOW](specs/SPEC-SHALLOW.md)): a
  window of commits whose tree and parent IDs the hash chain fixes, with no
  commit beyond the boundary reported as verified.
- `.git` on-disk interop and SHA-1 objects.
- Shadowing the `git` binary on `PATH`.

## Permanent non-goals

Four non-goals follow from the BLAKE3 object model. They stay while kit object
IDs are BLAKE3 hashes. The other non-goals are choices of scope.

### Git wire protocol v2 and smart-HTTP

- **Constraint.** A Git client names objects by SHA-1 ID. A kit object has a
  64-hex BLAKE3 ID and its own byte format. A Git client cannot name, fetch or
  verify a kit object.
- **Supported alternative.** The URL scheme picks a kit transport:
  `kit+file`, `kit+ssh`, `kit+s3` or `kit+https`. To move history to or from a
  Git server, use `kit git`.
- **Would reopen.** An object format whose IDs and bytes a Git client can also
  read, for example a SHA-256 format that matches the Git SHA-256 format. No
  spec plans one.

### `.git` on-disk interop and SHA-1 objects

- **Constraint.** A BLAKE3 object store cannot share bytes with a SHA-1 object
  store. kit keeps its state in `.kit/` and does not detect a repository by
  `.git/`.
- **Supported alternative.** `kit git import` writes a signed downstream fork
  of a Git remote. `kit git export` writes a deterministic Git mirror. Each
  command translates every object, and each loses something.
- **Import loses** ([`SPEC-GIT-IMPORT`](specs/SPEC-GIT-IMPORT.md)):
  - Every commit and tag becomes a new kit object that the importer signs. The
    kit ID depends on the importer key. Two importers of one upstream get
    unrelated histories.
  - The kit commit does not hold the committer line, the time zones, the author
    timestamp, a Git GPG or SSH signature, `mergetag`, `encoding` or unknown
    headers. kit keeps the original Git bytes under `.kit/git/<remote>/` as
    audit evidence.
  - A ref is refused when its history holds a submodule entry or a name kit
    does not store. A SHA-256 repository is refused. Some historic file modes
    are normalized.
  - `refs/notes`, `refs/replace` and grafts are not imported. A shallow import
    is impossible, because a kit parent ID needs the full closure.
  - `kit git import` needs `git` on `PATH`.
- **Export loses** ([`SPEC-GIT-BRIDGE`](specs/SPEC-GIT-BRIDGE.md)):
  - The author and committer lines are synthesized from the kit identity, with
    the address `bridge@kit.invalid`. The real identity and the signature ride
    in `kit-*` headers, and the signature still verifies.
  - A chunked file becomes one Git blob. A remix is refused. Attestations are
    not translated. Export mints one new `git-bridge/v1` attestation.
  - A rewrite on the Git side, such as a rebase or an amend, drops the `kit-*`
    headers. The result is no longer a translated kit object.
- **Would reopen.** The same change as the wire protocol: a shared object
  format.

### Two-way sync through `kit git`

- **Constraint.** Import is not the inverse of export. Import signs each commit
  with the importer key, so a commit that goes from kit to Git and back has a
  new kit ID and loses its original signature. A commit that goes from Git to
  kit and back gets a Git ID that differs from the original, because export
  synthesizes the author line and adds the `kit-*` headers.
- **Supported alternative.** Work in one direction at a time.
  `kit git pull` fast-forwards from the Git upstream, and `kit merge` integrates
  a diverged branch. `kit git format-patch` writes `git am` patches. `kit git
  export --passthrough` keeps the original Git IDs of imported objects, so the
  pushed branch shares history with the upstream. A passthrough push can only
  fast-forward. Plain export toward an imported-from upstream is refused.
- **Would reopen.** A shared object format. Without one, a round trip that
  keeps IDs would need kit to accept Git commit bytes as its own and drop the
  per-commit signature.

### Shadowing the `git` binary on `PATH`

- **Constraint.** kit differs from Git in the places that tools notice. IDs
  have 64 hex characters, a Git hash never resolves, the repository directory
  is `.kit/`, and remote URLs start with `kit+`. A binary named `git` would
  break callers that expect Git behavior.
- **Supported alternative.** A script calls `kit`. The machine-output contract
  below keeps the shape of the Git output. kit and Git run side by side.
- **Would reopen.** kit reads Git IDs and `.git/` directories, which needs the
  shared object format.

## Decisions on submodules, hooks and notes

Each of these is a non-goal today. Each entry says what Git does, what kit does
instead, what it costs, and what would reopen the decision.

### Submodules and subtrees

- **Git.** A submodule stores a pointer to another repository at one commit,
  as a `gitlink` entry in a tree. A subtree merges another history into a
  directory.
- **kit.** A tree entry is a blob, a tree, a symlink or an executable
  ([`SPEC-OBJECTS`](specs/SPEC-OBJECTS.md)). It has no entry for a pointer to
  another repository, and kit has no subtree merge. A project vendors the
  files of a dependency into its own tree, so one signed commit covers them.
  `kit git import` refuses a ref whose tree holds a submodule entry and says to
  vendor it or to exclude the ref.
- **Cost.** kit does not check out, update or verify a pinned dependency for
  you. A vendored copy does not share history with its upstream.
- **Would reopen.** A request for a pin that kit verifies. It needs a new tree
  entry kind or a new object, which changes the object format. The spec would
  have to say how the pin names the remote and how a fetch verifies it.

### Hooks, including `core.hooksPath`

- **Git.** A hook is a script that Git runs at a step such as commit or push.
  `core.hooksPath` picks the directory that holds the scripts.
- **kit.** kit has no hooks. `commit` always signs. kit does not read
  `core.hooksPath`: `core.*` is an unknown config key, and an unknown key is
  an error.
- **Why.** Repository config cannot choose a signing key, a signer, an
  external signer program or an admission helper
  ([`SPEC-CONFIG-SECURITY`](specs/SPEC-CONFIG-SECURITY.md)). A cloned
  repository then cannot make kit run its code or redirect its keys. A hook
  that the repository supplies would be that kind of code. There is no
  user-scoped hook either, so no hook can come from a repository by mistake.
- **Cost.** A check that Git runs in a hook runs in a script or in CI that
  calls `kit`. kit cannot stop a commit or a push because of a failed check.
- **Would reopen.** A user need that a wrapper script does not meet. The change
  would be a hook key that only the user-scoped config can set, listed in
  `REPO_FORBIDDEN_KEYS`, and never a hook from the repository.

### `git notes`

- **Git.** A note attaches text to a commit under `refs/notes/*` without
  changing the commit ID. A note is not signed, and its author can rewrite it.
- **kit.** `kit attest` attaches a signed statement to a commit without
  changing its ID. The statement is an in-toto v1 Statement in a DSSE envelope
  ([`SPEC-ATTESTATIONS`](specs/SPEC-ATTESTATIONS.md)). kit stores it in
  `.kit/attestations/<commit>/`, and it is not an object of the commit graph.
  An attestation takes the place of a note. `kit git import` does not bring in
  `refs/notes`.
- **Cost.** An attestation is signed, so it has a predicate type and it cannot
  be edited. A correction is a new attestation. Attestations travel apart
  from the commit graph, on the remote's `refs/kit/attestmap` log.
  `kit push` publishes the envelopes you authored only with `--attestations`
  or `push.attestations = true`, and a published envelope is permanent.
  `kit clone`, `kit fetch` and `kit pull` fetch the published envelopes by
  default and keep each valid one whose commit exists locally;
  `--no-attestations` or `fetch.attestations = false` skips them. A fetched
  envelope is never pushed again, and trusting its signer stays a
  `kit verify-attest` decision.
- **Would reopen.** A need for an annotation that is unsigned and editable. A
  shared attestation store does not reopen it, because that answers the sharing
  cost.

## Safety divergences

kit refuses some silent data loss that Git allows. These divergences stay
even when a command reaches parity on everything else.

- `restore` and `reset --hard` refuse to discard local edits or staged
  content. `-f` or `--force` overrides the guard. Git discards the edits
  without a warning.
- `worktree remove` refuses to delete a tree with untracked files or local
  changes. `--force` overrides the guard.
- `worktree lock` writes a `locked` file in the state directory of the tree,
  as Git does. A kit that predates the file ignores it. `worktree remove` and
  `move` refuse a locked tree unless `-f` is given twice, as Git does.
  `worktree prune` keeps a locked entry. `worktree move` refuses an existing
  destination, even an empty directory, a destination with a `..` component
  and a missing parent. It does not fall back to a copy across filesystems.
  `worktree repair <path>` fixes the back-pointer only, from the pointer file
  of the tree. A tree whose pointer file is relative and that moved by hand
  needs the pointer file fixed first, and `repair` with no path does that only
  when the tree is at the recorded place.
- `update-ref -d` refuses to delete the current branch. Git deletes it.
- Repository config cannot hold the signing key. `config --local signing_key`
  is an error. `-c signing_key=...` is ignored with a warning. A cloned
  repository cannot redirect signing.
- `commit --amend`, `reset` and `rebase` record the replaced commit in a
  recovery log. `gc` keeps the commit for the grace window.

## Machine-output contract

Output that tools parse is stable and has the shape of the Git output.
Object IDs are the only difference. They are 64 hex characters.

- `status --porcelain` and `status -s` print `XY <path>` lines. A path with
  special bytes uses C-style quoting. `-z` prints raw paths with NUL
  terminators.
- `status --porcelain=v2` prints `1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>`
  for a tracked change. It prints `2 ... R<score>` for a staged rename and
  `? <path>` for an untracked path. It prints no `--branch` header lines.
- `diff --name-only -z` and `ls-files -z` print raw paths with NUL
  terminators.
- `cat-file --batch` prints `<id> <type> <size>`, then the content. It prints
  `<name> missing` for an unknown object.
- `ls-files -s` prints `<mode> <id> <stage>\t<path>`. `ls-tree` prints
  `<mode> <type> <id>\t<path>`.
- `for-each-ref --format` and `rev-parse --short` follow Git.

## Output channels

kit writes human summaries to **stderr**. kit writes data to **stdout**.
A clean `kit status` prints nothing to stdout, so a pipeline stays quiet.
Git writes some of these summaries to stdout.

The summaries have the shape of the Git summaries:

- `push` prints `To <url>`, then one line for each ref. It prints
  `* [new branch]`, `<old>..<new>`, `+ <old>...<new> (forced update)` or
  `! [rejected] ... (non-fast-forward)`, and ` - [deleted]` for
  `push --delete`. It prints `Everything up-to-date` when nothing changes.
- `pull` prints `Updating <a>..<b>`, `Fast-forward` and a diffstat. It prints
  `Already up to date.` when nothing changes.
- `fetch` prints `From <url>` and one line for each ref. It prints nothing
  when nothing changes.
- `clone` prints `Cloning into '<dir>'...`.
- `commit` prints `[<branch> <id>] <subject>`, a diffstat and the file modes.
- `merge` prints `Merge made by the 'ort' strategy.` or
  `CONFLICT (content): Merge conflict in <path>`.
- `switch` and `checkout` print `Switched to branch '<name>'` or
  `Switched to a new branch '<name>'`.
- `reset --hard` prints `HEAD is now at <id> <subject>`.

kit does not print the Git object-count and delta-compression lines. It prints
its own `Writing objects` and `Unpacking objects` lines with real counts.

## Documented divergences

- **Empty commit.** `commit` creates a commit when the index equals `HEAD`.
  Git refuses without `--allow-empty`. kit accepts `--allow-empty` and does not
  need it there. A first commit with nothing staged needs the flag, as in
  Git.
- **`diff` base.** `kit diff` without a revision compares `HEAD` with the
  working tree. The result includes staged changes and untracked files. Git
  compares the index with the working tree. `kit diff --staged` matches Git.
- **Untracked directories.** `status` lists each untracked file. Git lists the
  directory, for example `u/`.
- **Ignore files.** kit reads `.gitignore` and `.kitignore` in each visited
  directory. Deeper files win, with `.kitignore` last at each level.
  Per-directory rules override `.kit/info/exclude`, then the global
  `$XDG_CONFIG_HOME/git/ignore` (default `~/.config/git/ignore`).
  kit does not read Git’s `core.excludesFile` config key.
- **Conflict markers.** kit labels the sides `ours` and `theirs`. Git uses
  `HEAD` and the name of the merged branch.
- **Author and date.** `log` prints the signing identity, for example
  `ed25519:11de6447`, and a UTC date. Git prints `Name <email>` and a local
  date.
- **`log` filters.** `--author` and `--grep` use the Rust `regex` syntax,
  which is close to git's extended syntax but has no back-references.
  `--since` and `--until` accept `@<unix>`, `now`,
  `today`, `yesterday`, `<N> <unit> ago`, `YYYY-MM-DD` and
  `YYYY-MM-DD HH:MM:SS`. Git accepts more forms.
- **`<rev>:<path>`.** `show`, `cat-file` and `rev-parse` resolve
  `<rev>:<path>` against the tree of `<rev>`. The path is relative, with no
  empty, `.` or `..` component, so `HEAD:dir/` and `HEAD:./f` are errors. It
  is at most 4096 bytes. The index form `:<path>` and `:<n>:<path>` is an
  error. `show <rev>:<dir>` prints the `ls-tree` listing, not the Git
  header and the names.
- **Rename detection.** `diff`, `status`, `show`, `log -p`, `log --follow`
  and the three-way merge of `merge`, `cherry-pick`, `revert` and `rebase`
  pair renames by similarity with git's scoring, threshold grammar and
  limit warning.
  Three things differ. Pathspecs filter after detection, so a rename keeps
  its source path when only its destination matches; Git limits the
  candidates first. Ties between equal scores break by path order, where
  Git's order depends on its sort. Copy detection (`-C`), break detection
  (`-B`) and the `diff.renames` and `diff.renameLimit` config keys are not
  supported; `show` and `log` have no rename flags and use the default 50%.
  The merge uses the default 50% and takes no `-X find-renames` or
  `-X no-renames`. It detects no directory renames, where git moves the
  files that the other side added to a renamed directory. When the other
  side also adds a file at the new path, kit does not follow the rename,
  and both files meet at that path as an add/add conflict.
- **`rebase` `edit` and `exec` stops.** At an `edit` stop, `--continue`
  does not commit staged changes into the edited commit, as Git does;
  commit them with `kit commit --amend` first. `--skip` at an `edit` or
  `exec` stop is an error. An `exec` command that leaves files changed
  does not stop the rebase. kit has no `break`, `label`, `reset` or
  `merge` todo lines, and no `--reschedule-failed-exec`.
- **Autosquash.** `rebase --autosquash` and `commit --fixup` and
  `--squash` follow git, with three differences. Only an earlier commit of
  the range that is not itself moved can be a target, where git can also
  match a later commit by id or a moved commit by subject prefix. An id
  prefix needs 4 or more hex digits and names a commit of the range only.
  `commit --fixup=amend:` and `--fixup=reword:`, and `amend!` subjects,
  are not supported.
- **`rebase --update-refs`.** If a stacked branch moved during the rebase,
  kit moves no branch and keeps the rebase in progress, where git updates
  the rebased branch and reports the refs it could not update. kit moves
  only local branches; an `update-ref` line must name `refs/heads/<branch>`
  of an existing branch other than the rebased one.
- **`apply` and `am`.** kit applies a hunk only where its context matches
  exactly, with no fuzz and no whitespace options, and either the whole
  patch applies or nothing changes; there is no `--reject` or `-3`. Binary
  patches, copies and symlinks are refused. `am` keeps no mail date: the
  commit date is the time of the commit, and the applier signs it. It reads
  no `-s`, `-k`, `--3way`, `--interactive` or `--quoted-cr`, and refuses a
  base64 or quoted-printable mail.
- **`archive`.** The formats are `tar` and `tar.gz`; there is no `zip`,
  no `--remote`, no `--add-file` and no `export-ignore` or `export-subst`
  attributes. File modes are 0644 and 0755 where git applies its umask
  (0664 and 0775 by default), and a tree id gives mtime 0 where git uses
  the current time, so the bytes differ from `git archive` while the files
  are the same.
- **Bundles.** kit has no `git bundle` file. `kit closure export --history
  --branch <name>` writes a directory (a `MANIFEST.mkcl` and packs) that
  `clone` and `fetch` read as a `kit+closure://` remote, and `--since <rev>`
  makes it incremental. An export carries one branch and no tags. A fetch
  from a path, with no configured remote, writes
  `refs/remotes/closure/<branch>`, where git writes `FETCH_HEAD`.
- **`log -L`.** kit does not follow a renamed file: the range ends at
  the commit that creates the file under its name. There is no
  `:<funcname>:<file>` or `/<regex>/` form, and no `--author`, `--grep`,
  `--since`, `--until`, `--no-merges` or `--stat` with `-L`. Commits come in
  kit's date order, where git uses topological order, so the order of two
  branches of a merge can differ. When a file repeats lines, several
  smallest diffs exist, and kit's line diff may pick another one than
  git's; kit follows the copy that `kit blame` credits.
- **`range-diff`.** kit pairs the commits with git's costs, but it solves
  the assignment with its own Hungarian method, so two pairings of equal
  cost may come out differently. The `## Metadata ##` section names the
  author as `kit log` prints it. The diff under a `!` line is a plain diff of the two
  patches, without git's dual coloring or its section names in the hunk
  headers. There are no `--left-only`, `--right-only` or diff options, and
  a side over 1,000 commits is an error.
- **`shortlog`.** The author is the name `kit log` prints, so a commit
  made with a signing key groups under its key, not under a name and
  email. There is no `-c`/`--committer`, `--group`, `-w` or `--format`
  other than `json`. On standard input kit reads the default `kit log`
  format only.
- **`describe`.** A name reads `<tag>-<n>-k<id>` where git writes
  `g<id>`, so it never passes for a git name. kit counts `<n>` exactly over
  the whole history and picks the smallest, where git stops its walk after
  ten candidates. With no tag kit exits 1 where git exits 128. There is no
  `--contains`, `--all`, `--first-parent` or `--candidates`.
- **`grep`.** Patterns use Rust's `regex` syntax: there is no `-P` and no
  backreference, and `-G` reads a pattern as `-E` does instead of as a basic
  regular expression. Symlinks are not searched. There are no context,
  color or `--and`/`--or` options, and an invalid pattern or an unknown
  argument exits 64 where git exits 128.
- **`rerere`.** kit writes a conflict as whole-file markers, so an entry
  records one whole file and replays only when both sides match exactly,
  where git records each conflicting hunk and merges a resolution into a
  file whose context changed. `rerere clear` deletes every entry, where
  git drops only the entries of the conflict in progress. `kit gc` does not
  run `rerere gc`. `rerere remaining` and `rerere.enabled` turning on by the
  presence of `rr-cache/` are not supported.
- **Strategy options.** `merge`, `cherry-pick`, `revert`, `rebase` and
  `pull` take `-X ours` and `-X theirs`, and `merge` takes `-s ours`, `-s
  ort` and `-s recursive`. Other strategies and options, such as
  `octopus`, `subtree`, `patience` or `ignore-space-change`, are usage
  errors. kit merges changes to adjacent lines without a conflict, where
  Git reports one; under `-X` Git then keeps only the favored side's
  lines, and kit keeps both changes. A file and a directory at one path,
  or two different modes, still stop the merge under `-X`.
- **`log -p` and `--stat`.** A merge commit shows its diff against its
  first parent, as `show` does. Git `log -p` shows no diff for a merge.
  `-p` and `--stat` together are a usage error. Git prints both, with a
  `---` line between the message and the stat. Neither flag combines
  with `--format=json`. A blank line ends each commit, also the last
  one. The diff text is the text of `diff` and `show`.
- **`log -- <path>`.** kit applies git's default history simplification
  and no other mode: it has no `--full-history`, `--simplify-merges`,
  `--dense` or `--sparse`. A path is a file or a directory; globs and
  pathspec magic are usage errors. `--follow` finds a rename by
  similarity, with the default 50%.
- **`log --all`.** The walk starts at `HEAD`, the local branches, the
  remote-tracking refs and the tags. Git also starts at `refs/stash` and at
  other refs. kit leaves out a ref with unreadable content and a ref that ends
  at an object that is not a commit. A revision or a range together with
  `--all` is a usage error. Git accepts both.
- **`log --decorate`.** The names follow the order `HEAD`, the local
  branches, the tags, then the remote-tracking refs. Git can order them
  differently. The flag does not combine with `--format=json`, so the JSON
  record keeps its fixed keys. kit prints each name with control characters
  escaped.
- **`log --graph`.** kit draws the graph with `*`, `|`, `/` and `\` for
  `--oneline` and the default format. The layout differs from Git. The line
  `|\` of a merge follows the text of the merge commit, where Git widens the
  commit line. An octopus merge opens one column per extra parent, with no
  `*-.` line. A column that ends shifts the columns on its right one line at a
  time. kit draws an edge only to a parent that the output shows, so a
  filter such as `--grep` or `--no-merges`, a limit or a range leaves no open
  line, and it does not join the commits on each side of a hidden one.
  `--first-parent` draws one column. The text lines of a commit that has no
  parent in the output have a blank margin. A history with more than 1024
  open branches is an error. `-p`, `--stat` and `--format=json` do not
  combine with `--graph`.
- **`rev-list`.** `rev-list` takes one revision or range, with `-n` or
  `--max-count`. It does not take several revisions, `^<rev>` or `--not`.
  It does not read the `-<n>` form. A negative count is an error. Git
  reads `--max-count=-1` as no limit. `rev-list HEAD` in a repository
  without a commit is an error, as in Git.
- **`push` refspec.** `push <remote> <src>:<dst>` pushes the local branch
  `<src>` to the remote branch `<dst>`, and `push <remote> <branch>` pushes
  `<branch>` under its own name, the current branch or not. Both sides must be branches, as a
  name or as `refs/heads/<name>`. A refspec push records no upstream unless
  `-u` is set. Git also takes a tag, a wildcard, a leading `+` and an empty
  `<src>`; kit rejects each of them, and deletes through `--delete`.
- **`fetch --prune`.** `fetch --prune` deletes the tracking refs of one
  remote whose branch the remote lost. It deletes a ref only after a complete
  fetch, and only when a fresh read of the remote branch finds nothing. It
  prints ` - [deleted]         (none) -> <remote>/<branch>`. Git also prunes
  tags that a refspec maps; kit prunes no tag.
- **Tags on `push`.** `push --tags` pushes every local tag and nothing else,
  and conflicts with `--all` and a refspec, as in Git. `push <remote> <t>`
  pushes one tag; a name that is both a branch and a tag is an error, and
  `refs/heads/<n>` or `refs/tags/<n>` picks one. A remote tag with another
  value is refused unless `--force` (or `--force-with-lease`), and a forced
  update conditions on the value kit read. Unlike Git, kit refuses an
  unsigned annotated tag and an annotated tag
  whose object names another tag. Each tag is reported on its own line, and
  the push exits 1 if any was refused.
- **`push --delete`.** `push --delete <remote> <name>` deletes one remote
  branch or tag, as Git's does, and takes `refs/heads/<n>` or
  `refs/tags/<n>` for a name the remote holds as both. Unlike Git, a branch
  is deleted only while it holds its tracking ref's value, the lease of a
  push, and a branch with no tracking ref is refused. The tracking ref goes
  with it. Git refuses to delete a ref the remote does not hold; kit does
  so for a tag, but reports a tracked branch the remote no longer holds as
  deleted. The branch's packmap or the tag's tag map goes too
  (SPEC-TRANSPORT §7.3). Git takes several refs and `:<dst>`; kit takes one
  ref, and refuses `--delete` with `--all`, `--tags`, `--force`,
  `--force-with-lease` and `-u`. An S3 remote refuses every delete, since
  kit cannot delete there under a condition.
- **Tags on `fetch`, `pull` and `clone`.** kit takes every remote tag by
  default, as Git's `--tags` does; Git follows only the tags that point into
  the fetched history. `--tags` is accepted and means the same, and
  `--no-tags` skips them. A tag publishes only once kit proves its closure,
  its tag object's name and, with signature checks on, its history. A remote
  tag with another value than the local one is refused with `would clobber
  existing tag`, as in Git, and kit has no `--force` for it. A refused tag
  prints ` ! [rejected]        <t> -> <t> (<reason>)` and the command exits 1
  after the branches and the other tags are published.
- **`branch -r` / `-a`.** `branch -r` lists the `refs/remotes/<remote>/*`
  refs of every remote as `<remote>/<branch>`. `branch -a` lists the local
  branches, then the tracking refs as `remotes/<remote>/<branch>`. The `*`
  marks only a local branch. A pattern filters the displayed names, and
  `--format=json` adds `"remote":true` to a tracking row. `-r` and `-a`
  exclude each other and do not combine with `-d`, `-D` or `-m`. kit prints
  no `<remote>/HEAD -> ...` line.
- **`rebase --onto`.** `rebase --onto <newbase> <upstream> [<branch>]`
  replays the commits of `<branch>` that `<upstream>` does not reach onto
  `<newbase>`. Git takes the configured upstream when `<upstream>` is
  missing. kit has no upstream for `rebase`, so a missing `<upstream>` is a
  usage error. `--onto` does not combine with `--continue`, `--skip` or
  `--abort`. The state that a paused rebase keeps is the same as for a rebase
  without `--onto`, so the three flags work after a conflict. A `<branch>`
  must be a local branch.
- **`pull --rebase`.** `pull --rebase` fetches, then runs the replay of
  `rebase` onto the tip of the fetched branch. A conflict leaves the state of
  `rebase`, and `rebase --continue`, `--skip` and `--abort` finish it. A branch
  that holds the fetched tip prints `Current branch <branch> is up to date.`
  and does not change. kit does not look for a fork point in the reflog, so
  it replays every commit that the fetched tip does not reach. `--rebase`
  does not combine with `--all`, needs a branch `HEAD` with a commit, and
  ignores `pull.rebase`. `--format=json` prints the object of `rebase`.
- **`add -n` / `--dry-run`.** `add -n` prints `add '<path>'` for each file that
  a real add would stage or update, and `remove '<path>'` for each deletion
  that `-A` would record. It sorts the lines by path, quotes a path with
  special bytes as `ls-files` does, writes no index and no object, and keeps
  the errors of a real add. It does not combine with `-p` or `-u`, which is a
  usage error. A file whose bytes equal the staged bytes but whose chunking
  differs shows as `add`.
- **`rev-parse --verify`.** `--verify` takes exactly one revision, or
  `<rev>:<path>`, and prints its full ID. The object must exist in the store.
  Any other input prints nothing on stdout and exits `1`, or `64` when the
  count of revisions is not one. Git exits `128`. `-q` / `--quiet` drops the
  message and keeps the exit code, and it needs `--verify`. `--short` works
  with `--verify`. `--abbrev-ref` and `--show-toplevel` do not.
- **`show-ref <pattern>`.** A pattern keeps a ref when it equals the full ref
  name or equals its trailing path components, so `main` keeps
  `refs/heads/main` and `refs/heads/feature/main`, and drops
  `refs/heads/domain`. Several patterns give the union. `show-ref` exits `1`
  with no output when nothing matches, as Git does and as `rev-parse
  --verify` does. kit rejects an empty pattern as a usage error. kit has no
  `--verify`, `--hash`, `--dereference` or `-q` on `show-ref`.
- **`init <dir>` / `init -q`.** `init <dir>` creates `<dir>`, nested levels
  included, and initialises it. An existing empty directory works. kit refuses
  a `<dir>` that is a symlink, a dangling one included, with or without a
  trailing slash, and a `<dir>` that is a file. Git follows a symlink. kit
  prints its success line on stderr. `-q` drops that line and never an error.
  `init` in an existing repository stays an error, and `-q` does not change
  that. kit has no `--bare`, `--initial-branch` or `--template`.
- **`checkout -- <path>`.** `checkout [-f] -- <path>...` runs `restore
  [-f] <path>...`, with the same output, exit codes and refusals. It restores
  from the index. Git discards an edited file without `-f`, and kit refuses it
  as `restore` does. `checkout [-f] <rev> -- <path>...` runs `restore [-f]
  --source <rev> --staged --worktree <path>...`, with the same refusal.
  Anything else before the `--` is a usage error.
- **`revert -m`.** `revert -m <parent-number> <merge>` undoes a merge
  relative to the chosen parent, counted from 1, as `cherry-pick -m` picks
  one. A merge without `-m`, a number out of range and `-m` on a commit that
  is not a merge are errors. `-m` does not combine with `--continue` or
  `--abort`.
- **`branch -u` / `--unset-upstream`.** `branch -u <remote>/<branch>
  [<branch>]` (also `--set-upstream-to=<upstream>`) sets the upstream of a
  branch, or of the current branch. It writes the `branch.<name>.remote` and
  `branch.<name>.merge` keys of `.kit/config` that `push -u` writes. The
  remote-tracking ref must exist, and kit tries each split of the name at a
  `/` from the left. `--unset-upstream` removes those keys from `.kit/config`
  only. A user-scoped value stays. Git also accepts a local branch as an
  upstream. kit does not.
- **`pull --no-ff`.** `pull --no-ff` fetches, then merges the tip of the
  fetched branch as `merge` does, and writes a merge commit even when a
  fast-forward is possible. The message is `Merge remote-tracking branch
  '<remote>/<branch>'`. A branch that holds the fetched tip prints `Already up
  to date.` and gets no commit. A conflict leaves the state of `merge`, and
  `merge --continue` and `--abort` finish it. `--no-ff` does not combine with
  `--all` or `--rebase`, needs a branch `HEAD` with a commit, and ignores
  `pull.ff`. `--format=json` prints the object of `merge`.
- **`tag` listing.** `kit tag` prints the tag name, the short ID and the tag
  kind. Git prints the names.
- **`stash`.** Each linked worktree has its own stash. Git shares one stash.
  `stash` also saves and removes untracked files. Git leaves them in place
  unless you pass `-u`.
- **`bisect`.** `bisect` prints the next candidate and does not check it out.
  `HEAD` stays on your branch. Git checks out each candidate and leaves
  `HEAD` detached.
- **`reflog`.** `reflog` lists the first-parent chain of a branch. It does not
  record operations, and it omits commits that `commit --amend` or `reset`
  replaced. `reflog --recovery` lists those replaced commits, and
  `recovery@{N}` names them, where Git uses `HEAD@{N}` from the reflog of
  `HEAD`. The recovery log records only the commits that a rewrite replaced,
  not every move of `HEAD`.
- **`blame` output.** The default line is `<short id>\t<line>\t<text>`.
  `--porcelain` follows the Git header fields. The author fields hold the kit
  identity, and kit prints no `previous` line.
- **`blame --ignore-rev-precise`.** This option is only in kit. It follows a
  line by content instead of by position.
- **Sparse checkout.** `sparse-checkout set` keeps files that are already in
  the working tree. `sparse-checkout reapply` does not create a file that a
  pattern excludes, and `status` lists that file as deleted.
- **`gc`.** `gc` prunes unreachable objects and has `-n`. Git `gc` has no
  `-n`.
- **`config`.** kit accepts a fixed set of keys. `user.name`, `user.email` and
  `core.*` are unknown keys. An unknown key is an error.
- **Aliases.** `alias.<name>` lives in the user config only; a repository
  config or a `-c` override that sets one is ignored with a warning. An alias
  expands to kit arguments. The `!<shell command>` form is refused, an alias
  that names another alias is an error, and a built-in command name always
  wins over an alias.

## Deferred flags

kit does not implement these flags. A command with a missing flag is
`divergent` on the matrix.

- `stash push` pathspec glob and magic syntax &mdash; kit accepts file and
  directory prefixes only. `-u` / `--include-untracked` is supported.
