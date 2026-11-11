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
  `https://` and plain paths are errors.

## Non-goals

- Submodules and subtrees.
- Hooks, including `core.hooksPath`.
- The full refspec grammar. `push` takes `<src>:<dst>` for branches and
  nothing else: no wildcard, no leading `+` and no ref outside `refs/heads/`.
  `push` does not take `--tags` or `--delete`. A remote delete and a tag
  transfer need a transport verb that kit does not have.
- Git wire protocol v2 and smart-HTTP negotiation.
- `git notes`.
- Shallow clone. `clone --depth` is a usage error. A clone holds the full
  history, so every commit verifies with its ancestors.
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
  be edited. A correction is a new attestation. Attestations are local today.
  `kit push`, `kit pull` and `kit fetch` move only the object graph, so a
  teammate does not receive them. The spec plans transport for them.
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
  for a tracked change. It prints `2 ... R100` for an exact rename and
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
  `! [rejected] ... (non-fast-forward)`. It prints `Everything up-to-date`
  when nothing changes.
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
  Git refuses. kit has no `--allow-empty`.
- **`diff` base.** `kit diff` without a revision compares `HEAD` with the
  working tree. The result includes staged changes and untracked files. Git
  compares the index with the working tree. `kit diff --staged` matches Git.
- **Untracked directories.** `status` lists each untracked file. Git lists the
  directory, for example `u/`.
- **Ignore files.** kit reads `.gitignore` and `.kitignore` at the repository
  root. kit does not read ignore files in subdirectories.
- **Conflict markers.** kit labels the sides `ours` and `theirs`. Git uses
  `HEAD` and the name of the merged branch.
- **Author and date.** `log` prints the signing identity, for example
  `ed25519:11de6447`, and a UTC date. Git prints `Name <email>` and a local
  date.
- **`log` filters.** `--author` and `--grep` match a substring. Git matches a
  regular expression. `--since` and `--until` accept `@<unix>`, `now`,
  `today`, `yesterday`, `<N> <unit> ago`, `YYYY-MM-DD` and
  `YYYY-MM-DD HH:MM:SS`. Git accepts more forms.
- **`<rev>:<path>`.** `show`, `cat-file` and `rev-parse` resolve
  `<rev>:<path>` against the tree of `<rev>`. The path is relative, with no
  empty, `.` or `..` component, so `HEAD:dir/` and `HEAD:./f` are errors. It
  is at most 4096 bytes. The index form `:<path>` and `:<n>:<path>` is an
  error. `show <rev>:<dir>` prints the `ls-tree` listing, not the Git
  header and the names.
- **`log -p` and `--stat`.** A merge commit shows its diff against its
  first parent, as `show` does. Git `log -p` shows no diff for a merge.
  `-p` and `--stat` together are a usage error. Git prints both, with a
  `---` line between the message and the stat. Neither flag combines
  with `--format=json`. A blank line ends each commit, also the last
  one. The diff text is the text of `diff` and `show`.
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
  `<src>` to the remote branch `<dst>`. Both sides must be branches, as a
  name or as `refs/heads/<name>`. A refspec push records no upstream unless
  `-u` is set. Git also takes a tag, a wildcard, a leading `+` and an empty
  `<src>`; kit rejects each of them.
- **`fetch --prune`.** `fetch --prune` deletes the tracking refs of one
  remote whose branch the remote lost. It deletes a ref only after a complete
  fetch, and only when a fresh read of the remote branch finds nothing. It
  prints ` - [deleted]         (none) -> <remote>/<branch>`. Git also prunes
  tags that a refspec maps; kit has no tag transfer and prunes no tag.
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
  replaced.
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

## Deferred flags

kit does not implement these flags. A command with a missing flag is
`divergent` on the matrix.

- `branch -u` / `--unset-upstream` &mdash; kit has no upstream setting
  on `branch`. `push -u` sets one.
- `fetch --tags` &mdash; kit rejects the flag. A fetch does not transfer
  tags.
- `pull --no-ff` &mdash; kit rejects the flag. `pull` never creates a merge
  commit.
- `rebase -i` `edit` &mdash; the todo action is not available.
- `revert -m` &mdash; kit does not revert a merge commit.
- `stash push -u` / `--include-untracked` and `stash push <pathspec>` &mdash;
  kit rejects each form. `stash` always saves the whole working tree.
- `checkout -- <path>` &mdash; `checkout` takes a branch or a revision. Use
  `restore` for files.
- `init <dir>` / `init -q` &mdash; `init` takes no argument, and it is an error
  in an existing repository.
- `worktree move` / `lock` / `repair` &mdash; kit has no such subcommand.
