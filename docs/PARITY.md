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
- The full refspec grammar. `push` takes a remote and no refspec. `push`
  does not take `--tags` or `--delete`.
- Git wire protocol v2 and smart-HTTP negotiation.
- `git notes`.
- Shallow clone. `clone --depth` is a usage error.
- `.git` on-disk interop and SHA-1 objects.
- Shadowing the `git` binary on `PATH`.

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

kit does not print the Git object-count and delta-compression lines. kit
transfers one object per pack and has no cross-branch delta graph. Those
numbers would be invented.

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
- **`tag` listing.** `kit tag` prints the tag name, the short ID and the tag
  kind. Git prints the names.
- **`stash`.** Each linked worktree has its own stash. Git shares one stash.
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

- `log -p` / `--stat` / `--decorate` / `--all` / `--graph` &mdash; kit rejects
  each flag as an unknown argument.
- `branch -r` / `-a` / `-u` / `--unset-upstream` &mdash; no remote-tracking
  listing and no upstream setting.
- `add -n` / `--dry-run` &mdash; kit rejects the flag.
- `rev-parse --verify` &mdash; kit rejects the flag.
- `rev-list --max-count` &mdash; kit rejects the flag. `rev-list` takes one
  revision and no range.
- `show-ref <pattern>` &mdash; kit rejects the pattern.
- `fetch --prune` / `--tags` &mdash; kit rejects each flag.
- `pull --rebase` / `--no-ff` &mdash; kit rejects each flag.
- `rebase --onto` &mdash; kit rejects the flag. The `edit` todo action is not
  available either.
- `revert -m` &mdash; kit does not revert a merge commit.
- `stash push` / `--include-untracked` &mdash; kit rejects each form.
- `checkout -- <path>` &mdash; `checkout` takes a branch or a revision. Use
  `restore` for files.
- `init <dir>` / `init -q` &mdash; `init` takes no argument, and it is an error
  in an existing repository.
- `<rev>:<path>` &mdash; kit does not resolve this form in `show`, `cat-file`
  or `rev-parse`.
- `worktree move` / `lock` / `repair` &mdash; kit has no such subcommand.
