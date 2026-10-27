# libkit

The kit library. One crate re-exports the kit crates that a program embeds.

kit is a content-addressed, signed version-control system. The `kit` command
line is built from these crates. This crate adds the repository handle and
the environment that the other crates do not have.

## Repository and environment

`libkit::Environment` holds every input that the library would otherwise read
from the process: the working directory, the home directory, configuration
overrides, the author identity and the credential sources. The library never
reads environment variables, never changes the working directory and keeps no
global state.

`libkit::Repo` is a cheap, `Clone`, `Send + Sync` handle to one repository.
`Repo::open` opens the repository at a path. `Repo::discover` searches the
path and its parents. Both refuse a path with a `..` component.

## Revisions, locks and HEAD

`libkit::revspec::resolve_revision` turns a revision string into one object
hash. It accepts a full or short hash, a branch, a tag, a remote-tracking ref
and `HEAD`, each with `~n` and `^n` steps. `peel_tags` and `tree_of` follow
tag objects and find the tree of a commit.

`libkit::lock` takes the worktree lock and the registry lock. The caller
decides the scope: it holds the returned guard for as long as other writers
must wait, then drops the guard. A `lock::Event` tells the caller when a live
server holds the repository.

`libkit::head::advance` moves the current branch, or a detached HEAD, to a
new commit. A `RefWriteCondition` refuses a write that would discard a
concurrent advance. `libkit::worktrees` lists the trees of a repository and
finds the tree that has a branch checked out.

## History, diffs and blame

`libkit::log::history` walks the commits that a revision selection reaches.
The selection can be a revision, `A..B` or `A...B`. A `Query` limits the walk
and filters it by author, message, path and date. `libkit::log::date::parse`
reads the date forms of `kit log`.

`libkit::diff::compute` returns the changed entries between two trees. The
trees come from revisions, the index or the worktree. A `Diff` gives the body
of each patch and the change counts of each file.

`libkit::blame::blame` finds the commit that last changed each line of a
file. It also walks forward over a `<start>..<end>` range. A `Request` can
keep a range of lines, skip commits, and detect moved or copied lines.

`libkit::identity` writes an identity in its short and full text forms.

## Errors

`libkit::Error` is a `#[non_exhaustive]` enum. Each variant wraps the error
enum of one module, such as `libkit::repo::Error`. Every error enum is
`#[non_exhaustive]` and is `Error + Send + Sync + 'static`. The `kit` command
line maps these errors to the exit codes in `docs/CLI.md`.

## Modules

| Module | Source crate | Feature |
|---|---|---|
| `libkit::core` | `kit-core` | always |
| `libkit::attest` | `kit-attest` | always |
| `libkit::keystore` | `kit-keystore` | always |
| `libkit::sync` | `kit-sync` | `sync` (default) |
| `libkit::git_bridge` | `kit-git-bridge` | `git-bridge` |
| `libkit::transport::file` | `kit-transport-file` | `transport-file` |
| `libkit::transport::ssh` | `kit-transport-ssh` | `transport-ssh` |
| `libkit::transport::s3` | `kit-transport-s3` | `transport-s3` |
| `libkit::transport::connect` | `kit-transport-connect` | `transport-connect` |

Two features change what a module contains. They add no module.

| Feature | Effect |
|---|---|
| `history-mmr` | Turns on `kit-core` history snapshots. Also turns on snapshot publishing in `kit-sync` when `sync` is on. |
| `sparse-checkout` | Turns on `kit-core` sparse checkout. Also turns it on in `kit-transport-s3` when `transport-s3` is on. |

Features are additive. Turning one on never removes an item.

## Not re-exported

The `kit-bin`, `kit-serve` and `kit-rpc` crates are not re-exported. `kit-bin`
is the command line. `kit-serve` is the self-hosted server. `kit-rpc` is a
wire-framing detail of the signer and server protocols.

## Versions

All kit crates share one version. Use the same version of `libkit` and of any
`kit-*` crate that you name directly.

## License

MIT OR Apache-2.0.
