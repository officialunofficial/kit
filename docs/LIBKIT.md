# libkit

`libkit` is the kit library for programs that embed kit. One crate
re-exports the kit crates that an embedder needs. The `kit` command line is
built from the same crates.

This guide gives the shape of the crate. The module reference is in
[`rust/crates/libkit/README.md`](../rust/crates/libkit/README.md). The crate
layout is in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## What libkit adds

The crate adds two types that the other crates do not have.

- `libkit::Environment` holds every input that the library would otherwise
  read from the process. These are the working directory, the home directory,
  the configuration overrides, the author identity and the credential
  sources.
- `libkit::Repo` is a cheap handle to one repository. `Repo::open` opens the
  repository at a path. `Repo::discover` searches the path and its parents.
  Both refuse a path with a `..` component.

The library never reads environment variables, never changes the working
directory and keeps no global state. It prints nothing. An embedder that
wants progress passes an `Observer`.

## What libkit re-exports

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

The features `history-mmr` and `sparse-checkout` add no module. They forward
to `kit-core`. They also turn on the matching code in `kit-sync` and
`kit-transport-s3` when those crates are on.

Features are additive. Turning one on never removes an item.

## What libkit leaves out

`libkit` does not re-export these crates.

| Crate | Reason |
|---|---|
| `kit-bin` | It is the command line. It owns argument parsing, printing, `kit mcp`, `kit serve` and `kit self`. |
| `kit-serve` | It is the self-hosted server. An embedder that wants a server depends on `kit-serve` directly. |
| `kit-rpc` | It holds the wire framing of the signer and server protocols. It is an implementation detail. |

The crates `kit-client`, `kit-transport-memory` and the test crates are also
not re-exported. [`ARCHITECTURE.md`](ARCHITECTURE.md) explains why each item
stays in `kit-bin`.

## Add the crate

```toml
[dependencies]
libkit = "0.7.1"
```

Turn on a transport with its feature.

```toml
[dependencies]
libkit = { version = "0.7.1", features = ["transport-ssh"] }
```

All kit crates share one version. Use the same version of `libkit` and of
any `kit-*` crate that you name directly.

## Example

The example in
[`rust/crates/libkit/examples/open_repo.rs`](../rust/crates/libkit/examples/open_repo.rs)
opens the repository that contains a directory. It then hashes a message with
`libkit::core::hash`. `cargo test -p libkit` builds it. Run it with this
command.

```sh
cd rust
cargo run -p libkit --example open_repo -- <directory>
```

The crate documentation also holds a doctest. It hashes a message and names a
signing algorithm.

## Errors

`libkit::Error` is a `#[non_exhaustive]` enum. Each variant wraps the error
enum of one module. Match on it with a wildcard arm.

## Where to go next

- [`rust/crates/libkit/README.md`](../rust/crates/libkit/README.md) lists
  every module.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) shows how the crates fit together.
- [`CLI.md`](CLI.md) gives the exit codes that the command line maps from
  these errors.
