# mkit-cli

The `mkit` command-line tool: a content-addressed VCS with native attestation
support. The published binary is `mkit`.

Published to crates.io so `cargo install mkit-cli` works; it also ships as a
signed binary via GitHub Release archives (see `docs/INSTALL.md`). The crate
is exposed as a library (`mkit_cli::…`) purely so integration tests can drive
commands in-process without shelling out &mdash; that surface is **not** a stable
API, is excluded from `cargo-semver-checks`, and should not be depended on.
Depend on the `mkit-core` / `mkit-attest` / `mkit-transport-*` crates
instead.

## Features

`git-bridge` is on by default. The others are off by default to keep the
baseline build lean:

| Feature | Adds |
|---|---|
| `s3` | `mkit+s3://` remotes on S3-compatible storage (`mkit-transport-s3`). |
| `git-bridge` (default) | `mkit git …` (SPEC-GIT-BRIDGE/SPEC-GIT-IMPORT). |
| `sparse-checkout` | Verifiable sparse-checkout (issue #158). |
| `pack-shards` | `mkit pack-shard <hash>` and shard-aware HTTP/S3 downloads (issue #159). |
| `history-mmr` | Append-only Merkle Mountain Belt ref-write journal (issue #157). |
| `bls-threshold` | BLS12-381 threshold-signing exhaustiveness (compile-time only today). |

See the top-level README and `docs/CLI.md` for the full command reference
and agent-integration notes (`mkit mcp`).

