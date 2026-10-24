# kit-storage

The `kit` command-line tool: a content-addressed VCS with native attestation
support. The published binary is `kit`.

Published to crates.io so `cargo install kit-storage` works; it also ships as a
signed binary via GitHub Release archives (see `docs/INSTALL.md`). The crate
is exposed as a library (`kit_storage::…`) purely so integration tests can drive
commands in-process without shelling out &mdash; that surface is **not** a stable
API, is excluded from `cargo-semver-checks`, and should not be depended on.
Depend on the `kit-core` / `kit-attest` / `kit-transport-*` crates
instead.

## Features

`git-bridge` is on by default. The others are off by default to keep the
baseline build lean:

| Feature | Adds |
|---|---|
| `s3` | `kit+s3://` remotes on S3-compatible storage (`kit-transport-s3`). |
| `git-bridge` (default) | `kit git …` (SPEC-GIT-BRIDGE/SPEC-GIT-IMPORT). |
| `sparse-checkout` | Verifiable sparse-checkout. |
| `pack-shards` | `kit pack-shard <hash>` and shard-aware HTTP/S3 downloads. |
| `history-mmr` | Append-only Merkle Mountain Belt ref-write journal. |
| `bls-threshold` | BLS12-381 threshold-signing exhaustiveness (compile-time only today). |

See the top-level README and `docs/CLI.md` for the full command reference
and agent-integration notes (`kit mcp`).

`kit serve <path>` is only the `kit+ssh://` forced-command server. It has
no network listener, which keeps the HTTP server stack and `SQLite` out of
this crate.
