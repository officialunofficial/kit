# libkit

The kit library. One crate re-exports the kit crates that a program embeds.

kit is a content-addressed, signed version-control system. The `kit` command
line is built from these crates. This crate adds no behavior of its own.

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
