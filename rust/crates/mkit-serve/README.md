# mkit-serve

The self-host server for mkit. It speaks the `mkit.rpc.v1.ssh` frame
protocol (SPEC-TRANSPORT §4.2) over a repository on disk. The `mkit serve`
command is a thin wrapper around this crate.

The server has no async runtime, no network listener and no database. A
session reads frames from a `FrameSource`, writes frames to a `FrameSink`
and keeps its state in the files that `mkit-transport-file` and local `mkit`
commands already use:

```text
<root>/
  packs/<64-hex>      pack bytes, published only after the hash verifies
  refs/...            one file per ref
  .mkit/refs/.lock    the lock that every ref write takes
```

## Authority

Authentication belongs to the transport. The caller of `serve_session` passes
the key that sshd asserted for the connection, or `None`. A `Repo` has a
`WritePolicy`:

- `Open`: every session may write.
- `OwnedBy(key)`: only a session with that key may write.
- `ReadOnly`: no session may write.

Reads are always allowed. A refused write gets the fixed reply
`write not permitted`, after the server reads the rest of an upload stream.

## Limits

A session ends after 10,000 top-level frames or 1 GiB of estimated request
bytes. An upload has at most 10,000 chunks and 1 GiB. Every frame is at most
1 MiB. Pack memory use is one chunk, never the whole pack.
