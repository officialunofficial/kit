# kit-transport-ssh

SSH transport for kit using a forced-command server pattern over a system
`ssh(1)` child process.

Implements the `Transport` trait (`docs/specs/SPEC-TRANSPORT.md`) over a long-lived
system `ssh(1)` child process, exchanging the seven kit verbs as
length-prefixed protobuf `SshFrame` messages defined in
`kit-rpc/proto/kit/rpc/v1/ssh/ssh.proto`.

## Design choice: `std::process::Command`, not `russh`

kit does not implement its own SSH client. It shells out to `ssh(1)` and
delegates host-key verification, agent handling, credential selection, and
key exchange to the user's installed `OpenSSH` &mdash; the same posture `git+ssh://`
takes:

- No crypto stack to ship (no `russh`, `rustls`, `openssl`, `native-tls`).
- `ssh-agent`, `~/.ssh/config`, `ProxyCommand`, and every other knob the user
  already configured just work, with zero kit code.
- Host-key rotation/trust escalation stays on the `OpenSSH` side.

The `Transport` trait itself is synchronous (object-safe, `&self`), so
wrapping `Command::spawn` and blocking stdio is the shortest path to parity
with the other transports.
