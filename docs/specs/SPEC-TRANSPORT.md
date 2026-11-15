---
spec: SPEC-TRANSPORT
version: 1
status: stable-normative
audience: implementers of compatible transport clients and servers
---

# SPEC-TRANSPORT &mdash; kit v1 transport protocols

kit talks to remote stores through a small set of pluggable
transports (memory, file, Connect, S3, SSH). All implement the same
[`Transport`](../../rust/crates/kit-core/src/protocol.rs) trait &mdash;
a small set of verbs over a synchronous, object-safe interface &mdash; but the
wire shape and authentication model differ per scheme.

There is no negotiation between transports and no scheme fallback.
The URL scheme is part of the remote address; if the scheme is
unsupported, the dispatcher returns an error rather than guessing
([`libkit::transfer::open`](../../rust/crates/libkit/src/transfer/open.rs)
performs the scheme switch).

The SSH wire format is defined in
[`SPEC-RPC`](SPEC-RPC.md) and lives in the generated
[`ssh.proto`](../../rust/crates/kit-rpc/proto/kit/rpc/v1/ssh/ssh.proto) bindings.
This document covers the cross-transport contract: verbs, URL
parsing, authentication, the forced-command server pattern, size
caps, retry policy, and the error taxonomy.

---

## 1. Verbs

Every transport implements the verbs exposed by the
[`Transport`](../../rust/crates/kit-core/src/protocol.rs) trait. Method
signatures are synchronous and take `&self`; transports that need
interior mutability (connection pools, child-process stdio) use an
internal `Mutex` so the trait object remains object-safe.

| Verb | Purpose |
|---|---|
| `upload_pack(pack, key, head_ref)` | Store a packfile keyed by its 32-byte BLAKE3 digest (`PackKey`). `pack` is a `PackBody` (§1.1). `head_ref` names the branch the pack is for, a hint for a transport that authorizes uploads by ref. |
| `download_pack(key, ref_hint, sink)` | Fetch a packfile by digest into a `PackSink` (§1.1). `ref_hint` names the ref the caller reads it for. |
| `pack_exists(key, ref_hint)` | HEAD-check a pack by digest. |
| `upload_blob(bytes, key, head_ref)` | Store an auxiliary content-addressed blob &mdash; transfer metadata that is NOT a packfile (for example a packlist chain node). Shares the digest-keyed store with packs; a default trait impl delegates to `upload_pack`, so the verb only marks the *kind* explicit at the call site. |
| `download_blob(key, ref_hint, max)` | Fetch an auxiliary blob of at most `max` bytes. The default runs `download_pack` into an in-memory sink of limit `max`, so a blob whose length the transport knows first is refused before any byte of it is read. |
| `update_ref(name, condition, hash)` | CAS ref write. |
| `advance_refs(head, head_condition, head_value, packmap, packmap_condition, packmap_value)` | Move a branch head and its packmap together (§7.2). The default writes the packmap, then the head, each under its own condition. |
| `read_ref(name)` | Read a ref's current hash, or `None` if absent. |
| `list_refs(prefix)` | List refs whose full name starts with `prefix`. Returned names have `prefix` stripped per SPEC-REFS §4. |
| `write_ref(name, hash)` | Convenience: `update_ref(name, RefWriteCondition::Any, hash)`. A default trait impl delegates here, so transports only need to implement `update_ref`. |
| `repo_cursor()` | The repository cursor (§1.2), or none when the transport does not offer one. The default offers none. |

Consumers MUST verify that downloaded pack and auxiliary-blob bytes hash to
the caller's requested PackKey before parsing them into authoritative state,
writing objects, or recording a pack as applied. BLAKE3 covers the entire
returned byte sequence, including a pack's trailer. A transport's internal
checks, a valid pack trailer, or a content-addressed lookup URL do not replace
this consumer-boundary check. Mismatch is `InvalidResponse` and is not retryable.

### 1.1 Pack bodies and sinks

`upload_pack` reads a pack from a `PackBody` and `download_pack` writes one
to a `PackSink`, so neither verb needs the whole pack in memory. A push
seals each pack into an unnamed spool file in `.kit/tmp/` and hands that
file to the transport as the body. A fetch hands the transport a sink that
spools the pack into an unnamed file in `.kit/tmp/` and checks its length,
key and trailer as it arrives (Pack-chain fetch, below).

A `PackBody` has a length, and its bytes can be read from any offset as
often as the transport needs: once per attempt, per part, per hash pass.
Every read sees the same bytes, so every attempt sends the same pack.

A `PackSink` takes one body:

- `begin(declared)` starts a body, or starts it again after a failed
  attempt; bytes taken earlier are discarded. A declared length over the
  sink's limit is refused with `PayloadTooLarge` before any byte. A
  transport that writes the body to the sink as it arrives and learns the
  length first (a file's size, the SSH `DownloadPackHeader.total_bytes`, an
  HTTP `Content-Length`) MUST pass it to `begin` before it reads the body.
- `write(bytes)` appends. A byte past the declared length or the limit is
  refused with `PayloadTooLarge`.
- `failed()` names the local I/O error that ended the sink, a full disk say.
  It stays set: after it, `begin` and `write` return `ProtocolError`, which
  no transport retries. A caller checks `failed()` before it retries, falls
  back to another location or maps an error, and reports the local error,
  not a transport failure.

The memory and file transports copy bodies in chunks of `SPOOL_BUFFER`
(1 MiB). SSH sends a body as `PackChunk` frames read from it one at a time
(§4.2), and S3 streams it in one sized `PUT` (§6.7); both read it again
from offset 0 on every attempt. On download, SSH passes the header's
`total_bytes` to `begin` and writes each `PackChunk` frame to the sink as
it arrives; S3 passes a `200` answer's `Content-Length` to `begin` and
writes its body to the sink as it arrives (§6.7). Connect reads the body as
it builds each chunk or part, and passes `total_bytes` to `begin` and each
`PackChunk`, or a pack location's bytes, to the sink as they arrive,
holding one frame of at most 4 MiB (SPEC-TRANSPORT-CONNECT §6).

Spool files have no name on Unix (`O_TMPFILE`, or unlinked on creation); on
Windows they are `.tmp` files deleted on close. Only the handle that wrote
one reaches it, and a crash on Unix leaves nothing on disk. Fetch, push and
gc remove every spool file (named `.tmp` and a random suffix) in `.kit/tmp/`
when they start, which clears what a power loss leaves on Windows. A spool that
another process holds open is left alone.

`update_ref`'s condition is one of:

- `Any` &mdash; clobber the ref unconditionally.
- `Missing` &mdash; write only if the ref is absent.
- `Match(expected)` &mdash; write only if the ref currently contains `expected`.

CAS failure (`Missing` on an existing ref, or `Match` on a mismatched
hash) returns `TransportError::RefConflict`. Because the §7 retry ladder
can re-issue a write whose first attempt landed, a caller MUST follow
up a `RefConflict` with `read_ref` before treating it as a true conflict
(§7).

---

### 1.2 Repository cursor (additive, opt-in)

**Protocol requirement.** A transport that offers a repository cursor
returns an opaque byte string of 1 to 64 bytes that names the state of the
repository's refs. A client compares two cursors for equality and for nothing
else: a cursor carries no order.

- Every write that changes a ref MUST change the cursor before the write
  reports success. A cursor read after a write reported success therefore
  differs from every cursor read before that write began.
- Equal cursors mean no ref changed between the two reads, apart from writes
  still in progress at the later read. A client that reads the cursor, then
  lists the refs, may reuse that listing while a fresh cursor equals the one it
  read first. The listing misses no write that completed before the fresh
  cursor was read.
- A repository that is deleted and created again MUST NOT return a cursor
  that the old repository returned.
- Reading the cursor MUST NOT read the refs one by one. It may list where
  they are kept, as the file transport lists its ref directories.

A cursor never replaces `read_ref` for a compare-and-swap. A client that
needs one ref's current value reads it.

A transport that cannot vouch for its cursor at the moment of a read offers
none for that read. A client then does its full work, which is always
correct.

**Reference-client behavior.** A fetch reads the cursor before it lists the
refs and records it after a complete fetch. A later fetch returns without
another request when the cursor, the remote-tracking refs, the signature
policy, the tag setting and the local tags are as that fetch recorded them,
and the object of every tracked tip and every local tag is in the local store.
A fetch that refused a tag or could not list the tags (§1.4) records nothing. It checks the tips and not the closure below them. An
object below a tip that the local store lost stays missing through such a
fetch. The next fetch that does its full work, because the cursor changed or
no record matches it, checks the closure and fetches the chain again.

**Reference-server behavior.** The memory transport's cursor is a number
unique to the instance and the count of its committed ref writes. The file
transport's is described in SPEC-REFS §5.1.2. The SSH transport offers the
cursor of the transport that `kit serve` serves (§4.2.2), so it offers one
exactly when the file transport does and a server that knows the request
answers. The S3 transport's is a digest of its ref listing (§6.8). The Connect
transport offers none: its wire carries no cursor yet.

### 1.3 Pruning remote-tracking refs

A fetch that prunes deletes the remote-tracking refs of a remote whose branch
the remote no longer has. It deletes nothing else: no local branch, no tag and
no ref of another remote.

- It prunes only after every branch of the listing was fetched and verified.
  A fetch that fails prunes nothing.
- A pruning fetch lists the remote even when the repository cursor (§1.2) is
  unchanged, because a tracking ref can outlive its branch from an earlier
  fetch that did not prune.
- A listing can be stale (SPEC-TRANSPORT-CONNECT §7.9). A tracking ref whose
  branch the listing lacks is deleted only when `read_ref` of
  `refs/heads/<name>` answers absent. A branch that the read finds is kept. A
  failed read fails the fetch and prunes no further ref.
- The deletes run under the worktree lock. A tracking ref that is gone already
  counts as pruned.

Pruning is local. It uses `list_refs` and `read_ref` and sends no write, so no
transport verb or wire format changes.

### 1.4 Fetching tags

A fetch takes every remote tag after it has published the branches, unless the
caller turns tags off (`--no-tags`). A tag is published to `refs/tags/<t>`
only whole and proved. A tag that fails is refused alone: it never fails a
branch or another tag.

- **Transfer chain.** The objects of remote tag `refs/tags/<t>` travel in the
  pack list chain that `refs/kit/tagmap/<t>` names (SPEC-REFS §2), shaped like
  a packmap chain. Its first node may graft on a node of a branch chain.
- **Listing.** The fetch lists `refs/tags/` once. It lists
  `refs/kit/tagmap/` once, and only when some tag cannot be proved from local
  objects. A tag that this listing lacks is read again with `read_ref` of both
  refs. A tag that is gone is skipped, and a tag with no tag map is refused.
- **Names.** A remote tag whose name cannot be pushed (SPEC-REFS §3) is
  skipped with a warning and no read. It is not a refusal.
- **Local tags.** A local tag with the same value is up to date. A local tag
  with another value is refused ("would clobber existing tag"): no fetch moves
  a tag. A remote tag whose name is a directory of a local tag's name, or the
  reverse, as `v1` and `v1/rc` are, is refused too ("conflicts with existing
  tag"). Of two such remote tags, the later in listing order is refused when
  the earlier one proved. A file system that folds case can report the clash
  only when the tag is read or written, as for `V1/rc` beside `v1`, and that
  tag is refused the same way. No fetch deletes a tag, with or without
  `--prune`.
- **Proof.** A tag is proved when all of these hold:
  - its peel reaches a commit, remix, tree or blob through at most 16 tags;
  - the name of its outermost tag object equals `<t>`;
  - with signature checking on, every commit, remix and tag object in its
    history passes its signature check, down to history already verified;
  - every object of its closure is in the local store.

  History already verified means the tips recorded as verified, as for a
  branch, plus every history walk of this fetch. Tags and branches share the
  record and the walk. A tip that a local ref reaches counts as present for the
  closure check. It counts as verified only when a signed fetch recorded it. A
  proof that would visit more than 10,000,000 objects refuses only that tag.
  A failed proof proves nothing, and a later tag over the same failed object is
  refused without another walk. A proof that finds an object missing records
  the walk path to it, so a later tag over the same incomplete history stops
  there without another walk, until a pack brings the object.
- **Download.** A tag that is not proved from local objects downloads its tag
  map chain. The walk stops at a node that this fetch already applied for a
  branch or a tag, or at a checkpoint head. So a grafted tag downloads only its
  own nodes and packs. This stop set holds at most 100,000 nodes. The packs
  apply as for a branch (Pack-chain fetch), and the tag is proved again.
- **Retry and self-heal.** When the proof finds an object missing, the fetch
  reads both refs again with `read_ref` and tries once more. If a run skipped a
  pack that the applied-pack record lists, or stopped at a node of the stop
  set, the fetch clears the record and applies the whole chain again. The tag
  phase of one fetch does this at most once, whatever the number of tags. A
  pack that this fetch refused for one tag refuses every later tag whose chain
  holds it, with no second download.
- **Failure scope.** A refusal names the tag and its reason. The fetch reports
  it and goes on. A failed tag listing stops the tag phase with "tag listing
  failed (possibly too many tags): `<error>`", and the branches stay
  published. An interrupt, a transport failure other than a bad reply to a
  node or pack download, or a local I/O error, including one while a tag's
  pack is written, fails the fetch, as for a branch. The tags proved before
  such a failure still publish, unless the fetch was interrupted.
- **Publish.** The tags publish under the worktree lock, each with a create
  that fails when the tag exists. A tag that appears locally during the fetch
  with the same value is up to date, and one with another value is refused
  as one that would clobber.

The CLI prints `! [rejected] <t> -> <t> (<reason>)` for each refused tag. It
exits 1 after everything else is published. `clone` and `pull` do the same.
A refused tag is tried and reported again by the next fetch.

## 2. Error taxonomy

Implementations MAY wrap transport-specific errors internally but
MUST surface one of the following variants at the trait boundary
([`TransportError`](../../rust/crates/kit-core/src/protocol.rs)):

```rust
TransportError::PackNotFound        // download_pack on missing digest
TransportError::AccessDenied        // HTTP 401/403, SSH auth refusal, S3 SignatureDoesNotMatch
TransportError::RemoteError(msg)    // catch-all remote failure; message is advisory only
TransportError::RefConflict         // update_ref CAS precondition failed
TransportError::InvalidRef(name)    // ref name failed SPEC-REFS §3, or URL parse failed
TransportError::ConnectionFailed    // DNS / TCP / TLS / SSH spawn / mutex poisoning
TransportError::ServerError{status} // unexpected status code (transports without a status integer use 0)
TransportError::InvalidResponse     // truncated frame, unknown opcode, bad JSON, mismatched server-returned digest
TransportError::ProtocolError       // malformed frame, failed handshake
TransportError::PayloadTooLarge(n)  // payload exceeded a transport-specific cap (see §4.4)
TransportError::InsecureScheme      // plain http:// supplied for a non-loopback host
```

Programs MUST NOT pattern-match on the advisory message strings.

---

## 3. URL schemes

| Scheme prefix | Transport | Notes |
|---|---|---|
| `kit+memory://…` | In-memory (`MemoryTransport`) | Test / fuzz only. Cannot be opened by `libkit::transfer::open` &mdash; the URL is accepted by `kit remote add` for round-tripping, but actual construction happens in-process. |
| `kit+file:///abs/path` | Filesystem (`FileTransport`) | Triple slash; everything after `kit+file://` is taken as the on-disk root path. |
| `kit+https://host/project` | ConnectRPC (`kit-transport-connect`'s `ConnectTransport`) &mdash; see [SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md) | The `kit+` prefix is stripped before the inner call; production uses `https://`. |
| `kit+http://localhost…` | Same dispatch as above, plain HTTP for local dev | Plain `http://` is restricted to loopback hosts (`127.0.0.1`, `::1`, `localhost`) per `validate_http_scheme`; any other host returns `InsecureScheme`. |
| `kit+s3://endpoint/bucket[/prefix]` | S3-compatible (`S3Transport`) | The endpoint becomes `https://<endpoint>`. The store must honor conditional writes (see §6.3). |
| `kit+ssh://user@host[:port]/path` | SSH child and `kit serve` (`SshTransport`) | The `user@` prefix is REQUIRED. Path is restricted to `[A-Za-z0-9._-/]` with no empty/`.`/`..` segments. See [`kit-transport-ssh/src/url.rs`](../../rust/crates/kit-transport-ssh/src/url.rs). |

Bare `ssh://`, `https://`, `http://`, `s3://`, `file://` URLs (without
the `kit+` prefix) are deliberately rejected. The prefix marks a URL
as something kit recognizes; kit does not silently extend the namespace
of any sibling tool.

---

## 4. SSH transport

kit's SSH transport spawns a long-lived `ssh(1)` child process and
exchanges length-prefixed [`SshFrame`](../../rust/crates/kit-rpc/proto/kit/rpc/v1/ssh/ssh.proto)
messages on its stdin/stdout. The framing layer is defined in
[SPEC-RPC §1](SPEC-RPC.md#1-wire-framing).

The transport is implemented with `std::process::Command` &mdash; kit does
NOT ship its own SSH stack (no `russh`, no in-process crypto). See
[`SSH-SECURITY.md`](../SSH-SECURITY.md) for the trade-offs that choice
implies.

### 4.1 Forced-command server pattern

Server-side, the user configures their `~/.ssh/authorized_keys` to
force `kit serve <repo-path>` on connection:

```
command="kit serve /srv/kit/myrepo",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ecdsa-sha2-nistp256 AAAA…
```

This binds an SSH key to a single repository on the server side. The
server process never sees a shell prompt; sshd hands it an open
stdin/stdout pair against the `authorized_keys`-resolved command.

The client spawns `ssh` with `kit serve <path>` as three separate
argv tokens so sshd invokes the binary directly without an
intervening `sh -c` (which broke the handshake on some sshd
configurations). The path is already restricted to a safe ASCII
subset by `validate_ssh_path`, so passing it as a separate token is
sound.

**Root mode.** A server that hosts many repositories under one
filesystem root can instead force `kit serve --root <dir>`:

```
command="kit serve --root /srv/kit --principal <hex>",restrict ssh-ed25519 AAAA…
```

sshd places the client's command in `SSH_ORIGINAL_COMMAND`, and `kit
serve` accepts only the exact form `kit serve <path>` from it —
three space-separated tokens, no flags, quoting, or shell syntax —
reading the path as a `<NAMESPACE>/<NAME>` repository identity
([SPEC-TRANSPORT-CONNECT §7.4](SPEC-TRANSPORT-CONNECT.md#74-repository-addressing))
resolved under `<dir>`. One process serves one repository, and the
client cannot name a flag or a different command through
`SSH_ORIGINAL_COMMAND`. Writes run the namespace's owner rule:
`--principal` asserts the client's Ed25519 public key (a raw 32-byte
key as 64 lowercase hex), and only a principal equal to the
namespace's key may write; a forced command asserting no principal
serves reads only. `--principal` is a trust assertion made by the
sshd configuration — never by the peer, and never from the
environment; see [SSH-SECURITY.md](../SSH-SECURITY.md) §5. The server
does not track which packs a session uploaded. A packmap write is an
ordinary ref write, and a client verifies what it fetches.

### 4.2 Conversation

```
client → server:    Hello { proto = PROTOCOL_VERSION_1, client_id }
server → client:    HelloResponse { proto, server_id }
                      OR
                    Error

client → server:    one of: ListRefs, ReadRef, UpdateRef, ReadRepoCursor,
                            PackExists, UploadPack (+ PackChunks),
                            DownloadPack, Close
server → client:    matching *Response, OR Error
```

`Close` is advisory &mdash; either side MAY drop the underlying stream
without a `Close` frame and the peer detects EOF. The client always
emits a best-effort `Close` from its `Drop` impl.

Pack uploads stream as `UploadPack { pack_id, total_bytes }` followed
by one or more `PackChunk { pack_id, offset, data, last }` frames.
The client caps each chunk's `data` segment at 800 KiB so the framing
layer's 1 MiB `MAX_FRAME_BYTES` cap accommodates the protobuf
overhead. Empty packs still emit a single `last=true` chunk so the
server sees an unambiguous end-of-stream. The server emits
`UploadPackResponse{}` once `last=true` is observed and the bytes
verify against the announced digest.

The reference client reads each chunk from the pack's body (§1.1) as it
sends it, so it holds one chunk, not the pack. `total_bytes` is the body's
length. A body longer than `PACK_BODY_LIMIT` is refused with
`PayloadTooLarge` before any byte of it is read and before any frame. A
retried upload reconnects (§4.5) and reads the body again from offset 0, so
every attempt sends the same bytes. A body that cannot be read, or ends
before its length, is a local failure: the upload ends with
`ProtocolError`, which is not retried. The client opens the body before it
sends the header; once the header is sent, a failure makes it close the
connection, since the server still waits for the rest of the upload.

The server MUST reject malformed upload streams before storing bytes:
`total_bytes` is required and MUST be within the server upload cap;
every `PackChunk.pack_id` MUST match the `UploadPack.pack_id`; every
`PackChunk.offset` MUST equal the next expected byte offset; the stream
MUST end exactly at `total_bytes`; and `BLAKE3(received_bytes)` MUST
equal `UploadPack.pack_id`. A rejected upload MUST NOT create or
overwrite the destination pack.

Pack downloads: client sends `DownloadPack { pack_id }`; server
replies with `DownloadPackHeader { total_bytes }` followed by a
sequence of `PackChunk`s ending in `last=true`. If the pack is
absent the server replies with `Error { code = ERROR_CODE_KEY_NOT_FOUND }`
before any header is emitted.

#### 4.2.1 `UpdateRef` CAS encoding

CAS intent is carried entirely by the `RefExpectation` enum in
`UpdateRef.expectation`. `expected_id` carries the digest only when
`expectation = REF_EXPECTATION_MATCH`; it is ignored for `ANY` /
`MISSING`. `RefExpectation` is defined once, in
[`kit/common/v1/refs.proto`](../../proto/kit/common/v1/refs.proto),
and imported by `ssh.proto` &mdash; it is the same enum (same wire numbers)
the `kit.repo.v1` multiplayer protocol uses for its own `UpdateRef`.

| `RefWriteCondition` | `expectation`             | `expected_id`       | Semantics |
|---|---|---|---|
| `Any`        | `REF_EXPECTATION_ANY`      | empty               | Last-writer-wins; current ref value is ignored. |
| `Missing`    | `REF_EXPECTATION_MISSING`  | empty               | Create-only; the ref MUST NOT exist on the server. |
| `Match(h)`   | `REF_EXPECTATION_MATCH`    | 32-byte digest `h`  | Current ref value MUST equal `h`. |

A conforming server MUST treat `REF_EXPECTATION_UNSPECIFIED` (the
zero value, sent when the client omits the field) as a protocol
error and reply with `ERROR_CODE_INVALID_REQUEST`.

A server serves only ref names under `refs/` (SPEC-REFS §2). An
`UpdateRef` or `ReadRef` whose name passes the SPEC-REFS §3 grammar but
lies outside `refs/` is answered, before any storage access, with:

| Request | Reply |
|---|---|
| `UpdateRef`/`ReadRef` naming a grammar-valid ref outside `refs/` | `Error { code = ERROR_CODE_INVALID_REQUEST, message = "ref name must start with refs/ (…)" }`, empty `details` |

Never with an absent-ref answer. Having empty `details`, it is not a
CAS conflict; a client surfaces it as a remote error with its message.

On a CAS mismatch the server returns `Error { code =
ERROR_CODE_INVALID_REQUEST }` with the current ref value in
`Error.details`. Per SPEC-RPC §3.3, `Error.details` is opaque and
programs MUST NOT pattern-match on its contents; conforming clients
today check only whether `details` is **non-empty** as a boolean
signal to reclassify the error as `TransportError::RefConflict`
(rather than a generic invalid-request), and do not decode the 32
bytes themselves as the current ref value. **Disambiguation &mdash; actually
learning what the ref's current value is &mdash; is a separate, explicit
`read_ref` call after the fact (§7), not a side effect of parsing this
field.** The current-ref bytes in `details` exist for
forward-compatibility and out-of-band diagnostics (for example a log line),
not as a client-consumed protocol value; a future revision MAY define
a structured, non-opaque field for this if a real need for it emerges,
rather than asking clients to parse an "opaque" field.

#### 4.2.2 `ReadRepoCursor` request

`ReadRepoCursor` asks for the repository cursor (§1.2). The request holds no
field. The reply is `ReadRepoCursorResponse`, which has one optional field,
`cursor`:

| Reply | Meaning |
|---|---|
| `ReadRepoCursorResponse { cursor }`, 1 to 64 bytes | The cursor of the served repository. |
| `ReadRepoCursorResponse {}`, no `cursor` field | The repository offers none for this read. |

The request and the reply are new oneof variants of `SshFrame` (field numbers
16 and 17), which SPEC-RPC §2 allows in v1. No existing field, number or
frame changes.

**Server.** A server returns the cursor of the transport that it serves, as
that transport defines it (§1.2). `kit serve` serves the file transport, so
the cursor is the one of SPEC-REFS §5.1.2, with the same rule for the 2 s
window, a system without a boot id and a root that has too many directories.
A server that cannot vouch for the cursor at that moment, or fails to read
it, sends a reply with no `cursor` field and never an invented value. The
request reads no ref. It takes the repo lock and the stripe locks shared, as
SPEC-REFS §5.1.2 says. A session that may not write may send it, and it
changes no ref or pack. It reads only the repository. Its answer does not
depend on any session, so one client's request cannot change another's
answer. It costs one frame of the per-connection budget (§4.4).

**Client.** The client sends the request once per fetch, before it lists the
refs (§1.2). It treats the reply strictly:

- A `cursor` field of 0 bytes or of more than 64 bytes is a protocol error,
  not "no cursor". The client checks the length against the bound of §1.2
  before it copies the bytes. The frame cap of SPEC-RPC §1 bounds the frame
  before that.
- A reply that holds a field other than `cursor` is a protocol error.
- Any frame but `ReadRepoCursorResponse` and `Error` is a protocol error.
- An `Error` with `ERROR_CODE_INVALID_REQUEST` means that the server does not
  know the request, as SPEC-RPC §2 says, so the client offers no cursor and
  does its full work. Any other `Error` is an error.

**Older peers.** A client that predates the request never sends it, so a new
server serves it as before, and the golden sessions 1 to 3 are unchanged. A
server that predates the request answers the unknown body with `Error {
ERROR_CODE_INVALID_REQUEST }` and keeps the session open, so the client
offers no cursor and its fetch works as it did. The failed request costs one
frame of the budget. Neither side needs a version or a capability field.

**Trust.** A client takes the cursor from the server, as it takes the ref
listing. A server that holds back a changed cursor can equally hold back a
changed ref. The fetch verifies every object and signature it applies, so a
stale cursor can only leave the client at a state the server once offered.

### 4.3 Trust model

SSH transport security is delegated to the user's `ssh(1)` CLI:

- Host-key verification → `ssh(1)`.
- Identity selection → `ssh-agent`/`~/.ssh/config`.
- Kex / cipher / auth → `ssh(1)` / sshd.

Three `.kit/config` keys override `ssh(1)` defaults for the kit SSH
child only (see [`SshOptions`](../../rust/crates/kit-transport-ssh/src/lib.rs)):

```
ssh.strict_host_key_checking = yes
ssh.user_known_hosts_file    = /path/to/project.known_hosts
ssh.identity_file            = /path/to/id_ed25519
```

These plumb to `-o StrictHostKeyChecking=…`, `-o UserKnownHostsFile=…`,
and `-i …` respectively.

When `ssh.strict_host_key_checking` is not set, the transport
implicitly passes `-o StrictHostKeyChecking=accept-new` so the first
connection is not an interactive prompt. `-o BatchMode=yes` is
always passed so a missing key never blocks on a password prompt.

See [`SSH-SECURITY.md`](../SSH-SECURITY.md) for the full trust model.

### 4.4 Resource caps

The `kit serve` server enforces per-connection budgets to bound a
misbehaving or malicious client (see
[`kit-serve/src/budget.rs`](../../rust/crates/kit-serve/src/budget.rs)):

- `MAX_FRAMES_PER_CONN = 10_000` &mdash; hard cap on frames after `Hello`.
- `MAX_BYTES_PER_CONN  = 1 GiB`  &mdash; cap on cumulative request payload bytes.

Each cap trips emits an `Error{ ERROR_CODE_INVALID_REQUEST }` and
closes the connection with `exit::PROTOCOL_ERROR`. The frame cap's reply
names it: `per-connection frame budget exceeded: at most 10000 frames per
session (SPEC-TRANSPORT 4.4)`.

**Reference-server behavior.** What fits in one session follows from the
frame cap. A fetch costs one `ListRefs` frame, then per branch a `ReadRef` of
the packmap and a `DownloadPack` of each node of its packmap chain, even when no
branch changed: the SSH transport names no repository, so a fetch keeps no
per-branch checkpoint for it and walks each packmap chain again. The tag phase
(§1.4) adds one `ListRefs` of `refs/tags/`, and one of `refs/kit/tagmap/` only
when some tag is not yet proved from local objects. With one node per packmap
chain and no new tag that is two frames plus two per branch, so one session
fetches at most 4,999 branches; a fetch of more fails closed with the reply
above. A new annotated tag pushed alone adds one node and one pack download,
so a clone of a remote with about 5,000 such tags fails the same way; tags
pushed together share their node and pack.
When the served repository offers a cursor (§4.2.2), a fetch that finds the
cursor it recorded after its last complete fetch costs one frame, the
`ReadRepoCursor` request, and the 4,999-branch limit does not apply to it. A
fetch that finds another cursor, or none, works as above. A server that
predates the request makes every fetch work as above, plus one frame.
`kit fetch`, `kit pull` and `kit clone` open one session each. A push walks
the branch's whole packmap chain over its session. A push re-baselines the
chain (§7.2), so the walk stays within the re-baseline depth while one node
can list the chain's packs. Past that, a push's frames grow with the number
of pushes the branch has had. The cap is not raised: it is what bounds
a client that sends requests without end.

Nested `UploadPack` chunk drains enforce the same 1 GiB byte ceiling on
the declared upload length and additionally cap the number of chunk
frames at `MAX_FRAMES_PER_CONN`, so a client cannot bypass the outer
frame loop by streaming unbounded chunks inside one upload request.

The budgets bound how much a client can make the server do; an idle
timeout bounds a client that goes silent. `kit serve` ends a session after `--idle-timeout-secs`
seconds (default 60; `0` disables it) in which no byte arrives from the
client, whether before `Hello`, between requests or inside an upload
(whose partial pack is discarded). It answers, best effort, with
`Error{ ERROR_CODE_INVALID_REQUEST, "idle timeout" }` and exits with
`exit::PROTOCOL_ERROR`. The timer counts only silence: an upload that is
still arriving never trips it, however long one chunk frame takes, and
time the server spends answering is not counted. It does not bound a
client that trickles bytes or stops reading; the budgets do, in part,
and an operator can cap the whole session with `--max-session-secs`
(off by default). See [`SSH-SECURITY.md`](../SSH-SECURITY.md) §4.

The framing layer's per-frame `MAX_FRAME_BYTES = 1 MiB` cap (per
[SPEC-RPC §1](SPEC-RPC.md#1-wire-framing)) bounds individual frames;
pack data flows through `PackChunk` streams to stay under that limit.

Client side, the SSH transport applies the
`PACK_BODY_LIMIT = 4 GiB` cap on `download_pack`. A server-advertised
`DownloadPackHeader.total_bytes` greater than 4 GiB is rejected
before the sink's `begin`, as `TransportError::RemoteError` with a
message mentioning the client cap. The header's length goes to
`begin`, so a sink with a smaller limit refuses the pack before any
chunk is read; chunks past the declared length or the sink's limit
stop at the sink as `TransportError::PayloadTooLarge`.

### 4.5 Retry / reconnect

`SshTransport` is connection-oriented (a single long-lived `ssh(1)`
child), so honoring the §7 retry ladder for `ConnectionFailed` takes
more than re-issuing the same request the way a request-oriented transport does:
a frame-level I/O failure can leave the child's stdin/stdout pipe
mid-message, so the transport marks that connection `closed` and
resuming writes/reads on it would desync every subsequent frame.
`SshTransport` therefore reconnects before it retries &mdash; every verb is
driven through [`kit_core::protocol::retrying`], and each attempt
that finds the connection `closed` first respawns `ssh` from the
original `target`/`options` and redoes the `Hello` handshake before
re-issuing the verb against the fresh child. `upload_pack` is
content-addressed and safe to resend in full on the new connection;
each new attempt reads the pack's body again from offset 0.
`update_ref` is not idempotent across retries per §7, so a CAS write
that returns `RefConflict` still requires the caller's `read_ref`
disambiguation.

---

## 5. HTTP remotes

`kit+https://` and `kit+http://` remotes use the Connect transport. Read
[SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md) for its wire contract.
Verifiable sparse-checkout fetch has no Connect equivalent. The S3
transport carries it (§6.6).

---

## 6. S3 transport

The S3 transport ([`kit-transport-s3`](../../rust/crates/kit-transport-s3/))
talks SigV4 against any S3-compatible store that honors conditional
writes (see §6.3).

*Informative.* `list_refs` on this transport issues one `ListObjectsV2` per
page and then one `GET` per listed ref, because a ref's id lives only in its
object body. A fetch adds a packmap read and a node download per branch. The
transport suits repositories with few concurrent writers and few refs.
Deployments with many concurrent writers use the Connect service.

**Protocol requirement.** A listing returns every listed ref that its `GET`
finds, or fails. A `GET` that fails, after the retries of §6.5, with an error
status fails the whole listing with that error. Only a `404` skips the ref,
because the ref was deleted after the page was listed; the result is then an
older listing (SPEC-TRANSPORT-CONNECT §7.9 allows one). A `200` whose body is
not a canonical 65-byte ref wire (SPEC-REFS §1) fails the whole listing, as it
fails `read_ref`.

**Reference-server behavior.** The client keeps at most 16 of those `GET`s in
flight. It returns the first failure in key order, as one read after another
would, and starts no new read after a failure.

### 6.1 Object layout

The table below lists canonical repository-relative keys. For a URL of
the form `kit+s3://endpoint/bucket/prefix`, the transport prepends
`prefix/` to every canonical object key and every `ListObjectsV2`
query prefix. A no-prefix URL continues to address keys at bucket root.
Prefixes MUST NOT be empty path segments, `.`, `..`, contain duplicate
slashes, contain backslashes, or begin/end with `/`.

| Object | S3 key |
|---|---|
| Pack | `packs/<64-hex-blake3-digest>` |
| Ref  | `<ref-name>` (for example `refs/heads/main`) |

Examples:

| URL | Canonical key | Effective S3 path |
|---|---|---|
| `kit+s3://host/bucket` | `packs/<hex>` | `/bucket/packs/<hex>` |
| `kit+s3://host/bucket/repo-a` | `packs/<hex>` | `/bucket/repo-a/packs/<hex>` |
| `kit+s3://host/bucket/repo-a` | `refs/heads/main` | `/bucket/repo-a/refs/heads/main` |

For `list_refs("refs/heads/")` under `repo-a`, the transport sends
`ListObjectsV2` to `/bucket?list-type=2&prefix=repo-a/refs/heads/`,
fetches returned ref bodies through `/bucket/repo-a/...`, then strips
both the URL namespace and requested ref prefix before returning names.

The ref body is the 65-byte wire form: 64 hex chars + `\n`.

### 6.2 Authentication

Credentials from environment at `connect` time
([`kit-transport-s3::ENV_*`](../../rust/crates/kit-transport-s3/src/lib.rs)):

- `KIT_S3_ACCESS_KEY_ID`
- `KIT_S3_SECRET_ACCESS_KEY`
- `KIT_S3_REGION` (optional; defaults to `us-east-1`)

Missing credentials do NOT fail `connect`. The first signed call
surfaces `TransportError::AccessDenied`.

### 6.3 CAS encoding

`update_ref` maps to a signed `PUT`:

| `RefWriteCondition` | Header | Comment |
|---|---|---|
| `Any`        | (none) | Last writer wins. |
| `Missing`    | `If-None-Match: *` | The store MUST honor this for conditional create. |
| `Match(h)`   | `If-Match: "<md5-of-expected-wire>"` | The store MUST return the body MD5 as the ETag on a single `PUT`; matching against that value is how kit gets CAS without server-side hash awareness. |

`409` and `412` → `RefConflict`; never retried.

`upload_pack` carries no `RefWriteCondition` &mdash; packs are content-addressed
and every write is one plain unconditional `PUT` (§6.7).

### 6.4 Limits

- `PACK_BODY_LIMIT = 4 GiB` &mdash; the absolute pack-body ceiling enforced
  on both `upload_pack` and `download_pack` (every transport that
  ingests or emits pack bytes shares this limit; see
  [`kit_core::protocol::PACK_BODY_LIMIT`](../../rust/crates/kit-core/src/protocol.rs)).
  `upload_pack` refuses a longer body with `PayloadTooLarge` before it
  reads it. The limit is below S3's 5 GiB cap on one `PUT`, so every pack
  goes up in one `PUT` (§6.7).
  A writer applies the limit whether or not the remote advertises
  `max_pack_bytes`: it seals no pack above `min(advertised, PACK_BODY_LIMIT)`,
  so a pack that was uploaded can be fetched. The `kit+file://` transport
  refuses an upload above it, as the S3 transport does.
- `REF_BODY_LIMIT = 256` bytes for a ref `GET`. It bounds the read; a
  body other than the 65-byte ref wire is rejected after it.
- `REF_LIST_BODY_LIMIT = 16 MiB` for the `ListObjectsV2` XML
  response.
- These limits bound a success's body. An error answer's body is never
  read: the status alone gives the error. A store's error document can be
  longer than the success it stands for (a missing ref's `NoSuchKey`
  document names the key, the request and the host), and a limit must not
  turn a `404` into `PayloadTooLarge`.
- HTTP timeout: 60 s for a request up to its response headers, and 60 s
  for each read of a response body. A pack `PUT` sends its body before it
  awaits the answer, so it gets 60 s plus one second per MiB of the pack.

### 6.5 Retry

Same ladder as §7. 5xx and 429 retry; 4xx including 412 does not.

### 6.6 Verifiable sparse-checkout fetch 

Feature-gated extension. Off by default &mdash; built only when the
`sparse-checkout` cargo feature is enabled on the consuming crate
chain.

S3 has no "POST a request, get a computed response" verb, so the
sparse delivery is content-addressed at a canonical object key the
server pre-populates:

```
GET /<bucket>[/<url-prefix>]/sparse/<tree-hex>/<filter-hex>
```

The response body IS the SPEC-SPARSE-CHECKOUT §5 envelope. SigV4
signing is unchanged &mdash; this is just another signed GET on the same
bucket. The client runs `verify_sparse` on the decoded result.

| Status | Maps to |
|---|---|
| `200 OK` | `Ok(SparseResponse)` |
| `404 Not Found` | `TransportError::PackNotFound` (no precomputed sparse for that `(tree, filter)`) |
| `403`/`401` | `TransportError::AccessDenied` |
| Other | mapped per `ServerError { status }` |

The object key already encodes the filter hash, so the client sends no
`?sparse=<filter-hex>` query. The SigV4 canonical request stays tight.

### 6.7 Pack transfer

Neither direction holds a pack in memory.

**Upload.** `upload_pack` makes one pass over the pack's body (§1.1) to
compute its SHA-256, the SigV4 payload hash (`x-amz-content-sha256`). It
then sends one `PUT` of `Content-Length` equal to the body's length, whose
body streams from the pack's body read again from offset 0. Every attempt
of the §6.5 ladder reads the body again from offset 0 and sends the same
bytes under the same payload hash. The store checks the bytes it receives
against that hash, so a body that changed between the hash pass and the
send is refused (`400`), and nothing is stored. A body that cannot be read,
or ends before its length, during either pass is a local failure:
`upload_pack` returns `ProtocolError`, which is not retried, and a `PUT`
in progress ends unfinished. The reference client reads the body in
256 KiB chunks and keeps at most two queued ahead of the request.

**Download.** `download_pack` sends one `GET`. Only a `200` answer's body
reaches the sink: its `Content-Length`, when present, goes to `begin`
before any byte is read, so a pack over `PACK_BODY_LIMIT` or the sink's
limit is refused unread, and each piece of the body is written to the sink
as it arrives. Any other answer's body is never read (§6.4). A retried
attempt begins the sink again. `download_blob` is the same `GET` into a
sink limited to the caller's bound.

### 6.8 Repository cursor

The S3 transport offers the repository cursor of §1.2. It adds no object and
needs no change to a writer, so a repository written by any version of the
client has one.

**Protocol requirement.** The cursor is the BLAKE3 digest of the tag
`kit-s3-repo-cursor-v1`, a zero byte, and then every entry that
`ListObjectsV2` returns for the prefix `refs/` (under the URL prefix, if any),
in listing order. Each entry adds its key, its `ETag` and its `LastModified`
text. Each of the three is an 8-byte little-endian length and the bytes. The
cursor is 32 bytes.

- A ref write changes the `ETag` of its object, because the `ETag` is the MD5
  of the 65-byte ref wire (§6.3). A new ref adds an entry. The write reports
  success only when the store holds the object, so the next listing shows it.
- A bucket that is emptied and filled again with the same refs has other
  `LastModified` values, so it returns another cursor.
- The listing follows the rules of `list_refs`: pages of at most 1,000 keys,
  keys strictly increasing across pages, a page cap and a retained-state cap.
  A listing that breaks a rule is an error.
- A body that is not UTF-8, or an entry with no key, no `ETag` or no
  `LastModified`, gives no cursor for that read. The fetch then does its full
  work.

**Reference-client behavior.** An unchanged fetch lists `refs/` once per 1,000
refs and reads no ref and no packmap. It costs one request for a repository of
at most 1,000 refs. The listing covers every branch, tag and packmap. A client
that sees another cursor does its full work.

**Trust.** The listing comes from the store, as the one of `list_refs` does. A
store that returns an old listing can only leave the client at a state that the
store once held.

---

## 7. Retry / idempotency

All transports MUST retry the following errors with exponential
backoff: `ConnectionFailed`, `ServerError{status >= 500}`, and
`ServerError{status == 429}`. The default ladder is `1s, 2s, 4s,
8s, 16s` (5 attempts), with subsequent delays doubling and capped
at 300 s. An `AdmissionRequired` error (HTTP 402; see
[SPEC-TRANSPORT-CONNECT §5.1](SPEC-TRANSPORT-CONNECT.md#51-admission-challenges))
is not a `ServerError` for this rule and is never retried by the
ladder. The ladder is exposed via
[`BackoffIterator`](../../rust/crates/kit-core/src/protocol.rs), the
classifier as [`is_retryable`], and the retry loop itself as
[`retrying`](../../rust/crates/kit-core/src/protocol.rs) &mdash; a single
transport-agnostic driver every transport's client wraps, so the
ladder/classification policy is defined once instead of per crate.
Request-oriented transports (Connect, S3) satisfy this by re-issuing a
fresh request per attempt; connection-oriented transports (SSH)
MUST reconnect before re-attempting once a prior attempt has left the
connection in a possibly-desynced state &mdash; see §4.5.

`update_ref` with `Missing` or `Match`, and `advance_refs`, are NOT
idempotent across retries: a network timeout after the server applied
the write looks identical to a write that never landed. The network
transports' clients still send them through the ladder above (SSH
and Connect through `kit_core::protocol::retrying`; S3 through
its own loop over `BackoffIterator` and `is_retryable`), so a call can be
re-issued after its first attempt landed. The re-issue cannot apply the write twice: the
landed attempt has already falsified the precondition the re-issue
carries (a `Missing` ref now exists; a `Match(h)` ref no longer holds
`h`). It can, however, report a conflict for the caller's own write, and
the caller cannot observe whether the ladder re-issued the call. The
caller obligations are therefore:

- On `RefConflict` from `update_ref`, the caller MUST call `read_ref`
  on that ref before reporting a conflict. If the ref holds the value
  the caller wrote, the caller MUST treat the write as having landed.
- On `HeadConflict` or `PackmapConflict` from `advance_refs`, the caller
  MUST likewise read the ref whose precondition failed. A packmap that
  already holds the caller's node means only the head write remains; a
  head that already holds the caller's value means the advance landed.
- `update_ref` with `Any` may be re-issued freely: it writes the same
  value again. Like any `Any` write, it can overwrite a value another
  writer stored between the two attempts.

The one case where a re-issue reports the true outcome is a Connect
deployment that keeps the auth v2 replay ledger
([SPEC-TRANSPORT-CONNECT §7.1](SPEC-TRANSPORT-CONNECT.md#71-reference-server)):
`kit-transport-connect` reuses one nonce and validity window for every
attempt of one logical call (`RetryIdentity`), so the server returns the
committed attempt's stored result. That covers only re-issues within one
call's ladder, inside the signed validity window. A caller that invokes
the operation again gets a fresh nonce, and the obligations above apply.
A caller MAY skip the `read_ref` only when it knows the remote keeps
that ledger.

`upload_pack` IS idempotent (content-addressed: re-uploading the
same bytes produces the same digest and is a no-op on the server
side).

`download_pack` and `pack_exists` are pure reads; no idempotency
concerns.

### 7.1 Cross-transport CAS guarantee summary

| Transport | `Missing` | `Match(h)` | Cross-process safe |
|---|---|---|---|
| Memory | `Mutex`-protected read-then-write | `Mutex`-protected | N/A (test only) |
| File   | `link(2)` after `write_atomic` (atomic per POSIX) | OS exclusive lock on the ref's stripe, `<root>/.kit/refs/refs-<hh>.lock` (via `std::fs::File::lock`), with the repo lock `<root>/.kit/refs/.lock` held shared, wraps a read-then-`write_atomic` (SPEC-REFS §5.1.1); in-process locks keep multi-threaded callers within one process from contending on the OS locks | Yes |
| S3     | `If-None-Match: *` enforced by the store | `If-Match: "<md5-of-wire>"` enforced by the store | Yes |
| SSH    | Server-enforced via `expectation = REF_EXPECTATION_MISSING` | Server-enforced via `expectation = REF_EXPECTATION_MATCH` plus 32-byte `expected_id` | Depends on server-side ref-store atomicity |

`upload_pack` itself carries no `RefWriteCondition` (it addresses
content by digest, not by a caller-supplied CAS condition), so the
table above &mdash; `Missing`/`Match(h)` &mdash; describes `update_ref` only.
An S3 pack is one `PUT` (§6.7), which is atomic: the object either holds
all the uploaded bytes or does not exist.

### 7.2 Two-ref advance and the packmap reset

`advance_refs` moves a branch head and its packmap together. The push
driver keeps one invariant for every state a reader without locks, or a
crash, can expose: when the head resolves to `T`, the packmap chain
reconstructs the closure of `T`. A transport reports how strongly its
advance commits:

| Capability | Writers | Readers and crashes | Transports |
|---|---|---|---|
| none (ordered) | the packmap write, then the head write, each conditioned alone; another writer can run between them | may see the new packmap with the old head | default `advance_refs` (memory, S3, SSH) |
| `supports_serialized_advance` | both conditions are checked before either write; a conflict changes nothing; no other write to either ref interleaves | may see the new packmap with the old head | file (SPEC-REFS §5.1.1) |
| `supports_atomic_advance` | one indivisible step | see both refs move together | Connect servers that advertise `atomic_advance` |

An atomic advance is also serialized. An append to the packmap chain is a
superset of the prior chain, so the new packmap with the old head is
consistent on every transport.

A push re-baselines a chain that its node would make deeper than the
re-baseline depth. The depth is 64 by default, and a depth of zero never
re-baselines. The re-baseline is one node with no `prev`. It lists every pack
of the chain, oldest first, and then each new pack the chain does not list.
The push uploads no pack again, and a fetcher that holds the chain's packs
downloads only the new ones. The node is a superset of the chain it
replaces, so it is consistent on every transport and under every head
condition, as an append is. Its packmap write is conditioned on the chain
head the push read, and a push that loses that write reads the chain and
decides again. A re-baseline lists at most 4,096 packs
([SPEC-TRANSPORT-CONNECT §7.4](SPEC-TRANSPORT-CONNECT.md)). A chain that
holds more with the new packs keeps appending.

A reset replaces a chain with a node that does not list every pack of that
chain, so it is not a superset. The reference push driver resets only a
chain it cannot read, and only with packs that hold the full closure of the
new head. A client that resets a chain it can read MUST request the reset
only when one of these holds:

- the advance is atomic and the head condition is `Missing` or `Match`;
- the advance is serialized, not atomic, and the head condition is
  `Match(h)` with `h` an ancestor of the new head in the client's own
  store. The reset holds the new head's full closure, which contains the
  closure of `h`, so the old head stays reconstructable between the two
  writes and after a crash between them.

A push plans its packs against the head it reads, and leaves out what that
head holds. It decides what the head holds from the head alone: the commits
that are ancestors of the head, and the trees of the head's own snapshot. A
plan may send an object the remote holds. It never omits one the remote lacks.
A push conditioned on `Missing` or `Match` MUST plan only
against a head its condition holds for. When the head it reads fails the
condition, the push is refused as a non-fast-forward before it plans,
unless that head is already the new head, in which case an earlier
attempt landed and the push writes nothing. A retry that plans the full
closure of the new head depends on no head and reads none. A condition that differs from
the planned head could hold again after the head moves away and back while
a reset drops what the plan left out, and the advance would then publish a
head its chain cannot reconstruct, on every kind of advance.

A force push (`Any`) never requests a reset. On a serialized or an atomic
advance it uses the guarded force driver: it conditions the packmap write
on the chain its plan read, and plans again when that chain no longer
contains the node the plan depended on, so it never appends packs whose
bases a concurrent reset dropped. A re-baseline replaces that node too, so
a force push plans again after one. On an ordered advance no reset happens
except over a broken chain, and a force push appends on the ordered path.

**Tag maps.** A tag push moves `refs/tags/<t>` and its tag map
`refs/kit/tagmap/<t>` (§1.4) as a branch push moves a head and its
packmap: the tag map first, then the tag, with `advance_refs` on the
transport's advance kind. When the tag resolves to `v`, the tag map's
chain rebuilds the closure of `v`. Every tag map write is a create
(`Missing`) or an append whose node's `prev` is the value it replaces,
written under `Match` on that value, and covers both the remote tag's
current value and its new value. A tag map is therefore a superset of
every value its tag held, a reader of an earlier value is still served in
whatever order the two refs land, and a crash between the writes leaves
nothing to clean up. A tag map is never re-baselined or reset.

A tag map create may **graft**: its node's `prev` names the packmap node
of one of the remote's branches, and several tag maps may name the same
node. A tag chain never grafts on another tag chain. The push finds the
base by walking each tag's peeled commit backward to the nearest commit
that is the local tracking tip of one of this remote's branches, at most
100,000 commits not seen before per tag. It reads that branch stably: its
head, then its packmap `p`, then its head again, up to eight times, and
uses the base only when both head reads agree on a commit the local store
holds. Tags that share a base form one group. A group is planned once,
against that head, under one node `{prev: p, packs}` that every tag of the
group takes as its tag map, or takes `p` itself when the plan is empty.
Without a base the node has no `prev` and lists the full closure. The
base changes only how much is sent, never what a reader can rebuild.

For each tag with local value `v`, from the remote tag `T` and tag map
`M` it reads:

| Remote `T` | Remote `M` | Push |
|---|---|---|
| absent | absent | Create: tag map `Missing`, then tag `Missing`. |
| absent | present | Append to `M` a node of the full closure of `v` under `Match(M)`, then tag `Missing`. |
| `v` | present | Up to date. |
| `v` | absent | Repair: tag map `Missing`, then tag `Match(v) → v`. |
| other | any | Refused, unless forced. |
| other, forced | present | Append to `M` a node planned against `T` when the local store holds `T`'s whole closure, else the full closure of `v`, under `Match(M)`; then tag `Match(T)`. |
| other, forced | absent | Tag map `Missing` on a node whose plan includes `T`, then tag `Match(T)`. Refused when the local store lacks `T` or its closure. |

A forced update conditions on the value it read, never `Any`. A push
refuses, before it reads the remote, a tag whose `refs/kit/tagmap/<t>`
would not be a valid ref name, an annotated tag whose object names
another tag, and an unsigned annotated tag. On a remote whose tag listing
comes in one `kit serve` frame (`kit+ssh`, `kit+file`), a push refuses a
create that would take the listing of `refs/tags/` or `refs/kit/tagmap/`
past 960 KiB, counting each name without its prefix plus 48 bytes. A
conflict reads that tag again and decides again, at most eight times.

---

## 8. Pack format

`upload_pack` and `download_pack` move opaque pack bytes, through a
`PackBody` and a `PackSink` (§1.1). The pack
format itself (object index, delta encoding, and chunk store) is
defined in [SPEC-PACKFILE](SPEC-PACKFILE.md). Transport
implementations MUST NOT inspect or rewrite pack bytes.

`upload_blob`/`download_blob` move opaque **auxiliary** bytes &mdash;
content-addressed transfer metadata that is NOT a packfile (today only
packlist chain nodes; their format is defined in `kit_core::transfer`,
not SPEC-PACKFILE). They share the same digest-keyed content-addressed
store as packs (the store is a general blob store; "pack" is just the
primary content kind), so a transport MAY back both with one keyspace &mdash;
the default trait impls delegate the blob verbs to the pack verbs.
Transports MUST NOT inspect or rewrite blob bytes either.

The 32-byte digest is the BLAKE3 hash of the full bytes buffer, wrapped
in [`PackKey`](../../rust/crates/kit-core/src/protocol.rs) to keep digests
and object hashes from silently crossing purposes at API boundaries.
(The `PackKey` name predates the blob verbs; it addresses any
content-addressed blob the transport stores, pack or auxiliary.)

---

## 9. Versioning

This document and `ssh.proto` are jointly v1. The cross-transport
trait surface (`Transport`, `TransportError`, `PackKey`,
`RefWriteCondition`) is API-stable within the v0.1.x line. See
[SPEC-RPC §2](SPEC-RPC.md#2-versioning) for SSH wire-format
versioning.

A native SSH implementation (with in-process host-key pinning) is a
future enhancement; [`SSH-SECURITY.md`](../SSH-SECURITY.md) tracks the
gaps inherited from delegating to `ssh(1)`.

---

## 10. Invariants

These hold for every conformant transport, regardless of scheme:

| Invariant | Enforced by |
|---|---|
| Errors form a closed taxonomy; no coupling to message strings | `TransportError` variants at the trait boundary; advisory messages MUST NOT be pattern-matched (§2) |
| No scheme guessing or fallback | `kit+` prefix required; unsupported schemes error at dispatch instead of guessing (§3) |
| No plaintext HTTP off loopback | `validate_http_scheme` → `InsecureScheme` for any non-loopback `http://` host (§3) |
| Stored pack bytes match their announced digest | SSH: server verifies `BLAKE3(received) == pack_id` before storing (§4.2) |
| A rejected upload never creates or overwrites the destination pack | SSH upload-stream validation: `total_bytes` required and capped, `pack_id` match, contiguous offsets, exact end (§4.2) |
| Ref CAS conflicts surface, never silently clobber | `Missing`/`Match` encodings per transport (§4.2.1, §6.3); conflict → `RefConflict`; 409/412 never retried (§6.5, §7.1) |
| A retry never duplicates a conditional ref write | a landed attempt falsifies the precondition its re-issue carries; 4xx is not retryable; on `RefConflict` (or an `advance_refs` conflict outcome) callers MUST `read_ref` before reporting a conflict (§7) |
| `upload_pack` is idempotent across retries | content-addressed keys: same bytes → same digest → server-side no-op (§7) |
| A misbehaving peer cannot exhaust memory | `MAX_FRAME_BYTES` 1 MiB, `MAX_FRAMES_PER_CONN`, `MAX_BYTES_PER_CONN` used by the SSH frame loop (§4.4); `PACK_BODY_LIMIT` 4 GiB checked before the body and against the bytes taken (§4.4, §6.4); ref/list body caps (§6.4) |
| A body over a sink's limit is refused before its first byte when its length is known | transports pass a known length to `PackSink::begin` before they read the body (§1.1) |
| A download never ends silently short | a sink takes exactly the declared length; SSH reads the server's `last` flag (§1.1, §4.2) |
| A local disk error is never retried and never falls back | `PackSink::failed()` stays set and `begin` refuses after it with `ProtocolError`, which is not retryable (§1.1, §7) |
| Pack and blob bytes cross transports opaque and unmodified | transports MUST NOT inspect or rewrite them (§8) |

Per-transport CAS strength differs; the normative summary is the table
in §7.1.

### Pack-chain fetch

Fetch MUST authenticate each requested pack and pack-list node before decoding
or applying it. The CLI downloads the missing packs of a chain one at a time
in chain order. It spools each pack into an unnamed file in `.kit/tmp/`,
checking its length, its digest and its trailer as the bytes arrive. Only a
pack that passes all three is read: it is unpacked into the object store one
window at a time, the signatures of the objects it wrote are checked, it is
recorded as applied, and its file is closed before the next download. A
partial spool is never read. On Unix a killed fetch leaves nothing in
`.kit/tmp/`; on Windows a power loss can leave a spool there until the
next fetch, push or gc removes it (§1.1). No repository lock is held while the packs download and
apply, so other commands run during a fetch of any size. The CLI limits chain packs to one million and
pack-list nodes to 100,000.

The fetch takes the repository's prune guard, a shared lock on the `format`
file, before it reads its record of applied packs, and holds it until after
its last ref publish (SPEC-CONCURRENCY §3.4). While a guard is held, gc
deletes no object at any grace period, so the objects of an applied pack
survive until a ref names them. Signature and closure validation precede ref
publication. The fetch takes `worktree.lock` only around the remote-tracking
ref write and the checkpoint. It waits for that lock with no deadline, tells
its observer once that it waits, and stops on an interrupt, because its
downloads are done and a timeout would discard them.

The applied-pack record gains a line for each pack as the pack is applied,
after the pack's objects are committed and its signatures are checked. A
fetch that dies resumes after its last applied pack. A failed, interrupted or
killed fetch leaves the packs it applied in the store and in the record, with
no ref naming their objects. A later `gc` may prune those objects. The record
is then stale, and the next fetch repairs the store: when a run that skipped
a recorded pack finds an object missing, whether a delta base during unpack
or an object of the tip's closure, it clears the record and applies the whole
chain again, once. Every other failure propagates. A failed download, digest
check, write or apply publishes no ref. A local disk error on the spool or on
a store write, a full disk say, ends the fetch as a local I/O error; the spool
error names `.kit/tmp/`. It is not retried, and no other location is tried.

Stored-object ID lists are checked per pack and are not accumulated over the
chain. The closure check before ref publication reads the type of each chunk
of a chunked blob without queueing it, so its 10,000,000-object cap counts
commits, trees, blobs and chunked-blob manifests only. It remembers at most
2,097,152 checked chunk IDs; past that, a chunk is checked again for each
manifest that names it.

A tag map chain (§1.4) applies the same way. Its walk stops at the nodes of
the chains this fetch applied and at checkpoint heads, so a chain that grafts
on a branch chain downloads only its own nodes and packs. The tag phase
self-heals at most once per fetch, so a remote whose every tag lacks an object
costs one full walk, not one per tag.

A fetch holds one window of one pack, not the pack, except over a transport
that buffers the body (§1.1). The signature check
reads only the commits, remixes and tags a pack stored, in runs whose
objects together stay within 256 MiB, charged twice their size; one object
over that is checked alone. What still grows with a pack is per-object
bookkeeping, a few hundred bytes for each entry.
