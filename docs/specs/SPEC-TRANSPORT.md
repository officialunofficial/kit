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
| `upload_pack(bytes, key)` | Store a packfile keyed by its 32-byte BLAKE3 digest (`PackKey`). |
| `download_pack(key)` | Fetch a packfile by digest. |
| `pack_exists(key)` | HEAD-check a pack by digest. |
| `upload_blob(bytes, key)` | Store an auxiliary content-addressed blob &mdash; transfer metadata that is NOT a packfile (for example a packlist chain node). Shares the digest-keyed store with packs; a default trait impl delegates to `upload_pack`, so the verb only marks the *kind* explicit at the call site. |
| `download_blob(key)` | Fetch an auxiliary blob by digest. Default impl delegates to `download_pack`. |
| `update_ref(name, condition, hash)` | CAS ref write. |
| `read_ref(name)` | Read a ref's current hash, or `None` if absent. |
| `list_refs(prefix)` | List refs whose full name starts with `prefix`. Returned names have `prefix` stripped per SPEC-REFS §4. |
| `write_ref(name, hash)` | Convenience: `update_ref(name, RefWriteCondition::Any, hash)`. A default trait impl delegates here, so transports only need to implement `update_ref`. |

Consumers MUST verify that downloaded pack and auxiliary-blob bytes hash to
the caller's requested PackKey before parsing them into authoritative state,
writing objects, or recording a pack as applied. BLAKE3 covers the entire
returned byte sequence, including a pack's trailer. A transport's internal
checks, a valid pack trailer, or a content-addressed lookup URL do not replace
this consumer-boundary check. Mismatch is `InvalidResponse` and is not retryable.

### 1.1 Streaming pack transfer (additive, opt-in)

`upload_pack_streaming(key, total_bytes, chunks)` and
`download_pack_streaming(key)` are additive verbs alongside
`upload_pack`/`download_pack`: they move a pack as a sequence of
bounded-size `PackChunk { offset, data, last }` segments (the same
shape `ssh.proto`'s `PackChunk` already defines) instead of one
`Vec<u8>`, so a transport that forwards chunks straight to its own
wire never holds more than roughly one chunk in memory regardless of
total pack size. Both have default trait implementations expressed in
terms of the whole-buffer verbs &mdash; buffer-then-delegate for upload,
delegate-then-wrap-as-one-chunk for download &mdash; so **no transport is
required to change**; a caller may always use the streaming entry
point, even against a transport that has not opted into real
streaming.

The SSH transport overrides both methods to expose the
`PackChunk` frame loop it already ran internally for the
whole-buffer path (§4.2, §6). The Connect transport streams packs through a
client-streaming `UploadPack` and a server-streaming `DownloadPack` RPC
on the `kit.transport.v1` service
([SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md) §6), which reuses
this same `PackChunk` shape on the wire.

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

client → server:    one of: ListRefs, ReadRef, UpdateRef,
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
the packmap and a `DownloadPack` of each node of its pack list, even when no
branch changed: the SSH transport names no repository, so a fetch keeps no
per-branch checkpoint for it and walks each pack list again. With one node
per pack list that is one frame plus two per branch, so one session fetches
at most 4,999 branches; a fetch of more fails closed with the reply above.
`kit fetch`, `kit pull` and `kit clone` open one session each. A push walks
the branch's whole pack list over its session, and an SSH push never
re-baselines the pack list, so a push's frames grow with the number of
pushes the branch has had. The cap is not raised: it is what bounds
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
before any allocation; if the announced size is honest but the
streamed chunks overshoot, the running total check terminates the
read mid-stream rather than letting the `Vec` grow without bound.
Both paths surface as `TransportError::RemoteError` with a message
mentioning the client cap.

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
| `Match(h)`   | `If-Match: "<md5-of-expected-wire>"` | The store MUST return the body MD5 as the ETag on a single `PUT`; matching against that value is how kit gets CAS without server-side hash awareness. Multipart uploads break the equivalence (a multipart `ETag` is derived from the parts' ETags, not the body MD5), which is why §6.4's single-PUT cap gates `upload_pack` into the multipart path of §6.7 instead. |

`409` and `412` → `RefConflict`; never retried.

`upload_pack` carries no `RefWriteCondition` &mdash; packs are content-addressed
and every write is either a plain unconditional `PUT` (below the
single-PUT cap) or the multipart path of §6.7, which uses
`If-None-Match: *` on `CompleteMultipartUpload` rather than any
`Match(h)`-style condition. See §7.1 for the resulting CAS-guarantee
note on large packs.

### 6.4 Limits

- `S3_SINGLE_PUT_MAX = 5 GiB` &mdash; packs at or below this go through a
  single `PUT`; anything larger goes through the multipart path (§6.7).
- `PACK_BODY_LIMIT = 4 GiB` &mdash; the absolute pack-body ceiling enforced
  on both `upload_pack` and `download_pack` (every transport that
  ingests or emits pack bytes shares this limit; see
  [`kit_core::protocol::PACK_BODY_LIMIT`](../../rust/crates/kit-core/src/protocol.rs)).
  On a 64-bit target this is smaller than `S3_SINGLE_PUT_MAX`, so in
  today's builds it &mdash; not the single-PUT cap &mdash; is what actually bounds
  a pack's size; §6.7's multipart path exists for API correctness and
  for targets/future revisions where `PACK_BODY_LIMIT` is raised or
  not the binding constraint (for example a 32-bit target, where
  `PACK_BODY_LIMIT` widens to `usize::MAX` and `S3_SINGLE_PUT_MAX`
  becomes the real gate). Raising `PACK_BODY_LIMIT` itself is the
  streaming/constant-memory `Transport` redesign, which is out of scope here.
- `REF_BODY_LIMIT = 256` bytes (a ref is 64 hex + newline; the
  256-byte ceiling accommodates trailing whitespace and trivial
  S3 metadata).
- `REF_LIST_BODY_LIMIT = 16 MiB` for the `ListObjectsV2` XML
  response.
- HTTP timeout: 60 s per request.

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

### 6.7 Multipart upload

`upload_pack` for a pack larger than `S3_SINGLE_PUT_MAX` (§6.4) uses
the standard S3 multipart-upload API instead of a single `PUT`:

1. `POST <key>?uploads` &mdash; `CreateMultipartUpload`. The response body's
   `<UploadId>` addresses the rest of the sequence.
2. `PUT <key>?partNumber=<n>&uploadId=<id>` once per fixed-size part
   (`n` starting at 1), body = that part's raw bytes. The response
   `ETag` header is recorded for step 3. Each part is retried
   independently through the same backoff ladder as every other S3
   call (§6.5/§7) &mdash; a transient failure on one part does not require
   restarting the upload from part one.
3. `POST <key>?uploadId=<id>` &mdash; `CompleteMultipartUpload`, body a
   `<CompleteMultipartUpload>` manifest listing every part number and
   its `ETag`. Carries `If-None-Match: *` (see §6.3's note on why
   `Match(h)` doesn't apply here).
4. On any terminal failure in steps 2–3 &mdash; a part exhausting its
   retries, or `CompleteMultipartUpload` failing for a reason other
   than `409`/`412` &mdash; `DELETE <key>?uploadId=<id>` (`AbortMultipartUpload`)
   before returning the error, so a partial attempt does not leave
   orphaned parts (and their storage cost) in the bucket. `409`/`412`
   on `CompleteMultipartUpload` also triggers the abort (the object
   was never materialized), but is not itself an error &mdash; see below.

Every part except the last MUST be at least 5 MiB (an S3 API
requirement); the implementation's fixed part size (64 MiB in
production) satisfies this for any part but the last.

**Idempotency and the `409`/`412` case:** because pack objects are
content-addressed and immutable, an existing object at the target key
is guaranteed to hold identical bytes to whatever this upload would
have produced. A `409`/`412` on `CompleteMultipartUpload` (the
`If-None-Match: *` precondition losing a race against an earlier,
identical upload of the same digest) is therefore treated as the
idempotent no-op that SPEC-TRANSPORT §7 requires of `upload_pack`,
not a caller-visible error &mdash; matching the single-PUT path's
unconditional-overwrite behavior for the same scenario.

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
| S3     | `If-None-Match: *` enforced by the store | `If-Match: "<md5-of-wire>"` enforced by the store | Yes (S3 multipart breaks `Match` &mdash; see §6.3) |
| SSH    | Server-enforced via `expectation = REF_EXPECTATION_MISSING` | Server-enforced via `expectation = REF_EXPECTATION_MATCH` plus 32-byte `expected_id` | Depends on server-side ref-store atomicity |

`upload_pack` itself carries no `RefWriteCondition` (it addresses
content by digest, not by a caller-supplied CAS condition), so the
table above &mdash; `Missing`/`Match(h)` &mdash; describes `update_ref` only.
For packs large enough to cross `S3_SINGLE_PUT_MAX` (§6.4), the S3
transport's multipart path (§6.7) downgrades even the informal
CAS-adjacent guarantee the single-PUT path gets for free: a plain
`PUT` is atomic (the object either fully exists with the uploaded
bytes or doesn't exist at all), while a multipart upload's
`CompleteMultipartUpload` only supports `If-None-Match: *`
(existence-only) &mdash; never `If-Match(h)` &mdash; because a multipart `ETag`
is not the body MD5. This is an accepted downgrade specific to large
S3 packs; content-addressing (§8) makes it safe (see §6.7's
idempotency note).

---

## 8. Pack format

`upload_pack` and `download_pack` move opaque pack bytes. The pack
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
| A misbehaving peer cannot exhaust memory | `MAX_FRAME_BYTES` 1 MiB, `MAX_FRAMES_PER_CONN`, `MAX_BYTES_PER_CONN` used by the SSH frame loop (§4.4); `PACK_BODY_LIMIT` 4 GiB with pre-check and running-total streaming counters (§4.4, §6.4); ref/list body caps (§6.4) |
| `*_streaming` is additive &mdash; no transport is forced to implement real streaming | default trait impls express both streaming verbs in terms of the existing whole-buffer verbs (§1.1) |
| A `PackChunk` stream never ends silently without a `last = true` item | `upload_pack_streaming` (all overrides) rejects a stream that ends without one; `download_pack_streaming` overrides read the server's own `last` flag (§1.1, §4.2, §6) |
| Pack and blob bytes cross transports opaque and unmodified | transports MUST NOT inspect or rewrite them (§8) |

Per-transport CAS strength differs (AWS S3 multipart breaks `Match`);
the normative summary is the table in §7.1.

### Bounded pack-chain fetch staging

Fetch MUST authenticate each requested pack and pack-list node before decoding
or applying it. The CLI stages missing packs sequentially in a private temporary
directory outside the repository lock. It retains keys and file descriptors,
then reads and applies one staged pack at a time under the existing repository
lock. Signature and closure validation still precede ref publication; GC
exclusion is unchanged. A failed download, digest check, write or apply drops
the temporary-directory owner, removing completed and partial stage files.

The CLI limits staged payloads to 64 GiB, chain packs to one million, and
pack-list nodes to 100,000. Disk exhaustion and limit failures abort before ref
publication. Applied-pack markers are rechecked under the lock; stale markers
retain the existing object-closure recovery behavior. Stored-object ID lists
are checked per pack and are not accumulated over the chain.

Unpack working memory remains bounded by one pack, rather than total
chain payload size. This is not a chunk-streaming pack parser and does not
claim a small fixed RSS ceiling.
