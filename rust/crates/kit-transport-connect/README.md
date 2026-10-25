# kit-transport-connect

The native host adapter for `kit.transport.v1.TransportService`
([SPEC-TRANSPORT-CONNECT](../../../docs/specs/SPEC-TRANSPORT-CONNECT.md)).
`kit-client` owns request construction, signatures, framing, and decoding.
`ClientSource` in `kit-sync` owns bounded native uploads and ref advances.

`ConnectTransport` retains the synchronous `Transport` API and native host
configuration: TLS trust, bearer credentials, grants, admission helpers,
scheduling, and progress callbacks. The CLI lends its configured `ClientSource`
through `ConnectTransport::with_source` for `kit+https` and `kit+http`
push, fetch, pull, and clone. Other schemes use `TransportSource`.

The server side is not in this crate or in this repository.

[ConnectRPC]: https://connectrpc.com/

See `docs/specs/SPEC-TRANSPORT-CONNECT.md` for the full normative wire
contract: verb-to-RPC mapping, CAS semantics, the `TransportError` <->
Connect-code mapping (the client direction is `src/error.rs`), and the
`UploadPack`/`DownloadPack` streaming design.

## Codegen

`kit-rpc` owns the generated messages and Connect bindings behind its opt-in
`transport` feature. This client re-exports the shared types at `proto` and
`generated`; its native runtime features stay here. Both the client and server
use the canonical `<repo-root>/proto/kit/transport/v1/transport.proto`.

- **Default path**: `kit-rpc` stages committed sources from
  `generated/transport/` into `$OUT_DIR`; consumers and docs.rs need no `protoc`.
- **Regeneration path**: run `scripts/regen-transport-proto.sh` from the repo
  root (requires `protoc >= 27` on `PATH`, or via `PROTOC`). It enables
  `KIT_TRANSPORT_CODEGEN=1` for the owning crate and refreshes the single
  shared tree. Commit that output after editing the canonical proto.

## Native and wasm

The protocol client is runtime-independent and builds for native and wasm.
This adapter uses `kit-sync::NativeHttp`, a current-thread Tokio runtime and
Hyper over rustls. TLS verifies chain and hostname against the compiled Mozilla
roots. Browser clients retain browser-managed trust.

The native CLI can add trusted certificates with `http.sslCAInfo`, or with
`KIT_SSL_CA_FILE`, which takes precedence. The selected PEM file augments
the Mozilla roots for every Connect HTTPS RPC, including upload and download
streams. Certificate-chain and hostname verification remain enabled.
Missing, unreadable, empty, or malformed files are hard errors. Supply
certificates only; keep private keys out of the CA file. These settings cover
Connect remotes only: the self-updater is excluded by design, S3 remotes are
not yet covered, and wasm/browser Fetch trust is unaffected. See the
[CLI certificate trust reference](../../../docs/CLI.md#https-certificate-trust).

## Synchronous operations and recovery

`Transport` remains synchronous and object-safe. The adapter lends a borrowed
client and caller-owned `ClientSession` for each operation. Short internal locks
protect shared session state and release before host callbacks, which may reenter
the adapter. A CLI repository operation keeps the same source
from upload through the consuming advance. Stored part receipts keep their
existing format and durability boundary.

The host uses the core backoff ladder for classified transient failures.
Ambiguous writes retain their authenticated operation, body, and identity until
expiry. Grants are selected per signed request. Only `BeginUpload`, `UpdateRef`,
and ticketless `AdvanceRefs` run a one-shot admission helper, followed by a new
retry ladder. Ticket-consuming calls return admission challenges without a helper.
Pending verification and membership waits retain their deadlines and cancellation
checkpoints. HTTP request budgets are clipped to the remaining advance deadline.

## Native behavior

| Behavior | Detail |
| --- | --- |
| Uploads | Pull frames through a bounded channel. No producer thread. |
| Downloads | Incremental bounded Connect and protobuf decoding into the final pack buffer. |
| Runtime | Current-thread runtime, driven by the synchronous caller. |
| Connections | One idle connection per origin, including streams, with a ten-second idle timeout. Hyper retries only untouched requests canceled before writing starts. |
| HTTP and content coding | HTTP/1.1, gzip or identity. |
| Request budgets | 30 seconds for metadata, 300 seconds for transfers. Signing consumes the local budget. Remaining advance time bounds both. The timeout header advertises the locally clamped remaining budget. |
| Channel failures | The default `kit-client` validation applies. Body-read failures and deadlines are terminal. Metadata-bound failures retry on 429. |
| Gzip validation | The streaming decoder rejects trailing bytes and concatenated members. |
| Shared adapter operations | A caller-owned session with short internal state locks. Callbacks may reenter the adapter. |

Neither upload framing nor download decoding holds a complete framed transfer
next to the final pack. Generic `HttpTransport` implementations can use the
buffered streaming fallback. The native adapter implements bounded streaming.

Reads and signed writes both reuse connections on the same owned current-thread
runtime. Hyper's cancellation retry can recover only a request that has not
started writing. It preserves the original request, including signed headers,
nonce, body, and streaming receiver. A failure after writing starts returns to
the host's recovery policy. Idle checkout checks elapsed monotonic time
even when the runtime is paused. The channel sets `TCP_NODELAY`.

The host request policy uses the protocol client's default validation and
response limits.

This adapter keeps pack-location negotiation disabled. Native hosts using
`kit-client` directly can negotiate verified locations through
`kit-sync::NativeHttp`.

## Adapter users

The CLI uses this adapter for TLS and bearer configuration, envelope signers,
per-request grants, admission helpers, durable receipt storage, and progress.
Its epoch and visibility commands use the concrete adapter's `Completion`
result. Config validates admission header names through its public helper.
In-process sync tests use `Transport`. Server conformance uses that facade and
the generated aliases. None keeps a second per-RPC protocol driver.

## Testing

Existing roundtrip, retry, timeout, TLS, grant, admission, multipart, and
conformance tests exercise the retained adapter APIs. Native streaming tests
check incremental delivery, bounded frames and gzip, end markers, checksums,
and request deadlines. Both-backend sync push tests pin pack bytes and ids,
CAS behavior, grants, admission recovery, and receipt reuse after interruption.
