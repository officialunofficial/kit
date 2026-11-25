# kit-transport-s3

Generic S3-compatible transport for kit, with `SigV4` signing over rustls.

Implements the 7-verb `Transport` trait (`docs/specs/SPEC-TRANSPORT.md`) on top of
a `reqwest` blocking client with an in-crate `SigV4` signer (`sigv4`). The
store must support conditional writes (`If-Match` and `If-None-Match`). A ref
compare-and-swap sends the MD5 of the expected ref body as `If-Match`. The
store must therefore return the body MD5 as the `ETag` of a single `PUT`.
MinIO is one store that does this.

URL shape: `kit+s3://<endpoint>/<bucket>[/prefix]`. The transport reads
`KIT_S3_ACCESS_KEY_ID` and `KIT_S3_SECRET_ACCESS_KEY` at `connect` time. It
reads the signing region from `KIT_S3_REGION` and uses `us-east-1` when that
variable is unset. An unset key pair does not fail construction. The first
signed call returns `TransportError::AccessDenied`.

Retry policy mirrors SPEC-TRANSPORT §7 via
`kit_core::protocol::BackoffIterator`: `5xx`, HTTP `408` and `429` retry up to 5
attempts; `412 Precondition Failed` never retries, so CAS writes can't
silently turn into duplicate `PUT`s.

Packs stream both ways (SPEC-TRANSPORT §6.7). An upload hashes the pack's
body once for the `SigV4` payload hash, then sends it in one sized `PUT`,
reading it again from offset 0 on every attempt. A download writes only a
`200` answer's body to the sink, as it arrives. Neither holds the pack in
memory.

Pack uploads send `Expect: 100-continue`. They wait for `100 Continue`
before sending bytes, or at most one second if the store omits it.
An early 4xx refusal ends the upload without retry. HTTP 408 and 429,
and S3 timeout, internal-error and slow-down codes, remain retryable.
The error names the HTTP status and the S3 code from the response header
or at most 4 KiB of its XML body. Other response details stay private.
