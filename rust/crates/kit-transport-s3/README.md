# kit-transport-s3

Generic S3-compatible transport for kit, with `SigV4` signing over rustls.

Implements the 7-verb `Transport` trait (`docs/specs/SPEC-TRANSPORT.md`) on top of
a `reqwest` blocking client with an in-crate `SigV4` signer (`sigv4`). The
store must support conditional writes (`If-Match` and `If-None-Match`). A ref
compare-and-swap sends the MD5 of the expected ref body as `If-Match`. The
store must therefore return the body MD5 as the `ETag` of a single `PUT`.
Stores that do this include Cloudflare R2 and MinIO.

URL shape: `kit+s3://<endpoint>/<bucket>[/prefix]`. Credentials are pulled
from `KIT_R2_ACCESS_KEY_ID` / `KIT_R2_SECRET_ACCESS_KEY` at `connect` time
(the names are historical and apply to any S3-compatible store);
an unset pair does not fail construction &mdash; the first signed call surfaces
`TransportError::AccessDenied`.

Retry policy mirrors SPEC-TRANSPORT §7 via
`kit_core::protocol::BackoffIterator`: `5xx` and HTTP `429` retry up to 5
attempts; `412 Precondition Failed` never retries, so CAS writes can't
silently turn into duplicate `PUT`s.
