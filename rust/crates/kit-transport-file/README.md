# kit-transport-file

File-system transport for kit, used in tests and local content-addressed
repositories.

This is a real local/served transport, not a test-only fixture: it's the
backend for `kit+file://` remotes and for repositories served via
`kit serve`. It also doubles as the in-tree test transport. See
`docs/specs/SPEC-TRANSPORT.md` for the `Transport` trait it implements.

## On-disk layout

```text
<root>/
  packs/<64-hex>          — raw pack bytes, written atomically
  refs/heads/main         — 65-byte wire (64-hex + '\n')
  refs/tags/v1.0          — nested dirs created on demand
```

## Multi-ref commits

`advance_refs` commits a branch head and its packmap as one step
(SPEC-REFS §5.1.3), so `supports_atomic_advance` is true and a push may
re-baseline a long pack chain. Under the stripe locks of both refs, in
ascending stripe order, it checks both conditions, then makes an intent
record durable under `<root>/.kit/refs/intents/`: that is the commit point.
Readers report the record's new ids until the ref files hold them, and the
next writer on either stripe finishes a record a crash left behind.

## CAS atomicity guarantees

| Variant    | Mechanism                                                        | Race behavior |
| ---------- | ----------------------------------------------------------------- | --------------- |
| `Any`      | `write_atomic`: tmp file → `fsync` → `rename` → parent           | Last writer wins; `rename(2)` is atomic on POSIX, so no half-written file is ever exposed. |
| `Missing`  | `write_create_new`: same tmp+fsync, then a hard-link              | Only the first writer succeeds; the loser gets `AlreadyExists` → `RefConflict`. |
| `Match(H)` | OS file-locks and in-process locks around read-then-`write_atomic` | Atomic across processes on the same root, via `std::fs::File::lock` on the ref's stripe `<root>/.kit/refs/refs-<hh>.lock` and on the repo lock `<root>/.kit/refs/.lock` (shared), held for the read-compare-write and released on `Drop` (including on panic). Writes to refs in different stripes run in parallel. |
