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

## CAS atomicity guarantees

| Variant    | Mechanism                                                        | Race behavior |
| ---------- | ----------------------------------------------------------------- | --------------- |
| `Any`      | `write_atomic`: tmp file → `fsync` → `rename` → parent           | Last writer wins; `rename(2)` is atomic on POSIX, so no half-written file is ever exposed. |
| `Missing`  | `write_create_new`: same tmp+fsync, then a hard-link              | Only the first writer succeeds; the loser gets `AlreadyExists` → `RefConflict`. |
| `Match(H)` | OS file-locks and in-process locks around read-then-`write_atomic` | Atomic across processes on the same root, via `std::fs::File::lock` on the ref's stripe `<root>/.kit/refs/refs-<hh>.lock` and on the repo lock `<root>/.kit/refs/.lock` (shared), held for the read-compare-write and released on `Drop` (including on panic). Writes to refs in different stripes run in parallel. |

Every ref write holds its stripe lock and the shared repo lock, whatever its
condition.

## Two-ref advance

`advance_refs` moves a branch head and its packmap under the locks of both
refs. It checks both conditions before it writes either ref, so a conflict
changes nothing. It writes the packmap, then the head, and puts the packmap
back when the head write fails. An advance that creates a ref holds the repo
lock exclusive instead. Readers take no lock: a reader, or a crash between
the two writes, can see the new packmap with the old head. So the transport
reports `supports_serialized_advance`, not `supports_atomic_advance`.

## Ref reads

A ref read reports the ref absent when a ref file sits above its name
(`refs/heads/a` for `refs/heads/a/b`) or a directory of other refs sits at
it. A listing under a prefix that names a ref file is empty. Other I/O
failures of a ref read are errors.
