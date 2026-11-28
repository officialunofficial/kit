---
spec: SPEC-SHALLOW
version: 0
status: draft-advisory
audience: implementers of shallow clone, fetch depth and the commands that walk history
---

# SPEC-SHALLOW &mdash; shallow clone and the history boundary

Status: **Draft, advisory.** This is a design. No release ships it, and
`kit clone --depth` stays a usage error until the work in §11 lands. When it
lands, this document becomes normative and the THREAT-MODEL text of §9 goes
into THREAT-MODEL.md.
Scope: what a shallow repository holds, the trust model of its boundary, the
boundary record, the protocol that fills it, and how each command behaves at
the boundary. See SPEC-CONVENTIONS §2 for the keywords.

---

## 1. Decision

**Go**, with these limits for the first version:

- The trust model is the hash-anchored boundary (§3). A shallow repository
  never reports a commit beyond its boundary as verified.
- Only servers that build packs on request serve a shallow fetch: the Connect
  service (`kit+https`) and `kit serve` over SSH. A file or S3 remote refuses
  `--depth` with a typed error. It never falls back to a full clone in silence.
- A full clone stays the default. Shallow is opt-in for each clone or fetch.
- A shallow repository can push a fast-forward of a branch that the remote
  holds (§7). It cannot create the first branch of an empty remote.
- The git bridge does not change: export refuses a shallow repository and
  import still needs the full git history (§8).

The reasons: the boundary costs no integrity of the checked-out tree, because
a commit ID covers its tree and its parent IDs. What a shallow repository gives
up is the signature check of the commits it omits. THREAT-MODEL §3.1 states
that a fetch proves each signature is well-formed but does not bind the key to
a trust root. So the omitted checks protect less than they appear to, and the
loss is visible (§3.3) instead of silent.

## 2. Terms

- **Window.** The commits that a shallow repository holds for one tip.
- **Boundary commit.** A commit in the window with at least one parent that is
  not in the window.
- **Boundary record.** The file `.kit/shallow` (SPEC-REFS §2), which lists the
  boundary commits.
- **Depth.** The number of commits from the tip along the shortest parent
  path. Depth 1 holds the tip alone.
- **Deepen.** A fetch that moves the boundary toward the roots.
- **Unshallow.** A deepen that removes the boundary record.

The window for `(tip, depth)` is the set of commits at a shortest parent
distance of less than `depth` from `tip`. The distance of `tip` is 0. A depth
of 0 is a usage error. This matches `git clone --depth`.

For several tips, the window is the union of the windows of each tip, and the
boundary is computed over that union: a commit is a boundary commit only when
a parent is in no window.

## 3. Trust model

### 3.1 What a commit ID authenticates

A commit's serialized bytes hold its tree ID and its parent IDs (SPEC-OBJECTS).
Its ID is the BLAKE3 hash of those bytes. So once the tip ID is trusted, every
commit of the window and every parent ID of a boundary commit is fixed by the
hash chain. A server cannot substitute a different boundary commit, a
different tree, or a different parent ID without changing the tip ID. The
checked-out tree of a shallow clone is as authentic as that of a full clone.

### 3.2 What a shallow repository gives up

1. The content of the commits beyond the boundary, so `log`, `blame` and the
   merge base stop there (§6).
2. The signature check of the commits beyond the boundary. A full fetch checks
   each commit it introduces, down to a tip that an earlier signed fetch
   verified (THREAT-MODEL §3.1). A shallow fetch checks each commit of the
   window and stops at the boundary.

### 3.3 No silent trust

A shallow repository MUST keep the two classes apart in every output:

- A commit in the window whose signature checks is **verified**, as today.
- A commit beyond the boundary is **beyond the shallow boundary**. No command
  reports it as verified, unsigned or missing. `kit verify` of a revision
  whose history reaches the boundary checks the window, prints one line that
  names the boundary, and exits 0. A new `kit verify --full` flag exits
  non-zero in a shallow repository.
- A deepen or an unshallow checks the signature of each commit it introduces,
  exactly as a full fetch does. Once the record is gone, the repository is
  indistinguishable from a full clone of the same tips.

### 3.4 Options not taken

| Option | Why not |
|---|---|
| **Server-asserted boundary.** The server states that it checked the history beyond the boundary, and the client records that. | A remote cannot authenticate its own claims (SPEC-HISTORY-PROOF, remote descriptors). THREAT-MODEL §3.1 treats the remote author as hostile. The claim adds no assurance beyond §3.1, and it makes an unchecked commit look checked. |
| **Signed checkpoint.** A trusted key signs an attestation that the history to a commit passed a signature policy, and the client trusts the boundary on that. | It needs a binding from keys to trust roots, which kit does not have yet (THREAT-MODEL §3.1). It can come later as an extra layer on top of §3, through SPEC-ATTESTATIONS, without a change to the boundary record. |
| **History-proof boundary.** The client takes a first-parent ancestry proof (SPEC-HISTORY-PROOF) for the boundary. | A proof covers the first-parent chain only, not the commits of other parents, and it carries no signature check. It proves membership, which the hash chain already proves for the window. |
| **No shallow clone.** Keep `--depth` a usage error. | Large histories cost a full download for CI and one-off reads. The hash chain keeps the tree authentic, so the cost buys little for those uses. |

## 4. The boundary record

`.kit/shallow` keeps the form of SPEC-REFS §2 and §6: one 64-character
lowercase hex commit ID and `\n` per line, at most 1 MiB, in the common
directory (SPEC-WORKTREE). This document adds:

- **Canonical form.** Lines are sorted by byte value with no duplicates. A
  writer MUST write the canonical form. A reader MUST reject a file that is
  not canonical, with a typed error, as it rejects a file over the cap.
- **No empty file.** When the boundary is empty, the file is removed. An
  empty file is not canonical.
- **Atomic replacement.** A writer writes a temporary file in the common
  directory, syncs it, and renames it over `.kit/shallow`, under the lock
  `shallow.lock`. SPEC-CONCURRENCY places `shallow.lock` after the ref-history
  lock of the fetch that holds it and before any CAS lock.
- **Absent means full.** A repository with no record is a full repository.
  No command treats a missing parent as a boundary unless the record lists the
  child.

## 5. Invariants

- **SH1, closure.** Each object reachable from a ref, where the walk does not
  follow the parents of a commit in the record, is present.
- **SH2, an exact record.** For each commit reachable from a ref in that walk,
  the commit is in the record if and only if at least one of its parents is
  absent.
- **SH3, a deterministic window.** The window and the boundary of a set of
  `(tip, depth)` pairs are a pure function of the commit graph. Two servers
  with the same objects send the same set of commits.
- **SH4, depth agrees with a full walk.** A window with a depth at or above
  the longest parent path from the tip is the full history, and its record is
  empty.
- **SH5, deepen only adds.** A deepen never removes an object or a ref, and it
  only removes or replaces records with commits nearer the roots. An unshallow
  of tips `T` leaves the same object set and the same refs as a full clone of
  `T`.
- **SH6, verify to the boundary.** A shallow fetch checks the signature of
  each commit of the window that it introduces, and no other. A deepen checks
  each commit it introduces.
- **SH7, a safe push.** A push from a shallow repository never publishes a
  head whose packmap chain fails to rebuild the closure of the head
  (SPEC-TRANSPORT §7.2).
- **SH8, crash order.** A fetch writes objects, then the record, then refs. A
  crash at any point leaves SH1 and SH2 true for the refs on disk. Objects
  that no ref reaches are left for `kit gc`.
- **SH9, no silent trust.** No output names a commit beyond the boundary as
  verified (§3.3).

## 6. Commands at the boundary

| Command | Behavior in a shallow repository |
|---|---|
| `log`, `rev-list`, `shortlog` | The walk stops at each commit in the record. `log --decorate` marks that commit `grafted`, as git does. |
| `blame`, `log -L` | A line older than the boundary is assigned to the boundary commit, with a mark that it is a boundary. |
| `merge-base`, `merge`, `rebase`, `cherry-pick` | When the merge base can be beyond the boundary, the command exits with the typed error "the merge base is beyond the shallow boundary" and the hint `kit fetch --deepen`. It never merges against a wrong base. |
| `describe` | A tag beyond the boundary is not found. With no tag in the window, the command fails as it does with no tag. |
| `verify` | §3.3. |
| `gc` | Reachability stops at the record. `gc` never removes a commit in the record. |
| `fsck` | A missing parent of a commit in the record is not corruption. A missing parent of any other commit is. A record that breaks SH2 is corruption. |
| `push` | §7. |
| `bisect` | A step that needs a commit beyond the boundary fails with the same hint. |
| History proofs | A shallow repository does not publish first-parent ancestry (SPEC-HISTORY-PROOF): it cannot hold the chain from the root. Verifying a proof needs no history and still works. |
| Attestation sync | An attestation about a commit beyond the boundary is fetched and stored, and reported as beyond the boundary, not as verified. |

## 7. Push

A shallow repository sends the objects of its new commits, as any push does.
The remote holds the full closure of its own head (SPEC-TRANSPORT §7.2). So the
push is safe when the remote head is in the local window, or is an ancestor of
a commit in the record: then every object the push omits is on the remote.

The rule: a push from a shallow repository MUST check that the remote head of
the target ref is present locally and is an ancestor of the pushed tip by a
walk inside the window. Otherwise the push exits with a typed error before it
uploads a pack. A push that creates a ref on a remote whose other refs reach
the boundary MAY use the same check against one of those refs, as the base of
its packmap graft (SPEC-TRANSPORT §1). A push to an empty remote always fails.

## 8. Protocol

### 8.1 Why dumb storage cannot serve it

On a file or S3 remote, a branch is a packmap chain of the packs each push
uploaded (SPEC-TRANSPORT §7.2). A re-baseline lists those packs again. It does
not repack them. The objects of the tip tree are spread over old packs, so a
depth-limited fetch would download almost the same bytes as a full one. Such a
remote refuses `--depth` until it can store a window pack (§12).

### 8.2 The window request

A server that builds packs adds one request:

```
DownloadWindow { tips: [commit id], depth: u32, have: [commit id] }
  -> stream of pack bytes (SPEC-PACKFILE), then the boundary list
```

- The server computes the window and boundary of §2 over `tips` and `depth`.
  It sends a pack of the commits of the window and the snapshot closure of each
  (SPEC-DISCLOSURE §7.1, snapshot mode), less the closure of `have`.
- The boundary list is advisory. The client computes the boundary again from
  the objects it received and MUST reject a response whose list differs (SH3).
- The client checks that the pack holds the full snapshot closure of each
  window commit before it writes the record or any ref (SH1, SH8).
- Limits: `depth` at most 2^31 - 1, at most 1,000 tips, and the pack limits
  of the transport. A deepen sends the record as `have` and a greater depth.

The Connect service advertises the request in `GetServerInfo` (STC §2.1). The
SSH conversation (SPEC-TRANSPORT §4.2) advertises it in `HelloResponse` and
adds the request frame and its two reply frames.

`kit serve` stores packs as pushes uploaded them, like a file remote. To
answer a window it unpacks every pack into a private object store in the
system temporary directory, builds the window pack from that store, and
removes the store when the request ends. The server pays for the full
unpack; the client downloads only the window. A client that finds no
advertisement fails with "this remote cannot serve a shallow fetch".

### 8.3 Sparse

Shallow limits the history and sparse limits the paths. They are orthogonal.
The first version makes `--depth` with a sparse filter a usage error, because
SPEC-SPARSE-CHECKOUT witnesses cover one tree and the window holds many. A
later version can send a witness for each window commit.

## 9. Changes to THREAT-MODEL when this ships

Add to the defenses of §3.1, after the item on unsigned or forged history:

> - Shallow history. A clone or fetch with `--depth` holds a window of
>   commits. The tree and the parent IDs of each commit of the window are
>   fixed by the hash chain from the tip, so a remote cannot alter them. The
>   fetch checks the signature of each commit of the window and of no commit
>   beyond it. No command reports a commit beyond the boundary as verified
>   (SPEC-SHALLOW §3.3). A deepen or `--unshallow` checks each commit it
>   introduces, as a full fetch does.

Add to the list of what kit does not defend in §3.1:

> - The signatures of commits beyond the shallow boundary. A shallow repository
>   has not seen them. Run `kit fetch --unshallow` before an audit that needs
>   them.

## 10. The git bridge

Import does not change: a kit parent ID is the BLAKE3 hash of the translated
parent, so the import needs the full git history (SPEC-GIT-IMPORT §1.3).
Export needs the full kit history for the same reason, so `kit git export`
from a shallow repository exits with a typed error. A git client can clone a
mirror that kit exported with `git clone --depth` as usual. That is git's own
feature.

## 11. Implementation plan

Each step lands its tests first and then its code. Each step adds its rows to
docs/INVARIANTS.md and its parsers to docs/FUZZ.md.

1. **Boundary record and walks.** Canonical read and write of `.kit/shallow`,
   `shallow.lock`, and a boundary-aware walk shared by `log`, `rev-list`,
   `merge-base`, `gc` and `fsck`. Tests: SH2 property tests on random graphs,
   a fuzz target for the record parser, and the typed merge-base error.
2. **Window computation and window pack.** A pure function from tips and depth
   to window and boundary, and a pack builder over the snapshot closure.
   Tests: SH3 and SH4 as property tests, and a check that depth equal to the
   history length gives the full closure.
3. **Protocol.** `DownloadWindow` in the Connect service and the SSH
   conversation, the capability, and the typed refusal of file and S3
   remotes. Tests: a client that rejects a wrong boundary list or a pack that
   misses part of a closure.
4. **Clone and fetch.** `clone --depth`, `fetch --depth`, `fetch --deepen`,
   `fetch --unshallow` and `rev-parse --is-shallow-repository`, with the
   signature check of SH6 and the output of §3.3. Tests: differential tests
   against `git clone --depth` for `log` output, SH5 against a full clone, and
   crash points for SH8.
5. **Push and the other commands.** The push rule of §7, export refusal,
   history-proof refusal, attestation reporting, and the CLI.md, man page,
   PARITY.md and THREAT-MODEL.md text. Tests: SH7 with a push from a shallow
   clone to a remote that moved, and each row of §6.

## 12. Later work

- A window pack that a push writes to dumb storage, at a content-addressed key
  as SPEC-TRANSPORT §6.6 does for sparse, so S3 and file remotes can serve
  depth 1.
- Signed checkpoints (§3.4) once keys bind to trust roots.
- `--shallow-since` and `--shallow-exclude`.
- Sparse witnesses for each commit of a window (§8.3).
