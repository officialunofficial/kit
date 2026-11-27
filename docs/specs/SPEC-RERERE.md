---
spec: SPEC-RERERE
version: 1
status: draft-normative
audience: implementers of local conflict-resolution reuse
---

# SPEC-RERERE &mdash; recorded conflict resolutions

Status: **Draft, normative** for the local resolution cache. Local-only;
not exchanged between peers. See SPEC-CONVENTIONS §2.
Scope: when kit records a conflict resolution, how it names the conflict,
the layout of `rr-cache/`, and when a recorded resolution is applied.

---

## 1. Role

A branch that is rebased or merged often meets the same conflict again.
kit can record how the user resolved a conflict and write the same
resolution the next time the same conflict appears. The cache is advisory:
deleting it loses only convenience. It is never signed, never sent to a
peer, and never read from one.

The cache lives in `<common-dir>/rr-cache/`, so linked worktrees share it.

## 2. Enablement

The cache is used only when the config key `rerere.enabled` is `true`. The
default is `false`. The key runs no external code, so repository config MAY
set it, as user config may. `rerere.autoUpdate = true` makes a replayed
resolution staged as well as written (§6).

## 3. Which conflicts

Only a text conflict takes part: one whose file kit writes with
`<<<<<<< ours`, `=======` and `>>>>>>> theirs` markers. That is a
modify/modify or add/add conflict whose two sides are each absent or a
blob with no NUL byte that is valid UTF-8, with neither side a symlink or
an executable. Every other conflict is skipped.

## 4. Conflict id

Let `O` be the bytes of the ours side and `T` the bytes of the theirs
side, an absent side being empty. Let `A` be the lesser of `O` and `T` in
byte order and `B` the greater. The conflict id is

```
BLAKE3( "kit-rerere-v1" || 0x00 || u64le(len(A)) || A || u64le(len(B)) || B )
```

written as 64 lowercase hex digits. Sorting the sides makes a conflict
and the same conflict with its sides swapped share one id, as git's
normalization does.

## 5. Layout

```
rr-cache/
  version            "kit-rerere 1\n"
  <id>/
    side1            A
    side2            B
    postimage        the recorded resolution (absent until recorded)
```

kit writes `version` with the first entry. Each file is written to a
temporary file in its directory and renamed into place. A later write
replaces an earlier one; two processes that record at once leave one of
the two resolutions.

An entry is valid only when all of these hold:

- `version` holds exactly `kit-rerere 1` and a newline;
- the directory name is 64 lowercase hex digits;
- `side1` and `side2` are regular files of at most 256 MiB, `side1` is not
  greater than `side2` in byte order, and the id of §4 computed from them
  equals the directory name;
- `postimage`, when present, is a regular file of at most 256 MiB.

kit MUST NOT apply an invalid entry. It warns once for the entry and
otherwise treats the conflict as having no entry; it does not delete or
overwrite the invalid entry, except through `kit rerere clear`, `gc` or
`forget`. A `version` file with any other content makes kit warn and ignore
the whole cache.

## 6. Replay

When a merge, cherry-pick, revert or rebase step writes the material of a
conflict, kit looks up each text conflict by its id:

- With a valid entry that holds a `postimage`, kit replaces the file with
  the postimage and prints `Resolved '<path>' using previous resolution.`
  The index keeps the conflict, so the operation does not continue until
  the user stages the file, unless `rerere.autoUpdate` is `true`, in which
  case kit stages the postimage as a regular file.
- Otherwise kit creates the entry's `side1` and `side2` if they are absent
  and prints `Recorded preimage for '<path>'`.

## 7. Recording

When the user continues a rebase, cherry-pick or revert, or commits a
merge, after resolving its conflicts, kit records the staged content of
each text conflict as the `postimage` of its entry, creating the entry if
needed, and prints `Recorded resolution for '<path>'.` A path resolved by
deletion records nothing. A postimage equal to the staged content is left
as it is, with no message.

## 8. Maintenance

- `kit rerere forget <path>` deletes the postimage of the current conflict
  at `<path>`, so the next resolution is recorded afresh.
- `kit rerere clear` deletes every entry.
- `kit rerere gc` deletes each entry whose `postimage` was last modified
  more than `gc.rerereResolved` days ago (default 60), and each entry with
  no postimage whose `side1` was last modified more than
  `gc.rerereUnresolved` days ago (default 15).
