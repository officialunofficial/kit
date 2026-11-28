---
spec: SPEC-PATCH
version: 1
status: draft-normative
audience: implementers of patch application (`kit apply`, `kit am`)
---

# SPEC-PATCH &mdash; applying patches and patch mails

Status: **Draft, normative** for `kit apply` and `kit am`. A patch is
local input, never a signed object, and is not exchanged by the kit
protocol. See SPEC-CONVENTIONS §2.
Scope: the unified-diff text kit reads, the bounds on it, how a patch is
applied, how a mailbox splits into patch mails, and the state of a paused
`kit am`.

---

## 1. Role

`kit diff` and `kit git format-patch` write patches. This spec lets a
contributor without push access send a change that kit applies. The input
is hostile: it comes from mail or the web. Every rule below either accepts
a patch whole or refuses it before any file, index entry or ref changes.

## 2. Patch text

A patch is a sequence of file patches. Text before the first file patch,
between file patches and after the last is ignored, so a mail body, a
`---` summary and a signature may surround the diff.

A file patch starts at a line `diff --git a/<old> b/<new>`, or at a line
`--- <old>` followed by a line `+++ <new>` when no `diff --git` line came
first. After a `diff --git` line, these extended header lines may follow,
in any order:

```
old mode <mode>            new mode <mode>
deleted file mode <mode>   new file mode <mode>
rename from <path>         rename to <path>
similarity index <n>%      dissimilarity index <n>%
index <id>..<id>[ <mode>]
```

then `--- <old>` and `+++ <new>`, which are absent when the file patch has
no hunk (a pure rename or mode change). `<old>` and `<new>` are
`/dev/null`, or a path with one leading component (`a/`, `b/` or any other)
that kit strips. A path in double quotes uses git's C escapes (`\\`, `\"`,
`\a`, `\b`, `\t`, `\n`, `\v`, `\f`, `\r`, and three octal digits for one
byte). An unquoted path on a `---` or `+++` line ends at the first tab. A
path is refused when, after stripping, it is empty, absolute, holds an
empty, `.` or `..` component, or is not a valid index path (SPEC-INDEX),
which refuses a component that names the repository directory.

On a `diff --git` line two unquoted paths that hold a space are ambiguous.
kit takes the split that gives the same path on both sides. When none
does, the paths come from the `rename from` and `rename to` lines or the
`---` and `+++` lines, and a file patch with none of these is refused.

A hunk is `@@ -<l>[,<s>] +<l>[,<s>] @@[ <text>]` followed by its body. A
missing `<s>` is 1. Each body line starts with ` ` (context), `-` (removed)
or `+` (added). A line `\ No newline at end of file` says that the line
before it has no newline on its side. The body must hold exactly `<s>` old
lines (context and removed) and `<s>` new lines (context and added).

kit refuses, as malformed: a hunk whose counts disagree with its body, a
body line with any other first byte, a hunk outside a file patch, a file
patch that names a path twice, and a mode other than `100644` or `100755`.
It refuses a `GIT binary patch`, a `Binary files ... differ` line, a
`copy from` or `copy to` line, and mode `120000`, each with its own error,
because kit does not apply them.

## 3. Bounds

- The patch text is at most 64 MiB.
- A patch holds at most 100,000 file patches and 1,000,000 hunks.
- A line number or count is at most 2^31 - 1 and is checked before use.
- A mailbox is at most 64 MiB and `kit am` takes at most 9,999 mails.

## 4. Application

kit applies the file patches in order to an image of each file: its
content in the worktree, in the index (`--cached`), or in both
(`--index`, where the two must be equal for every path the patch names).

- A file patch that creates a file needs the path absent from the image.
  One that deletes a file needs the whole file to equal the old side of
  its hunks. One that renames moves the image from `<old>` to `<new>`,
  and `<new>` must be absent.
- A hunk applies where its old lines, context and removed, equal the
  image lines. kit tries the line the header names first, then the lines
  nearest it, one at a time on each side, and takes the first match. No
  context line may differ: kit never applies with fuzz.
- The hunks of one file apply in order and must not overlap.
- A mode line sets the executable bit. Without one the mode stays.

With `-R` kit reverses every file patch first: the sides, the paths, the
modes and the creation and deletion swap. With `--check` kit does all of
the above and writes nothing. Otherwise, once every file patch applies,
kit writes the results. A patch that does not apply changes nothing.

## 5. Mailboxes

A mailbox splits at each line that `git mailsplit` splits on, a `From `
line with a ctime date. A file with no such line is one mail. Each mail
has headers up to the first empty line. A header line that starts with a
space or tab continues the one before it. kit reads:

- `From:` as the author, after decoding RFC 2047 encoded words in UTF-8
  (`B` and `Q`). A `From:` line at the very start of the body overrides
  it, as `git am` reads it.
- `Subject:` as the first line of the message, with RFC 2047 decoded, and
  with a leading `[...]` group, such as `[PATCH 2/3]`, and `Re:` removed.
- The body up to a line `---` or the first file patch, with trailing blank
  lines removed, as the rest of the message.

A mail with a `Content-Transfer-Encoding` other than `7bit` or `8bit` is
refused. A mail with no file patch is refused.

## 6. `kit am`

`kit am` applies each mail as a commit on the current branch: it applies
the patch with `--index` semantics and commits the index with the
message of §5 and the author `opaque:<From>`, signed by the applier as
any commit is. The commit date is the time of the commit; the date of the
mail is not kept.

The state of a paused `am` lives in `<worktree-state>/am/` (kit's
`rebase-apply/` holds the state of a rebase):

```
am/
  orig-head   the 64-hex commit HEAD named when am started, and a newline
  next        the 1-based number of the mail to apply next, and a newline
  last        the number of mails, and a newline
  0001 ...    each mail, as split
```

Each file is written to a temporary file and renamed into place, and
`next` is written last. While `am/` exists, merge, cherry-pick, revert,
rebase and a second `am` refuse to start.

- When a patch does not apply, kit stops, changes nothing, and exits 1.
- `--continue` commits the index with the message and author of the
  stopped mail, then goes on. It refuses when the index equals `HEAD`.
- `--skip` drops the stopped mail and goes on. A stopped mail changed
  nothing, so there is nothing to undo.
- `--abort` restores the index and the worktree to `orig-head`, moves the
  branch back to it, and removes `am/`. It refuses, before any change,
  when a tracked file holds a change that is not committed or when the
  restore would overwrite an untracked file.

When the last mail is committed, kit removes `am/`.
