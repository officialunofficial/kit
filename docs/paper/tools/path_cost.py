#!/usr/bin/env python3
# Per-path proof cost in a real git repository, from the entries of each tree on
# the path. For every file at HEAD it computes the kit disclosure steps
# (43 + |name| per path component, plus 33 + |separator| for each step of its
# keyed tree proof, SPEC-MERKLE-OBJECTS section 5.8, over entries sorted by
# name bytes) and the git cost (the sum of the raw tree objects on the path).
# Neither figure includes the commit, the header or the payload.
# Usage: python3 -I -B path_cost.py <git-repo>   (a blobless clone suffices)
import statistics, subprocess, sys

repo = sys.argv[1]


def git(*args):
    return subprocess.run(["git", "-C", repo, *args], check=True,
                          capture_output=True).stdout


def separators(p, names):
    """Separators of the keyed proof of the entry at position p."""
    out, level, size = [], 0, len(names)
    while size > 1:
        sibling = p ^ 1
        if sibling < size:
            out.append(names[(p | 1) << level])
        p, size, level = p // 2, (size + 1) // 2, level + 1
    return out


root = git("rev-parse", "HEAD^{tree}").decode().strip()
sizes = {}
for line in git("cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype) %(objectsize)").split(b"\n"):
    if line:
        oid, typ, size = line.split()
        if typ == b"tree":
            sizes[oid.decode()] = int(size)

children, tree_oid, files = {}, {b"": root}, []
for rec in git("ls-tree", "-r", "-t", "-z", "HEAD").split(b"\0"):
    if not rec:
        continue
    meta, path = rec.split(b"\t", 1)
    _, typ, oid = meta.split()
    parent, _, name = path.rpartition(b"/")
    children.setdefault(parent, []).append(name)
    if typ == b"tree":
        tree_oid[path] = oid.decode()
    elif typ == b"blob":
        files.append(path)

pos = {}
for parent, names in children.items():
    names.sort()
    for i, name in enumerate(names):
        pos[(parent, name)] = i

kit, gitc, depth = [], [], []
for path in files:
    parts = path.split(b"/")
    k = g = 0
    for j, name in enumerate(parts):
        parent = b"/".join(parts[:j])
        i = pos[(parent, name)]
        k += 43 + len(name) + sum(33 + len(sep) for sep in separators(i, children[parent]))
        g += sizes[tree_oid[parent]]
    kit.append(k); gitc.append(g); depth.append(len(parts))


def q(xs, f):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(f * len(xs)))]


widest = max(len(v) for v in children.values())
print(f"files={len(files)} dirs={len(children)} widest={widest} "
      f"depth median={statistics.median(depth)} max={max(depth)}")
for label, xs in (("kit", kit), ("git", gitc)):
    print(f"{label} median={q(xs, 0.5)} p99={q(xs, 0.99)} max={max(xs)}")
