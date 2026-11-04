#!/usr/bin/env python3
# Per-path proof cost in a real git repository, from the width of each tree on
# the path. For every file at HEAD it computes the kit disclosure steps
# (75 + |name| + 32 * siblings per path component, with the exact sibling count
# of the selection rule of SPEC-MERKLE-OBJECTS section 5.3 over entries sorted
# by name bytes) and the git cost (the sum of the raw tree objects on the
# path). Neither figure includes the commit, the header or the payload.
# Usage: python3 -I -B path_cost.py <git-repo>   (a blobless clone suffices)
import statistics, subprocess, sys

repo = sys.argv[1]


def git(*args):
    return subprocess.run(["git", "-C", repo, *args], check=True,
                          capture_output=True).stdout


def sibs(p, n):
    k = 0
    while n > 1:
        s = (p + 1 if p + 1 < n else p) if p % 2 == 0 else p - 1
        k += s != p
        p, n = p // 2, (n + 1) // 2
    return k


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
        pos[(parent, name)] = (i, len(names))

kit, gitc, depth = [], [], []
for path in files:
    parts = path.split(b"/")
    k = g = 0
    for j, name in enumerate(parts):
        parent = b"/".join(parts[:j])
        i, n = pos[(parent, name)]
        k += 75 + len(name) + 32 * sibs(i, n)
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
