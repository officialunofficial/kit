#!/usr/bin/env python3
# Count the sibling digests that the sibling-selection rule of
# SPEC-MERKLE-OBJECTS section 5.3 puts on the wire for a set of positions.
# Usage: python3 -B sibling_count.py [chunk_count]   (default 16384)
import sys


def sibs(positions, leaf_count):
    P, size, n = set(positions), leaf_count, 0
    while size > 1:
        for p in sorted(P):
            s = (p + 1 if p + 1 < size else p) if p % 2 == 0 else p - 1
            if s != p and s not in P:
                n += 1
        P, size = {p // 2 for p in P}, (size + 1) // 2
    return n


N = int(sys.argv[1]) if len(sys.argv) > 1 else 16384
worst = max(sibs([0, i + 1], N + 1) for i in range(N))
print(f"chunks={N} leaves={N + 1} worst-case chunk-step siblings={worst} bytes={32 * worst}")
print("golden fixture (15 chunks, chunk 1):", sibs([0, 2], 16))
print("golden fixture root tree (5 entries), per position:", [sibs([i], 5) for i in range(5)])
