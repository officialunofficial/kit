//! The pairing behind `kit range-diff`: match the commits of an old and a
//! new version of a series by the assignment of least total cost, as git
//! does.
//!
//! The cost of a pair is the size of the diff between the diff parts of
//! the two patches, context included; the messages do not count. A commit
//! left without a partner costs `creation_factor`% of the size of its own
//! diff part. The square assignment problem is solved with the
//! Hungarian method in `O(n^3)`, so each side is bounded by
//! [`MAX_SERIES`].

use std::collections::HashMap;

use super::diff::{WhitespaceMode, unified_hunks_opts};

/// The most commits one side of a range-diff holds.
pub const MAX_SERIES: usize = 1000;

/// The cost that rules a pair out.
const COST_MAX: i64 = 1 << 40;

/// One commit of a series, as a patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// The patch text: the message, then the diff part. Two commits with
    /// the same text are the same patch.
    pub text: Vec<u8>,
    /// The offset in `text` where the diff part starts.
    pub diff_start: usize,
    /// The number of lines of its diff part.
    pub size: u64,
}

impl Patch {
    /// The diff part of the text, which the cost of a pair compares.
    #[must_use]
    pub fn diff(&self) -> &[u8] {
        self.text.get(self.diff_start..).unwrap_or(&[])
    }
}

/// How a pair of the output compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The same patch.
    Same,
    /// A changed patch.
    Changed,
    /// An old commit with no partner.
    Dropped,
    /// A new commit with no partner.
    Added,
}

/// One line of the output: indexes into the old and the new series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    /// The old commit, when there is one.
    pub old: Option<usize>,
    /// The new commit, when there is one.
    pub new: Option<usize>,
    /// How they compare.
    pub status: Status,
}

/// The number of lines of a diff of `a` to `b` with three lines of
/// context, as git counts it: the hunk headers, the context and the changed
/// lines.
#[must_use]
pub fn diff_size(a: &[u8], b: &[u8]) -> u64 {
    let lines = |t: &[u8]| t.split(|&c| c == b'\n').count();
    match unified_hunks_opts(a, b, 3, WhitespaceMode::Exact) {
        Some(d) => u64::try_from(lines(&d).saturating_sub(1)).unwrap_or(u64::MAX),
        None => u64::try_from(lines(a) + lines(b)).unwrap_or(u64::MAX),
    }
}

/// Pair `old` with `new` and order the pairs for output, as git does: new
/// commits in order, each unpaired old commit as soon as the old commits
/// before it are shown.
///
/// # Panics
/// Never for sides of at most [`MAX_SERIES`] commits.
#[must_use]
pub fn correspond(old: &[Patch], new: &[Patch], creation_factor: u32) -> Vec<Pair> {
    let (na, nb) = (old.len(), new.len());
    let n = na + nb;
    // Identical patches pair first, each new patch with the first old one.
    let mut matched_old: Vec<Option<usize>> = vec![None; na];
    let mut matched_new: Vec<Option<usize>> = vec![None; nb];
    let mut by_text: HashMap<&[u8], Vec<usize>> = HashMap::new();
    for (j, p) in new.iter().enumerate().rev() {
        by_text.entry(p.text.as_slice()).or_default().push(j);
    }
    for (i, p) in old.iter().enumerate() {
        if let Some(j) = by_text.get_mut(p.text.as_slice()).and_then(Vec::pop) {
            matched_old[i] = Some(j);
            matched_new[j] = Some(i);
        }
    }
    let factor = i64::from(creation_factor);
    let alone = |p: &Patch| {
        i64::try_from(p.size)
            .unwrap_or(COST_MAX)
            .saturating_mul(factor)
            / 100
    };
    let mut cost = vec![vec![0i64; n]; n];
    for i in 0..na {
        for j in 0..nb {
            cost[i][j] = match (matched_old[i], matched_new[j]) {
                (Some(m), _) if m == j => 0,
                (None, None) => i64::try_from(diff_size(old[i].diff(), new[j].diff()))
                    .unwrap_or(COST_MAX)
                    .min(COST_MAX),
                _ => COST_MAX,
            };
        }
        let c = if matched_old[i].is_none() {
            alone(&old[i])
        } else {
            COST_MAX
        };
        for cell in &mut cost[i][nb..n] {
            *cell = c;
        }
    }
    for j in 0..nb {
        let c = if matched_new[j].is_none() {
            alone(&new[j])
        } else {
            COST_MAX
        };
        for row in &mut cost[na..n] {
            row[j] = c;
        }
    }
    let assigned = assignment(&cost);
    for (i, &j) in assigned.iter().enumerate().take(na) {
        if j < nb {
            matched_old[i] = Some(j);
            matched_new[j] = Some(i);
        } else {
            matched_old[i] = None;
        }
    }
    for (j, m) in matched_new.iter_mut().enumerate() {
        if m.is_some_and(|i| matched_old[i] != Some(j)) {
            *m = None;
        }
    }
    order(old, new, &matched_old, &matched_new)
}

/// The pairs in output order, as git prints them: new commits in order,
/// each unpaired old commit as soon as the old commits before it are shown.
fn order(
    old: &[Patch],
    new: &[Patch],
    matched_old: &[Option<usize>],
    matched_new: &[Option<usize>],
) -> Vec<Pair> {
    let (na, nb) = (old.len(), new.len());
    let pair = |i: Option<usize>, j: Option<usize>| {
        let status = match (i, j) {
            (Some(i), Some(j)) if old[i].text == new[j].text => Status::Same,
            (Some(_), Some(_)) => Status::Changed,
            (Some(_), None) => Status::Dropped,
            _ => Status::Added,
        };
        Pair {
            old: i,
            new: j,
            status,
        }
    };
    let mut out = Vec::with_capacity(na + nb);
    let mut shown = vec![false; na];
    let (mut i, mut j) = (0, 0);
    while i < na || j < nb {
        while i < na && shown[i] {
            i += 1;
        }
        if i < na && matched_old[i].is_none() {
            out.push(pair(Some(i), None));
            shown[i] = true;
            i += 1;
            continue;
        }
        while j < nb && matched_new[j].is_none() {
            out.push(pair(None, Some(j)));
            j += 1;
        }
        if j < nb {
            let a = matched_new[j];
            out.push(pair(a, Some(j)));
            if let Some(a) = a {
                shown[a] = true;
            }
            j += 1;
        } else {
            // Every new commit is out, and so is every old one it paired.
            i = na;
        }
    }
    out
}

/// The assignment of least total cost of a square matrix: the column of
/// each row. The Hungarian method with potentials, `O(n^3)`.
#[must_use]
pub fn assignment(cost: &[Vec<i64>]) -> Vec<usize> {
    let n = cost.len();
    if n == 0 {
        return Vec::new();
    }
    // 1-based arrays; column 0 is the virtual start.
    let inf = i64::MAX / 4;
    let mut u = vec![0i64; n + 1];
    let mut v = vec![0i64; n + 1];
    let mut row_of = vec![0usize; n + 1];
    let mut way = vec![0usize; n + 1];
    for row in 1..=n {
        row_of[0] = row;
        let mut col0 = 0usize;
        let mut minv = vec![inf; n + 1];
        let mut used = vec![false; n + 1];
        loop {
            used[col0] = true;
            let r = row_of[col0];
            let mut delta = inf;
            let mut col1 = 0usize;
            for col in 1..=n {
                if !used[col] {
                    let cur = cost[r - 1][col - 1] - u[r] - v[col];
                    if cur < minv[col] {
                        minv[col] = cur;
                        way[col] = col0;
                    }
                    if minv[col] < delta {
                        delta = minv[col];
                        col1 = col;
                    }
                }
            }
            for col in 0..=n {
                if used[col] {
                    u[row_of[col]] += delta;
                    v[col] -= delta;
                } else {
                    minv[col] -= delta;
                }
            }
            col0 = col1;
            if row_of[col0] == 0 {
                break;
            }
        }
        loop {
            let col1 = way[col0];
            row_of[col0] = row_of[col1];
            col0 = col1;
            if col0 == 0 {
                break;
            }
        }
    }
    let mut out = vec![0usize; n];
    for col in 1..=n {
        if row_of[col] > 0 {
            out[row_of[col] - 1] = col - 1;
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn patch(text: &str) -> Patch {
        Patch {
            text: text.as_bytes().to_vec(),
            diff_start: 0,
            size: u64::try_from(text.lines().count()).unwrap(),
        }
    }

    fn total(cost: &[Vec<i64>], a: &[usize]) -> i64 {
        a.iter().enumerate().map(|(r, &c)| cost[r][c]).sum()
    }

    /// Every permutation of `0..n`.
    fn permutations(n: usize) -> Vec<Vec<usize>> {
        if n == 0 {
            return vec![Vec::new()];
        }
        let mut out = Vec::new();
        for p in permutations(n - 1) {
            for at in 0..=p.len() {
                let mut q = p.clone();
                q.insert(at, n - 1);
                out.push(q);
            }
        }
        out
    }

    #[test]
    fn identical_series_pair_in_order() {
        let s = [patch("a\n+1\n"), patch("b\n+2\n"), patch("c\n+3\n")];
        let pairs = correspond(&s, &s, 60);
        assert!(pairs.iter().all(|p| p.status == Status::Same));
        assert_eq!(
            pairs.iter().map(|p| (p.old, p.new)).collect::<Vec<_>>(),
            [(Some(0), Some(0)), (Some(1), Some(1)), (Some(2), Some(2))]
        );
    }

    #[test]
    fn drops_adds_and_changes() {
        let old = [
            patch("one\n+1\n"),
            patch("drop\n+x\n+y\n+z\n"),
            patch("three\n+1\n+2\n+3\n+4\n+5\n+6\n+7\n+8\n"),
        ];
        let new = [
            patch("one\n+1\n"),
            patch("three\n+1\n+2\n+3\n+X\n+5\n+6\n+7\n+8\n"),
            patch("add\n+q\n+r\n+s\n"),
        ];
        let got: Vec<Status> = correspond(&old, &new, 60)
            .iter()
            .map(|p| p.status)
            .collect();
        assert_eq!(
            got,
            [
                Status::Same,
                Status::Dropped,
                Status::Changed,
                Status::Added
            ]
        );
    }

    proptest! {
        /// The assignment is a permutation with the least total cost, as
        /// brute force finds it.
        #[test]
        fn assignment_is_optimal(cells in proptest::collection::vec(0i64..20, 0..=36), n in 0usize..=6) {
            let n = n.min(cells.len().isqrt());
            let cost: Vec<Vec<i64>> = (0..n).map(|r| cells[r * n..(r + 1) * n].to_vec()).collect();
            let a = assignment(&cost);
            let mut seen = a.clone();
            seen.sort_unstable();
            prop_assert_eq!(seen, (0..n).collect::<Vec<_>>());
            let best = permutations(n).iter().map(|p| total(&cost, p)).min().unwrap_or(0);
            prop_assert_eq!(total(&cost, &a), best);
        }

        /// Every commit of both series appears exactly once, a series
        /// against itself is all `Same`, and swapping the series swaps
        /// drops and adds.
        #[test]
        fn correspondence_invariants(
            old in proptest::collection::vec("[ab]\n[+-][xyz]{1,3}\n", 0..6),
            new in proptest::collection::vec("[ab]\n[+-][xyz]{1,3}\n", 0..6),
        ) {
            let old: Vec<Patch> = old.iter().map(|t| patch(t)).collect();
            let new: Vec<Patch> = new.iter().map(|t| patch(t)).collect();
            let pairs = correspond(&old, &new, 60);
            let mut olds: Vec<usize> = pairs.iter().filter_map(|p| p.old).collect();
            let mut news: Vec<usize> = pairs.iter().filter_map(|p| p.new).collect();
            olds.sort_unstable();
            news.sort_unstable();
            prop_assert_eq!(olds, (0..old.len()).collect::<Vec<_>>());
            prop_assert_eq!(news, (0..new.len()).collect::<Vec<_>>());
            prop_assert!(correspond(&old, &old, 60).iter().all(|p| p.status == Status::Same));
            let dropped = pairs.iter().filter(|p| p.status == Status::Dropped).count();
            let added = pairs.iter().filter(|p| p.status == Status::Added).count();
            let back = correspond(&new, &old, 60);
            let swapped_pairs = pairs.len() - dropped - added;
            let back_pairs = back.iter().filter(|p| p.old.is_some() && p.new.is_some()).count();
            prop_assert_eq!(back_pairs, swapped_pairs);
            prop_assert_eq!(back.iter().filter(|p| p.status == Status::Added).count(), dropped);
        }
    }
}
