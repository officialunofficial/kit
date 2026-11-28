//! The choice of tag behind `kit describe`: the tag that reaches a commit
//! with the fewest commits between them.
//!
//! The distance from a tag `t` to a commit `r` is the number of commits
//! that `r` reaches and `t` does not, which `rev-list t..r` counts. When `t`
//! is an ancestor of `r`, everything `t` reaches `r` reaches too, so the
//! distance is the size of the ancestry of `r` less the size of the
//! ancestry of `t`.

use std::collections::HashSet;

use crate::hash::Hash;
use crate::object::Object;
use crate::store::{ObjectSource, StoreError};

/// A tag that may name the commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The tag name.
    pub name: String,
    /// The commit the tag names.
    pub commit: Hash,
    /// Seconds since the epoch: the tag date of an annotated tag, or the
    /// commit date of a lightweight one. A newer tag wins a tie.
    pub date: u64,
}

/// The tag [`nearest`] chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Described {
    /// The index of the tag in the candidates.
    pub index: usize,
    /// The commits that the described commit reaches and the tag does not.
    pub distance: u64,
}

/// The commits `start` reaches, itself included, through `parents`.
///
/// # Errors
/// Whatever `parents` returns.
pub fn ancestry<E>(
    start: Hash,
    mut parents: impl FnMut(Hash) -> Result<Vec<Hash>, E>,
) -> Result<HashSet<Hash>, E> {
    let mut seen = HashSet::new();
    let mut stack = vec![start];
    while let Some(c) = stack.pop() {
        if seen.insert(c) {
            stack.extend(parents(c)?);
        }
    }
    Ok(seen)
}

/// The candidate that reaches `commit` at the smallest distance. A tie
/// goes to the newest date, then to the lesser name. `None` when no
/// candidate reaches `commit`.
///
/// # Errors
/// Whatever `parents` returns.
pub fn nearest<E>(
    commit: Hash,
    candidates: &[Candidate],
    mut parents: impl FnMut(Hash) -> Result<Vec<Hash>, E>,
) -> Result<Option<Described>, E> {
    let reach = ancestry(commit, &mut parents)?;
    let total = u64::try_from(reach.len()).unwrap_or(u64::MAX);
    let mut best: Option<(Described, &Candidate)> = None;
    for (index, c) in candidates.iter().enumerate() {
        if !reach.contains(&c.commit) {
            continue;
        }
        let own = u64::try_from(ancestry(c.commit, &mut parents)?.len()).unwrap_or(u64::MAX);
        let here = Described {
            index,
            distance: total.saturating_sub(own),
        };
        let better = best.as_ref().is_none_or(|(b, bc)| {
            (here.distance, std::cmp::Reverse(c.date), &c.name)
                < (b.distance, std::cmp::Reverse(bc.date), &bc.name)
        });
        if better {
            best = Some((here, c));
        }
    }
    Ok(best.map(|(d, _)| d))
}

/// The parents of a commit or a remix in `store`. An object the store does
/// not hold, as below a shallow boundary, has none.
///
/// # Errors
/// [`StoreError`] when an object cannot be read for another reason.
pub fn parents_in<S: ObjectSource + ?Sized>(store: &S, h: Hash) -> Result<Vec<Hash>, StoreError> {
    match store.read_object(&h) {
        Ok(Object::Commit(c)) => Ok(c.parents),
        Ok(Object::Remix(r)) => Ok(r.parents),
        Ok(_) | Err(StoreError::ObjectNotFound(_)) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;

    use super::*;

    fn h(i: usize) -> Hash {
        crate::hash::hash(&i.to_le_bytes())
    }

    /// A DAG where commit `i` has the parents `dag[i]`, each less than `i`.
    fn parents_of(dag: &[Vec<usize>]) -> impl FnMut(Hash) -> Result<Vec<Hash>, Infallible> + '_ {
        let index: BTreeMap<Hash, usize> = (0..dag.len()).map(|i| (h(i), i)).collect();
        move |c| Ok(dag[index[&c]].iter().map(|p| h(*p)).collect())
    }

    fn tag(name: &str, commit: usize, date: u64) -> Candidate {
        Candidate {
            name: name.to_owned(),
            commit: h(commit),
            date,
        }
    }

    #[test]
    fn the_nearest_reaching_tag_wins_and_a_tie_goes_to_the_newest() {
        // 0 - 1 - 2 - 3, and 4 off 1, merged at 5 with 3.
        let dag = vec![vec![], vec![0], vec![1], vec![2], vec![1], vec![3, 4]];
        let tags = [tag("old", 0, 1), tag("mid", 2, 2), tag("side", 4, 3)];
        let d = nearest(h(3), &tags, parents_of(&dag)).unwrap().unwrap();
        assert_eq!((d.index, d.distance), (1, 1));
        // From 5: mid leaves 3, 4, 5 and side leaves 2, 3, 5. Side is newer.
        let d = nearest(h(5), &tags, parents_of(&dag)).unwrap().unwrap();
        assert_eq!((d.index, d.distance), (2, 3));
        let none = nearest(h(0), &tags[1..], parents_of(&dag)).unwrap();
        assert_eq!(none, None);
    }

    proptest::proptest! {
        #[test]
        fn describe_invariants(
            shape in proptest::collection::vec(
                (proptest::num::usize::ANY, proptest::option::of(proptest::num::usize::ANY)),
                1..14,
            ),
            tags in proptest::collection::vec(
                (proptest::num::usize::ANY, 0u64..4),
                0..5,
            ),
            at in proptest::num::usize::ANY,
        ) {
            let dag: Vec<Vec<usize>> = shape
                .iter()
                .enumerate()
                .map(|(i, (a, b))| {
                    if i == 0 {
                        return Vec::new();
                    }
                    let mut ps = vec![a % i];
                    if let Some(b) = b
                        && b % i != a % i
                    {
                        ps.push(b % i);
                    }
                    ps
                })
                .collect();
            let n = dag.len();
            let cands: Vec<Candidate> = tags
                .iter()
                .enumerate()
                .map(|(k, (c, d))| tag(&format!("t{k}"), c % n, *d))
                .collect();
            let target = at % n;
            let reach = ancestry(h(target), parents_of(&dag)).unwrap();
            // The model distance of each tag: commits the target reaches and
            // the tag does not, as rev-list counts them.
            let distance = |c: &Candidate| {
                let theirs = ancestry(c.commit, parents_of(&dag)).unwrap();
                reach.difference(&theirs).count() as u64
            };
            match nearest(h(target), &cands, parents_of(&dag)).unwrap() {
                None => {
                    proptest::prop_assert!(cands.iter().all(|c| !reach.contains(&c.commit)));
                }
                Some(d) => {
                    let chosen = &cands[d.index];
                    // Reachability and count.
                    proptest::prop_assert!(reach.contains(&chosen.commit));
                    proptest::prop_assert_eq!(d.distance, distance(chosen));
                    // Minimality, with the tie rule.
                    for c in cands.iter().filter(|c| reach.contains(&c.commit)) {
                        proptest::prop_assert!(distance(c) >= d.distance);
                        if distance(c) == d.distance {
                            proptest::prop_assert!(c.date <= chosen.date);
                        }
                    }
                    // Exact: a tag on the target is chosen at distance 0.
                    if cands.iter().any(|c| c.commit == h(target)) {
                        proptest::prop_assert_eq!(d.distance, 0);
                        proptest::prop_assert_eq!(chosen.commit, h(target));
                    }
                }
            }
        }
    }
}
