//! Properties every `Transport::commit_refs` must hold (SPEC-TRANSPORT
//! §1.3), checked against a model over random requests.

use std::collections::BTreeMap;

use kit_core::hash::Hash;
use kit_core::protocol::{
    CommitRefsOutcome, RefUpdate, RefWriteCondition, Transport, TransportError,
};
use kit_core::refs::PACKMAP_REF_PREFIX;

/// A small deterministic generator, so a failing seed replays.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap_or(0)
    }
}

fn id(byte: u8) -> Hash {
    [byte; 32]
}

/// The names requests draw from: three branches (head and packmap) and two
/// tags.
fn universe() -> Vec<String> {
    let mut names = Vec::new();
    for b in 0..3 {
        names.push(format!("refs/heads/b{b}"));
        names.push(format!("{PACKMAP_REF_PREFIX}b{b}"));
    }
    for t in 0..2 {
        names.push(format!("refs/tags/t{t}"));
    }
    names
}

/// A random request: 1 to 4 names, the packmap of each head included,
/// each with a condition that holds or fails against `model`.
fn request(rng: &mut Rng, model: &BTreeMap<String, Hash>) -> Vec<RefUpdate> {
    let all = universe();
    let mut names: Vec<String> = Vec::new();
    for _ in 0..=rng.below(3) {
        let name = all[rng.below(all.len())].clone();
        if let Some(branch) = name.strip_prefix("refs/heads/") {
            names.push(format!("{PACKMAP_REF_PREFIX}{branch}"));
        }
        names.push(name);
    }
    names.sort();
    names.dedup();
    // Request order is not byte order, so a conflict must pick its name.
    for i in (1..names.len()).rev() {
        names.swap(i, rng.below(i + 1));
    }
    names
        .into_iter()
        .map(|name| {
            let current = model.get(&name).copied();
            let condition = match rng.below(5) {
                0 => RefWriteCondition::Any,
                1 => RefWriteCondition::Missing,
                2 => RefWriteCondition::Match(id(200)),
                _ => current.map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
            };
            let value = id(u8::try_from(1 + rng.below(100)).unwrap_or(1));
            RefUpdate {
                name,
                condition,
                value,
            }
        })
        .collect()
}

/// Run `steps` random requests on a fresh transport from `make` for each of
/// `seeds` seeds and check after each one: a request whose every condition
/// holds commits every ref (all); one where any fails changes nothing (or
/// none) and names the first failed ref in byte order, which is in the
/// request; refs the request does not name never change.
///
/// # Panics
/// On the first request whose outcome or resulting refs differ from the
/// model, naming the seed.
pub fn check_against_model(make: &dyn Fn() -> Box<dyn Transport>, seeds: u64, steps: usize) {
    for seed in 0..seeds {
        let tx = make();
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut model: BTreeMap<String, Hash> = BTreeMap::new();
        for step in 0..steps {
            let updates = request(&mut rng, &model);
            let failed = updates
                .iter()
                .filter(|u| {
                    let current = model.get(&u.name).copied();
                    match u.condition {
                        RefWriteCondition::Any => false,
                        RefWriteCondition::Missing => current.is_some(),
                        RefWriteCondition::Match(h) => current != Some(h),
                    }
                })
                .map(|u| u.name.clone())
                .min();
            let expected = if let Some(name) = failed {
                CommitRefsOutcome::Conflict { name }
            } else {
                for u in &updates {
                    model.insert(u.name.clone(), u.value);
                }
                CommitRefsOutcome::Committed
            };
            let got = tx.commit_refs(&updates);
            assert!(
                matches!(&got, Ok(Some(outcome)) if *outcome == expected),
                "seed {seed} step {step}: {updates:?} gave {got:?}, want {expected:?}"
            );
            for name in universe() {
                assert_eq!(
                    tx.read_ref(&name).ok().flatten(),
                    model.get(&name).copied(),
                    "seed {seed} step {step}: {name}"
                );
            }
            let listed = tx.list_refs("").map_or(usize::MAX, |refs| refs.len());
            assert_eq!(listed, model.len(), "seed {seed} step {step}: listing");
        }
    }
}

/// Requests a conforming transport refuses before it takes any lock: none,
/// a name twice, one name a directory of another, and a branch head
/// without its packmap. None of them changes a ref.
///
/// # Panics
/// When a request is accepted or a ref changes.
pub fn check_refusals(tx: &dyn Transport) {
    let any = |name: &str| RefUpdate {
        name: name.to_owned(),
        condition: RefWriteCondition::Any,
        value: id(1),
    };
    let requests = [
        vec![],
        vec![any("refs/tags/a"), any("refs/tags/a")],
        vec![any("refs/tags/a"), any("refs/tags/a/b")],
        vec![any("refs/heads/main")],
        vec![
            any("refs/heads/main"),
            any(&format!("{PACKMAP_REF_PREFIX}other")),
        ],
        vec![any("refs/tags/.hidden")],
    ];
    for updates in requests {
        let got = tx.commit_refs(&updates);
        assert!(
            matches!(got, Err(TransportError::InvalidRef(_))),
            "{updates:?} gave {got:?}"
        );
    }
    assert_eq!(tx.list_refs("").map(|r| r.len()).ok(), Some(0));
}

/// `writers` threads each commit `steps` times to their own branch head,
/// packmap and tag, each conditioned on its previous values. Disjoint
/// requests never conflict, whatever stripes or locks they share.
///
/// # Panics
/// On any conflict or error, or a ref without its last value.
pub fn check_disjoint_writers(
    make: &(dyn Fn() -> Box<dyn Transport> + Sync),
    writers: usize,
    steps: usize,
) {
    std::thread::scope(|s| {
        for w in 0..writers {
            s.spawn(move || {
                let tx = make();
                let names = [
                    format!("refs/heads/w{w}"),
                    format!("{PACKMAP_REF_PREFIX}w{w}"),
                    format!("refs/tags/w{w}"),
                ];
                let mut prev: Option<Hash> = None;
                for step in 0..steps {
                    let value = id(u8::try_from(step % 250 + 1).unwrap_or(1));
                    let updates: Vec<RefUpdate> = names
                        .iter()
                        .map(|name| RefUpdate {
                            name: name.clone(),
                            condition: prev
                                .map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
                            value,
                        })
                        .collect();
                    let got = tx.commit_refs(&updates);
                    assert!(
                        matches!(got, Ok(Some(CommitRefsOutcome::Committed))),
                        "writer {w} step {step}: {got:?}"
                    );
                    prev = Some(value);
                }
            });
        }
    });
    let tx = make();
    for w in 0..writers {
        let last = id(u8::try_from((steps - 1) % 250 + 1).unwrap_or(1));
        assert_eq!(
            tx.read_ref(&format!("refs/tags/w{w}")).ok().flatten(),
            Some(last)
        );
    }
}
