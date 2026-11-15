use super::*;
use crate::{CloneRemote, NoopObserver, PushLease, PushOptions, PushTarget, TransportSource};
use kit_core::object::{Blob, Commit, EntryMode, Identity, Tree, TreeEntry};
use kit_core::protocol::Transport;
use kit_transport_memory::MemoryTransport;

fn write(store: &ObjectStore, object: &Object) -> Hash {
    store
        .write(&kit_core::serialize::serialize(object).unwrap())
        .unwrap()
}

/// `count` commits on `parent`, each over a tree of one file of its own.
fn commits(store: &ObjectStore, parent: Option<Hash>, count: usize, seed: &str) -> Vec<Hash> {
    let mut out = Vec::new();
    let mut parent = parent;
    for n in 0..count {
        let blob = write(
            store,
            &Object::Blob(Blob {
                data: format!("{seed} {n}").into_bytes(),
            }),
        );
        let tree = write(
            store,
            &Object::Tree(Tree {
                entries: vec![TreeEntry {
                    name: b"f".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: blob,
                }],
            }),
        );
        let commit = write(
            store,
            &Object::Commit(Commit::new_unannotated(
                tree,
                parent.into_iter().collect(),
                Identity::ed25519([1; 32]),
                [1; 32],
                format!("{seed} {n}").into_bytes(),
                1_700_000_000,
                [0; 64],
            )),
        );
        out.push(commit);
        parent = Some(commit);
    }
    out
}

/// One tag whose base search runs out of budget sends its whole closure;
/// another tag of the push keeps its base.
#[test]
fn a_tag_past_the_base_walk_budget_sends_its_closure_and_others_keep_their_bases() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("work");
    let layout = crate::init_clone_dir(
        &path,
        &CloneRemote {
            name: "default".to_owned(),
            url: "kit+memory://x".to_owned(),
            kind: "memory".to_owned(),
        },
    )
    .unwrap();
    let store = ObjectStore::open(&layout).unwrap();
    let tx = MemoryTransport::new();
    let source = TransportSource::new(&tx);
    let main = commits(&store, None, 1, "main");
    refs::write_ref(&layout, "main", &main[0]).unwrap();
    let options = PushOptions {
        target: PushTarget::Branch {
            local: "main".to_owned(),
            remote: "main".to_owned(),
            lease: PushLease::Force,
        },
        ..PushOptions::default()
    };
    crate::push(&path, &source, &options).unwrap();
    let packmap = tx.read_ref("refs/kit/packmap/main").unwrap().unwrap();

    let near = commits(&store, Some(main[0]), 2, "near");
    let far = commits(&store, Some(main[0]), 8, "far");
    refs::write_tag(&layout, "near", &near[1]).unwrap();
    refs::write_tag(&layout, "far", &far[7]).unwrap();

    let context = PushContext::new(&source, &NoopObserver, &store);
    let results = push_tags_with(
        &layout,
        &store,
        &context,
        "default",
        &TagSelection::All,
        false,
        crate::push::DEFAULT_PACK_PAYLOAD_CAP,
        4,
    )
    .unwrap();
    assert!(
        results
            .iter()
            .all(|r| matches!(r.outcome, TagPushOutcome::Created { .. })),
        "{results:?}"
    );
    let node = |tag: &str| {
        let key = tx
            .read_ref(&format!("refs/kit/tagmap/{tag}"))
            .unwrap()
            .unwrap();
        let bytes = tx
            .download_blob(&PackKey::from_hash(key), None, u64::MAX)
            .unwrap();
        kit_core::transfer::decode_packlist(&bytes).unwrap()
    };
    assert_eq!(node("near").prev, Some(packmap));
    assert_eq!(node("far").prev, None, "no base: the whole closure");
}

/// The memo answers a later tag's search from an earlier one's walk.
#[test]
fn the_base_memo_answers_a_later_search() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    let base = commits(&store, None, 1, "base");
    let above = commits(&store, Some(base[0]), 10, "above");
    let mut search = BaseSearch {
        candidates: HashMap::from([(base[0], vec!["main".to_owned()])]),
        excluded: HashSet::new(),
        memo: HashMap::new(),
        seeded: false,
        seeds: 0,
        reads: HashMap::new(),
        budget: 11,
    };
    let mut budget = 11;
    assert_eq!(
        search.nearest(&store, above[9], &mut budget).unwrap(),
        Some(base[0])
    );
    assert_eq!(budget, 1, "ten commits walked above the candidate");
    // Every commit on the path is remembered, so a search from one of them
    // visits nothing new, even with no budget left.
    let mut budget = 0;
    assert_eq!(
        search.nearest(&store, above[4], &mut budget).unwrap(),
        Some(base[0])
    );
    // A candidate that gives no base is passed over.
    search.excluded.insert(base[0]);
    let mut budget = 100;
    assert_eq!(search.nearest(&store, above[4], &mut budget).unwrap(), None);
}

/// A commit below a candidate, on its own history, finds that candidate
/// once the candidates' ancestries are seeded, and so does a commit that
/// forks from that history.
#[test]
fn a_seeded_search_finds_the_branch_above_a_commit() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    let main = commits(&store, None, 10, "main");
    let fork = commits(&store, Some(main[3]), 1, "fork");
    let mut search = BaseSearch {
        candidates: HashMap::from([(main[9], vec!["main".to_owned()])]),
        excluded: HashSet::new(),
        memo: HashMap::new(),
        seeded: false,
        seeds: 0,
        reads: HashMap::new(),
        budget: 100,
    };
    let mut budget = 100;
    assert_eq!(search.nearest(&store, main[2], &mut budget).unwrap(), None);
    search.seed(&store).unwrap();
    for start in [main[2], fork[0]] {
        let mut budget = 100;
        assert_eq!(
            search.nearest(&store, start, &mut budget).unwrap(),
            Some(main[9])
        );
    }
}
