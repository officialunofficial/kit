//! The cost bounds of [`TagProver`], counted in objects read.

use super::*;
use crate::observer::NoopObserver;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Tag, Tree, TreeEntry};
use kit_core::sign::{self, KeyPair};

struct Repo {
    _dir: tempfile::TempDir,
    layout: RepoLayout,
    store: ObjectStore,
    key: KeyPair,
    seq: std::cell::Cell<u64>,
}

impl Repo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        Self {
            _dir: dir,
            layout,
            store,
            key: KeyPair::generate().unwrap(),
            seq: std::cell::Cell::new(0),
        }
    }

    fn put(&self, object: &Object) -> Hash {
        self.store
            .write(&kit_core::serialize::serialize(object).unwrap())
            .unwrap()
    }

    /// A commit over its own one-file tree.
    fn commit(&self, parent: Option<Hash>, signed: bool) -> Hash {
        self.seq.set(self.seq.get() + 1);
        let n = self.seq.get();
        let blob = self.put(&Object::Blob(Blob {
            data: format!("{n}").into_bytes(),
        }));
        let tree = self.put(&Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"f".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        }));
        let mut commit = Commit::new_unannotated(
            tree,
            parent.into_iter().collect(),
            Identity::ed25519(self.key.public.0),
            self.key.public.0,
            format!("c{n}").into_bytes(),
            n,
            [0; 64],
        );
        if signed {
            commit.signature = sign::sign_commit(&commit, &self.key).unwrap().0;
        }
        self.put(&Object::Commit(commit))
    }

    /// `n` signed commits on `parent`, oldest first.
    fn line(&self, parent: Option<Hash>, n: usize) -> Vec<Hash> {
        let mut out = Vec::new();
        let mut at = parent;
        for _ in 0..n {
            let c = self.commit(at, true);
            out.push(c);
            at = Some(c);
        }
        out
    }

    fn tag(&self, name: &str, target: Hash) -> Hash {
        let mut tag = Tag {
            target,
            target_type: ObjectType::Commit,
            name: name.as_bytes().to_vec(),
            tagger: Identity::ed25519(self.key.public.0),
            signer: self.key.public.0,
            message: Vec::new(),
            timestamp: 1,
            signature: [0; 64],
        };
        tag.signature = sign::sign_tag(&tag, &self.key).unwrap().0;
        self.put(&Object::Tag(tag))
    }

    fn prove(
        &self,
        prover: &mut TagProver,
        verified: &mut VerifiedHistory,
        name: &str,
        value: Hash,
    ) -> Proof {
        prover
            .prove(
                &self.store,
                &self.layout,
                &NoopObserver,
                verified,
                name,
                value,
            )
            .unwrap()
    }
}

/// A tag on an old commit below a tracking tip that a signed fetch verified
/// reads only the tag object: the trusted set covers the commit's closure,
/// and the verified set its history.
#[test]
fn a_tag_on_a_commit_the_tracking_refs_reach_checks_only_its_tag_object() {
    let repo = Repo::new();
    let history = repo.line(None, 50);
    let tip = *history.last().unwrap();
    refs::write_remote_ref(&repo.layout, "origin", "main", &tip).unwrap();
    // The tip an earlier signed fetch recorded.
    let mut verified: VerifiedHistory = [tip].into_iter().collect();
    let mut prover = TagProver::new(true);
    let tag = repo.tag("v1", history[9]);

    assert_eq!(
        repo.prove(&mut prover, &mut verified, "v1", tag),
        Proof::Proved
    );
    assert_eq!(prover.signed_read, 1, "the tag object only");
    assert_eq!(prover.objects_checked, 1, "the tag object only");
}

/// 64 tags along one new history: the first proof walks it, and each
/// other one reads only its tag object.
#[test]
fn tags_along_one_new_history_share_one_walk() {
    let repo = Repo::new();
    let history = repo.line(None, 64);
    let tags: Vec<(String, Hash)> = history
        .iter()
        .enumerate()
        .rev()
        .map(|(i, c)| {
            let name = format!("t{i}");
            let tag = repo.tag(&name, *c);
            (name, tag)
        })
        .collect();
    let mut verified = VerifiedHistory::new();
    let mut prover = TagProver::new(true);

    for (name, tag) in &tags {
        assert_eq!(
            repo.prove(&mut prover, &mut verified, name, *tag),
            Proof::Proved
        );
    }

    assert_eq!(prover.signed_read, 128, "each commit and tag once");
    // Each commit, tree and blob once, and each tag object.
    assert_eq!(prover.objects_checked, 256);
}

/// A failed proof adds nothing to the proved set, and a second tag on the
/// same history is refused at once, through the failed set.
#[test]
fn a_second_tag_over_a_refused_history_is_refused_at_once() {
    let repo = Repo::new();
    let c1 = repo.commit(None, true);
    let c2 = repo.commit(Some(c1), false);
    let c3 = repo.commit(Some(c2), true);
    let first = repo.tag("t1", c3);
    let second = repo.tag("t2", c3);
    let mut verified = VerifiedHistory::new();
    let mut prover = TagProver::new(true);
    let unsigned = to_hex(&c2);

    let refused = repo.prove(&mut prover, &mut verified, "t1", first);
    assert!(
        matches!(&refused, Proof::Refused(TagRejectReason::Signature { hash, .. }) if *hash == unsigned),
        "{refused:?}"
    );
    assert!(prover.proved.is_empty() && verified.is_empty());
    let (read, checked) = (prover.signed_read, prover.objects_checked);

    let refused = repo.prove(&mut prover, &mut verified, "t2", second);
    assert!(
        matches!(&refused, Proof::Refused(TagRejectReason::Signature { hash, .. }) if *hash == unsigned),
        "{refused:?}"
    );
    assert_eq!(prover.signed_read, read, "no history walk ran");
    assert_eq!(prover.objects_checked, checked);
    assert!(prover.proved.is_empty());
}

/// A history past the bound refuses only its own tag.
#[test]
fn a_proof_past_the_bound_refuses_only_that_tag() {
    let repo = Repo::new();
    let long = repo.line(None, 30);
    let short = repo.line(None, 2);
    let big = repo.tag("big", *long.last().unwrap());
    let small = repo.tag("small", *short.last().unwrap());
    for signed in [true, false] {
        let mut verified = VerifiedHistory::new();
        let mut prover = TagProver::with_cap(signed, 20);
        assert!(matches!(
            repo.prove(&mut prover, &mut verified, "big", big),
            Proof::Refused(TagRejectReason::ClosureTooLarge(20))
        ));
        assert_eq!(
            repo.prove(&mut prover, &mut verified, "small", small),
            Proof::Proved
        );
    }
}

/// A tag nesting more than 16 tags is refused, and T5 checks only the
/// outermost one.
#[test]
fn the_peel_is_bounded_and_names_only_the_outermost_tag() {
    let repo = Repo::new();
    let c = repo.commit(None, true);
    let mut at = c;
    for i in 0..MAX_TAG_DEPTH {
        at = repo.tag(&format!("inner{i}"), at);
    }
    let mut verified = VerifiedHistory::new();
    let mut prover = TagProver::new(true);
    assert_eq!(
        repo.prove(
            &mut prover,
            &mut verified,
            &format!("inner{}", MAX_TAG_DEPTH - 1),
            at
        ),
        Proof::Proved
    );
    let over = repo.tag("over", at);
    assert_eq!(
        repo.prove(&mut prover, &mut verified, "over", over),
        Proof::Refused(TagRejectReason::TooDeep)
    );
}

/// An opt-out fetch published a tracking ref at signed `C3` over unsigned
/// `C2`. `C3` is reached by a local ref, so its closure is trusted, but no
/// signed fetch verified it, so a tag above it is checked down to `C2`.
#[test]
fn a_tracking_tip_no_signed_fetch_verified_is_not_trusted_for_signatures() {
    let repo = Repo::new();
    let c1 = repo.commit(None, true);
    let c2 = repo.commit(Some(c1), false);
    let c3 = repo.commit(Some(c2), true);
    refs::write_remote_ref(&repo.layout, "origin", "b2", &c3).unwrap();
    let tag = repo.tag("t", c3);
    let mut verified = VerifiedHistory::new();

    let refused = TagProver::new(true)
        .prove(
            &repo.store,
            &repo.layout,
            &NoopObserver,
            &mut verified,
            "t",
            tag,
        )
        .unwrap();
    assert!(
        matches!(&refused, Proof::Refused(TagRejectReason::Signature { hash, .. }) if *hash == to_hex(&c2)),
        "{refused:?}"
    );

    let mut prover = TagProver::new(false);
    assert_eq!(
        repo.prove(&mut prover, &mut VerifiedHistory::new(), "t", tag),
        Proof::Proved
    );
    assert_eq!(prover.objects_checked, 1, "the closure check stops at C3");
}

/// One blob is missing from a long history. The first tag over it walks
/// the history; each later tag over the same history stops where the first
/// walk found the closure incomplete. A pack that brings the blob drops that
/// memory, and the tags then prove.
#[test]
fn tags_over_one_history_with_a_missing_blob_share_one_walk() {
    let repo = Repo::new();
    let history = repo.line(None, 200);
    let base = *history.last().unwrap();
    // The blob of the oldest commit.
    let Object::Commit(c) = repo.store.read_object(&history[0]).unwrap() else {
        unreachable!()
    };
    let Object::Tree(tree) = repo.store.read_object(&c.tree_hash).unwrap() else {
        unreachable!()
    };
    let blob = tree.entries[0].object_hash;
    let blob_bytes = repo.store.read(&blob).unwrap();
    repo.store.remove_object(&blob).unwrap();

    let tips: Vec<(String, Hash)> = (0..20)
        .map(|i| {
            let tip = repo.commit(Some(base), true);
            let name = format!("t{i}");
            let tag = repo.tag(&name, tip);
            (name, tag)
        })
        .collect();
    for signed in [false, true] {
        let mut verified = VerifiedHistory::new();
        let mut prover = TagProver::new(signed);
        let (name, tag) = &tips[0];
        assert_eq!(
            repo.prove(&mut prover, &mut verified, name, *tag),
            Proof::Missing(to_hex(&blob))
        );
        let first = prover.objects_checked;
        assert!(first > 400, "the first walk reads the history: {first}");
        for (name, tag) in &tips[1..] {
            assert_eq!(
                repo.prove(&mut prover, &mut verified, name, *tag),
                Proof::Missing(to_hex(&blob))
            );
        }
        let later = prover.objects_checked - first;
        assert!(
            later <= 19 * 6,
            "each later tag reads only its own objects: {later}"
        );

        repo.store.write(&blob_bytes).unwrap();
        prover.refresh_missing(&repo.store);
        for (name, tag) in &tips {
            assert_eq!(
                repo.prove(&mut prover, &mut verified, name, *tag),
                Proof::Proved
            );
        }
        repo.store.remove_object(&blob).unwrap();
    }
}

/// A commit is missing from a long signed history. The signature walk of the
/// first tag reads down to it; each later tag stops where that walk did.
#[test]
fn tags_over_one_history_with_a_missing_commit_share_one_signature_walk() {
    let repo = Repo::new();
    let history = repo.line(None, 200);
    let base = *history.last().unwrap();
    let gone = history[10];
    repo.store.remove_object(&gone).unwrap();
    let mut verified = VerifiedHistory::new();
    let mut prover = TagProver::new(true);
    for i in 0..20 {
        let tip = repo.commit(Some(base), true);
        let name = format!("t{i}");
        let tag = repo.tag(&name, tip);
        assert_eq!(
            repo.prove(&mut prover, &mut verified, &name, tag),
            Proof::Missing(to_hex(&gone))
        );
    }
    // The first walk reads its tag, its tip and 189 commits of the history;
    // each later one its tag and its tip.
    assert_eq!(prover.signed_read, 2 + 189 + 19 * 2);
}

/// A local store failure while a tag's pack is written fails the fetch; a
/// store refusal the remote's object causes refuses only that tag.
#[test]
fn a_store_failure_while_a_tag_pack_applies_is_fatal() {
    use kit_core::pack::PackError;
    let io = SyncError::from(PackError::Store(StoreError::Io(std::io::Error::other(
        "disk full",
    ))));
    assert!(matches!(io, SyncError::Io(_)));
    assert!(matches!(ChainFailure::from(io), ChainFailure::Fatal(_)));
    let too_large = SyncError::Pack(PackError::Store(StoreError::ObjectTooLarge));
    assert!(matches!(
        ChainFailure::from(too_large),
        ChainFailure::Refused(TagRejectReason::Transfer(_))
    ));
}

/// Names in a directory relation conflict, in both directions; siblings and
/// names that only share a prefix do not.
#[test]
fn name_conflicts_are_directory_relations() {
    let names: BTreeSet<String> = ["v1", "rel/a", "x"].into_iter().map(String::from).collect();
    assert_eq!(name_conflict(&names, "v1/rc"), Some("v1".to_owned()));
    assert_eq!(name_conflict(&names, "rel"), Some("rel/a".to_owned()));
    assert_eq!(name_conflict(&names, "v10"), None);
    assert_eq!(name_conflict(&names, "rel/b"), None);
    assert_eq!(name_conflict(&names, "x"), None);
    assert_eq!(name_conflict(&names, "re"), None);
}

/// A tag read or write that meets a file where a directory should be, or the
/// reverse, is a name clash; any other I/O failure is not.
#[test]
fn a_directory_clash_from_the_file_system_is_a_name_clash() {
    use std::io::{Error, ErrorKind};
    for kind in [ErrorKind::NotADirectory, ErrorKind::IsADirectory] {
        assert!(is_name_clash(&refs::RefError::Io(Error::from(kind))));
    }
    assert!(!is_name_clash(&refs::RefError::Io(Error::other(
        "disk full"
    ))));
    assert_eq!(
        TagRejectReason::NameConflict { other: None }.to_string(),
        "conflicts with the name of an existing tag"
    );
    assert_eq!(
        TagRejectReason::NameConflict {
            other: Some("v1".to_owned())
        }
        .to_string(),
        "conflicts with existing tag `v1`"
    );
}
