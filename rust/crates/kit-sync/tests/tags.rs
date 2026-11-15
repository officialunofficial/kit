//! Tags travel with `clone`, `fetch` and `pull` (SPEC-TRANSPORT §1.4).
//!
//! Each test seeds a memory or file remote the way a tag push leaves one: a
//! branch chain under `refs/kit/packmap/<b>`, and for each tag a chain under
//! `refs/kit/tagmap/<t>` whose first node grafts on a node of a branch chain.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::cell::Cell;
use std::path::Path;

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{
    Blob, Commit, EntryMode, Identity, Object, ObjectType, Tag, Tree, TreeEntry,
};
use kit_core::pack::{self, PackWriter};
use kit_core::protocol::{PackKey, Transport};
use kit_core::refs::{self, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::store::ObjectStore;
use kit_core::transfer;
use kit_sync::{
    CloneRemote, FetchReport, NoopObserver, RemoteSource, SyncError, SyncOptions, TagRejectReason,
    TransportSource, clone, fetch,
};
use kit_transport_file::FileTransport;
use kit_transport_memory::MemoryTransport;

include!("support/counting.rs");

#[derive(Clone, Copy, Debug)]
enum Kind {
    Memory,
    File,
}

const KINDS: [Kind; 2] = [Kind::Memory, Kind::File];

/// A remote that a tag push has populated.
struct Remote {
    tx: Box<dyn Transport>,
    key: KeyPair,
    seq: Cell<u64>,
    _root: Option<tempfile::TempDir>,
}

impl Remote {
    fn new(kind: Kind) -> Self {
        let (tx, root): (Box<dyn Transport>, _) = match kind {
            Kind::Memory => (Box::new(MemoryTransport::new()), None),
            Kind::File => {
                let root = tempfile::tempdir().unwrap();
                (
                    Box::new(FileTransport::new(root.path().join("r"))),
                    Some(root),
                )
            }
        };
        Self {
            tx,
            key: KeyPair::generate().unwrap(),
            seq: Cell::new(0),
            _root: root,
        }
    }

    fn source(&self) -> TransportSource<'_> {
        TransportSource::new(&*self.tx)
    }

    fn next(&self) -> u64 {
        self.seq.set(self.seq.get() + 1);
        self.seq.get()
    }

    /// A commit over a one-file tree, parented on `parent`, with the objects
    /// it adds. `signed = false` leaves the signature zeroed.
    fn commit(&self, parent: Option<Hash>, signed: bool) -> (Vec<Object>, Hash) {
        let n = self.next();
        let blob = Object::Blob(Blob {
            data: format!("content {n}\n").into_bytes(),
        });
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"f.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob.id().unwrap(),
            }],
        });
        let mut commit = Commit::new_unannotated(
            tree.id().unwrap(),
            parent.into_iter().collect(),
            Identity::ed25519(self.key.public.0),
            self.key.public.0,
            format!("commit {n}").into_bytes(),
            1_700_000_000 + n,
            [0u8; 64],
        );
        if signed {
            commit.signature = sign::sign_commit(&commit, &self.key).unwrap().0;
        }
        let commit = Object::Commit(commit);
        let id = commit.id().unwrap();
        (vec![blob, tree, commit], id)
    }

    /// An annotated tag object named `name` over the commit `target`.
    fn tag_object(&self, name: &str, target: Hash, signed: bool) -> (Object, Hash) {
        let mut tag = Tag {
            target,
            target_type: ObjectType::Commit,
            name: name.as_bytes().to_vec(),
            tagger: Identity::ed25519(self.key.public.0),
            signer: self.key.public.0,
            message: format!("release {name}").into_bytes(),
            timestamp: 1_700_000_000 + self.next(),
            signature: [0u8; 64],
        };
        if signed {
            tag.signature = sign::sign_tag(&tag, &self.key).unwrap().0;
        }
        let tag = Object::Tag(tag);
        let id = tag.id().unwrap();
        (tag, id)
    }

    /// Upload one pack of `objects` and return its key.
    fn upload(&self, objects: &[Object]) -> Hash {
        let mut writer = PackWriter::new();
        for object in objects {
            writer
                .push_raw(
                    object.id().unwrap(),
                    &kit_core::serialize::serialize(object).unwrap(),
                )
                .unwrap();
        }
        let bytes = writer.finish().unwrap();
        let key = pack::pack_key(&bytes);
        self.tx
            .upload_pack(&bytes, &PackKey::from_hash(key))
            .unwrap();
        key
    }

    /// Upload a packlist node and return its key.
    fn node(&self, prev: Option<Hash>, packs: &[Hash]) -> Hash {
        let node = transfer::encode_packlist(prev, packs).unwrap();
        let key = hash::hash(&node);
        self.tx
            .upload_blob(&node, &PackKey::from_hash(key))
            .unwrap();
        key
    }

    fn set(&self, name: &str, value: Hash) {
        self.tx
            .update_ref(name, RefWriteCondition::Any, &value)
            .unwrap();
    }

    fn read(&self, name: &str) -> Option<Hash> {
        self.tx.read_ref(name).unwrap()
    }

    /// Append one pack of `objects` to branch `b`'s chain and move `b` to
    /// `tip`. Returns the new node.
    fn push_branch(&self, b: &str, objects: &[Object], tip: Hash) -> Hash {
        let prev = self.read(&format!("refs/kit/packmap/{b}"));
        let pack = self.upload(objects);
        let node = self.node(prev, &[pack]);
        self.set(&format!("refs/kit/packmap/{b}"), node);
        self.set(&format!("refs/heads/{b}"), tip);
        node
    }

    /// A new commit on `b`, signed or not. Returns the commit and its node.
    fn grow(&self, b: &str, signed: bool) -> (Hash, Hash) {
        let parent = self.read(&format!("refs/heads/{b}"));
        let (objects, tip) = self.commit(parent, signed);
        (tip, self.push_branch(b, &objects, tip))
    }

    /// Publish tag `t` at `value`. Its tag map is a node grafted on `base`
    /// carrying one pack of `objects`, or `base` itself when there are none.
    /// Returns the tag map.
    fn push_tag(&self, t: &str, objects: &[Object], value: Hash, base: Option<Hash>) -> Hash {
        let node = if objects.is_empty() {
            base.expect("a tag with no objects grafts on a branch node")
        } else {
            let pack = self.upload(objects);
            self.node(base, &[pack])
        };
        self.set(&format!("refs/kit/tagmap/{t}"), node);
        self.set(&format!("refs/tags/{t}"), value);
        node
    }
}

fn default_remote() -> CloneRemote {
    CloneRemote {
        name: "default".to_owned(),
        url: "kit+memory://x".to_owned(),
        kind: "memory".to_owned(),
    }
}

fn clone_with(source: &dyn RemoteSource, dir: &Path, options: &SyncOptions) -> FetchReport {
    clone(dir, source, &default_remote(), options, &NoopObserver)
        .unwrap()
        .pull
        .fetch
}

fn clone_from(remote: &Remote, dir: &Path) -> FetchReport {
    clone_with(&remote.source(), dir, &SyncOptions::default())
}

fn fetch_with(source: &dyn RemoteSource, dir: &Path, options: &SyncOptions) -> FetchReport {
    fetch(dir, source, "default", options, &NoopObserver).unwrap()
}

fn fetch_from(remote: &Remote, dir: &Path) -> FetchReport {
    fetch_with(&remote.source(), dir, &SyncOptions::default())
}

fn local_tag(dir: &Path, t: &str) -> Option<Hash> {
    refs::read_tag(&RepoLayout::single(dir), t).unwrap()
}

fn rejected(report: &FetchReport) -> Vec<(&str, &TagRejectReason)> {
    report
        .tags_rejected
        .iter()
        .map(|r| (r.name.as_str(), &r.reason))
        .collect()
}

fn work() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    (dir, target)
}

/// The calls of `calls` that start with `what`.
fn count(calls: &[String], what: &str) -> usize {
    calls.iter().filter(|c| c.starts_with(what)).count()
}

/// The calls of the tag phase: those from the tag listing on. A source that
/// names no repository keeps no checkpoint, so its branch phase walks the
/// branch chain again on every fetch.
fn tag_phase(calls: &[String]) -> &[String] {
    let start = calls
        .iter()
        .position(|c| c == "ListRefs refs/tags/")
        .expect("the tag phase listed tags");
    &calls[start..]
}

/// A source that serves a fixed listing under one prefix and otherwise
/// delegates.
struct Listing<'a> {
    inner: &'a dyn RemoteSource,
    prefix: &'static str,
    refs: Vec<refs::Ref>,
}

impl RemoteSource for Listing<'_> {
    fn list_branches(&self) -> Result<Vec<refs::Ref>, kit_sync::SourceError> {
        self.inner.list_branches()
    }
    fn list_refs(&self, prefix: &str) -> Result<Vec<refs::Ref>, kit_sync::SourceError> {
        if prefix == self.prefix {
            return Ok(self.refs.clone());
        }
        self.inner.list_refs(prefix)
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, kit_sync::SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.inner.download_blob_via_ref(key, name)
    }
    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.inner.download_pack_via_ref(key, name)
    }
    fn repo_cursor(&self) -> Result<Option<kit_core::protocol::RepoCursor>, kit_sync::SourceError> {
        self.inner.repo_cursor()
    }
}

/// A source whose branch listing leaves out `hidden`.
struct HideBranch<'a> {
    inner: &'a dyn RemoteSource,
    hidden: &'static str,
}

impl RemoteSource for HideBranch<'_> {
    fn list_branches(&self) -> Result<Vec<refs::Ref>, kit_sync::SourceError> {
        let mut listed = self.inner.list_branches()?;
        listed.retain(|r| r.name != self.hidden);
        Ok(listed)
    }
    fn list_refs(&self, prefix: &str) -> Result<Vec<refs::Ref>, kit_sync::SourceError> {
        self.inner.list_refs(prefix)
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, kit_sync::SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.inner.download_blob_via_ref(key, name)
    }
    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.inner.download_pack_via_ref(key, name)
    }
}

#[test]
fn lightweight_and_annotated_tags_are_fetched_and_a_signed_tag_verifies() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        remote.push_tag("light", &[], c1, Some(main));
        let (tag, v1) = remote.tag_object("v1", c1, true);
        remote.push_tag("v1", std::slice::from_ref(&tag), v1, Some(main));
        let (_dir, target) = work();

        let report = clone_from(&remote, &target);

        assert_eq!(report.tags_fetched, ["light", "v1"], "{kind:?}");
        assert!(report.tags_rejected.is_empty() && report.tag_warnings.is_empty());
        assert_eq!(local_tag(&target, "light"), Some(c1));
        assert_eq!(local_tag(&target, "v1"), Some(v1));
        // The tag arrives byte for byte and verifies, as `kit verify` checks it.
        let store = ObjectStore::open(&RepoLayout::single(&target)).unwrap();
        assert_eq!(
            store.read(&v1).unwrap(),
            kit_core::serialize::serialize(&tag).unwrap()
        );
        sign::verify_object_signature(&store.read_object(&v1).unwrap()).unwrap();
    }
}

#[test]
fn a_tag_that_would_clobber_a_local_tag_is_refused_and_branches_still_publish() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, _) = remote.grow("main", true);
        let (_dir, target) = work();
        clone_from(&remote, &target);
        let layout = RepoLayout::single(&target);
        refs::write_tag(&layout, "v1", &c1).unwrap();

        let (c2, main) = remote.grow("main", true);
        remote.push_tag("v1", &[], c2, Some(main));
        let report = fetch_from(&remote, &target);

        assert_eq!(
            rejected(&report),
            [("v1", &TagRejectReason::WouldClobber)],
            "{kind:?}"
        );
        assert_eq!(local_tag(&target, "v1"), Some(c1), "the local tag stays");
        assert_eq!(
            refs::read_remote_ref(&layout, "default", "main").unwrap(),
            Some(c2),
            "the branch is still published"
        );
    }
}

#[test]
fn a_tag_with_no_tag_map_is_refused_and_a_stale_listing_is_skipped() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, _) = remote.grow("main", true);
        // An annotated tag no chain carries, with no tag map.
        let (_tag, orphan) = remote.tag_object("orphan", c1, true);
        remote.set("refs/tags/orphan", orphan);
        let (_dir, target) = work();
        clone_from(&remote, &target);

        // A listing that still names a deleted tag.
        let source = remote.source();
        let mut listing = source.list_refs("refs/tags/").unwrap();
        listing.push(refs::Ref {
            name: "zz-gone".to_owned(),
            hash: Some(hash::hash(b"deleted since")),
        });
        let stale = Listing {
            inner: &source,
            prefix: "refs/tags/",
            refs: listing,
        };
        let report = fetch_with(&stale, &target, &SyncOptions::default());

        assert_eq!(
            rejected(&report),
            [("orphan", &TagRejectReason::NoTransferChain)],
            "{kind:?}"
        );
        assert!(report.tags_fetched.is_empty());
        assert_eq!(local_tag(&target, "zz-gone"), None);
    }
}

/// A remote tag name `refs/kit/tagmap/<t>` cannot hold is a warning, not a
/// refusal: no request is made for it, the fetch succeeds and the cursor is
/// written, so the next fetch of an unchanged remote makes no listing.
#[test]
fn a_remote_tag_name_that_is_not_pushable_warns_with_no_read() {
    let remote = Remote::new(Kind::Memory);
    let (c1, _) = remote.grow("main", true);
    let long = "t".repeat(refs::MAX_TAG_NAME_BYTES + 1);
    remote.set(&format!("refs/tags/{long}"), c1);
    let (_dir, target) = work();

    let report = clone_from(&remote, &target);

    assert_eq!(report.tag_warnings.len(), 1);
    assert_eq!(report.tag_warnings[0].name, long);
    assert!(report.tags_rejected.is_empty() && report.tags_fetched.is_empty());
    assert!(
        fetch_from(&remote, &target).remote_unchanged,
        "the cursor was written"
    );

    // A fetch that lists the remote again makes no request for the tag.
    let source = remote.source();
    let counted = CountingSource::new(&source);
    let report = fetch_with(&counted, &target, &SyncOptions::default());
    assert_eq!(report.tag_warnings.len(), 1);
    let calls = counted.take();
    assert!(
        !calls.iter().any(|c| c.contains(&long)),
        "no request names the tag: {calls:?}"
    );
    assert_eq!(count(&calls, "ListRefs refs/kit/tagmap/"), 0, "{calls:?}");
}

/// T5: a validly signed `v1.0` cannot be published as `v2.0`.
#[test]
fn a_tag_object_named_for_another_tag_is_refused() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (tag, v1) = remote.tag_object("v1.0", c1, true);
        remote.push_tag("v2.0", std::slice::from_ref(&tag), v1, Some(main));
        let (_dir, target) = work();

        let report = clone_from(&remote, &target);

        assert_eq!(
            rejected(&report),
            [(
                "v2.0",
                &TagRejectReason::NameMismatch {
                    object_name: "v1.0".to_owned()
                }
            )],
            "{kind:?}"
        );
        assert_eq!(local_tag(&target, "v2.0"), None);
    }
}

/// `latest` sorts first and names the object `v1`: it is refused, and its
/// refusal is not remembered against the object, so `v1` still publishes.
#[test]
fn two_refs_on_one_annotated_object_publish_only_the_matching_name() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (tag, v1) = remote.tag_object("v1", c1, true);
        let map = remote.push_tag("v1", std::slice::from_ref(&tag), v1, Some(main));
        remote.set("refs/kit/tagmap/latest", map);
        remote.set("refs/tags/latest", v1);
        let (_dir, target) = work();

        let report = clone_from(&remote, &target);

        assert_eq!(report.tags_fetched, ["v1"], "{kind:?}");
        assert!(matches!(
            rejected(&report)[..],
            [("latest", TagRejectReason::NameMismatch { .. })]
        ));
    }
}

#[test]
fn an_unsigned_annotated_tag_is_refused_when_signatures_are_required() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (tag, rc) = remote.tag_object("rc", c1, false);
        remote.push_tag("rc", std::slice::from_ref(&tag), rc, Some(main));
        let (_dir, target) = work();

        let report = clone_from(&remote, &target);
        assert!(
            matches!(
                rejected(&report)[..],
                [("rc", TagRejectReason::Signature { hash, .. })] if *hash == hash::to_hex(&rc)
            ),
            "{kind:?}: {:?}",
            report.tags_rejected
        );
        assert_eq!(local_tag(&target, "rc"), None);

        let (_dir, unsigned) = work();
        let report = clone_with(
            &remote.source(),
            &unsigned,
            &SyncOptions::default().with_verify_signatures(false),
        );
        assert_eq!(report.tags_fetched, ["rc"]);
        assert_eq!(local_tag(&unsigned, "rc"), Some(rc));
    }
}

/// A refused tag's objects stay in the store. A tag the remote then points
/// at them is refused too, and nothing is downloaded for it.
#[test]
fn a_tag_repointed_at_objects_a_refused_fetch_left_is_refused_with_no_download() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (objects, forged) = remote.commit(Some(c1), false);
        let map = remote.push_tag("t1", &objects, forged, Some(main));
        let (_dir, target) = work();
        let report = clone_from(&remote, &target);
        assert_eq!(report.tags_rejected.len(), 1, "{kind:?}");
        let store = ObjectStore::open(&RepoLayout::single(&target)).unwrap();
        assert!(store.contains(&forged), "the refused objects stay");

        remote.set("refs/kit/tagmap/t2", map);
        remote.set("refs/tags/t2", forged);
        let source = remote.source();
        let counted = CountingSource::new(&source);
        let report = fetch_with(&counted, &target, &SyncOptions::default());

        let reasons = rejected(&report);
        assert!(
            reasons.iter().any(|(name, reason)| *name == "t2"
                && matches!(reason, TagRejectReason::Signature { hash, .. } if *hash == hash::to_hex(&forged))),
            "{reasons:?}"
        );
        let calls = counted.take();
        let tags = tag_phase(&calls);
        assert_eq!(count(tags, "Node"), 0, "{calls:?}");
        assert_eq!(count(tags, "Pack"), 0, "{calls:?}");
        assert_eq!(local_tag(&target, "t2"), None);
    }
}

/// A refused fetch leaves unsigned `C2` in the store. A tag on its signed
/// child `C3` is refused, because the check goes below `C3`. A second tag on
/// `C3` is refused too, with the same cause.
#[test]
fn unchecked_history_below_a_signed_child_is_refused() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (objects, c2) = remote.commit(Some(c1), false);
        let t1 = remote.push_tag("t1", &objects, c2, Some(main));
        let (_dir, target) = work();
        assert_eq!(clone_from(&remote, &target).tags_rejected.len(), 1);

        let (objects, c3) = remote.commit(Some(c2), true);
        let map = remote.push_tag("t3", &objects, c3, Some(t1));
        remote.set("refs/kit/tagmap/t3b", map);
        remote.set("refs/tags/t3b", c3);
        let report = fetch_from(&remote, &target);

        let below = hash::to_hex(&c2);
        for name in ["t3", "t3b"] {
            assert!(
                rejected(&report).iter().any(|(n, reason)| *n == name
                    && matches!(reason, TagRejectReason::Signature { hash, .. } if *hash == below)),
                "{kind:?} {name}: {:?}",
                report.tags_rejected
            );
            assert_eq!(local_tag(&target, name), None);
        }
    }
}

/// The branch gap is closed: a fetch with the opt-out published a branch at
/// signed `C3` over unsigned `C2`. A signed fetch refuses that branch, and a
/// tag above `C3` is refused too, because `C2` is not proved.
#[test]
fn a_tag_above_an_unproved_commit_is_refused() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, _) = remote.grow("main", true);
        let (_dir, target) = work();
        clone_from(&remote, &target);
        let (objects, c2) = remote.commit(Some(c1), false);
        remote.push_branch("b2", &objects, c2);
        let (objects, c3) = remote.commit(Some(c2), true);
        let b2 = remote.push_branch("b2", &objects, c3);
        fetch_with(
            &remote.source(),
            &target,
            &SyncOptions::default().with_verify_signatures(false),
        );
        let layout = RepoLayout::single(&target);
        assert_eq!(
            refs::read_remote_ref(&layout, "default", "b2").unwrap(),
            Some(c3)
        );
        remote.push_tag("t", &[], c3, Some(b2));

        // With `b2` listed, the branch path refuses the fetch.
        let error = fetch(
            &target,
            &remote.source(),
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap_err();
        assert!(
            matches!(&error, SyncError::UnsignedOrInvalidObject { hash, .. } if *hash == hash::to_hex(&c2)),
            "{kind:?}: {error:?}"
        );
        assert_eq!(local_tag(&target, "t"), None);

        // With `b2` gone from the listing, the stale tracking ref still
        // reaches `C3`, and the tag is refused on its own.
        let source = remote.source();
        let hidden = HideBranch {
            inner: &source,
            hidden: "b2",
        };
        let report = fetch_with(&hidden, &target, &SyncOptions::default());
        assert!(
            matches!(
                rejected(&report)[..],
                [("t", TagRejectReason::Signature { hash, .. })] if *hash == hash::to_hex(&c2)
            ),
            "{kind:?}: {:?}",
            report.tags_rejected
        );
        assert_eq!(local_tag(&target, "t"), None);
    }
}

/// A tag whose closure is already local publishes without its tag map and
/// without a node download.
#[test]
fn a_tag_whose_closure_is_local_publishes_with_no_tag_map_read() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (_dir, target) = work();
        clone_from(&remote, &target);
        remote.push_tag("light", &[], c1, Some(main));
        let source = remote.source();
        let counted = CountingSource::new(&source);

        let report = fetch_with(&counted, &target, &SyncOptions::default());

        assert_eq!(report.tags_fetched, ["light"], "{kind:?}");
        let calls = counted.take();
        assert_eq!(count(&calls, "ListRefs refs/tags/"), 1, "{calls:?}");
        assert_eq!(count(&calls, "ListRefs refs/kit/tagmap/"), 0, "{calls:?}");
        assert_eq!(count(&calls, "ReadRef refs/kit/tagmap/"), 0, "{calls:?}");
        assert_eq!(count(&calls, "ReadRef refs/tags/"), 0, "{calls:?}");
    }
}

/// A remote whose branch chain names every pack, tag objects included, and
/// that serves no tag maps: every tag publishes from the branch's objects,
/// and the fetch never lists tag maps.
#[test]
fn a_remote_whose_branch_packlist_holds_every_tag_needs_no_tag_maps() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (mut objects, c1) = remote.commit(None, true);
        let (tag, v1) = remote.tag_object("v1", c1, true);
        objects.push(tag);
        remote.push_branch("main", &objects, c1);
        remote.set("refs/tags/v1", v1);
        remote.set("refs/tags/light", c1);
        let (_dir, target) = work();
        let source = remote.source();
        let counted = CountingSource::new(&source);

        let report = clone_with(&counted, &target, &SyncOptions::default());

        assert_eq!(report.tags_fetched, ["light", "v1"], "{kind:?}");
        let calls = counted.take();
        assert_eq!(count(&calls, "ListRefs refs/kit/tagmap/"), 0, "{calls:?}");
        assert_eq!(count(&calls, "ReadRef refs/kit/tagmap/"), 0, "{calls:?}");
    }
}

/// A tag chain grafted on the branch chain downloads only its own node and
/// pack: the walk stops at the branch node this fetch applied.
#[test]
fn a_grafted_tag_chain_downloads_only_its_pack() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (_dir, target) = work();
        clone_from(&remote, &target);
        let (tag, v1) = remote.tag_object("v1", c1, true);
        let map = remote.push_tag("v1", std::slice::from_ref(&tag), v1, Some(main));
        let source = remote.source();
        let counted = CountingSource::new(&source);

        let report = fetch_with(&counted, &target, &SyncOptions::default());

        assert_eq!(report.tags_fetched, ["v1"], "{kind:?}");
        let calls = counted.take();
        assert_eq!(
            tag_phase(&calls)
                .iter()
                .filter(|c| c.starts_with("Node"))
                .collect::<Vec<_>>(),
            [&format!("Node {}", hash::to_hex(&map))],
            "{calls:?}"
        );
        assert_eq!(count(&calls, "Pack"), 1, "{calls:?}");
    }
}

/// Tags pushed together share one node: a clone downloads it once and each
/// pack once. Tags of two groups download two nodes.
#[test]
fn tags_of_one_group_share_one_node_download() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (d1, dev) = remote.grow("dev", true);
        let mut objects = Vec::new();
        let mut values = Vec::new();
        for i in 0..100 {
            let (tag, id) = remote.tag_object(&format!("r{i:03}"), c1, true);
            objects.push(tag);
            values.push(id);
        }
        let group = remote.node(Some(main), &[remote.upload(&objects)]);
        for (i, value) in values.iter().enumerate() {
            remote.set(&format!("refs/kit/tagmap/r{i:03}"), group);
            remote.set(&format!("refs/tags/r{i:03}"), *value);
        }
        let (tag, d) = remote.tag_object("d1", d1, true);
        let other = remote.push_tag("d1", std::slice::from_ref(&tag), d, Some(dev));
        let (_dir, target) = work();
        let source = remote.source();
        let counted = CountingSource::new(&source);

        let report = clone_with(&counted, &target, &SyncOptions::default());

        assert_eq!(report.tags_fetched.len(), 101, "{kind:?}");
        let calls = counted.take();
        for node in [group, other] {
            assert_eq!(
                count(&calls, &format!("Node {}", hash::to_hex(&node))),
                1,
                "{calls:?}"
            );
        }
        let mut packs: Vec<&String> = calls.iter().filter(|c| c.starts_with("Pack")).collect();
        let all = packs.len();
        packs.sort();
        packs.dedup();
        assert_eq!(all, packs.len(), "each pack once: {calls:?}");
    }
}

/// `kit tag -d v1; kit gc; kit fetch`: the tag's pack is recorded as applied
/// and its node is cut by the stop set, so the first try finds the tag object
/// missing, and the self-heal walks the whole chain again.
#[test]
fn a_deleted_and_collected_tag_is_restored_through_self_heal() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (tag, v1) = remote.tag_object("v1", c1, true);
        remote.push_tag("v1", std::slice::from_ref(&tag), v1, Some(main));
        let (_dir, target) = work();
        clone_from(&remote, &target);
        let layout = RepoLayout::single(&target);
        refs::delete_tag(&layout, "v1").unwrap();
        let store = ObjectStore::open(&layout).unwrap();
        kit_core::ops::gc::run_gc(&store, &layout, u64::MAX / 2, 0, false).unwrap();
        assert!(!store.contains(&v1), "gc removed the tag object");

        let report = fetch_from(&remote, &target);

        assert_eq!(report.tags_fetched, ["v1"], "{kind:?}");
        assert_eq!(local_tag(&target, "v1"), Some(v1));
        assert!(store.contains(&v1));
    }
}

/// The tag listing names a value that the listed tag map does not cover
/// yet (the tag was deleted and made again between the two listings). With
/// nothing skipped, the strong re-read of both refs fixes it.
#[test]
fn a_tag_map_listing_older_than_the_tag_listing_is_fixed_by_the_strong_retry() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (mut closure, c1) = remote.commit(None, true);
        remote.push_branch("main", &closure, c1);
        // Self-contained tag chains, so that no walk is cut short.
        let (tag, old) = remote.tag_object("v1", c1, true);
        closure.push(tag);
        let old_map = remote.push_tag("v1", &closure, old, None);
        let (_dir, target) = work();
        clone_with(
            &remote.source(),
            &target,
            &SyncOptions::default().with_tags(false),
        );
        let (tag, new) = remote.tag_object("v1", c1, true);
        *closure.last_mut().unwrap() = tag;
        remote.push_tag("v1", &closure, new, None);
        let source = remote.source();
        let stale = Listing {
            inner: &source,
            prefix: "refs/kit/tagmap/",
            refs: vec![refs::Ref {
                name: "v1".to_owned(),
                hash: Some(old_map),
            }],
        };

        let report = fetch_with(&stale, &target, &SyncOptions::default());

        assert_eq!(report.tags_fetched, ["v1"], "{kind:?}: {report:?}");
        assert_eq!(local_tag(&target, "v1"), Some(new));
    }
}

/// Every tag lacks one object. Only the first refusal runs a self-heal; the
/// others keep the record, so the branch's pack is downloaded again once,
/// not once per tag.
#[test]
fn a_remote_whose_every_tag_lacks_an_object_heals_once() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (_, main) = remote.grow("main", true);
        let (_dir, target) = work();
        clone_from(&remote, &target);
        let main_pack = transfer::decode_packlist(
            &remote
                .tx
                .download_blob_via_ref(&PackKey::from_hash(main), "refs/heads/main")
                .unwrap(),
        )
        .unwrap()
        .packs[0];
        // Each tag object names a commit no pack carries.
        for i in 0..3 {
            let (_, absent) = remote.commit(None, true);
            let (tag, id) = remote.tag_object(&format!("t{i}"), absent, true);
            remote.push_tag(&format!("t{i}"), std::slice::from_ref(&tag), id, Some(main));
        }
        let source = remote.source();
        let counted = CountingSource::new(&source);

        let report = fetch_with(&counted, &target, &SyncOptions::default());

        assert_eq!(report.tags_rejected.len(), 3, "{kind:?}: {report:?}");
        assert!(
            report
                .tags_rejected
                .iter()
                .all(|r| matches!(r.reason, TagRejectReason::Missing(_)))
        );
        let calls = counted.take();
        assert_eq!(
            count(&calls, &format!("Pack {}", hash::to_hex(&main_pack))),
            1,
            "one self-heal: {calls:?}"
        );
    }
}

#[test]
fn fetch_with_no_tags_then_a_fetch_takes_the_tags() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        remote.push_tag("light", &[], c1, Some(main));
        let (_dir, target) = work();
        let report = clone_with(
            &remote.source(),
            &target,
            &SyncOptions::default().with_tags(false),
        );
        assert!(report.tags_fetched.is_empty());
        assert_eq!(local_tag(&target, "light"), None);
        let report = fetch_with(
            &remote.source(),
            &target,
            &SyncOptions::default().with_tags(false),
        );
        // Only a source that names its repository keeps a cursor record.
        assert_eq!(report.remote_unchanged, matches!(kind, Kind::Memory));

        let report = fetch_from(&remote, &target);

        assert!(
            !report.remote_unchanged,
            "a record without tags is not reused"
        );
        assert_eq!(report.tags_fetched, ["light"]);
    }
}

#[test]
fn a_refused_tag_is_reported_again_on_the_next_fetch() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (tag, rc) = remote.tag_object("rc", c1, false);
        remote.push_tag("rc", std::slice::from_ref(&tag), rc, Some(main));
        let (_dir, target) = work();
        assert_eq!(clone_from(&remote, &target).tags_rejected.len(), 1);

        let report = fetch_from(&remote, &target);

        assert!(!report.remote_unchanged, "{kind:?}");
        assert_eq!(report.tags_rejected.len(), 1);
    }
}

#[test]
fn the_cursor_record_refetches_after_a_local_tag_delete() {
    let remote = Remote::new(Kind::Memory);
    let (c1, main) = remote.grow("main", true);
    remote.push_tag("light", &[], c1, Some(main));
    let (_dir, target) = work();
    clone_from(&remote, &target);
    assert!(fetch_from(&remote, &target).remote_unchanged);
    refs::delete_tag(&RepoLayout::single(&target), "light").unwrap();

    let report = fetch_from(&remote, &target);

    assert!(!report.remote_unchanged);
    assert_eq!(report.tags_fetched, ["light"]);
    assert!(fetch_from(&remote, &target).remote_unchanged);
}

/// A failed tag listing stops only the tag phase: the branches are
/// published, the failure is reported, and no cursor is written.
#[test]
fn a_failed_tag_listing_stops_only_the_tag_phase() {
    struct FailTags<'a>(&'a dyn RemoteSource);
    impl RemoteSource for FailTags<'_> {
        fn list_branches(&self) -> Result<Vec<refs::Ref>, kit_sync::SourceError> {
            self.0.list_branches()
        }
        fn list_refs(&self, _: &str) -> Result<Vec<refs::Ref>, kit_sync::SourceError> {
            Err(kit_sync::SourceError::PayloadTooLarge(2 << 20))
        }
        fn read_ref(&self, name: &str) -> Result<Option<Hash>, kit_sync::SourceError> {
            self.0.read_ref(name)
        }
        fn download_blob_via_ref(
            &self,
            key: &PackKey,
            name: &str,
        ) -> Result<Vec<u8>, kit_sync::SourceError> {
            self.0.download_blob_via_ref(key, name)
        }
        fn download_pack_via_ref(
            &self,
            key: &PackKey,
            name: &str,
        ) -> Result<Vec<u8>, kit_sync::SourceError> {
            self.0.download_pack_via_ref(key, name)
        }
        fn repo_cursor(
            &self,
        ) -> Result<Option<kit_core::protocol::RepoCursor>, kit_sync::SourceError> {
            self.0.repo_cursor()
        }
    }
    let remote = Remote::new(Kind::Memory);
    let (c1, _) = remote.grow("main", true);
    let (_dir, target) = work();
    let source = remote.source();
    let failing = FailTags(&source);

    let report = clone_with(&failing, &target, &SyncOptions::default());

    let failure = report.tag_listing_failed.as_deref().unwrap();
    assert!(
        failure.starts_with("tag listing failed (possibly too many tags): "),
        "{failure}"
    );
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(&target), "default", "main").unwrap(),
        Some(c1)
    );
    assert!(!fetch_with(&failing, &target, &SyncOptions::default()).remote_unchanged);
}

/// A remote tag whose name is a directory of a local tag, or the reverse, is
/// refused alone; the other tags and the branches still publish. Of two new
/// remote tags in that relation, which a remote that keeps refs as files
/// cannot hold but another can list, the first in listing order publishes.
#[test]
fn a_tag_whose_name_collides_with_another_tag_is_refused_alone() {
    for kind in KINDS {
        let remote = Remote::new(kind);
        let (c1, main) = remote.grow("main", true);
        let (_dir, target) = work();
        clone_with(
            &remote.source(),
            &target,
            &SyncOptions::default().with_tags(false),
        );
        let layout = RepoLayout::single(&target);
        refs::update_tag(&layout, "v1", RefWriteCondition::Missing, &c1).unwrap();
        remote.push_tag("v1/rc", &[], c1, Some(main));
        remote.push_tag("a", &[], c1, Some(main));
        remote.push_tag("v2", &[], c1, Some(main));
        let (c2, _) = remote.grow("main", true);
        let source = remote.source();
        let mut listing = source.list_refs("refs/tags/").unwrap();
        listing.push(refs::Ref {
            name: "a/b".to_owned(),
            hash: Some(c1),
        });
        listing.sort_by(|x, y| x.name.cmp(&y.name));
        let listed = Listing {
            inner: &source,
            prefix: "refs/tags/",
            refs: listing,
        };

        let report = fetch_with(&listed, &target, &SyncOptions::default());

        assert_eq!(report.tags_fetched, ["a", "v2"], "{kind:?}");
        let reasons = rejected(&report);
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(reasons.contains(&(
            "a/b",
            &TagRejectReason::NameConflict {
                other: "a".to_owned()
            }
        )));
        assert!(reasons.contains(&(
            "v1/rc",
            &TagRejectReason::NameConflict {
                other: "v1".to_owned()
            }
        )));
        assert_eq!(
            refs::read_remote_ref(&layout, "default", "main").unwrap(),
            Some(c2)
        );
    }
}

/// A source whose download of one node fails with a transport error.
struct FailNode<'a> {
    inner: &'a dyn RemoteSource,
    node: Hash,
}

impl RemoteSource for FailNode<'_> {
    fn list_branches(&self) -> Result<Vec<refs::Ref>, kit_sync::SourceError> {
        self.inner.list_branches()
    }
    fn list_refs(&self, prefix: &str) -> Result<Vec<refs::Ref>, kit_sync::SourceError> {
        self.inner.list_refs(prefix)
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, kit_sync::SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        if *key == PackKey::from_hash(self.node) {
            return Err(kit_sync::SourceError::ConnectionFailed);
        }
        self.inner.download_blob_via_ref(key, name)
    }
    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.inner.download_pack_via_ref(key, name)
    }
    fn supports_push(&self) -> bool {
        false
    }
}

/// A transport failure in the tag phase fails the fetch, but the tags proved
/// before it still publish.
#[test]
fn a_fatal_error_in_the_tag_phase_keeps_the_tags_proved_before_it() {
    let remote = Remote::new(Kind::Memory);
    let (c1, main) = remote.grow("main", true);
    remote.push_tag("a", &[], c1, Some(main));
    let (tag, b) = remote.tag_object("b", c1, true);
    let node = remote.push_tag("b", std::slice::from_ref(&tag), b, Some(main));
    let (_dir, target) = work();
    clone_with(
        &remote.source(),
        &target,
        &SyncOptions::default().with_tags(false),
    );

    let source = remote.source();
    let failing = FailNode {
        inner: &source,
        node,
    };
    let error = fetch(
        &target,
        &failing,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();

    assert!(matches!(error, SyncError::Source(_)), "{error:?}");
    assert_eq!(local_tag(&target, "a"), Some(c1));
    assert_eq!(local_tag(&target, "b"), None);
}
