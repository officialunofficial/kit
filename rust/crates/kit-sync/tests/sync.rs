//! End-to-end behaviour of `clone`, `fetch` and `pull` over the
//! `Transport`-backed remote source, against an in-memory remote that is
//! populated the way a push populates a real one (packs, a packmap chain, a
//! branch ref).
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::cell::{Cell, RefCell};
use std::path::Path;

use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::ops::pull_state::PullState;
use kit_core::pack::{self, PackWriter};
use kit_core::protocol::{PackKey, Transport};
use kit_core::refs::{self, RefWriteCondition};
use kit_core::sign::{self, KeyPair};
use kit_core::transfer;
use kit_sync::{
    CloneRemote, NoopObserver, Observer, PullOutcome, RemoteSource, SyncError, SyncEvent,
    SyncOptions, TransportSource, clone, fetch, init_clone_dir, pull,
};
use kit_transport_memory::MemoryTransport;

/// A remote repository: objects arrive in packs, each push appends a node to
/// the branch's packmap chain, then moves the branch ref.
struct Remote {
    tx: MemoryTransport,
    packmap_head: RefCell<Option<Hash>>,
    key: KeyPair,
}

impl Remote {
    fn new() -> Self {
        Self {
            tx: MemoryTransport::new(),
            packmap_head: RefCell::new(None),
            key: KeyPair::generate().unwrap(),
        }
    }

    /// Publish one commit on `main` carrying `files`, parented on `parent`.
    /// `signed = false` leaves the signature zeroed, as a hostile remote's
    /// forged history would.
    fn publish(&self, parent: Option<Hash>, files: &[(&str, &[u8])], signed: bool) -> Hash {
        let (objects, tip) = self.build(parent, files, signed);
        self.publish_objects(&objects, tip, false);
        tip
    }

    /// Replace the branch with `files` as a fresh single-node chain, the way
    /// a re-baselining push resets a packmap.
    fn publish_reset(&self, files: &[(&str, &[u8])]) -> Hash {
        let (objects, tip) = self.build(None, files, true);
        self.publish_objects(&objects, tip, true);
        tip
    }

    /// Publish one commit on `main` carrying `items`, each a path with `/`
    /// separators, a mode and its content (a symlink's content is its target),
    /// parented on `parent`.
    fn publish_paths(&self, parent: Option<Hash>, items: &[(&str, EntryMode, &[u8])]) -> Hash {
        let mut objects = Vec::new();
        let tree_hash = nested_tree(&mut objects, items);
        let mut commit = Commit::new_unannotated(
            tree_hash,
            parent.into_iter().collect(),
            Identity::ed25519(self.key.public.0),
            self.key.public.0,
            format!("commit {}", items.len()).into_bytes(),
            1_700_000_000 + u64::from(parent.is_some()),
            [0u8; 64],
        );
        commit.signature = sign::sign_commit(&commit, &self.key).unwrap().0;
        let commit = Object::Commit(commit);
        let tip = commit.id().unwrap();
        objects.push(commit);
        self.publish_objects(&objects, tip, false);
        tip
    }

    fn build(
        &self,
        parent: Option<Hash>,
        files: &[(&str, &[u8])],
        signed: bool,
    ) -> (Vec<Object>, Hash) {
        let mut objects = Vec::new();
        let mut entries = Vec::new();
        for (name, data) in files {
            let blob = Object::Blob(Blob {
                data: data.to_vec(),
            });
            entries.push(TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob.id().unwrap(),
            });
            objects.push(blob);
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let tree = Object::Tree(Tree { entries });
        let tree_hash = tree.id().unwrap();
        objects.push(tree);
        let mut commit = Commit::new_unannotated(
            tree_hash,
            parent.into_iter().collect(),
            Identity::ed25519(self.key.public.0),
            self.key.public.0,
            format!("commit {}", files.len()).into_bytes(),
            1_700_000_000 + u64::from(parent.is_some()),
            [0u8; 64],
        );
        if signed {
            commit.signature = sign::sign_commit(&commit, &self.key).unwrap().0;
        }
        let commit = Object::Commit(commit);
        let tip = commit.id().unwrap();
        objects.push(commit);
        (objects, tip)
    }

    fn publish_objects(&self, objects: &[Object], tip: Hash, reset: bool) {
        let mut writer = PackWriter::new();
        for object in objects {
            writer
                .push_raw(
                    object.id().unwrap(),
                    &kit_core::serialize::serialize(object).unwrap(),
                )
                .unwrap();
        }
        self.publish_pack(&writer.finish().unwrap(), tip, reset);
    }

    fn publish_pack(&self, pack: &[u8], tip: Hash, reset: bool) {
        let pack_key = pack::pack_key(pack);
        self.tx
            .upload_pack(pack, &PackKey::from_hash(pack_key))
            .unwrap();
        let prev = if reset {
            None
        } else {
            *self.packmap_head.borrow()
        };
        let node = transfer::encode_packlist(prev, &[pack_key]).unwrap();
        let node_key = hash::hash(&node);
        self.tx
            .upload_blob(&node, &PackKey::from_hash(node_key))
            .unwrap();
        let condition = if reset {
            RefWriteCondition::Any
        } else {
            prev.map_or(RefWriteCondition::Missing, RefWriteCondition::Match)
        };
        self.tx
            .update_ref("refs/kit/packmap/main", condition, &node_key)
            .unwrap();
        *self.packmap_head.borrow_mut() = Some(node_key);
        let head = self.tx.read_ref("refs/heads/main").unwrap();
        let condition = match (reset, head) {
            (true, _) => RefWriteCondition::Any,
            (false, None) => RefWriteCondition::Missing,
            (false, Some(head)) => RefWriteCondition::Match(head),
        };
        self.tx
            .update_ref("refs/heads/main", condition, &tip)
            .unwrap();
    }

    fn source(&self) -> TransportSource<'_> {
        TransportSource::new(&self.tx)
    }
}

/// The tree object of `items` (see [`Remote::publish_paths`]), with every blob
/// and subtree pushed to `objects`. Returns the root tree's id.
fn nested_tree(objects: &mut Vec<Object>, items: &[(&str, EntryMode, &[u8])]) -> Hash {
    type PathItem<'a> = (&'a str, EntryMode, &'a [u8]);
    let mut entries = Vec::new();
    let mut dirs: std::collections::BTreeMap<&str, Vec<PathItem>> =
        std::collections::BTreeMap::new();
    for &(path, mode, data) in items {
        if let Some((dir, rest)) = path.split_once('/') {
            dirs.entry(dir).or_default().push((rest, mode, data));
        } else {
            let blob = Object::Blob(Blob {
                data: data.to_vec(),
            });
            entries.push(TreeEntry {
                name: path.as_bytes().to_vec(),
                mode,
                object_hash: blob.id().unwrap(),
            });
            objects.push(blob);
        }
    }
    for (dir, sub) in dirs {
        entries.push(TreeEntry {
            name: dir.as_bytes().to_vec(),
            mode: EntryMode::Tree,
            object_hash: nested_tree(objects, &sub),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let tree = Object::Tree(Tree { entries });
    let id = tree.id().unwrap();
    objects.push(tree);
    id
}

#[derive(Default)]
struct Recorder {
    events: RefCell<Vec<SyncEvent>>,
    cancel: Cell<bool>,
    /// Cancel once this many checkpoints have been polled.
    cancel_after: Cell<Option<usize>>,
    polls: Cell<usize>,
}

impl Observer<SyncEvent> for Recorder {
    fn event(&self, event: &SyncEvent) {
        self.events.borrow_mut().push(event.clone());
    }
    fn cancelled(&self) -> bool {
        self.polls.set(self.polls.get() + 1);
        self.cancel.get()
            || self
                .cancel_after
                .get()
                .is_some_and(|n| self.polls.get() > n)
    }
}

/// A source that serves a stale branch listing and otherwise delegates.
struct StaleListing<'a> {
    inner: TransportSource<'a>,
    listing: Vec<kit_core::refs::Ref>,
}

impl RemoteSource for StaleListing<'_> {
    fn list_branches(&self) -> Result<Vec<kit_core::refs::Ref>, kit_sync::SourceError> {
        Ok(self.listing.clone())
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, kit_sync::SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.inner.download_blob_via_ref(key, ref_name)
    }
    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.inner.download_pack_via_ref(key, ref_name)
    }
}

fn default_remote(url: &str) -> CloneRemote {
    CloneRemote {
        name: "default".to_owned(),
        url: url.to_owned(),
        kind: "memory".to_owned(),
    }
}

fn clone_into(remote: &Remote, dir: &Path) -> kit_sync::CloneReport {
    clone(
        dir,
        &remote.source(),
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap()
}

#[test]
fn clone_materialises_the_branch_worktree_and_tracking_ref() {
    let remote = Remote::new();
    let tip = remote.publish(None, &[("a.txt", b"hello\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");

    let report = clone_into(&remote, &target);

    assert_eq!(report.pull.fetch.branches_fetched, 1);
    assert_eq!(report.pull.fetch.packs_downloaded, 1);
    assert_eq!(report.pull.fetch.packs_already_applied, 0);
    assert!(report.pull.fetch.objects_unpacked >= 3);
    assert_eq!(
        report.pull.outcome,
        PullOutcome::FastForwarded {
            branch: "main".to_owned(),
            old: None,
            new: tip
        }
    );
    let layout = RepoLayout::single(&target);
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(tip));
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(tip)
    );
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"hello\n");
}

#[test]
fn clone_refuses_values_that_would_inject_config_lines() {
    let dir = tempfile::tempdir().unwrap();
    for remote in [
        CloneRemote {
            name: "default".to_owned(),
            url: "kit+file:///x\nremote.evil.url = y".to_owned(),
            kind: "file".to_owned(),
        },
        CloneRemote {
            name: "up\nstream".to_owned(),
            url: "kit+file:///x".to_owned(),
            kind: "file".to_owned(),
        },
        CloneRemote {
            name: "dotted.name".to_owned(),
            url: "kit+file:///x".to_owned(),
            kind: "file".to_owned(),
        },
        CloneRemote {
            name: "default".to_owned(),
            url: "kit+file:///x".to_owned(),
            kind: "fi\rle".to_owned(),
        },
    ] {
        let target = dir.path().join("work");
        let err = init_clone_dir(&target, &remote).unwrap_err();
        assert!(
            matches!(err, kit_sync::CloneInitError::InvalidRemote(_)),
            "{err:?}"
        );
        assert!(!target.exists(), "nothing is created for a rejected remote");
    }
}

#[test]
fn clone_writes_the_flat_and_named_remote_config() {
    let dir = tempfile::tempdir().unwrap();
    let flat = dir.path().join("flat");
    let layout = init_clone_dir(&flat, &default_remote("kit+memory://x")).unwrap();
    assert_eq!(
        std::fs::read_to_string(layout.config_file()).unwrap(),
        "default_branch = main\nremote_endpoint = kit+memory://x\nremote_type = memory\n"
    );

    let named = dir.path().join("named");
    let remote = CloneRemote {
        name: "upstream".to_owned(),
        url: "kit+file:///srv/r".to_owned(),
        kind: "file".to_owned(),
    };
    let layout = init_clone_dir(&named, &remote).unwrap();
    assert_eq!(
        std::fs::read_to_string(layout.config_file()).unwrap(),
        "default_branch = main\nremote.upstream.url = kit+file:///srv/r\nremote.upstream.type = file\n"
    );
}

#[test]
fn pull_fast_forwards_and_a_second_pull_is_a_no_op() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);

    let second = remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    let report = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        report.outcome,
        PullOutcome::FastForwarded {
            branch: "main".to_owned(),
            old: Some(first),
            new: second
        }
    );
    // Only the new pack is downloaded; the first is recorded as applied.
    assert_eq!(report.fetch.packs_downloaded, 1);
    assert_eq!(report.fetch.packs_already_applied, 1);
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"two\n");

    let again = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        again.outcome,
        PullOutcome::UpToDate {
            branch: "main".to_owned()
        }
    );
    // The remote's cursor is unchanged, so the fetch skips every branch.
    assert!(again.fetch.remote_unchanged);
    assert_eq!(again.fetch.packs_downloaded, 0);
}

struct StopAfterHead {
    layout: RepoLayout,
    tip: Hash,
}

impl Observer<SyncEvent> for StopAfterHead {
    fn cancelled(&self) -> bool {
        refs::resolve_head(&self.layout).unwrap() == Some(self.tip)
    }
}

#[test]
fn pull_resumes_the_restore_after_head_was_written() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let second = remote.publish(
        Some(first),
        &[("a.txt", b"two\n"), ("b.txt", b"new\n")],
        true,
    );
    let layout = RepoLayout::single(&target);
    let result = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &StopAfterHead {
            layout: layout.clone(),
            tip: second,
        },
    );
    assert!(matches!(result, Err(SyncError::Interrupted)), "{result:?}");
    assert_eq!(refs::resolve_head(&layout).unwrap(), Some(second));
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"one\n");
    assert!(!target.join("b.txt").exists());
    assert_eq!(
        std::fs::read(layout.pull_head_file()).unwrap(),
        PullState {
            target: second,
            before_tree: match kit_core::store::ObjectStore::open(&layout)
                .unwrap()
                .read_object(&first)
                .unwrap()
            {
                Object::Commit(c) => c.tree_hash,
                _ => panic!("commit"),
            }
        }
        .encode()
    );

    let resumed = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"two\n");
    assert_eq!(std::fs::read(target.join("b.txt")).unwrap(), b"new\n");
    let index = kit_core::index::read_index(&layout).unwrap();
    assert_eq!(index.entries.len(), 2);
    assert!(matches!(resumed.outcome, PullOutcome::FastForwarded { new, .. } if new == second));
    assert!(!layout.pull_head_file().exists());
    // Once complete, a no-op pull must preserve subsequent local edits.
    std::fs::write(target.join("a.txt"), b"local edit\n").unwrap();
    let again = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert!(matches!(again.outcome, PullOutcome::UpToDate { .. }));
    assert_eq!(
        std::fs::read(target.join("a.txt")).unwrap(),
        b"local edit\n"
    );
}

#[test]
fn pull_resumes_a_partial_restore_before_landing_a_newer_tip() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n"), ("b.txt", b"old\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let second = remote.publish(
        Some(first),
        &[("a.txt", b"two\n"), ("b.txt", b"new\n")],
        true,
    );
    let layout = RepoLayout::single(&target);
    let result = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &StopAfterHead {
            layout: layout.clone(),
            tip: second,
        },
    );
    assert!(matches!(result, Err(SyncError::Interrupted)));
    // One file landed before interruption; the index still describes first.
    std::fs::write(target.join("a.txt"), b"two\n").unwrap();
    let third = remote.publish(
        Some(second),
        &[("a.txt", b"three\n"), ("b.txt", b"newest\n")],
        true,
    );
    let report = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert!(
        matches!(report.outcome, PullOutcome::FastForwarded { old: Some(old), new, .. } if old == second && new == third)
    );
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"three\n");
    assert_eq!(std::fs::read(target.join("b.txt")).unwrap(), b"newest\n");
    assert!(!layout.pull_head_file().exists());
}

#[test]
fn pull_retries_a_marker_written_before_the_branch_moves() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let second = remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    let layout = RepoLayout::single(&target);
    write_pull_marker(&layout, second);
    pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(refs::resolve_head(&layout).unwrap(), Some(second));
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"two\n");
    assert!(!layout.pull_head_file().exists());
}

#[test]
fn pull_refuses_malformed_markers_before_a_no_op() {
    let remote = Remote::new();
    let tip = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let layout = RepoLayout::single(&target);
    std::fs::write(target.join("a.txt"), b"local edit\n").unwrap();
    for bytes in [
        vec![],
        vec![b'a'; 66],
        vec![b'G'; 65],
        hash::to_hex(&tip).into_bytes(),
    ] {
        std::fs::write(layout.pull_head_file(), &bytes).unwrap();
        assert!(
            pull(
                &target,
                &remote.source(),
                "default",
                &SyncOptions::default(),
                &NoopObserver
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(target.join("a.txt")).unwrap(),
            b"local edit\n"
        );
        assert_eq!(std::fs::read(layout.pull_head_file()).unwrap(), bytes);
    }
}

#[test]
fn pull_preserves_local_changes_when_the_pending_target_is_not_head() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let second = remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    let layout = RepoLayout::single(&target);
    fetch(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    // The branch moved, but HEAD still names a different commit.
    refs::write_ref(&layout, "main", &second).unwrap();
    refs::write_ref(&layout, "dev", &first).unwrap();
    refs::write_head_branch(&layout, "dev").unwrap();
    write_pull_marker(&layout, second);
    std::fs::write(target.join("a.txt"), b"local edit\n").unwrap();
    let options = SyncOptions::default().with_target_branch(Some("main".to_owned()));
    let result = pull(
        &target,
        &remote.source(),
        "default",
        &options,
        &NoopObserver,
    );
    assert!(matches!(result, Err(SyncError::RestoreSafety(_))));
    assert_eq!(
        refs::read_head(&layout).unwrap(),
        refs::Head::Branch("dev".to_owned())
    );
    assert_eq!(
        std::fs::read(target.join("a.txt")).unwrap(),
        b"local edit\n"
    );
    assert!(layout.pull_head_file().exists());
    // With a clean worktree the same pending branch can finish safely.
    std::fs::write(target.join("a.txt"), b"one\n").unwrap();
    let report = pull(
        &target,
        &remote.source(),
        "default",
        &options,
        &NoopObserver,
    )
    .unwrap();
    assert!(matches!(report.outcome, PullOutcome::FastForwarded { new, .. } if new == second));
    assert_eq!(
        refs::read_head(&layout).unwrap(),
        refs::Head::Branch("main".to_owned())
    );
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"two\n");
    assert!(!layout.pull_head_file().exists());
}

#[test]
fn fetch_moves_only_the_tracking_ref() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let second = remote.publish(Some(first), &[("a.txt", b"two\n")], true);

    let report = fetch(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();

    assert_eq!(report.branches_fetched, 1);
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(second)
    );
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"one\n");
}

#[test]
fn fetch_past_the_staging_budget_applies_each_pack_as_it_arrives() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let second = remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    let third = remote.publish(Some(second), &[("a.txt", b"three\n")], true);
    let layout = RepoLayout::single(&target);
    let staging = dir.path().join("stage");
    std::fs::create_dir(&staging).unwrap();

    let small = SyncOptions::default()
        .with_max_staged_bytes(1)
        .with_staging_dir(Some(staging.clone()));
    let report = fetch(&target, &remote.source(), "default", &small, &NoopObserver).unwrap();

    assert_eq!(report.packs_downloaded, 2);
    assert_eq!(report.packs_already_applied, 1);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(third)
    );
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
}

/// A source whose `fail_at`-th pack download fails, counting from one.
struct FailingPack<'a> {
    inner: TransportSource<'a>,
    downloads: Cell<usize>,
    fail_at: usize,
}

impl RemoteSource for FailingPack<'_> {
    fn list_branches(&self) -> Result<Vec<kit_core::refs::Ref>, kit_sync::SourceError> {
        self.inner.list_branches()
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, kit_sync::SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.inner.download_blob_via_ref(key, ref_name)
    }
    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.downloads.set(self.downloads.get() + 1);
        if self.downloads.get() == self.fail_at {
            return Err(kit_sync::SourceError::ConnectionFailed);
        }
        self.inner.download_pack_via_ref(key, ref_name)
    }
}

#[test]
fn a_failure_past_the_staging_budget_keeps_the_applied_packs_recorded() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let second = remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    let third = remote.publish(Some(second), &[("a.txt", b"three\n")], true);
    let fourth = remote.publish(Some(third), &[("a.txt", b"four\n")], true);
    let layout = RepoLayout::single(&target);
    let staging = dir.path().join("stage");
    std::fs::create_dir(&staging).unwrap();
    let small = SyncOptions::default()
        .with_max_staged_bytes(1)
        .with_staging_dir(Some(staging.clone()));
    // The second pack is downloaded, dropped at the budget, then downloaded
    // and applied under the lock. The third pack's download fails.
    let failing = FailingPack {
        inner: remote.source(),
        downloads: Cell::new(0),
        fail_at: 3,
    };

    let err = fetch(&target, &failing, "default", &small, &NoopObserver).unwrap_err();

    assert!(
        matches!(
            err,
            SyncError::Source(kit_sync::SourceError::ConnectionFailed)
        ),
        "{err:?}"
    );
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(first)
    );
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    let report = fetch(&target, &remote.source(), "default", &small, &NoopObserver).unwrap();
    assert_eq!(report.packs_already_applied, 2);
    assert_eq!(report.packs_downloaded, 2);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(fourth)
    );
}

#[test]
fn pull_refuses_anything_that_is_not_a_fast_forward() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);

    // The remote branch is replaced by an unrelated history.
    let unrelated = remote.publish(None, &[("b.txt", b"other\n")], true);
    assert_ne!(first, unrelated);

    let err = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();
    assert!(
        matches!(err, SyncError::NonFastForwardPull { ref branch } if branch == "main"),
        "{err:?}"
    );
    let layout = RepoLayout::single(&target);
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"one\n");
}

#[test]
fn an_unsigned_commit_is_rejected_by_default_and_publishes_nothing() {
    let remote = Remote::new();
    let tip = remote.publish(None, &[("a.txt", b"forged\n")], false);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");

    let err = clone(
        &target,
        &remote.source(),
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();
    let kit_sync::CloneError::Sync(SyncError::UnsignedOrInvalidObject { hash, .. }) = err else {
        panic!("expected UnsignedOrInvalidObject");
    };
    assert_eq!(hash, hash::to_hex(&tip));
    let layout = RepoLayout::single(&target);
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), None);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        None
    );
    assert!(!target.join("a.txt").exists());
}

#[test]
fn the_explicit_opt_out_accepts_an_unsigned_commit() {
    let remote = Remote::new();
    let tip = remote.publish(None, &[("a.txt", b"unsigned\n")], false);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let options = SyncOptions::default().with_verify_signatures(false);

    let report = clone(
        &target,
        &remote.source(),
        &default_remote("kit+memory://x"),
        &options,
        &NoopObserver,
    )
    .unwrap();

    assert!(matches!(
        report.pull.outcome,
        PullOutcome::FastForwarded { new, .. } if new == tip
    ));
}

#[test]
fn a_missing_target_branch_is_an_error_not_a_fallback() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let options = SyncOptions::default().with_target_branch(Some("release".to_owned()));

    let err = clone(
        &target,
        &remote.source(),
        &default_remote("kit+memory://x"),
        &options,
        &NoopObserver,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        kit_sync::CloneError::Sync(SyncError::RemoteBranchMissing(ref b)) if b == "release"
    ));
}

#[test]
fn cancellation_is_polled_and_reported_as_interrupted() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let observer = Recorder::default();
    observer.cancel.set(true);

    let err = clone(
        &target,
        &remote.source(),
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &observer,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        kit_sync::CloneError::Sync(SyncError::Interrupted)
    ));
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        None
    );
}

#[test]
fn progress_arrives_as_events_not_output() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let observer = Recorder::default();

    clone(
        &dir.path().join("work"),
        &remote.source(),
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();

    let events = observer.events.borrow();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SyncEvent::ObjectsUnpacked { count } if *count >= 3)),
        "{events:?}"
    );
}

#[test]
fn a_stale_applied_packs_record_self_heals_with_a_visible_event() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);

    // Wipe the object store but keep the applied-packs record.
    let layout = RepoLayout::single(&target);
    let objects = layout.common_dir().join("objects");
    std::fs::remove_dir_all(&objects).unwrap();
    std::fs::create_dir_all(&objects).unwrap();
    let observer = Recorder::default();

    let report = fetch(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();

    assert_eq!(report.branches_fetched, 1);
    assert_eq!(report.packs_downloaded, 1);
    assert!(
        observer
            .events
            .borrow()
            .iter()
            .any(|e| matches!(e, SyncEvent::AppliedPacksStale { .. }))
    );
}

#[test]
fn the_source_trait_is_object_safe() {
    let remote = Remote::new();
    let source: &dyn RemoteSource = &remote.source();
    assert!(source.list_branches().unwrap().is_empty());
}

#[test]
fn a_listed_branch_deleted_since_the_listing_is_skipped_not_fetched() {
    let remote = Remote::new();
    let tip = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    init_clone_dir(&target, &default_remote("kit+memory://x")).unwrap();
    let mut listing = remote.tx.list_refs("refs/heads/").unwrap();
    listing.push(kit_core::refs::Ref {
        name: "ghost".to_owned(),
        hash: Some(tip),
    });
    let source = StaleListing {
        inner: remote.source(),
        listing,
    };
    let observer = Recorder::default();

    let report = fetch(
        &target,
        &source,
        "default",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();

    assert_eq!(report.branches_fetched, 1);
    assert_eq!(report.branches_skipped, vec!["ghost".to_owned()]);
    assert!(
        observer
            .events
            .borrow()
            .iter()
            .any(|e| matches!(e, SyncEvent::BranchSkippedStale { branch } if branch == "ghost"))
    );
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "ghost").unwrap(),
        None
    );
}

/// A clone of a one-branch remote with an extra tracking ref `gone`, a branch
/// the remote does not have.
fn clone_with_tracking_ghost(remote: &Remote) -> (tempfile::TempDir, std::path::PathBuf, Hash) {
    let tip = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(remote, &target);
    let layout = RepoLayout::single(&target);
    refs::write_remote_ref(&layout, "default", "gone", &tip).unwrap();
    (dir, target, tip)
}

#[test]
fn prune_deletes_only_the_tracking_refs_of_branches_the_remote_lost() {
    let remote = Remote::new();
    let (_dir, target, tip) = clone_with_tracking_ghost(&remote);
    let layout = RepoLayout::single(&target);
    refs::write_tag(&layout, "v1", &tip).unwrap();

    let kept = fetch(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert!(kept.branches_pruned.is_empty());
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "gone").unwrap(),
        Some(tip)
    );

    let report = fetch(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default().with_prune(true),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(report.branches_pruned, vec!["gone".to_owned()]);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "gone").unwrap(),
        None
    );
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(tip)
    );
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(tip));
    assert_eq!(refs::read_tag(&layout, "v1").unwrap(), Some(tip));
}

#[test]
fn prune_keeps_a_tracking_ref_whose_branch_a_stale_listing_omits() {
    let remote = Remote::new();
    let (_dir, target, tip) = clone_with_tracking_ghost(&remote);
    let source = StaleListing {
        inner: remote.source(),
        listing: Vec::new(),
    };

    let report = fetch(
        &target,
        &source,
        "default",
        &SyncOptions::default().with_prune(true),
        &NoopObserver,
    )
    .unwrap();

    // The strong read still finds `main`, so only `gone` goes.
    assert_eq!(report.branches_pruned, vec!["gone".to_owned()]);
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(tip)
    );
}

#[test]
fn a_failed_fetch_prunes_nothing() {
    let remote = Remote::new();
    let (_dir, target, tip) = clone_with_tracking_ghost(&remote);
    let bad = remote.publish(Some(tip), &[("a.txt", b"two\n")], false);
    assert_ne!(bad, tip);

    let err = fetch(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default().with_prune(true),
        &NoopObserver,
    );
    assert!(err.is_err(), "an unsigned commit fails the fetch");
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "gone").unwrap(),
        Some(tip)
    );
}

#[test]
fn a_concurrent_rebaseline_is_retried_once_with_the_fresh_tip() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    // The listing was taken before another pusher reset the packmap to a
    // single node covering only the new tip.
    let stale = remote.tx.list_refs("refs/heads/").unwrap();
    let fresh_tip = remote.publish_reset(&[("b.txt", b"rebaselined\n")]);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    init_clone_dir(&target, &default_remote("kit+memory://x")).unwrap();
    let source = StaleListing {
        inner: remote.source(),
        listing: stale,
    };

    let report = fetch(
        &target,
        &source,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();

    assert_eq!(report.branches_fetched, 1);
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(fresh_tip)
    );
}

#[test]
fn pull_refuses_to_overwrite_local_work_and_leaves_the_branch_alone() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    std::fs::write(target.join("a.txt"), b"local edit\n").unwrap();

    let err = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();

    assert!(matches!(err, SyncError::RestoreSafety(_)), "{err:?}");
    let layout = RepoLayout::single(&target);
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));
    assert_eq!(
        std::fs::read(target.join("a.txt")).unwrap(),
        b"local edit\n"
    );
}

#[cfg(unix)]
#[test]
fn a_failed_worktree_restore_rolls_the_branch_and_head_back() {
    use std::os::unix::fs::PermissionsExt;

    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    // HEAD sits on `dev`, so landing on `main` moves HEAD as well.
    let layout = RepoLayout::single(&target);
    refs::write_ref(&layout, "dev", &first).unwrap();
    refs::write_head_branch(&layout, "dev").unwrap();
    remote.publish(
        Some(first),
        &[("a.txt", b"two\n"), ("c.txt", b"new\n")],
        true,
    );
    // A read-only worktree root makes writing the new file fail after the
    // branch ref and HEAD have moved.
    let mut perms = std::fs::metadata(&target).unwrap().permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&target, perms.clone()).unwrap();
    if std::fs::write(target.join("probe"), b"x").is_ok() {
        // Running with privileges that ignore directory permissions.
        perms.set_mode(0o755);
        std::fs::set_permissions(&target, perms).unwrap();
        return;
    }
    let options = SyncOptions::default().with_target_branch(Some("main".to_owned()));

    let result = pull(
        &target,
        &remote.source(),
        "default",
        &options,
        &NoopObserver,
    );

    perms.set_mode(0o755);
    std::fs::set_permissions(&target, perms).unwrap();
    // The failure is the worktree write itself, after the ref and HEAD moved.
    assert!(
        matches!(&result, Err(SyncError::RestoreSafety(m)) if m.contains("restore worktree")),
        "{result:?}"
    );
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));
    assert_eq!(
        refs::read_head(&layout).unwrap(),
        refs::Head::Branch("dev".to_owned())
    );
    assert!(!layout.pull_head_file().exists());
    // A remote at the rolled-back tip must not see an abandoned marker.
    remote
        .tx
        .update_ref("refs/heads/main", RefWriteCondition::Any, &first)
        .unwrap();
    let report = pull(
        &target,
        &remote.source(),
        "default",
        &options,
        &NoopObserver,
    )
    .unwrap();
    assert!(matches!(report.outcome, PullOutcome::UpToDate { .. }));
}

#[test]
fn a_set_atomic_flag_cancels_a_clone() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let flag = std::sync::atomic::AtomicBool::new(true);

    let err = clone(
        &target,
        &remote.source(),
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &flag,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        kit_sync::CloneError::Sync(SyncError::Interrupted)
    ));
}

#[test]
fn events_reach_the_observer_in_the_order_they_happen() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let observer = Recorder::default();

    clone(
        &target,
        &remote.source(),
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();

    let events = observer.events.borrow();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, SyncEvent::ObjectsUnpacked { .. })),
        "{events:?}"
    );
}

#[test]
fn cancellation_after_the_first_checkpoint_stops_before_publishing() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    init_clone_dir(&target, &default_remote("kit+memory://x")).unwrap();
    let observer = Recorder::default();
    observer.cancel_after.set(Some(1));

    let err = fetch(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap_err();

    assert!(matches!(err, SyncError::Interrupted), "{err:?}");
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        None
    );
}

#[test]
fn a_live_server_is_reported_as_an_event() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    let layout = RepoLayout::single(&target);
    let _serving =
        kit_core::repo_lock::acquire_default(layout.common_dir(), kit_sync::SERVE_LOCK).unwrap();
    let observer = Recorder::default();

    pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();

    assert!(
        observer
            .events
            .borrow()
            .iter()
            .any(|e| matches!(e, SyncEvent::RepositoryServed { .. }))
    );
}

#[test]
fn staging_honours_the_configured_directory() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("stage");
    std::fs::create_dir(&staging).unwrap();
    let options = SyncOptions::default().with_staging_dir(Some(staging.clone()));

    clone(
        &dir.path().join("work"),
        &remote.source(),
        &default_remote("kit+memory://x"),
        &options,
        &NoopObserver,
    )
    .unwrap();

    // Staging directories are removed on success; the directory itself stays.
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    let missing = SyncOptions::default().with_staging_dir(Some(dir.path().join("nope")));
    let err = clone(
        &dir.path().join("work2"),
        &remote.source(),
        &default_remote("kit+memory://x"),
        &missing,
        &NoopObserver,
    )
    .unwrap_err();
    assert!(matches!(err, kit_sync::CloneError::Sync(SyncError::Io(_))));
}

/// A signed one-commit history whose pack carries a zstd entry
/// (`examples/gen_zstd_fixture.rs` regenerates it).
const ZSTD_PACK: &[u8] = include_bytes!("fixtures/zstd.pack");
const ZSTD_TIP: &str = "79810b90a7979f0e33a07f74054104a4254693eaafdea73f07acb47276743ae4";

fn remote_with_zstd_pack() -> Remote {
    // The blob alone is about 9.7 KB; the pack is far smaller only because an
    // entry is zstd-compressed.
    assert!(
        ZSTD_PACK.len() < 1024,
        "the fixture must carry a compressed entry"
    );
    let remote = Remote::new();
    let pack_key = pack::pack_key(ZSTD_PACK);
    remote
        .tx
        .upload_pack(ZSTD_PACK, &PackKey::from_hash(pack_key))
        .unwrap();
    let node = transfer::encode_packlist(None, &[pack_key]).unwrap();
    let node_key = hash::hash(&node);
    remote
        .tx
        .upload_blob(&node, &PackKey::from_hash(node_key))
        .unwrap();
    remote
        .tx
        .update_ref(
            "refs/kit/packmap/main",
            RefWriteCondition::Missing,
            &node_key,
        )
        .unwrap();
    remote
        .tx
        .update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash::from_hex(ZSTD_TIP).unwrap(),
        )
        .unwrap();
    remote
}

#[test]
fn a_zstd_compressed_pack_is_cloned() {
    let remote = remote_with_zstd_pack();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");

    clone_into(&remote, &target);

    let text = std::fs::read_to_string(target.join("big.txt")).unwrap();
    assert_eq!(text, "kit compresses repetitive text well. ".repeat(256));
}

include!("support/counting.rs");

fn identified(source: &dyn RemoteSource) -> CountingSource<'_> {
    let mut counted = CountingSource::new(source);
    counted.address = Some(("repository".into(), "https://example.invalid".into()));
    counted
}

fn checkpoint_file(target: &Path) -> std::path::PathBuf {
    std::fs::read_dir(
        RepoLayout::single(target)
            .applied_packs_dir()
            .join(".heads"),
    )
    .unwrap()
    .next()
    .unwrap()
    .unwrap()
    .path()
}

/// A source that names no repository, such as the ssh transport, keeps no
/// checkpoint, so an unchanged fetch lists once, then reads each branch's
/// packmap and downloads every node of its pack list again. SPEC-TRANSPORT
/// §4.4 derives what fits in one `kit serve` session from this count.
#[test]
fn an_unchanged_fetch_from_an_unnamed_source_walks_each_pack_list() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = CountingSource::new(&source);
    assert!(counted.address.is_none());
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    counted.take();
    let node = |h: Hash| format!("Node {}", hash::to_hex(&h));

    let head = remote.packmap_head.borrow().unwrap();
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        counted.take(),
        [
            "ListRefs".to_owned(),
            "ReadRef refs/kit/packmap/main".to_owned(),
            node(head)
        ]
    );

    remote.publish(Some(first), &[("a", b"2")], true);
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    counted.take();
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let calls = counted.take();
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert_eq!(calls[..2], ["ListRefs", "ReadRef refs/kit/packmap/main"]);
    assert!(
        calls[2..].iter().all(|c| c.starts_with("Node ")),
        "{calls:?}"
    );
}

#[test]
fn incremental_pull_counts_and_rebaseline_fallback() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let second = remote.publish(Some(first), &[("a", b"2")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let calls = counted.take();
    assert_eq!(calls.len(), 6); // listing, packmap, two nodes, two packs
    let report = pull(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        counted.take(),
        ["ListRefs", "ReadRef refs/kit/packmap/main"]
    );
    assert_eq!(report.fetch.objects_unpacked, 0);
    assert_eq!(report.fetch.packs_already_applied, 2);
    // A checkpoint established with verification also remains safe for an
    // explicit verification opt-out; the option does not discard prior trust.
    pull(
        &target,
        &counted,
        "default",
        &SyncOptions::default().with_verify_signatures(false),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        counted.take(),
        ["ListRefs", "ReadRef refs/kit/packmap/main"]
    );

    let third = remote.publish(Some(second), &[("a", b"3")], true);
    let new_head = remote.packmap_head.borrow().unwrap();
    let report = pull(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let calls = counted.take();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[2], format!("Node {}", hash::to_hex(&new_head)));
    assert!(calls[3].starts_with("Pack "));
    assert_eq!(report.fetch.packs_downloaded, 1);
    assert_eq!(report.fetch.packs_already_applied, 2);
    assert!(matches!(report.outcome, PullOutcome::FastForwarded { new, .. } if new == third));

    let reset = remote.publish_reset(&[("reset", b"new root")]);
    let reset_tip = remote.publish(Some(reset), &[("reset", b"new tip")], true);
    let report = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 6); // unrelated two-node chain, walked to root
    assert_eq!(report.packs_downloaded, 2);
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(&target), "default", "main").unwrap(),
        Some(reset_tip)
    );
}

#[test]
fn checkpoint_corruption_absence_and_identity_changes_walk_the_full_chain() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    remote.publish(Some(first), &[("a", b"2")], true);
    let source = remote.source();
    let mut counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    counted.take();
    let path = checkpoint_file(&target);
    for bytes in [Some(b"corrupt".as_slice()), None] {
        if let Some(bytes) = bytes {
            std::fs::write(&path, bytes).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        fetch(
            &target,
            &counted,
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap();
        assert_eq!(counted.take().len(), 4);
    }
    for address in [
        ("repository", "https://other.invalid"),
        ("other-repository", "https://example.invalid"),
    ] {
        counted.address = Some((address.0.into(), address.1.into()));
        fetch(
            &target,
            &counted,
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap();
        assert_eq!(counted.take().len(), 4);
    }
}

#[test]
fn checkpoint_self_heals_a_missing_prefix_and_verifies_new_signatures() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let path = checkpoint_file(&target);
    let before = std::fs::read(&path).unwrap();
    let layout = RepoLayout::single(&target);
    std::fs::remove_dir_all(layout.objects_dir()).unwrap();
    std::fs::create_dir_all(layout.objects_dir()).unwrap();
    let observer = Recorder::default();
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();
    assert!(
        observer
            .events
            .borrow()
            .iter()
            .any(|e| matches!(e, SyncEvent::AppliedPacksStale { .. }))
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    // Recovery also resolves an omitted prefix after a new suffix was applied.
    let second = remote.publish(Some(first), &[("a", b"2")], true);
    std::fs::remove_dir_all(layout.objects_dir()).unwrap();
    std::fs::create_dir_all(layout.objects_dir()).unwrap();
    let recovered = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(recovered.packs_downloaded, 2);
    let before = std::fs::read(&path).unwrap();
    remote.publish(Some(second), &[("a", b"unsigned")], false);
    let error = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();
    assert!(matches!(error, SyncError::UnsignedOrInvalidObject { .. }));
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(second)
    );
}

#[test]
fn omitted_prefix_restores_delta_bases_when_applied_record_is_missing() {
    let remote = Remote::new();
    let base = Object::Blob(Blob {
        data: vec![b'a'; 1024],
    });
    let first = remote.publish(None, &[("a", &vec![b'a'; 1024])], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let checkpoint = checkpoint_file(&target);
    let before = std::fs::read(&checkpoint).unwrap();
    let (objects, second) = remote.build(Some(first), &[("a", &vec![b'b'; 1024])], true);
    let mut writer = PackWriter::new();
    let base_bytes = kit_core::serialize::serialize(&base).unwrap();
    let target_bytes = kit_core::serialize::serialize(&objects[0]).unwrap();
    let delta = kit_core::delta::encode(&base_bytes, &target_bytes).unwrap();
    writer.push_delta(&base.id().unwrap(), &delta).unwrap();
    for object in &objects[1..] {
        writer
            .push_raw(
                object.id().unwrap(),
                &kit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
    }
    remote.publish_pack(&writer.finish().unwrap(), second, false);
    let layout = RepoLayout::single(&target);
    std::fs::remove_dir_all(layout.objects_dir()).unwrap();
    std::fs::create_dir_all(layout.objects_dir()).unwrap();
    // A stale applied-pack record already failed this way before checkpoints.
    // Falling back must retain those skips rather than broaden that recovery.
    let error = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SyncError::Pack(pack::PackError::DeltaBaseMissing(_))
    ));
    assert_eq!(std::fs::read(&checkpoint).unwrap(), before);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(first)
    );
    // With no pack record, the original full walk restores the raw prefix
    // before decoding its delta. An omitted prefix must preserve that behavior.
    std::fs::remove_file(layout.applied_packs_dir().join("default")).unwrap();
    counted.take();
    let report = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(report.packs_downloaded, 2);
    assert_eq!(counted.take().len(), 8); // suffix attempt, then one full walk
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(second)
    );
    assert_ne!(std::fs::read(checkpoint).unwrap(), before);
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        counted.take(),
        ["ListRefs", "ReadRef refs/kit/packmap/main"]
    );
}

#[test]
fn crash_between_tracking_publication_and_checkpoint_rewalks_safely() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let path = checkpoint_file(&target);
    let old_record = std::fs::read(&path).unwrap();
    let applied_path = RepoLayout::single(&target)
        .applied_packs_dir()
        .join("default");
    let old_applied = std::fs::read(&applied_path).unwrap();
    remote.publish(Some(first), &[("a", b"2")], true);
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    // Reconstruct exactly the durable crash boundary: objects and tracking ref
    // published, but neither the checkpoint rename nor the final applied-pack
    // persist has occurred.
    std::fs::write(&path, old_record).unwrap();
    std::fs::write(&applied_path, old_applied).unwrap();
    counted.take();
    let report = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 4); // missed suffix plus the not-yet-recorded new pack
    assert_eq!(report.packs_downloaded, 1);
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 2);
}

#[test]
fn concurrent_pulls_publish_consistent_checkpoints_under_the_lock() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let second = remote.publish(Some(first), &[("a", b"2")], true);
    let barrier = std::sync::Barrier::new(2);
    let tx = &remote.tx;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let target = &target;
                let barrier = &barrier;
                scope.spawn(move || {
                    let source = TransportSource::new(tx);
                    let mut counted = identified(&source);
                    // Both transfers rendezvous before either can publish.
                    counted.before_pack = Some(barrier);
                    barrier.wait();
                    pull(
                        target,
                        &counted,
                        "default",
                        &SyncOptions::default(),
                        &NoopObserver,
                    )
                    .unwrap()
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    });
    assert_eq!(
        refs::read_ref(&RepoLayout::single(&target), "main").unwrap(),
        Some(second)
    );
    counted.take();
    pull(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 2);
}

#[test]
fn checkpoints_are_per_branch_and_unchanged_heads_still_publish_listed_tips() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("kit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let second = remote.publish(Some(first), &[("a", b"2")], true);
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    // The listed tip and tracking tip can agree while the checkpoint records
    // a different historical tip under the same immutable packmap head.
    refs::write_remote_ref(&RepoLayout::single(&target), "default", "main", &first).unwrap();
    let stale = StaleListing {
        inner: remote.source(),
        listing: vec![refs::Ref {
            name: "main".into(),
            hash: Some(first),
        }],
    };
    let stale_counted = identified(&stale);
    pull(
        &target,
        &stale_counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(stale_counted.take().len(), 2); // no-op conditions hold despite the different recorded tip

    remote
        .tx
        .update_ref("refs/heads/topic", RefWriteCondition::Missing, &second)
        .unwrap();
    remote
        .tx
        .update_ref(
            "refs/kit/packmap/topic",
            RefWriteCondition::Missing,
            &remote.packmap_head.borrow().unwrap(),
        )
        .unwrap();
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(&target), "default", "main").unwrap(),
        Some(second)
    );
    counted.take();
    let report = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 3); // one listing, two packmap reads
    assert_eq!(report.branches_fetched, 2);
    assert_eq!(report.objects_unpacked, 0);
}

#[test]
fn checkpoint_directory_does_not_collide_with_a_remote_named_heads() {
    let remote = Remote::new();
    remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let mut named = default_remote("kit+memory://x");
    named.name = "heads".into();
    clone(
        &target,
        &counted,
        &named,
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let records = RepoLayout::single(&target).applied_packs_dir();
    assert!(records.join("heads").is_file());
    assert!(records.join(".heads").is_dir());
    assert!(!refs::validate_ref_name(".heads"));
    counted.take();
    let observer = Recorder::default();
    pull(
        &target,
        &counted,
        "heads",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 2);
    assert!(
        !observer
            .events
            .borrow()
            .iter()
            .any(|event| matches!(event, SyncEvent::AppliedPacksPersistFailed { .. }))
    );
}

fn pending_restore() -> (Remote, tempfile::TempDir, RepoLayout, Hash, Hash) {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n"), ("c.txt", b"same\n")], true);
    let dir = tempfile::tempdir().unwrap();
    clone_into(&remote, dir.path());
    let second = remote.publish(
        Some(first),
        &[("a.txt", b"two\n"), ("c.txt", b"same\n")],
        true,
    );
    let layout = RepoLayout::single(dir.path());
    let result = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &StopAfterHead {
            layout: layout.clone(),
            tip: second,
        },
    );
    assert!(matches!(result, Err(SyncError::Interrupted)));
    (remote, dir, layout, first, second)
}

#[test]
fn recovery_preserves_new_untracked_files() {
    let (remote, dir, layout, _, _) = pending_restore();
    std::fs::write(dir.path().join("notes.txt"), b"notes\n").unwrap();
    let result = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    );
    // A clean sweep cannot preserve this file, so recovery must refuse it.
    assert!(matches!(result, Err(SyncError::RestoreSafety(_))));
    assert_eq!(
        std::fs::read(dir.path().join("notes.txt")).unwrap(),
        b"notes\n"
    );
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"one\n");
    assert!(layout.pull_head_file().exists());
}

#[test]
fn recovery_refuses_edits_to_files_the_pull_did_not_change() {
    let (remote, dir, layout, _, _) = pending_restore();
    std::fs::write(dir.path().join("c.txt"), b"local edit\n").unwrap();
    let index = std::fs::read(layout.index_file()).unwrap();
    let marker = std::fs::read(layout.pull_head_file()).unwrap();
    let result = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    );
    assert!(matches!(result, Err(SyncError::RestoreSafety(_))));
    assert_eq!(
        std::fs::read(dir.path().join("c.txt")).unwrap(),
        b"local edit\n"
    );
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"one\n");
    assert_eq!(std::fs::read(layout.index_file()).unwrap(), index);
    assert_eq!(std::fs::read(layout.pull_head_file()).unwrap(), marker);
}

#[test]
fn recovery_refuses_later_edits_after_the_target_lands_another_way() {
    let (remote, dir, layout, _, second) = pending_restore();
    let store = kit_core::store::ObjectStore::open(&layout).unwrap();
    let Object::Commit(commit) = store.read_object(&second).unwrap() else {
        panic!("commit");
    };
    kit_sync::worktree::restore_worktree_and_index(&layout, &store, commit.tree_hash).unwrap();
    std::fs::write(dir.path().join("a.txt"), b"later edit\n").unwrap();
    let result = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    );
    assert!(matches!(result, Err(SyncError::RestoreSafety(_))));
    assert_eq!(
        std::fs::read(dir.path().join("a.txt")).unwrap(),
        b"later edit\n"
    );
    assert!(layout.pull_head_file().exists());
}

#[test]
fn detached_head_refuses_recovery_before_changing_files() {
    let (remote, dir, layout, _, second) = pending_restore();
    refs::write_head_detached(&layout, &second).unwrap();
    std::fs::write(dir.path().join("a.txt"), b"later edit\n").unwrap();
    remote.publish(Some(second), &[("a.txt", b"three\n")], true);
    let result = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    );
    assert!(matches!(result, Err(SyncError::DetachedHead)));
    assert_eq!(
        std::fs::read(dir.path().join("a.txt")).unwrap(),
        b"later edit\n"
    );
    assert!(layout.pull_head_file().exists());
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(second)
    );
}

#[test]
fn pull_discards_markers_that_neither_head_nor_the_selected_branch_names() {
    let (remote, dir, layout, first, second) = pending_restore();
    let third = remote.publish(
        Some(second),
        &[("a.txt", b"three\n"), ("c.txt", b"same\n")],
        true,
    );
    fetch(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let store = kit_core::store::ObjectStore::open(&layout).unwrap();
    let Object::Commit(commit) = store.read_object(&third).unwrap() else {
        panic!("commit");
    };
    kit_sync::worktree::restore_worktree_and_index(&layout, &store, commit.tree_hash).unwrap();
    refs::write_ref(&layout, "main", &third).unwrap();
    // Manual recovery followed by a newer commit leaves the old marker behind.
    let report = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert!(matches!(report.outcome, PullOutcome::UpToDate { .. }));
    assert!(!layout.pull_head_file().exists());
    // A remote rewind before the branch move leaves no restore to finish.
    refs::write_ref(&layout, "main", &first).unwrap();
    remote
        .tx
        .update_ref("refs/heads/main", RefWriteCondition::Any, &first)
        .unwrap();
    write_pull_marker(&layout, second);
    let report = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert!(matches!(report.outcome, PullOutcome::UpToDate { .. }));
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"three\n");
    assert!(!layout.pull_head_file().exists());
    // A well-formed marker from another branch is equally stale.
    write_pull_marker(&layout, hash::hash(b"other branch"));
    pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert!(!layout.pull_head_file().exists());
}

#[test]
fn pull_finishes_an_unborn_branch_after_its_selected_branch_already_moved() {
    let remote = Remote::new();
    let tip = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let layout = init_clone_dir(dir.path(), &default_remote("kit+memory://x")).unwrap();
    refs::write_head_branch(&layout, "unborn").unwrap();
    fetch(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    // Stop between the selected branch write and the HEAD write.
    write_pull_marker(&layout, tip);
    refs::write_ref(&layout, "main", &tip).unwrap();
    let report = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert!(matches!(report.outcome, PullOutcome::FastForwarded { new, .. } if new == tip));
    assert_eq!(
        refs::read_head(&layout).unwrap(),
        refs::Head::Branch("main".to_owned())
    );
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"one\n");
    assert!(!layout.pull_head_file().exists());
}

#[test]
fn marker_write_failure_cannot_move_the_branch_or_head() {
    struct BlockMarker {
        layout: RepoLayout,
        tip: Hash,
    }
    impl Observer<SyncEvent> for BlockMarker {
        fn cancelled(&self) -> bool {
            if refs::read_remote_ref(&self.layout, "default", "main").unwrap() == Some(self.tip) {
                std::fs::create_dir_all(self.layout.pull_head_file()).unwrap();
            }
            false
        }
    }
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    clone_into(&remote, dir.path());
    let second = remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    let layout = RepoLayout::single(dir.path());
    let result = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &BlockMarker {
            layout: layout.clone(),
            tip: second,
        },
    );
    assert!(result.is_err());
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));
    assert_eq!(refs::resolve_head(&layout).unwrap(), Some(first));
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"one\n");
}

#[test]
fn recovery_preserves_ignored_files_under_a_target_file_path() {
    let (remote, dir, layout, _, _) = pending_restore();
    std::fs::remove_file(dir.path().join("a.txt")).unwrap();
    std::fs::create_dir(dir.path().join("a.txt")).unwrap();
    std::fs::write(dir.path().join(".kitignore"), b"a.txt/notes.txt\n").unwrap();
    std::fs::write(dir.path().join("a.txt/notes.txt"), b"notes\n").unwrap();
    let result = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    );
    assert!(matches!(result, Err(SyncError::RestoreSafety(_))));
    assert_eq!(
        std::fs::read(dir.path().join("a.txt/notes.txt")).unwrap(),
        b"notes\n"
    );
    assert!(layout.pull_head_file().exists());
}

#[test]
fn recovery_keeps_untracked_files_that_the_ignore_rules_preserve() {
    let (remote, dir, layout, _, _) = pending_restore();
    std::fs::write(dir.path().join(".kitignore"), b"cache.bin\n").unwrap();
    std::fs::write(dir.path().join("cache.bin"), b"cache\n").unwrap();
    pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("cache.bin")).unwrap(),
        b"cache\n"
    );
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"two\n");
    assert!(!layout.pull_head_file().exists());
}

fn publish_nested_a(remote: &Remote, parent: Option<Hash>) -> Hash {
    let (mut objects, _) = remote.build(parent, &[("b.txt", b"nested\n")], true);
    let Object::Commit(mut commit) = objects.pop().unwrap() else {
        panic!("commit");
    };
    let root = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"a".to_vec(),
            mode: EntryMode::Tree,
            object_hash: commit.tree_hash,
        }],
    });
    commit.tree_hash = root.id().unwrap();
    commit.signature = sign::sign_commit(&commit, &remote.key).unwrap().0;
    let commit = Object::Commit(commit);
    let tip = commit.id().unwrap();
    objects.extend([root, commit]);
    remote.publish_objects(&objects, tip, false);
    tip
}

fn pending_file_directory_restore(
    to_directory: bool,
) -> (Remote, tempfile::TempDir, RepoLayout, Hash) {
    let remote = Remote::new();
    let first = if to_directory {
        remote.publish(None, &[("a", b"plain\n")], true)
    } else {
        publish_nested_a(&remote, None)
    };
    let dir = tempfile::tempdir().unwrap();
    clone_into(&remote, dir.path());
    let second = if to_directory {
        publish_nested_a(&remote, Some(first))
    } else {
        remote.publish(Some(first), &[("a", b"plain\n")], true)
    };
    let layout = RepoLayout::single(dir.path());
    let result = pull(
        dir.path(),
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &StopAfterHead {
            layout: layout.clone(),
            tip: second,
        },
    );
    assert!(matches!(result, Err(SyncError::Interrupted)));
    if to_directory {
        // One target descendant landed, but the index still tracks file a.
        std::fs::remove_file(dir.path().join("a")).unwrap();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        std::fs::write(dir.path().join("a/b.txt"), b"nested\n").unwrap();
    }
    (remote, dir, layout, second)
}

#[test]
fn recovery_preserves_edits_during_file_directory_transitions() {
    for to_directory in [true, false] {
        let (remote, dir, layout, second) = pending_file_directory_restore(to_directory);
        std::fs::write(dir.path().join("a/b.txt"), b"local edit\n").unwrap();
        let index = std::fs::read(layout.index_file()).unwrap();
        let marker = std::fs::read(layout.pull_head_file()).unwrap();
        let result = pull(
            dir.path(),
            &remote.source(),
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        );
        assert!(
            matches!(result, Err(SyncError::RestoreSafety(_))),
            "to_directory={to_directory}: {result:?}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("a/b.txt")).unwrap(),
            b"local edit\n"
        );
        assert_eq!(std::fs::read(layout.index_file()).unwrap(), index);
        assert_eq!(std::fs::read(layout.pull_head_file()).unwrap(), marker);
        assert_eq!(refs::resolve_head(&layout).unwrap(), Some(second));
    }
}

#[test]
fn recovery_finishes_unedited_file_directory_transitions() {
    for to_directory in [true, false] {
        let (remote, dir, layout, _) = pending_file_directory_restore(to_directory);
        pull(
            dir.path(),
            &remote.source(),
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap();
        if to_directory {
            assert_eq!(
                std::fs::read(dir.path().join("a/b.txt")).unwrap(),
                b"nested\n"
            );
        } else {
            assert_eq!(std::fs::read(dir.path().join("a")).unwrap(), b"plain\n");
        }
        assert!(!layout.pull_head_file().exists());
    }
}

fn write_pull_marker(layout: &RepoLayout, target: Hash) {
    let store = kit_core::store::ObjectStore::open(layout).unwrap();
    let index = kit_core::index::read_index(layout).unwrap();
    let before_tree =
        kit_core::worktree::build_tree_from_index_with(&store, &store, &index, false).unwrap();
    std::fs::write(
        layout.pull_head_file(),
        PullState {
            target,
            before_tree,
        }
        .encode(),
    )
    .unwrap();
}

/// Counts the requests a fetch makes and forwards the repository cursor.
struct CountingCursor<'a> {
    inner: TransportSource<'a>,
    calls: Cell<usize>,
}

impl RemoteSource for CountingCursor<'_> {
    fn list_branches(&self) -> Result<Vec<kit_core::refs::Ref>, kit_sync::SourceError> {
        self.calls.set(self.calls.get() + 1);
        self.inner.list_branches()
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, kit_sync::SourceError> {
        self.calls.set(self.calls.get() + 1);
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.calls.set(self.calls.get() + 1);
        self.inner.download_blob_via_ref(key, name)
    }
    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.calls.set(self.calls.get() + 1);
        self.inner.download_pack_via_ref(key, name)
    }
    fn repo_cursor(&self) -> Result<Option<kit_core::protocol::RepoCursor>, kit_sync::SourceError> {
        self.inner.repo_cursor()
    }
}

fn counted_fetch(
    remote: &Remote,
    dir: &Path,
    options: &SyncOptions,
) -> (kit_sync::FetchReport, usize) {
    let source = CountingCursor {
        inner: remote.source(),
        calls: Cell::new(0),
    };
    let report = fetch(dir, &source, "default", options, &NoopObserver).unwrap();
    (report, source.calls.get())
}

#[test]
fn an_unchanged_remote_costs_no_request_beyond_its_cursor() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let options = SyncOptions::default();

    // The clone saw the cursor: nothing changed, so no listing, no ref read.
    let (report, calls) = counted_fetch(&remote, &target, &options);
    assert!(report.remote_unchanged);
    assert_eq!((calls, report.branches_fetched), (0, 0));

    // A write changes the cursor, and the fetch does its full work.
    let second = remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    let (report, calls) = counted_fetch(&remote, &target, &options);
    assert!(!report.remote_unchanged);
    assert!(calls > 0);
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(second)
    );
    let (report, calls) = counted_fetch(&remote, &target, &options);
    assert!(report.remote_unchanged && calls == 0);

    // A changed tracking ref, or a fetch that wants signatures checked after
    // one that did not, is not trusted.
    refs::write_remote_ref(&layout, "default", "main", &first).unwrap();
    let (report, _) = counted_fetch(&remote, &target, &options);
    assert!(!report.remote_unchanged);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(second)
    );
    let unsigned = SyncOptions::default().with_verify_signatures(false);
    let (report, _) = counted_fetch(&remote, &target, &unsigned);
    assert!(report.remote_unchanged);
    std::fs::remove_dir_all(layout.applied_packs_dir().join(".cursors")).unwrap();
    let (report, _) = counted_fetch(&remote, &target, &unsigned);
    assert!(!report.remote_unchanged);
    let (report, _) = counted_fetch(&remote, &target, &options);
    assert!(
        !report.remote_unchanged,
        "an unsigned fetch's record does not satisfy a signed one"
    );
}

#[test]
fn a_recreated_remote_never_matches_an_old_cursor() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let again = Remote::new();
    again.publish(None, &[("a.txt", b"one\n")], true);
    let (report, _) = counted_fetch(&again, &target, &SyncOptions::default());
    assert!(!report.remote_unchanged);
}

/// An unchanged cursor checks that the object of each tracked tip is in the
/// store, not the closure below it. An object below a tip that the store
/// lost stays missing through such a fetch. The next fetch that does its
/// full work, because the cursor changed or no record matches, checks the
/// closure and fetches the chain again.
#[test]
fn an_unchanged_cursor_checks_the_tips_not_their_closure() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let layout = RepoLayout::single(&target);
    let store = kit_core::store::ObjectStore::open(&layout).unwrap();
    let blob = Object::Blob(Blob {
        data: b"one\n".to_vec(),
    })
    .id()
    .unwrap();
    assert!(store.contains(&blob));
    store.remove_object(&blob).unwrap();

    let options = SyncOptions::default();
    let (report, calls) = counted_fetch(&remote, &target, &options);
    assert!(report.remote_unchanged && calls == 0);
    assert!(!store.contains(&blob), "the skip does not walk the closure");

    std::fs::remove_dir_all(layout.applied_packs_dir().join(".cursors")).unwrap();
    let (report, _) = counted_fetch(&remote, &target, &options);
    assert!(!report.remote_unchanged);
    assert!(store.contains(&blob), "a full fetch heals the closure");
}

// ---- A pull writes only what the new tip changed ------------------------

#[cfg(unix)]
type Item = (&'static str, EntryMode, &'static [u8]);

/// Every file, directory and symlink under `root` outside `.kit`, with its
/// content and whether it is executable.
#[cfg(unix)]
fn worktree_snapshot(root: &Path) -> std::collections::BTreeMap<String, String> {
    use std::os::unix::fs::PermissionsExt;

    fn walk(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            if rel == ".kit" {
                continue;
            }
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                out.insert(rel, "dir".to_owned());
                walk(root, &path, out);
            } else if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                out.insert(rel, format!("symlink {}", target.display()));
            } else {
                let exec = meta.permissions().mode() & 0o111 != 0;
                let content = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
                out.insert(rel, format!("file exec={exec} {content:?}"));
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(root, root, &mut out);
    out
}

#[cfg(unix)]
/// The index entries without their stat cache, which differs by machine and time.
fn index_snapshot(root: &Path) -> Vec<(String, kit_core::index::EntryStatus, Hash)> {
    let layout = RepoLayout::single(root);
    kit_core::index::read_index(&layout)
        .unwrap()
        .entries
        .iter()
        .map(|e| (e.path.clone(), e.status, e.object_hash))
        .collect()
}

/// Each index entry's object id and stat cache, by path.
#[cfg(unix)]
fn index_snapshot_with_stat(
    root: &Path,
) -> std::collections::BTreeMap<String, (Hash, u64, u64, u64, u64)> {
    kit_core::index::read_index(&RepoLayout::single(root))
        .unwrap()
        .entries
        .iter()
        .map(|e| {
            (
                e.path.clone(),
                (e.object_hash, e.mtime_ns, e.size, e.ino, e.ctime_ns),
            )
        })
        .collect()
}

#[cfg(unix)]
fn pull_ok(dir: &Path, remote: &Remote) {
    let report = pull(
        dir,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert!(
        matches!(report.outcome, PullOutcome::FastForwarded { .. }),
        "{:?}",
        report.outcome
    );
}

/// Added, changed, deleted, renamed and mode-changed files, a file that
/// becomes a directory and a directory that becomes a file, and a symlink that
/// changes its target.
#[cfg(unix)]
#[test]
fn a_pull_leaves_the_worktree_and_index_equal_to_a_fresh_checkout_of_the_tip() {
    let before: &[Item] = &[
        ("keep.txt", EntryMode::Blob, b"keep\n"),
        ("change.txt", EntryMode::Blob, b"old\n"),
        ("delete.txt", EntryMode::Blob, b"gone\n"),
        ("old-name.txt", EntryMode::Blob, b"renamed\n"),
        ("mode.sh", EntryMode::Blob, b"#!/bin/sh\n"),
        ("flip.sh", EntryMode::Executable, b"#!/bin/sh\n"),
        ("file-to-dir", EntryMode::Blob, b"was a file\n"),
        ("dir-to-file/inner.txt", EntryMode::Blob, b"was a dir\n"),
        ("link", EntryMode::Symlink, b"keep.txt"),
        ("same-link", EntryMode::Symlink, b"keep.txt"),
        ("dir/same.txt", EntryMode::Blob, b"same\n"),
        ("dir/inner.txt", EntryMode::Blob, b"inner\n"),
        ("untouched/deep/a.txt", EntryMode::Blob, b"a\n"),
    ];
    let after: &[Item] = &[
        ("keep.txt", EntryMode::Blob, b"keep\n"),
        ("change.txt", EntryMode::Blob, b"new\n"),
        ("new-name.txt", EntryMode::Blob, b"renamed\n"),
        ("added.txt", EntryMode::Blob, b"added\n"),
        ("mode.sh", EntryMode::Executable, b"#!/bin/sh\n"),
        ("flip.sh", EntryMode::Blob, b"#!/bin/sh\n"),
        ("file-to-dir/now.txt", EntryMode::Blob, b"now a dir\n"),
        ("dir-to-file", EntryMode::Blob, b"now a file\n"),
        ("link", EntryMode::Symlink, b"change.txt"),
        ("same-link", EntryMode::Symlink, b"keep.txt"),
        ("dir/same.txt", EntryMode::Blob, b"same\n"),
        ("dir/inner.txt", EntryMode::Blob, b"inner changed\n"),
        ("untouched/deep/a.txt", EntryMode::Blob, b"a\n"),
    ];
    let remote = Remote::new();
    let first = remote.publish_paths(None, before);
    let dir = tempfile::tempdir().unwrap();
    let pulled = dir.path().join("pulled");
    clone_into(&remote, &pulled);
    remote.publish_paths(Some(first), after);
    pull_ok(&pulled, &remote);

    let fresh = dir.path().join("fresh");
    clone_into(&remote, &fresh);
    assert_eq!(worktree_snapshot(&pulled), worktree_snapshot(&fresh));
    assert_eq!(index_snapshot(&pulled), index_snapshot(&fresh));
    assert_eq!(
        worktree_snapshot(&pulled)["change.txt"],
        "file exec=false \"new\\n\""
    );
}

/// The files a pull did not change keep their inode and mtime.
#[cfg(unix)]
#[test]
fn a_pull_does_not_rewrite_the_files_the_tip_left_unchanged() {
    use std::os::unix::fs::MetadataExt;

    let before: &[Item] = &[
        ("keep.txt", EntryMode::Blob, b"keep\n"),
        ("change.txt", EntryMode::Blob, b"old\n"),
        ("dir/same.txt", EntryMode::Blob, b"same\n"),
        ("dir/inner/deep.txt", EntryMode::Blob, b"deep\n"),
        ("run.sh", EntryMode::Executable, b"#!/bin/sh\n"),
        ("link", EntryMode::Symlink, b"keep.txt"),
    ];
    let after: &[Item] = &[
        ("keep.txt", EntryMode::Blob, b"keep\n"),
        ("change.txt", EntryMode::Blob, b"new\n"),
        ("dir/same.txt", EntryMode::Blob, b"same\n"),
        ("dir/inner/deep.txt", EntryMode::Blob, b"deep\n"),
        ("run.sh", EntryMode::Executable, b"#!/bin/sh\n"),
        ("link", EntryMode::Symlink, b"keep.txt"),
    ];
    let remote = Remote::new();
    let first = remote.publish_paths(None, before);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let stat = |name: &str| {
        let meta = std::fs::symlink_metadata(target.join(name)).unwrap();
        (meta.ino(), meta.mtime(), meta.mtime_nsec())
    };
    let untouched = [
        "keep.txt",
        "dir/same.txt",
        "dir/inner/deep.txt",
        "run.sh",
        "link",
    ];
    let recorded: Vec<_> = untouched.iter().map(|n| stat(n)).collect();
    let changed_before = stat("change.txt");
    let index_before = index_snapshot_with_stat(&target);

    remote.publish_paths(Some(first), after);
    pull_ok(&target, &remote);

    let now: Vec<_> = untouched.iter().map(|n| stat(n)).collect();
    assert_eq!(recorded, now, "an unchanged file was rewritten");
    assert_ne!(
        changed_before.0,
        stat("change.txt").0,
        "the changed file was not replaced"
    );
    assert_eq!(std::fs::read(target.join("change.txt")).unwrap(), b"new\n");
    // The stat cache of an unchanged file survives, so the next command does
    // not re-hash it.
    let index_after = index_snapshot_with_stat(&target);
    for name in untouched {
        assert_eq!(index_before[name], index_after[name], "{name}");
    }
    assert_ne!(index_before["change.txt"].0, index_after["change.txt"].0);
}

/// A pull whose safety check finds a local change refuses with the same
/// messages as before, and the three message prefixes stay as they are.
#[test]
fn the_restore_safety_messages_are_unchanged() {
    fn refusal(result: Result<kit_sync::PullReport, SyncError>) -> String {
        match result {
            Err(SyncError::RestoreSafety(message)) => message,
            other => panic!("expected a restore safety refusal, got {other:?}"),
        }
    }
    let run = |dir: &Path, remote: &Remote| {
        pull(
            dir,
            &remote.source(),
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
    };

    // A local edit to a file the pull would rewrite.
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n"), ("c.txt", b"same\n")], true);
    let dir = tempfile::tempdir().unwrap();
    clone_into(&remote, dir.path());
    remote.publish(
        Some(first),
        &[("a.txt", b"two\n"), ("c.txt", b"same\n")],
        true,
    );
    std::fs::write(dir.path().join("a.txt"), b"local edit\n").unwrap();
    assert_eq!(
        refusal(run(dir.path(), &remote)),
        "restore would overwrite local changes; commit, stash, or reset 'a.txt' first"
    );
    // An edit to a file the pull would leave alone is refused too: recovery
    // and the safety check cover every tracked path.
    std::fs::write(dir.path().join("a.txt"), b"one\n").unwrap();
    std::fs::write(dir.path().join("c.txt"), b"local edit\n").unwrap();
    assert!(matches!(
        run(dir.path(), &remote),
        Err(SyncError::RestoreSafety(_))
    ));
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"one\n");

    // An untracked file in the way of the new tip.
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    clone_into(&remote, dir.path());
    remote.publish(Some(first), &[("a.txt", b"one\n"), ("b.txt", b"b\n")], true);
    std::fs::write(dir.path().join("b.txt"), b"mine\n").unwrap();
    assert_eq!(
        refusal(run(dir.path(), &remote)),
        "restore would overwrite untracked path 'b.txt'; move or remove it first"
    );

    // A recovery that would overwrite a local edit.
    let (remote, dir, _, _, _) = pending_restore();
    std::fs::write(dir.path().join("c.txt"), b"local edit\n").unwrap();
    let message = refusal(run(dir.path(), &remote));
    assert!(
        message.starts_with("pull recovery would overwrite local changes at 'c.txt'; "),
        "{message}"
    );

    // A recovery with no remote branch left to finish against.
    let (_, dir, layout, _, _) = pending_restore();
    refs::delete_remote_ref(&layout, "default", "main").unwrap();
    let message = refusal(run(dir.path(), &Remote::new()));
    assert!(
        message.starts_with("unfinished pull cannot recover without a remote branch"),
        "{message}"
    );
}
