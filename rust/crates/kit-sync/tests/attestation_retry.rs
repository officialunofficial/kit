#![allow(clippy::unwrap_used)]
include!("support/attestation_fetch.rs");

use kit_core::{
    hash::{Hash, hash},
    object::{Commit, Identity, Object, Tree},
    protocol::{PackKey, PackSink, SliceBody, Transport},
    refs::{ATTESTMAP_REF, Ref, RefWriteCondition},
    sign::{self, KeyPair},
};
use kit_sync::{RemoteSource, SourceError, TransportSource};
use std::cell::{Cell, RefCell};

/// Like `attestation_fetch::code`, on any branch, with a distinct message.
fn code_on(tx: &dyn Transport, branch: &str, msg: &[u8]) -> Hash {
    let key = KeyPair::generate().unwrap();
    let tree = Object::Tree(Tree { entries: vec![] });
    let tree_id = tree.id().unwrap();
    let mut commit = Commit::new_unannotated(
        tree_id,
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        msg.to_vec(),
        1,
        [0; 64],
    );
    commit.signature = sign::sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let tip = commit.id().unwrap();
    let mut pack = kit_core::pack::PackWriter::new_raw_only();
    for object in [tree, commit] {
        pack.push_raw(
            object.id().unwrap(),
            &kit_core::serialize::serialize(&object).unwrap(),
        )
        .unwrap();
    }
    let bytes = pack.finish().unwrap();
    let pkey = hash(&bytes);
    tx.upload_pack(
        &SliceBody(&bytes),
        &PackKey::from_hash(pkey),
        Some(&format!("refs/heads/{branch}")),
    )
    .unwrap();
    let node = kit_core::transfer::encode_packlist(None, &[pkey]).unwrap();
    let nkey = hash(&node);
    tx.upload_blob(&node, &PackKey::from_hash(nkey), Some(ATTESTMAP_REF))
        .unwrap();
    tx.update_ref(
        &format!("refs/kit/packmap/{branch}"),
        RefWriteCondition::Any,
        &nkey,
    )
    .unwrap();
    tx.update_ref(
        &format!("refs/heads/{branch}"),
        RefWriteCondition::Any,
        &tip,
    )
    .unwrap();
    tip
}

/// A Connect-like source: `ReadRef` is strong, `ListRefs` may lag (SPEC-TRANSPORT-CONNECT §7.9).
struct Lagging<'a> {
    tx: &'a kit_transport_memory::MemoryTransport,
    stale: RefCell<Option<Vec<Ref>>>,
    node_downloads: Cell<usize>,
    cursor: bool,
    fail_once: Cell<bool>,
}
impl RemoteSource for Lagging<'_> {
    fn supports_attestations(&self) -> bool {
        true
    }
    fn repo_cursor(&self) -> Result<Option<kit_core::protocol::RepoCursor>, SourceError> {
        if !self.cursor {
            return Ok(None);
        }
        TransportSource::new(self.tx).repo_cursor()
    }
    fn list_branches(&self) -> Result<Vec<Ref>, SourceError> {
        if let Some(stale) = self.stale.borrow_mut().take() {
            return Ok(stale);
        }
        TransportSource::new(self.tx).list_branches()
    }
    fn list_refs(&self, prefix: &str) -> Result<Vec<Ref>, SourceError> {
        TransportSource::new(self.tx).list_refs(prefix)
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        TransportSource::new(self.tx).read_ref(name)
    }
    fn download_blob(&self, key: &PackKey, name: &str) -> Result<Vec<u8>, SourceError> {
        TransportSource::new(self.tx).download_blob(key, name)
    }
    fn download_pack(
        &self,
        key: &PackKey,
        name: &str,
        sink: &mut dyn PackSink,
    ) -> Result<(), SourceError> {
        if name == ATTESTMAP_REF {
            if self.fail_once.replace(false) {
                return Err(SourceError::ProtocolError);
            }
            self.node_downloads.set(self.node_downloads.get() + 1);
        }
        TransportSource::new(self.tx).download_pack(key, name, sink)
    }
}

fn remote() -> kit_sync::CloneRemote {
    kit_sync::CloneRemote {
        name: "origin".into(),
        url: "kit+memory://test".into(),
        kind: "memory".into(),
    }
}

#[test]
fn lagging_listing_retries_when_subject_arrives() {
    let tx = kit_transport_memory::MemoryTransport::new();
    code_on(&tx, "main", b"main");
    let temp = tempfile::tempdir().unwrap();
    let layout = kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let source = Lagging {
        tx: &tx,
        stale: RefCell::new(None),
        node_downloads: Cell::new(0),
        cursor: false,
        fail_once: Cell::new(false),
    };
    let options = kit_sync::SyncOptions::default();
    kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    // The listing is captured, then CI pushes a new branch and attests it.
    let stale = TransportSource::new(&tx).list_branches().unwrap();
    let x = code_on(&tx, "feature", b"feature");
    let env = attestation_fetch::envelope(x);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    *source.stale.borrow_mut() = Some(stale);
    let first = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    let second = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    let path = kit_attest::store::envelope_path(&layout, &x, &hash(&env));
    assert!(
        kit_core::store::ObjectStore::open(&layout)
            .unwrap()
            .contains(&x),
        "commit fetched"
    );
    assert_eq!(first.attestations_dropped, 1);
    assert_eq!(second.attestations_stored, 1);
    assert!(path.exists());
}

#[test]
fn broken_chain_is_cached() {
    let tx = kit_transport_memory::MemoryTransport::new();
    code_on(&tx, "main", b"main");
    // 25 nodes listing 4096 non-existent packs each: over the 100,000 pack walk limit.
    let mut prev = None;
    for n in 0..25u32 {
        let packs: Vec<Hash> = (0..4096u32)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&n.to_le_bytes());
                h[4..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();
        let node = kit_core::transfer::encode_packlist(prev, &packs).unwrap();
        let key = hash(&node);
        tx.upload_blob(&node, &PackKey::from_hash(key), Some(ATTESTMAP_REF))
            .unwrap();
        prev = Some(key);
    }
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &prev.unwrap())
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let source = Lagging {
        tx: &tx,
        stale: RefCell::new(None),
        node_downloads: Cell::new(0),
        cursor: true,
        fail_once: Cell::new(false),
    };
    let options = kit_sync::SyncOptions::default();
    for round in 0..3 {
        source.node_downloads.set(0);
        let r = kit_sync::fetch(
            temp.path(),
            &source,
            "origin",
            &options,
            &kit_sync::NoopObserver,
        )
        .unwrap();
        if round > 0 {
            assert!(r.remote_unchanged);
            assert_eq!(source.node_downloads.get(), 0);
        }
    }
    let mut off = options.clone();
    off.attestations = false;
    kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &off,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert!(
        kit_sync::fetch(
            temp.path(),
            &source,
            "origin",
            &off,
            &kit_sync::NoopObserver
        )
        .unwrap()
        .remote_unchanged
    );
}

#[test]
fn missing_head_is_cached() {
    let tx = kit_transport_memory::MemoryTransport::new();
    code_on(&tx, "main", b"main");
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &[7; 32])
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let source = TransportSource::new(&tx);
    let options = kit_sync::SyncOptions::default();
    for round in 0..3 {
        let r = kit_sync::fetch(
            temp.path(),
            &source,
            "origin",
            &options,
            &kit_sync::NoopObserver,
        )
        .unwrap();
        if round > 0 {
            assert!(r.remote_unchanged);
        }
    }
}

#[test]
fn head_change_walks_only_new_nodes() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let tip = code_on(&tx, "main", b"main");
    let env = attestation_fetch::envelope(tip);
    let pack = kit_attest::pack::build(&[&env], 4096).unwrap();
    attestation_fetch::append(&tx, &pack);
    // A writer appends 2,000 empty nodes (each lists no pack).
    for _ in 0..2000 {
        let prev = tx.read_ref(ATTESTMAP_REF).unwrap();
        let node = kit_core::transfer::encode_packlist(prev, &[]).unwrap();
        let key = hash(&node);
        tx.upload_blob(&node, &PackKey::from_hash(key), Some(ATTESTMAP_REF))
            .unwrap();
        tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &key)
            .unwrap();
    }
    let temp = tempfile::tempdir().unwrap();
    kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let source = Lagging {
        tx: &tx,
        stale: RefCell::new(None),
        node_downloads: Cell::new(0),
        cursor: true,
        fail_once: Cell::new(false),
    };
    let options = kit_sync::SyncOptions::default();
    kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    let tip2 = code_on(&tx, "other", b"other");
    attestation_fetch::append(
        &tx,
        &kit_attest::pack::build(&[&attestation_fetch::envelope(tip2)], 4096).unwrap(),
    );
    source.node_downloads.set(0);
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestations_stored, 1);
    assert_eq!(source.node_downloads.get(), 2);
}

#[test]
fn named_branch_fetch_retries_only_after_subject_arrives() {
    let tx = kit_transport_memory::MemoryTransport::new();
    code_on(&tx, "main", b"main");
    let subject = code_on(&tx, "feature", b"feature");
    let env = attestation_fetch::envelope(subject);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    let layout = kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let source = Lagging {
        tx: &tx,
        stale: RefCell::new(None),
        node_downloads: Cell::new(0),
        cursor: false,
        fail_once: Cell::new(false),
    };
    let main_only: Vec<_> = TransportSource::new(&tx)
        .list_branches()
        .unwrap()
        .into_iter()
        .filter(|r| r.name == "main")
        .collect();
    *source.stale.borrow_mut() = Some(main_only.clone());
    let mut options = kit_sync::SyncOptions::default();
    options.target_branch = Some("main".into());
    let first = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(first.attestations_dropped, 1);
    source.node_downloads.set(0);
    *source.stale.borrow_mut() = Some(main_only);
    kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(source.node_downloads.get(), 0);
    assert!(!kit_attest::store::envelope_path(&layout, &subject, &hash(&env)).exists());
    options.target_branch = Some("feature".into());
    let second = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(second.attestations_stored, 1);
    assert_eq!(source.node_downloads.get(), 1);
}

#[test]
fn interrupted_walk_resumes_after_restart() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (tip, _) = attestation_fetch::code(&tx);
    let env = attestation_fetch::envelope(tip);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    let layout = kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let source = Lagging {
        tx: &tx,
        stale: RefCell::new(None),
        node_downloads: Cell::new(0),
        cursor: true,
        fail_once: Cell::new(true),
    };
    let first = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &kit_sync::SyncOptions::default(),
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert!(!first.attestation_warnings.is_empty());
    assert!(!kit_attest::store::envelope_path(&layout, &tip, &hash(&env)).exists());
    let second = kit_sync::fetch(
        temp.path(),
        &TransportSource::new(&tx),
        "origin",
        &kit_sync::SyncOptions::default(),
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(second.attestations_stored, 1);
}

#[test]
fn skipped_tag_subject_is_retried_when_tags_are_enabled() {
    let tx = kit_transport_memory::MemoryTransport::new();
    code_on(&tx, "main", b"main");
    let subject = code_on(&tx, "tag-only", b"tagged");
    let packmap = tx.read_ref("refs/kit/packmap/tag-only").unwrap().unwrap();
    tx.update_ref("refs/tags/release", RefWriteCondition::Missing, &subject)
        .unwrap();
    tx.update_ref(
        "refs/kit/tagmap/release",
        RefWriteCondition::Missing,
        &packmap,
    )
    .unwrap();
    tx.delete_ref("refs/heads/tag-only", &subject).unwrap();
    let env = attestation_fetch::envelope(subject);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let mut options = kit_sync::SyncOptions::default();
    options.tags = false;
    let source = TransportSource::new(&tx);
    let first = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(first.attestations_dropped, 1);
    options.tags = true;
    let second = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(second.attestations_stored, 1);
}

#[test]
fn removed_log_clears_pending_packs_after_an_interrupted_fetch() {
    use kit_sync::attestation_records::{Record, RecordKind};
    use std::collections::{BTreeMap, BTreeSet};
    let tx = kit_transport_memory::MemoryTransport::new();
    let (subject, _) = attestation_fetch::code(&tx);
    let pack = kit_attest::pack::build(&[&attestation_fetch::envelope(subject)], 4096).unwrap();
    let key = hash(&pack);
    attestation_fetch::append(&tx, &pack);
    tx.delete_ref(ATTESTMAP_REF, &tx.read_ref(ATTESTMAP_REF).unwrap().unwrap())
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let layout = kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let source = TransportSource::new(&tx);
    let path = kit_sync::attestation_records::path(&layout, &source, "origin", "", false);
    let record = Record {
        ids: BTreeSet::from([key]),
        pending: BTreeMap::from([(key, BTreeSet::from([subject]))]),
        ..Record::default()
    };
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, record.encode(RecordKind::Fetch)).unwrap();
    let report = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &kit_sync::SyncOptions::default(),
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestations_stored, 0);
    let after = Record::decode(&std::fs::read(path).unwrap(), RecordKind::Fetch).unwrap();
    assert!(after.pending.is_empty());
    assert!(after.ids.is_empty());
}

#[test]
fn a_new_baseline_discards_retries_for_packs_it_replaces() {
    use kit_sync::attestation_records::{Record, RecordKind};
    use std::collections::BTreeSet;
    let tx = kit_transport_memory::MemoryTransport::new();
    let main = code_on(&tx, "main", b"main");
    let main_only: Vec<_> = TransportSource::new(&tx).list_branches().unwrap();
    let subject = code_on(&tx, "feature", b"feature");
    let env = attestation_fetch::envelope(subject);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    let layout = kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let source = Lagging {
        tx: &tx,
        stale: RefCell::new(Some(main_only)),
        node_downloads: Cell::new(0),
        cursor: false,
        fail_once: Cell::new(false),
    };
    let options = kit_sync::SyncOptions::default();
    let first = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(first.attestations_dropped, 1);
    let pack = kit_attest::pack::build(&[&env, &attestation_fetch::envelope(main)], 4096).unwrap();
    let key = hash(&pack);
    tx.upload_blob(&pack, &PackKey::from_hash(key), None)
        .unwrap();
    let node = kit_core::transfer::encode_packlist(None, &[key]).unwrap();
    let head = hash(&node);
    tx.upload_blob(&node, &PackKey::from_hash(head), None)
        .unwrap();
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &head)
        .unwrap();
    source.node_downloads.set(0);
    let second = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(second.attestations_stored, 2);
    assert_eq!(second.attestations_rejected, 0);
    assert_eq!(source.node_downloads.get(), 2);
    let path = kit_sync::attestation_records::path(&layout, &source, "origin", "", false);
    let record = Record::decode(&std::fs::read(path).unwrap(), RecordKind::Fetch).unwrap();
    assert_eq!(record.ids, BTreeSet::from([key]));
}

#[test]
fn storage_limit_is_cumulative_and_skipped_pending_subjects_do_not_retry() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let main = code_on(&tx, "main", b"main");
    let feature = code_on(&tx, "feature", b"feature");
    let first = attestation_fetch::envelope(main);
    let pending = attestation_fetch::envelope(feature);
    let mut other = kit_attest::envelope::decode(&first).unwrap();
    other.payload.push(b' ');
    let other = other.encode().unwrap().into_bytes();
    attestation_fetch::append(
        &tx,
        &kit_attest::pack::build(&[&first, &pending], 4096).unwrap(),
    );

    let temp = tempfile::tempdir().unwrap();
    let layout = kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let source = Lagging {
        tx: &tx,
        stale: RefCell::new(None),
        node_downloads: Cell::new(0),
        cursor: true,
        fail_once: Cell::new(false),
    };
    seed_retention_usage(&layout, 99_998, 99_998 * first.len() as u64);
    let mut options = kit_sync::SyncOptions::default();
    options.target_branch = Some("main".into());
    let fetch = |options: &kit_sync::SyncOptions| {
        kit_sync::fetch(
            temp.path(),
            &source,
            "origin",
            options,
            &kit_sync::NoopObserver,
        )
        .unwrap()
    };
    let main_only: Vec<_> = source
        .list_branches()
        .unwrap()
        .into_iter()
        .filter(|branch| branch.name == "main")
        .collect();
    *source.stale.borrow_mut() = Some(main_only.clone());
    let before = fetch(&options);
    assert_eq!(before.attestations_stored, 1);
    assert_eq!(before.attestations_dropped, 1);
    assert!(before.attestation_warnings.is_empty());

    let mut third = kit_attest::envelope::decode(&first).unwrap();
    third.payload.extend(b"  ");
    let third = third.encode().unwrap().into_bytes();
    let mut fourth = kit_attest::envelope::decode(&first).unwrap();
    fourth.payload.extend(b"   ");
    let fourth = fourth.encode().unwrap().into_bytes();
    attestation_fetch::append(
        &tx,
        &kit_attest::pack::build(&[&other, &third, &fourth], 4096).unwrap(),
    );
    *source.stale.borrow_mut() = Some(main_only);
    let capped = fetch(&options);
    assert_eq!(capped.attestations_stored, 1);
    assert_eq!(capped.attestation_warnings.len(), 1);
    assert!(capped.attestation_warnings[0].contains("storage limit"));
    assert_eq!(kit_attest::store::list(&layout, &main).unwrap().len(), 2);
    assert!(kit_attest::store::envelope_path(&layout, &main, &hash(&first)).is_file());

    options.target_branch = Some("feature".into());
    source.node_downloads.set(0);
    let arrived = fetch(&options);
    assert_eq!(source.node_downloads.get(), 1);
    assert_eq!(arrived.attestation_warnings.len(), 1);
    assert_eq!(arrived.attestations_stored, 0);
    assert!(
        kit_core::store::ObjectStore::open(&layout)
            .unwrap()
            .contains(&feature)
    );
    assert!(
        kit_attest::store::list(&layout, &feature)
            .unwrap()
            .is_empty()
    );
    source.node_downloads.set(0);
    assert!(fetch(&options).attestation_warnings.is_empty());
    assert_eq!(source.node_downloads.get(), 0);
}

#[test]
fn storage_byte_limit_keeps_smaller_envelopes_and_is_independent_per_remote() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let subject = code_on(&tx, "main", b"main");
    let small = attestation_fetch::envelope(subject);
    let mut large = kit_attest::envelope::decode(&small).unwrap();
    large.payload.extend([b' '; 100]);
    let large = large.encode().unwrap().into_bytes();
    attestation_fetch::append(
        &tx,
        &kit_attest::pack::build(&[&large, &small], 4096).unwrap(),
    );
    let temp = tempfile::tempdir().unwrap();
    let layout = kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    seed_retention_usage(&layout, 1024, (512 << 20) - small.len() as u64);
    let source = TransportSource::new(&tx);
    let options = kit_sync::SyncOptions::default();
    let fetch = |remote| {
        kit_sync::fetch(
            temp.path(),
            &source,
            remote,
            &options,
            &kit_sync::NoopObserver,
        )
        .unwrap()
    };
    let capped = fetch("origin");
    assert_eq!(capped.attestations_stored, 1);
    assert_eq!(capped.attestation_warnings.len(), 1);
    assert!(kit_attest::store::envelope_path(&layout, &subject, &hash(&small)).is_file());
    assert!(!kit_sync::attestation_records::fetched_path(&layout, &hash(&large)).exists());
    let mut refetch = options.clone();
    refetch.refetch_attestations = true;
    refetch.remote_url = "kit+memory://changed".into();
    let replayed = kit_sync::fetch(
        temp.path(),
        &source,
        "origin",
        &refetch,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(replayed.attestations_stored, 0);
    assert_eq!(replayed.attestation_warnings.len(), 1);

    let independent = fetch("other");
    assert_eq!(independent.attestations_stored, 1);
    assert!(independent.attestation_warnings.is_empty());
    assert!(kit_attest::store::envelope_path(&layout, &subject, &hash(&large)).is_file());
}

#[test]
fn corrupt_storage_usage_fails_closed_and_checkpoints_the_pack() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let (subject, _) = attestation_fetch::code(&tx);
    let envelope = attestation_fetch::envelope(subject);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&envelope], 4096).unwrap());
    let temp = tempfile::tempdir().unwrap();
    let layout = kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
    let path = retention_usage_path(&layout);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let invalid = [0u8; 64];
    std::fs::write(&path, invalid).unwrap();
    let source = Lagging {
        tx: &tx,
        stale: RefCell::new(None),
        node_downloads: Cell::new(0),
        cursor: true,
        fail_once: Cell::new(false),
    };
    let fetch = || {
        kit_sync::fetch(
            temp.path(),
            &source,
            "origin",
            &kit_sync::SyncOptions::default(),
            &kit_sync::NoopObserver,
        )
        .unwrap()
    };
    let report = fetch();
    assert_eq!(report.branches_fetched, 1);
    assert_eq!(report.attestations_stored, 0);
    assert_eq!(report.attestation_warnings.len(), 1);
    assert!(report.attestation_warnings[0].contains("cannot read attestation storage usage"));
    assert_eq!(std::fs::read(path).unwrap(), invalid);
    source.node_downloads.set(0);
    assert!(fetch().remote_unchanged);
    assert_eq!(source.node_downloads.get(), 0);
}

#[test]
fn retry_reuses_one_charge_before_and_after_the_provenance_marker() {
    for marker_written in [false, true] {
        let tx = kit_transport_memory::MemoryTransport::new();
        let (subject, _) = attestation_fetch::code(&tx);
        let envelope = attestation_fetch::envelope(subject);
        let id = hash(&envelope);
        attestation_fetch::append(&tx, &kit_attest::pack::build(&[&envelope], 4096).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let layout = kit_sync::init_clone_dir(temp.path(), &remote()).unwrap();
        let path = retention_usage_path(&layout);
        let len = envelope.len() as u64;
        write_retention_usage(&path, 100_000, 100_000 * len, &[(id, len)]);
        if marker_written {
            std::fs::write(
                kit_sync::attestation_records::fetched_path(&layout, &id),
                [],
            )
            .unwrap();
        }
        let report = kit_sync::fetch(
            temp.path(),
            &TransportSource::new(&tx),
            "origin",
            &kit_sync::SyncOptions::default(),
            &kit_sync::NoopObserver,
        )
        .unwrap();
        assert_eq!(report.attestations_stored, 1);
        assert!(report.attestation_warnings.is_empty());
        assert_eq!(
            std::fs::read(kit_attest::store::envelope_path(&layout, &subject, &id)).unwrap(),
            envelope
        );
    }
}

fn seed_retention_usage(layout: &kit_core::layout::RepoLayout, count: u64, bytes: u64) {
    write_retention_usage(&retention_usage_path(layout), count, bytes, &[]);
}

fn write_retention_usage(
    path: &std::path::Path,
    count: u64,
    bytes: u64,
    reservations: &[(Hash, u64)],
) {
    let mut state = serde_json::to_vec(&([count, bytes], reservations)).unwrap();
    state.extend(hash(&state));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, state).unwrap();
}

fn retention_usage_path(layout: &kit_core::layout::RepoLayout) -> std::path::PathBuf {
    layout
        .attestations_dir()
        .join(".fetched")
        .join(format!("{}.usage", kit_core::to_hex(&hash(b"origin"))))
}
