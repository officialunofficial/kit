//! Manual full-push timing with attestation publication disabled.
#![allow(clippy::unwrap_used)]
use kit_core::{
    hash::{Hash, hash},
    object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry},
    protocol::{PackKey, SliceBody, Transport},
    refs::RefWriteCondition,
    sign::{self, KeyPair},
};

#[test]
#[ignore = "manual 100,000-file timing; run alone on an idle machine"]
fn push_100k_files_without_attestations() {
    let remote_dir = tempfile::tempdir().unwrap();
    let tx = kit_transport_file::FileTransport::new(remote_dir.path());
    let mut writer = kit_core::pack::PackWriter::new_raw_only();
    let mut put = |object: Object| -> Hash {
        let raw = kit_core::serialize::serialize(&object).unwrap();
        let id = object.id().unwrap();
        writer.push_raw(id, &raw).unwrap();
        id
    };
    let entries = (0u64..100_000)
        .map(|n| TreeEntry {
            name: format!("file-{n:06}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: put(Object::Blob(Blob {
                data: n.to_le_bytes().to_vec(),
            })),
        })
        .collect();
    let tree = put(Object::Tree(Tree { entries }));
    let key = KeyPair::generate().unwrap();
    let mut commit = Commit::new_unannotated(
        tree,
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        b"files".to_vec(),
        1,
        [0; 64],
    );
    commit.signature = sign::sign_commit(&commit, &key).unwrap().0;
    let tip = put(Object::Commit(commit));
    let bytes = writer.finish().unwrap();
    let key = hash(&bytes);
    tx.upload_pack(&SliceBody(&bytes), &PackKey::from_hash(key), None)
        .unwrap();
    let node = kit_core::transfer::encode_packlist(None, &[key]).unwrap();
    let node_key = hash(&node);
    tx.upload_blob(&node, &PackKey::from_hash(node_key), None)
        .unwrap();
    tx.update_ref("refs/kit/packmap/main", RefWriteCondition::Any, &node_key)
        .unwrap();
    tx.update_ref("refs/heads/main", RefWriteCondition::Any, &tip)
        .unwrap();

    let local = tempfile::tempdir().unwrap();
    let descriptor = kit_sync::CloneRemote {
        name: "seed".into(),
        url: "kit+file://seed".into(),
        kind: "file".into(),
    };
    let layout = kit_sync::init_clone_dir(local.path(), &descriptor).unwrap();
    kit_sync::fetch(
        local.path(),
        &kit_sync::TransportSource::new(&tx),
        "seed",
        &kit_sync::SyncOptions::default(),
        &kit_sync::NoopObserver,
    )
    .unwrap();
    kit_core::refs::write_ref(&layout, "main", &tip).unwrap();
    let destination = tempfile::tempdir().unwrap();
    let remote = kit_transport_file::FileTransport::new(destination.path());
    let mut options = kit_sync::PushOptions::default();
    options.target = kit_sync::PushTarget::Branch {
        local: "main".into(),
        remote: "main".into(),
        lease: kit_sync::PushLease::FastForward,
    };
    let start = std::time::Instant::now();
    kit_sync::push(
        local.path(),
        &kit_sync::TransportSource::new(&remote),
        &options,
    )
    .unwrap();
    eprintln!("push_100k_seconds={:.6}", start.elapsed().as_secs_f64());
}
