//! Manual cursor no-op timing over a signed tree of 100,000 file entries.
#![allow(clippy::unwrap_used)]
use kit_core::{
    hash::{Hash, hash},
    object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry},
    protocol::{PackKey, SliceBody, Transport},
    refs::RefWriteCondition,
    sign::{self, KeyPair},
};

#[test]
#[ignore = "manual no-op timing; run alone on an idle machine"]
fn unchanged_remote_fetch_cost() {
    let tx = kit_transport_memory::MemoryTransport::new();
    let mut writer = kit_core::pack::PackWriter::new_raw_only();
    let mut put = |object: Object| -> Hash {
        let raw = kit_core::serialize::serialize(&object).unwrap();
        let id = object.id().unwrap();
        writer.push_raw(id, &raw).unwrap();
        id
    };
    // Shared content keeps setup small; a cursor hit never traverses the tree.
    let blob = put(Object::Blob(Blob {
        data: b"file".to_vec(),
    }));
    let entries = (0u64..100_000)
        .map(|n| TreeEntry {
            name: format!("file-{n:06}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: blob,
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
    let temp = tempfile::tempdir().unwrap();
    let descriptor = kit_sync::CloneRemote {
        name: "origin".into(),
        url: "kit+file://timing".into(),
        kind: "file".into(),
    };
    kit_sync::init_clone_dir(temp.path(), &descriptor).unwrap();
    for round in 0..7 {
        for enabled in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let mut options = kit_sync::SyncOptions::default();
            options.attestations = enabled;
            kit_sync::fetch(
                temp.path(),
                &kit_sync::TransportSource::new(&tx),
                "origin",
                &options,
                &kit_sync::NoopObserver,
            )
            .unwrap();
            let start = std::time::Instant::now();
            for _ in 0..200 {
                let report = kit_sync::fetch(
                    temp.path(),
                    &kit_sync::TransportSource::new(&tx),
                    "origin",
                    &options,
                    &kit_sync::NoopObserver,
                )
                .unwrap();
                assert!(report.remote_unchanged);
                assert_eq!(report.objects_unpacked, 0);
                assert_eq!(report.packs_downloaded, 0);
            }
            eprintln!(
                "round={round} attestations={enabled} ms={:.6}",
                start.elapsed().as_secs_f64() * 1000.0 / 200.0
            );
        }
    }
}
