//! Alternating cold fetches with and without the empty attestation-log read.
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
fn empty_attestation_log_has_bounded_fetch_cost() {
    let remote_dir = tempfile::tempdir().unwrap();
    let tx = kit_transport_file::FileTransport::new(remote_dir.path());
    let mut writer = kit_core::pack::PackWriter::new_raw_only();
    let mut put = |object: Object| -> Hash {
        let raw = kit_core::serialize::serialize(&object).unwrap();
        let id = hash(&raw);
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
    let mut off = Vec::new();
    let mut on = Vec::new();
    for pair in 0..6 {
        for enabled in if pair % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let temp = tempfile::tempdir().unwrap();
            let descriptor = kit_sync::CloneRemote {
                name: "origin".into(),
                url: "kit+file://timing".into(),
                kind: "file".into(),
            };
            kit_sync::init_clone_dir(temp.path(), &descriptor).unwrap();
            let mut options = kit_sync::SyncOptions::default();
            options.attestations = enabled;
            let start = std::time::Instant::now();
            let report = kit_sync::fetch(
                temp.path(),
                &kit_sync::TransportSource::new(&tx),
                "origin",
                &options,
                &kit_sync::NoopObserver,
            )
            .unwrap();
            let elapsed = start.elapsed().as_secs_f64();
            assert_eq!(report.objects_unpacked, 100_002);
            eprintln!("pair={pair} attestations={enabled} seconds={elapsed:.6}");
            // The first pair warms filesystem and executable caches.
            if pair > 0 {
                if enabled {
                    on.push(elapsed);
                } else {
                    off.push(elapsed);
                }
            }
        }
    }
    off.sort_by(f64::total_cmp);
    on.sort_by(f64::total_cmp);
    eprintln!(
        "100k median off={:.6}s on={:.6}s overhead={:.3}%",
        off[2],
        on[2],
        100.0 * (on[2] / off[2] - 1.0)
    );
}
