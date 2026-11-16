// Transport-independent checks shared with subprocess transport coverage.
mod attestation_fetch {
    use kit_core::{hash::{hash, to_hex, Hash}, layout::RepoLayout, object::{Object, Tree, Commit, Identity}, protocol::{Transport, PackKey, SliceBody}, refs::{self, RefWriteCondition, ATTESTMAP_REF}, sign::{self, KeyPair}, store::ObjectStore};
    use kit_sync::{SyncOptions, TransportSource, NoopObserver, CloneRemote};

    fn upload(tx: &dyn Transport, bytes: &[u8]) -> Hash {
        let key = hash(bytes);
        tx.upload_blob(bytes, &PackKey::from_hash(key), Some(ATTESTMAP_REF)).unwrap(); key
    }
    pub(crate) fn append(tx: &dyn Transport, bytes: &[u8]) {
        let key = upload(tx, bytes);
        let prev = tx.read_ref(ATTESTMAP_REF).unwrap();
        let node = kit_core::transfer::encode_packlist(prev, &[key]).unwrap();
        let head = upload(tx, &node);
        tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &head).unwrap();
    }
    pub(crate) fn envelope(subject: Hash) -> Vec<u8> {
        let mut env = kit_attest::envelope::decode(include_bytes!("../../../../tests/golden/attest/envelope_basic.json")).unwrap();
        env.payload = format!(r#"{{"_type":"https://in-toto.io/Statement/v1","predicate":{{}},"predicateType":"https://example.com/test/v1","subject":[{{"name":"commit","digest":{{"blake3":"{}"}}}}]}}"#, to_hex(&subject)).into_bytes();
        env.encode().unwrap().into_bytes()
    }
    pub(crate) fn code(tx: &dyn Transport) -> (Hash, Hash) {
        let key = KeyPair::generate().unwrap();
        let tree = Object::Tree(Tree { entries: vec![] });
        let tree_id = tree.id().unwrap();
        let mut commit = Commit::new_unannotated(tree_id, vec![], Identity::ed25519(key.public.0), key.public.0, b"test".to_vec(), 1, [0;64]);
        commit.signature = sign::sign_commit(&commit, &key).unwrap().0;
        let commit = Object::Commit(commit);
        let tip = commit.id().unwrap();
        let mut pack = kit_core::pack::PackWriter::new_raw_only();
        for object in [tree, commit] {
            pack.push_raw(object.id().unwrap(), &kit_core::serialize::serialize(&object).unwrap()).unwrap();
        }
        let bytes = pack.finish().unwrap();
        let key = hash(&bytes);
        tx.upload_pack(&SliceBody(&bytes), &PackKey::from_hash(key), Some("refs/heads/main")).unwrap();
        let node = kit_core::transfer::encode_packlist(None, &[key]).unwrap();
        let node = upload(tx, &node);
        tx.update_ref("refs/kit/packmap/main", RefWriteCondition::Any, &node).unwrap();
        tx.update_ref("refs/heads/main", RefWriteCondition::Any, &tip).unwrap();
        (tip, tree_id)
    }
    #[allow(dead_code)] // Some transport harnesses use only publication helpers.
    pub(crate) fn roundtrip(tx: &dyn Transport) {
        let (tip, tree) = code(tx);
        let envelope = envelope(tip);
        let absent = envelope_for_absent();
        let pack = kit_attest::pack::build(&[&envelope, &absent], 4096).unwrap();
        append(tx, &pack);
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("clone");
        let source = TransportSource::new(tx);
        let mut options = SyncOptions::default();
        let descriptor = CloneRemote { name: "origin".into(), url: "kit+memory://test".into(), kind: "memory".into() };
        options.remote_url.clone_from(&descriptor.url);
        let report = kit_sync::clone(&dir, &source, &descriptor, &options, &NoopObserver).unwrap();
        assert_eq!(report.pull.fetch.attestations_stored, 1);
        assert_eq!(report.pull.fetch.attestations_dropped, 1);
        assert!(report.pull.fetch.attestation_warnings.is_empty());
        let layout = RepoLayout::single(&dir);
        let id = hash(&envelope);
        let path = kit_attest::store::envelope_path(&layout, &tip, &id);
        assert_eq!(std::fs::read(&path).unwrap(), envelope);
        assert!(kit_sync::attestation_records::fetched_path(&layout, &id).exists());
        assert!(!ObjectStore::open(&layout).unwrap().contains(&hash(&kit_core::serialize::serialize(&Object::Blob(kit_core::object::Blob { data: envelope.clone() })).unwrap())));
        std::fs::remove_file(&path).unwrap();
        let report = kit_sync::fetch(&dir, &source, "origin", &options, &NoopObserver).unwrap();
        assert_eq!(report.attestations_stored, 0);
        let mut refetch = options.clone(); refetch.refetch_attestations = true;
        let report = kit_sync::fetch(&dir, &source, "origin", &refetch, &NoopObserver).unwrap();
        assert_eq!(report.attestations_stored, 1);
        assert_eq!(kit_sync::fetch(&dir, &source, "origin", &refetch, &NoopObserver).unwrap().attestations_stored, 0);
        // A malformed pack is recorded once; the next fetch does not reject it again.
        let hostile = kit_core::pack::PackWriter::new_raw_only();
        let mut bytes = hostile.finish().unwrap(); bytes[0] ^= 1;
        append(tx, &bytes);
        let report = kit_sync::pull(&dir, &source, "origin", &options, &NoopObserver).unwrap();
        assert_eq!(report.fetch.attestations_rejected, 1);
        assert_eq!(kit_sync::fetch(&dir, &source, "origin", &options, &NoopObserver).unwrap().attestations_rejected, 0);
        // Leave an incomplete attested closure with no hard ref root.
        refs::delete_ref(&layout, "main").unwrap();
        refs::delete_remote_ref(&layout, "origin", "main").unwrap();
        let hex = to_hex(&tree);
        std::fs::remove_file(layout.objects_dir().join(&hex[..2]).join(&hex[2..])).unwrap();
        let store = ObjectStore::open(&layout).unwrap();
        let gc = kit_core::ops::gc::run_gc(&store, &layout, u64::MAX, 0, false).unwrap();
        assert!(gc.skipped_state_files.contains(&layout.attestations_dir().join(to_hex(&tip))));
        assert!(!store.contains(&tip));
        assert!(path.exists());
    }
    fn envelope_for_absent() -> Vec<u8> { envelope([42;32]) }
}
