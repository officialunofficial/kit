// Transport-independent checks shared with subprocess transport coverage.
mod attestation_fetch {
    use kit_core::{
        hash::{Hash, hash, to_hex},
        layout::RepoLayout,
        object::{Commit, Identity, Object, Tree},
        protocol::{PackKey, SliceBody, Transport},
        refs::{self, ATTESTMAP_REF, RefWriteCondition},
        sign::{self, KeyPair},
        store::ObjectStore,
    };
    use kit_sync::{CloneRemote, NoopObserver, SyncOptions, TransportSource};

    fn upload(tx: &dyn Transport, bytes: &[u8]) -> Hash {
        let key = hash(bytes);
        tx.upload_blob(bytes, &PackKey::from_hash(key), Some(ATTESTMAP_REF))
            .unwrap();
        key
    }
    pub(crate) fn append(tx: &dyn Transport, bytes: &[u8]) {
        let key = upload(tx, bytes);
        let prev = tx.read_ref(ATTESTMAP_REF).unwrap();
        let node = kit_core::transfer::encode_packlist(prev, &[key]).unwrap();
        let head = upload(tx, &node);
        tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &head)
            .unwrap();
    }
    pub(crate) fn hostile_claim() -> Vec<u8> {
        let mut bytes = b"KIT\0".to_vec();
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.push(3); // zstd-raw, with a claim that must fail before inflation.
        bytes.extend(4u32.to_le_bytes());
        bytes.extend(u32::MAX.to_le_bytes());
        let trailer = hash(&bytes);
        bytes.extend(trailer);
        bytes
    }
    pub(crate) fn envelope(subject: Hash) -> Vec<u8> {
        let mut env = kit_attest::envelope::decode(include_bytes!(
            "../../../../tests/golden/attest/envelope_basic.json"
        ))
        .unwrap();
        env.payload = format!(r#"{{"_type":"https://in-toto.io/Statement/v1","predicate":{{}},"predicateType":"https://example.com/test/v1","subject":[{{"name":"commit","digest":{{"blake3":"{}"}}}}]}}"#, to_hex(&subject)).into_bytes();
        env.encode().unwrap().into_bytes()
    }
    #[allow(dead_code)] // Some transport harnesses only use generic attestations.
    pub(crate) fn git_locator_envelope(subject: Hash, kind: &str, locator: &str) -> Vec<u8> {
        use kit_attest::{Envelope, PAYLOAD_TYPE_IN_TOTO, RepoKeySigner, Sig, Signer};

        let (field, version) = if kind == "git-bridge" {
            ("mirror", 1)
        } else {
            ("remoteUrl", 2)
        };
        let predicate = serde_json::json!({
            "gitCommit": "0000000000000000000000000000000000000000",
            (field): locator,
            "refName": "refs/heads/main",
            "schemaVersion": 1,
            "specVersion": version,
        });
        let payload = kit_attest::statement::encode(&kit_attest::Statement {
            subjects: vec![kit_attest::Subject {
                name: Some("refs/heads/main".into()),
                digest_blake3_hex: to_hex(&subject),
                digest_sha256_hex: "0".repeat(64),
            }],
            predicate_type: format!("https://kit.storage/spec/predicate/{kind}/v1"),
            predicate_jcs: predicate.to_string().as_bytes(),
        })
        .unwrap()
        .into_bytes();
        let mut signer = RepoKeySigner::new(KeyPair::from_seed([7; 32]));
        let sig = signer
            .sign(&kit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, &payload))
            .unwrap();
        Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.into(),
            payload,
            signatures: vec![Sig {
                keyid: signer.keyid().unwrap(),
                sig,
            }],
        }
        .encode()
        .unwrap()
        .into_bytes()
    }
    pub(crate) fn code(tx: &dyn Transport) -> (Hash, Hash) {
        let key = KeyPair::generate().unwrap();
        let tree = Object::Tree(Tree { entries: vec![] });
        let tree_id = tree.id().unwrap();
        let mut commit = Commit::new_unannotated(
            tree_id,
            vec![],
            Identity::ed25519(key.public.0),
            key.public.0,
            b"test".to_vec(),
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
        let key = hash(&bytes);
        tx.upload_pack(
            &SliceBody(&bytes),
            &PackKey::from_hash(key),
            Some("refs/heads/main"),
        )
        .unwrap();
        let node = kit_core::transfer::encode_packlist(None, &[key]).unwrap();
        let node = upload(tx, &node);
        tx.update_ref("refs/kit/packmap/main", RefWriteCondition::Any, &node)
            .unwrap();
        tx.update_ref("refs/heads/main", RefWriteCondition::Any, &tip)
            .unwrap();
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
        let descriptor = CloneRemote {
            name: "origin".into(),
            url: "kit+memory://test".into(),
            kind: "memory".into(),
        };
        options.remote_url.clone_from(&descriptor.url);
        // The gc assertion below needs to remove an individual tree.
        let layout = kit_sync::init_clone_dir(&dir, &descriptor).unwrap();
        kit_core::fault::keep_loose(&layout);
        let report = kit_sync::clone(&dir, &source, &descriptor, &options, &NoopObserver).unwrap();
        assert_eq!(report.pull.fetch.attestations_stored, 1);
        assert_eq!(report.pull.fetch.attestations_dropped, 1);
        assert!(report.pull.fetch.attestation_warnings.is_empty());
        let layout = RepoLayout::single(&dir);
        let id = hash(&envelope);
        let path = kit_attest::store::envelope_path(&layout, &tip, &id);
        assert_eq!(std::fs::read(&path).unwrap(), envelope);
        assert!(kit_sync::attestation_records::fetched_path(&layout, &id).exists());
        assert!(
            !ObjectStore::open(&layout).unwrap().contains(&hash(
                &kit_core::serialize::serialize(&Object::Blob(kit_core::object::Blob {
                    data: envelope.clone()
                }))
                .unwrap()
            ))
        );
        std::fs::remove_file(&path).unwrap();
        let report = kit_sync::fetch(&dir, &source, "origin", &options, &NoopObserver).unwrap();
        assert_eq!(report.attestations_stored, 0);
        let mut refetch = options.clone();
        refetch.refetch_attestations = true;
        let report = kit_sync::fetch(&dir, &source, "origin", &refetch, &NoopObserver).unwrap();
        assert_eq!(report.attestations_stored, 1);
        assert_eq!(
            kit_sync::fetch(&dir, &source, "origin", &refetch, &NoopObserver)
                .unwrap()
                .attestations_stored,
            0
        );
        push_up_to_date(tx, &dir, &layout, tip);
        // A malformed pack is recorded once; the next fetch does not reject it again.
        append(tx, &hostile_claim());
        let report = kit_sync::pull(&dir, &source, "origin", &options, &NoopObserver).unwrap();
        assert_eq!(report.fetch.attestations_rejected, 1);
        assert!(report.fetch.attestation_warnings[0].contains("decoded cap"));
        assert_eq!(
            kit_sync::fetch(&dir, &source, "origin", &options, &NoopObserver)
                .unwrap()
                .attestations_rejected,
            0
        );
        // Leave an incomplete attested closure with no hard ref root.
        refs::delete_ref(&layout, "main").unwrap();
        refs::delete_remote_ref(&layout, "origin", "main").unwrap();
        let hex = to_hex(&tree);
        std::fs::remove_file(layout.objects_dir().join(&hex[..2]).join(&hex[2..])).unwrap();
        let store = ObjectStore::open(&layout).unwrap();
        let gc = kit_core::ops::gc::run_gc(&store, &layout, u64::MAX, 0, false).unwrap();
        assert!(
            gc.skipped_state_files
                .contains(&layout.attestations_dir().join(to_hex(&tip)))
        );
        assert!(!store.contains(&tip));
        assert!(path.exists());
    }
    pub(crate) fn push_up_to_date(tx: &dyn Transport, dir: &std::path::Path, layout: &RepoLayout, tip: Hash) {
        let source = TransportSource::new(tx);
        let mut opts = kit_sync::PushOptions::default();
        opts.remote_name = "origin";
        opts.target = kit_sync::PushTarget::Branch { local: "main".into(), remote: "main".into(), lease: kit_sync::PushLease::FastForward };
        opts.attestations = true;
        let before = tx.read_ref(ATTESTMAP_REF).unwrap();
        let fetched = kit_sync::push(dir, &source, &opts).unwrap();
        assert_eq!(fetched.attestations_pushed, 0);
        assert_eq!(tx.read_ref(ATTESTMAP_REF).unwrap(), before);
        let mut env = kit_attest::envelope::decode(&envelope(tip)).unwrap();
        env.payload = String::from_utf8(env.payload).unwrap().replace("example.com/test/v1", "example.com/local/v1").into_bytes();
        let bytes = env.encode().unwrap().into_bytes();
        kit_attest::store::save(layout, &tip, &bytes).unwrap();
        let report = kit_sync::push(dir, &source, &opts).unwrap();
        assert_eq!(report.steps, 0);
        assert_eq!(report.attestations_pushed, 1);
        assert_eq!(report.attestation_warnings.len(), 1);
        assert!(report.attestation_warnings[0].contains("permanent"));
        let report = kit_sync::push(dir, &source, &opts).unwrap();
        assert_eq!(report.attestations_pushed, 0);
        assert!(report.attestation_warnings.is_empty());
        let cache = kit_sync::attestation_records::path(layout, &source, "origin", "", true);
        std::fs::remove_file(cache).unwrap();
        assert_eq!(kit_sync::push(dir, &source, &opts).unwrap().attestations_pushed, 1);
        let temp = tempfile::tempdir().unwrap();
        let descriptor = CloneRemote { name: "origin".into(), url: "kit+memory://second".into(), kind: "memory".into() };
        kit_sync::clone(temp.path(), &source, &descriptor, &SyncOptions::default(), &NoopObserver).unwrap();
        assert_eq!(std::fs::read(kit_attest::store::envelope_path(&RepoLayout::single(temp.path()), &tip, &hash(&bytes))).unwrap(), bytes);
    }
    fn envelope_for_absent() -> Vec<u8> {
        envelope([42; 32])
    }
}
