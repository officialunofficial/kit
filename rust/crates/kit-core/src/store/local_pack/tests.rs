use std::fmt::Write as _;
use std::fs;
use std::io::{Seek, SeekFrom, Write};

use crate::layout::RepoLayout;
use crate::object::{Blob, Object, ObjectType};
use crate::pack::{MAX_ENTRIES, MAX_TOTAL_PAYLOAD};
use crate::serialize::serialize;
use crate::store::{ObjectStore, StoreError};

use super::writer::Writer;
use super::{Pair, index};

fn fresh() -> (tempfile::TempDir, RepoLayout, ObjectStore) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    (dir, layout, store)
}

fn blob(data: &[u8]) -> Vec<u8> {
    serialize(&Object::Blob(Blob {
        data: data.to_vec(),
    }))
    .unwrap()
}

fn writer(store: &ObjectStore) -> Writer<'_> {
    Writer::new(store, MAX_ENTRIES, MAX_TOTAL_PAYLOAD).unwrap()
}

#[test]
fn staged_pair_and_lone_pack_are_invisible_until_index_publication() {
    let (_dir, layout, store) = fresh();
    let mut writer = writer(&store);
    let bytes = blob(b"pack publication");
    let id = writer.write(&bytes).unwrap();
    let (staged, _guard) = writer.stage().unwrap();
    let reader = ObjectStore::open(&layout).unwrap();
    assert!(staged.pack.path().is_file() && staged.idx.path().is_file());
    assert!(!reader.contains(&id));

    let pair = staged.pair.clone();
    let after_pack = staged.publish_with(&store, || {
        assert!(pair.pack.is_file());
        assert!(!pair.index.exists());
        assert!(!reader.contains(&id));
        Err(std::io::Error::other("interrupted after pack sync").into())
    });
    assert!(after_pack.is_err());
    assert!(!reader.contains(&id));

    let mut retry = Writer::new(&store, MAX_ENTRIES, MAX_TOTAL_PAYLOAD).unwrap();
    retry.write(&bytes).unwrap();
    retry.finish().unwrap();
    assert_eq!(reader.read(&id).unwrap(), bytes);
}

#[test]
fn rescans_from_legacy_open_and_covers_the_object_accessors() {
    let (_dir, layout, store) = fresh();
    let stale = ObjectStore::open(&layout).unwrap();
    let mut writer = writer(&store);
    let bytes = blob(b"present only in a pack");
    let id = writer.write(&bytes).unwrap();
    writer.finish().unwrap();

    assert!(!store.path_for(&id).exists());
    assert!(stale.contains(&id));
    assert_eq!(stale.read(&id).unwrap(), bytes);
    assert_eq!(stale.read_unverified(&id).unwrap(), bytes);
    assert_eq!(stale.read_raw_for_verification(&id).unwrap(), bytes);
    assert_eq!(
        stale
            .read_with_allocator::<StoreError>(&id, |size| Ok(Vec::with_capacity(size)))
            .unwrap(),
        bytes
    );
    assert_eq!(
        stale.read_object(&id).unwrap(),
        Object::Blob(Blob {
            data: b"present only in a pack".to_vec()
        })
    );
    assert_eq!(stale.object_type(&id).unwrap(), ObjectType::Blob);
    assert_eq!(stale.verify_object_type(&id).unwrap(), ObjectType::Blob);
    assert_eq!(
        stale.object_head(&id).unwrap(),
        (ObjectType::Blob, Some(22))
    );
    assert_eq!(stale.object_size(&id).unwrap(), bytes.len() as u64);
    assert_eq!(stale.iter_object_hashes().unwrap(), [id]);
    assert_eq!(stale.list_shard(id[0]).unwrap(), [id]);
    let mut bulk = stale.bulk_writer();
    assert!(bulk.reuse_object(&id).unwrap().is_empty());
    bulk.commit().unwrap();
    assert!(!store.path_for(&id).exists());
}

#[test]
fn write_sink_presence_checks_use_staged_loose_and_known_pack_objects() {
    use crate::store::ObjectSink;

    let (_dir, layout, store) = fresh();
    let mut writer = writer(&store);
    let packed = writer.write(&blob(b"packed object")).unwrap();
    writer.finish().unwrap();

    let reader = ObjectStore::open(&layout).unwrap();
    let loose = reader.write(&blob(b"loose object")).unwrap();
    let batch = reader.batch();
    let staged = batch.write(&blob(b"staged object")).unwrap();

    assert!(!batch.has(&packed));
    assert!(reader.contains(&packed));
    assert!(batch.has(&packed));
    assert!(batch.has(&loose));
    assert!(batch.has(&staged));
    assert!(!batch.has(&[0; 32]));
}

#[test]
fn delta_base_adapters_verify_packed_bytes_and_admit_allocation() {
    use crate::pack::{DeltaBaseSource, PackError};

    let (_dir, _layout, store) = fresh();
    let bytes = blob(b"packed delta base");
    let mut writer = writer(&store);
    let id = writer.write(&bytes).unwrap();
    writer.finish().unwrap();

    let mut source = &store;
    assert_eq!(source.base(&id).unwrap().as_deref(), Some(bytes.as_slice()));
    assert!(source.base(&[0; 32]).unwrap().is_none());

    let mut admissions = 0;
    let base = source.base_with_admission(&id, |len| {
        assert_eq!(len, bytes.len());
        admissions += 1;
        Ok(())
    });
    assert_eq!(base.unwrap().as_deref(), Some(bytes.as_slice()));
    assert_eq!(admissions, 1);
    assert!(matches!(
        source.base_with_admission(&id, |_| Err(PackError::PackfileTooLarge)),
        Err(PackError::PackfileTooLarge)
    ));
    assert!(
        source
            .base_with_admission(&[0; 32], |_| panic!("admitted an absent base"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn corrupt_pack_copy_falls_back_to_verified_loose_bytes() {
    let (_dir, layout, store) = fresh();
    let bytes = blob(b"pack damage");
    let mut w = writer(&store);
    let id = w.write(&bytes).unwrap();
    let (staged, _guard) = w.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&pair.pack).unwrap();
    file.seek(SeekFrom::Start(12 + 5 + 10)).unwrap();
    file.write_all(b"x").unwrap();
    assert!(matches!(
        store.read(&id),
        Err(StoreError::HashMismatch { .. })
    ));
    assert!(matches!(
        store.read_unverified(&id),
        Err(StoreError::HashMismatch { .. })
    ));
    assert_ne!(store.read_raw_for_verification(&id).unwrap(), bytes);
    store.write(&bytes).unwrap();
    assert_eq!(store.read(&id).unwrap(), bytes);
    assert_eq!(store.read_raw_for_verification(&id).unwrap(), bytes);
    assert_eq!(
        ObjectStore::open(&layout).unwrap().read(&id).unwrap(),
        bytes
    );
    assert!(store.check_local_packs(true).is_err());
}

#[test]
fn verified_accessors_try_another_pack_after_the_cached_copy_fails() {
    let (_dir, _layout, store) = fresh();
    let bytes = blob(b"survives in another pack");
    let mut good = writer(&store);
    let id = good.write(&bytes).unwrap();
    good.write(&blob(b"pack key differs")).unwrap();
    good.finish().unwrap();

    let mut damaged = writer(&store);
    damaged.write(&bytes).unwrap();
    let (staged, _guard) = damaged.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&pair.pack).unwrap();
    file.seek(SeekFrom::Start(12 + 5 + 10)).unwrap();
    file.write_all(b"x").unwrap();

    assert_eq!(store.read(&id).unwrap(), bytes);
    let mut allocations = 0;
    let result = store.read_with_allocator::<StoreError>(&id, |size| {
        allocations += 1;
        Ok(Vec::with_capacity(size))
    });
    assert_eq!(allocations, 2);
    assert_eq!(result.unwrap(), bytes);
    assert_eq!(store.read_unverified(&id).unwrap(), bytes);
    assert_eq!(store.read_raw_for_verification(&id).unwrap(), bytes);
}

#[test]
fn malformed_packed_objects_keep_mismatch_classification() {
    use crate::object::{EntryMode, Tree, TreeEntry};

    let tree = serialize(&Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"entry".to_vec(),
            mode: EntryMode::Blob,
            object_hash: [0; 32],
        }],
    }))
    .unwrap();

    // Change a blob's length and a tree's entry count. Neither byte
    // sequence decodes, but the verifier must report the wrong id.
    for (bytes, offset) in [(blob(b"blob"), 6), (tree, 6)] {
        let (_dir, _layout, store) = fresh();
        let mut writer = writer(&store);
        let id = writer.write(&bytes).unwrap();
        let (staged, _guard) = writer.stage().unwrap();
        let pair = staged.pair.clone();
        staged.publish(&store).unwrap();
        let mut file = fs::OpenOptions::new().write(true).open(&pair.pack).unwrap();
        file.seek(SeekFrom::Start(12 + 5 + offset)).unwrap();
        file.write_all(b"x").unwrap();

        assert!(matches!(
            store.read(&id),
            Err(StoreError::HashMismatch { .. })
        ));
        assert!(matches!(
            store.read_object(&id),
            Err(StoreError::HashMismatch { .. })
        ));
        assert_ne!(store.read_raw_for_verification(&id).unwrap(), bytes);
        let index = fs::read(&pair.index).unwrap();
        assert!(store.check_local_packs(true).is_err());
        assert_eq!(fs::read(&pair.index).unwrap(), index);
    }
}

#[test]
fn rejects_invalid_index_rows_even_with_a_valid_checksum() {
    let (_dir, layout, store) = fresh();
    let mut writer = writer(&store);
    let id = writer.write(&blob(b"first frame")).unwrap();
    writer.write(&blob(b"second frame")).unwrap();
    let (staged, _guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();
    let original = fs::read(&pair.index).unwrap();
    for (offset, bad_value) in [
        (0, b'X'),                                                // magic
        (4, 2),                                                   // version
        (8, 0),                                                   // count
        (12, 9),                                                  // fanout
        (12 + 1024 + 64 + 7, 0xff),                               // offset outside pack
        (12 + 1024 + 80 + 3, 0xff),                               // payload length over cap
        (original.len() - 64, original[original.len() - 64] ^ 1), // key
    ] {
        let mut damaged = original.clone();
        damaged[offset] = bad_value;
        let checksum_at = damaged.len() - 32;
        let checksum = blake3::hash(&damaged[..checksum_at]);
        damaged[checksum_at..].copy_from_slice(checksum.as_bytes());
        fs::write(&pair.index, damaged).unwrap();
        let reader = ObjectStore::open(&layout).unwrap();
        assert!(
            reader
                .check_presence(&id)
                .unwrap_err()
                .to_string()
                .contains("local pack")
        );
    }
}

#[test]
fn rebuild_only_a_published_index_from_a_verified_pack() {
    let (_dir, layout, store) = fresh();
    let mut writer = writer(&store);
    let bytes = blob(b"index repair");
    let id = writer.write(&bytes).unwrap();
    let (staged, guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();
    drop(guard);
    let idx = fs::read(&pair.index).unwrap();
    fs::write(&pair.index, b"damaged").unwrap();
    let reopened = ObjectStore::open(&layout).unwrap();
    assert!(
        reopened
            .read(&id)
            .unwrap_err()
            .to_string()
            .contains("local pack")
    );
    assert!(reopened.check_local_packs(false).is_err());
    let guard = store.prune_guard().unwrap();
    assert!(reopened.check_local_packs(true).is_err());
    assert_eq!(fs::read(&pair.index).unwrap(), b"damaged");
    drop(guard);
    assert_eq!(reopened.check_local_packs(true).unwrap(), 1);
    assert_eq!(fs::read(&pair.index).unwrap(), idx);
    assert_eq!(reopened.read(&id).unwrap(), bytes);
    fs::remove_file(&pair.index).unwrap();
    assert_eq!(reopened.check_local_packs(true).unwrap(), 0);
    assert!(!pair.index.exists());
}

#[test]
fn a_reader_refreshes_a_rebuilt_index_with_the_same_key() {
    let (_dir, layout, store) = fresh();
    let mut writer = writer(&store);
    let first = blob(b"aaaa");
    let id = writer.write(&first).unwrap();
    writer.write(&blob(b"bbbb")).unwrap();
    let (staged, guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();
    drop(guard);

    // Exchange the equal-length frames' offsets. The index is structurally
    // valid but names the wrong bytes for each id.
    let mut idx = fs::read(&pair.index).unwrap();
    let at = 12 + 1024 + 2 * 32;
    let (left, right) = idx[at..at + 16].split_at_mut(8);
    left.swap_with_slice(right);
    let checksum_at = idx.len() - 32;
    let checksum = blake3::hash(&idx[..checksum_at]);
    idx[checksum_at..].copy_from_slice(checksum.as_bytes());
    fs::write(&pair.index, idx).unwrap();

    let reader = ObjectStore::open(&layout).unwrap();
    assert!(matches!(
        reader.read(&id),
        Err(StoreError::HashMismatch { .. })
    ));
    assert_eq!(store.check_local_packs(true).unwrap(), 1);
    assert_eq!(reader.read(&id).unwrap(), first);
}

#[test]
fn concurrent_publishers_deduplicate_and_make_the_pair_readable() {
    let (_dir, layout, store) = fresh();
    crate::store::format::activate(&store.format_path()).unwrap();
    let bytes = blob(b"two publishers");
    let barrier = std::sync::Barrier::new(2);
    let id = index::canonical_id(&bytes).unwrap();
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                let writer_store = ObjectStore::open(&layout).unwrap();
                let mut writer = writer(&writer_store);
                assert_eq!(writer.write(&bytes).unwrap(), id);
                barrier.wait();
                writer.finish().unwrap();
                assert_eq!(writer_store.read(&id).unwrap(), bytes);
            });
        }
    });
    assert_eq!(fs::read_dir(store.pack_dir()).unwrap().count(), 2);
    assert_eq!(store.read(&id).unwrap(), bytes);
}

#[test]
fn rolls_over_at_count_and_payload_caps() {
    for (max_entries, max_payload) in [(1, 1024), (2, 12)] {
        let (_dir, _layout, store) = fresh();
        let mut writer = Writer::new(&store, max_entries, max_payload).unwrap();
        let a = writer.write(&blob(b"a")).unwrap();
        assert_eq!(writer.write(&blob(b"a")).unwrap(), a);
        let b = writer.write(&blob(b"b")).unwrap();
        writer.finish().unwrap();
        assert_eq!(fs::read_dir(store.pack_dir()).unwrap().count(), 4);
        assert!(store.contains(&a) && store.contains(&b));
    }
}

#[test]
fn ignores_unknown_sidecars_and_lone_indexes() {
    let (_dir, _layout, store) = fresh();
    let mut writer = writer(&store);
    let id = writer.write(&blob(b"listed")).unwrap();
    writer.finish().unwrap();
    let pair = Pair::new(&store.pack_dir(), [42; 32]);
    fs::write(&pair.index, b"stale").unwrap();
    fs::write(store.pack_dir().join("unknown.meta"), b"ignored").unwrap();
    assert_eq!(store.iter_object_hashes().unwrap(), [id]);
}

#[test]
fn mixed_golden_vector() {
    use crate::hash::to_hex;
    use crate::object::{ChunkedBlob, EntryMode, Tree, TreeEntry};
    use std::path::PathBuf;

    let (_dir, layout, store) = fresh();
    let chunk_len = 16_384;
    let chunk = blob(&vec![0xa5; chunk_len]);
    let chunk_id = index::canonical_id(&chunk).unwrap();
    let manifest = ChunkedBlob::new(
        (chunk_len * 420) as u64,
        u32::try_from(chunk_len).unwrap(),
        (1..=420).map(|i| (chunk_id, (i * chunk_len) as u64)),
    )
    .unwrap();
    let manifest = serialize(&Object::ChunkedBlob(manifest)).unwrap();
    let whole = blob(b"whole file");
    let whole_id = index::canonical_id(&whole).unwrap();
    let tree = serialize(&Object::Tree(Tree {
        entries: (0..420)
            .map(|i| TreeEntry {
                name: format!("file-{i:04}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: whole_id,
            })
            .collect(),
    }))
    .unwrap();
    let mut writer = writer(&store);
    let objects = [chunk, manifest, tree, whole];
    let mut expected = String::new();
    for bytes in &objects {
        let id = writer.write(bytes).unwrap();
        writeln!(expected, "{} {}", to_hex(&id), bytes.len()).unwrap();
    }
    let (staged, _guard) = writer.stage().unwrap();
    let key = staged.pair.key;
    let pack = fs::read(staged.pack.path()).unwrap();
    let idx = fs::read(staged.idx.path()).unwrap();
    staged.publish(&store).unwrap();

    let dir = std::env::var_os("KIT_WRITE_LOCAL_PACK_VECTOR").map(PathBuf::from);
    let fixture = dir.clone().unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/local_pack_mixed")
    });
    writeln!(expected, "pack {}", to_hex(&key)).unwrap();
    let marker = fs::read(layout.format_file()).unwrap();
    let files: [(&str, &[u8]); 6] = [
        ("marker.bin", &marker),
        ("mixed.pack", &pack),
        ("mixed.idx", &idx),
        ("loose.bin", &objects[3]),
        ("unknown.meta", b"optional sidecar\n"),
        ("objects.txt", expected.as_bytes()),
    ];
    if dir.is_some() {
        fs::create_dir_all(&fixture).unwrap();
        for (name, bytes) in files {
            fs::write(fixture.join(name), bytes).unwrap();
        }
        return;
    }

    for (name, bytes) in files {
        assert_eq!(fs::read(fixture.join(name)).unwrap(), bytes, "{name}");
    }
    let (_dir, layout, store) = fresh();
    fs::write(
        layout.format_file(),
        fs::read(fixture.join("marker.bin")).unwrap(),
    )
    .unwrap();
    fs::create_dir(store.pack_dir()).unwrap();
    let pair = Pair::new(&store.pack_dir(), key);
    fs::copy(fixture.join("mixed.pack"), &pair.pack).unwrap();
    fs::copy(fixture.join("mixed.idx"), &pair.index).unwrap();
    fs::copy(
        fixture.join("unknown.meta"),
        store.pack_dir().join("unknown.meta"),
    )
    .unwrap();
    let loose = store.path_for(&whole_id);
    fs::create_dir_all(loose.parent().unwrap()).unwrap();
    fs::copy(fixture.join("loose.bin"), loose).unwrap();
    let store = ObjectStore::open(&layout).unwrap();
    assert_eq!(store.iter_object_hashes().unwrap().len(), 4);
    assert_eq!(store.check_local_packs(false).unwrap(), 0);
    let manifest_id = index::canonical_id(&objects[1]).unwrap();
    assert!(!crate::ops::check_closure_present(&store, [&manifest_id]).unwrap());
    let mut bulk = store.bulk_writer();
    let children = bulk.reuse_object(&manifest_id).unwrap();
    assert!(children.iter().all(|id| id == &chunk_id));
    assert_eq!(children.len(), 420);
    bulk.commit().unwrap();
    for bytes in objects {
        let id = index::canonical_id(&bytes).unwrap();
        assert!(store.check_presence(&id).is_ok());
        assert_eq!(store.object_size(&id).unwrap(), bytes.len() as u64);
        assert_eq!(store.read(&id).unwrap(), bytes);
    }
}
