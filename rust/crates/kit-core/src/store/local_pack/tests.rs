use std::fmt::Write as _;
use std::fs;
use std::io::{Seek, SeekFrom, Write};

use crate::hash::Hash;
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
fn bulk_reuse_reports_children_and_refreshes_a_packed_tree_once() {
    use crate::object::{EntryMode, Tree, TreeEntry};

    let (_dir, _layout, store) = fresh();
    let child = store.write(&blob(b"child")).unwrap();
    let tree = serialize(&Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"entry".to_vec(),
            mode: EntryMode::Blob,
            object_hash: child,
        }],
    }))
    .unwrap();
    let id = store.write(&tree).unwrap();
    assert_eq!(store.bulk_writer().reuse_object(&id).unwrap(), [child]);

    let mut writer = writer(&store);
    assert_eq!(writer.write(&tree).unwrap(), id);
    let (staged, _guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();
    fs::remove_file(store.path_for(&id)).unwrap();

    let file = fs::File::open(pair.pack).unwrap();
    let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1);
    let mut bulk = store.bulk_writer();
    file.set_modified(old).unwrap();
    assert_eq!(bulk.reuse_object(&id).unwrap(), [child]);
    assert!(file.metadata().unwrap().modified().unwrap() > old);
    file.set_modified(old).unwrap();
    assert_eq!(bulk.reuse_object(&id).unwrap(), [child]);
    assert_eq!(file.metadata().unwrap().modified().unwrap(), old);
}

#[test]
fn write_sink_presence_checks_use_staged_loose_and_known_pack_objects() {
    use crate::store::ObjectSink;

    let (_dir, layout, store) = fresh();
    let mut writer = writer(&store);
    let packed = writer.write(&blob(b"packed object")).unwrap();
    writer.finish().unwrap();

    assert!(store.batch().has(&packed));
    let loose = store.write(&blob(b"loose object")).unwrap();
    let reader = ObjectStore::open(&layout).unwrap();
    let batch = reader.batch();
    assert!(!batch.has(&packed));
    assert!(batch.has(&loose));

    let staged = batch.write(&blob(b"staged object")).unwrap();
    assert!(batch.has(&packed));
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
    assert!(matches!(
        store.bulk_writer().reuse_object(&id),
        Err(StoreError::HashMismatch { .. })
    ));
    assert_ne!(store.read_raw_for_verification(&id).unwrap(), bytes);
    let batch = store.batch();
    batch.write_fetched(&bytes).unwrap();
    batch.commit().unwrap();
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
    let (_dir, layout, store) = fresh();
    let bytes = blob(b"survives in another pack");
    let mut damaged = writer(&store);
    let id = damaged.write(&bytes).unwrap();
    let (staged, _guard) = damaged.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&pair.pack).unwrap();
    file.seek(SeekFrom::Start(12 + 5 + 10)).unwrap();
    file.write_all(b"x").unwrap();

    assert!(matches!(
        store.read(&id),
        Err(StoreError::HashMismatch { .. })
    ));
    let other = ObjectStore::open(&layout).unwrap();
    let mut good = writer(&other);
    good.write(&bytes).unwrap();
    good.write(&blob(b"pack key differs")).unwrap();
    good.finish().unwrap();

    let mut allocations = 0;
    let result = store.read_with_allocator::<StoreError>(&id, |size| {
        allocations += 1;
        Ok(Vec::with_capacity(size))
    });
    assert_eq!(allocations, 2);
    assert_eq!(result.unwrap(), bytes);
    assert_eq!(store.read(&id).unwrap(), bytes);
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
fn verifier_does_not_treat_invalid_encoding_as_a_hash_mismatch() {
    let (_dir, layout, store) = fresh();
    let mut bytes = blob(b"encoded object");
    let mut writer = writer(&store);
    writer.write(&bytes).unwrap();
    let (staged, _guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();

    bytes[0] = u8::MAX;
    let id = *blake3::hash(&bytes).as_bytes();
    let offset = (crate::pack::HEADER_LEN + crate::pack::ENTRY_FRAME_LEN) as u64;
    let frame = index::Frame {
        offset,
        len: u32::try_from(bytes.len()).unwrap(),
    };
    let mut pack = fs::OpenOptions::new().write(true).open(pair.pack).unwrap();
    pack.seek(SeekFrom::Start(offset)).unwrap();
    pack.write_all(&bytes).unwrap();
    fs::write(pair.index, index::encode(pair.key, &[(id, frame)])).unwrap();

    let reader = ObjectStore::open(&layout).unwrap();
    assert!(matches!(
        reader.read_raw_for_verification(&id),
        Err(StoreError::Decode(_))
    ));
}

#[test]
fn pack_scan_checks_the_trailer_before_returning_the_key() {
    let (_dir, _layout, store) = fresh();
    let mut writer = writer(&store);
    writer.write(&blob(b"pack trailer")).unwrap();
    let (staged, _guard) = writer.stage().unwrap();
    let mut bytes = fs::read(staged.pack.path()).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(staged.pack.path(), bytes).unwrap();

    let error = index::scan(&mut fs::File::open(staged.pack.path()).unwrap()).unwrap_err();
    assert!(error.to_string().contains("pack trailer"), "{error}");
}

#[test]
fn a_cached_location_refuses_a_pack_with_a_changed_count() {
    let (_dir, _layout, store) = fresh();
    let mut writer = writer(&store);
    let id = writer.write(&blob(b"cached frame")).unwrap();
    let (staged, _guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();
    assert!(store.object_size(&id).is_ok());
    let mut bytes = fs::read(&pair.pack).unwrap();
    bytes[8..12].copy_from_slice(&0_u32.to_le_bytes());
    fs::write(&pair.pack, bytes).unwrap();

    let error = store.object_size(&id).unwrap_err();
    assert!(
        error.to_string().contains("pack size or count changed"),
        "{error}"
    );
}

#[test]
fn unknown_live_pack_versions_refuse_lookup_and_repair() {
    fn incompatible(error: &StoreError, member: &str) {
        assert!(matches!(error, StoreError::IncompatibleRepoFormat { .. }));
        let text = error.to_string();
        assert!(text.contains("Update kit"), "{text}");
        assert!(text.contains(member), "{text}");
    }

    for unknown_index in [false, true] {
        let (_dir, layout, store) = fresh();
        let bytes = blob(b"object with a newer pack format");
        let mut writer = writer(&store);
        let id = writer.write(&bytes).unwrap();
        let (staged, guard) = writer.stage().unwrap();
        let pair = staged.pair.clone();
        staged.publish(&store).unwrap();
        drop(guard);
        let still_open = ObjectStore::open(&layout).unwrap();
        assert_eq!(store.read(&id).unwrap(), bytes);
        let batch = store.batch();
        batch.write_fetched(&bytes).unwrap();
        batch.commit().unwrap();

        let (path, kind) = if unknown_index {
            (&pair.index, "local index version 2")
        } else {
            (&pair.pack, "local pack version 2")
        };
        let mut newer = fs::read(path).unwrap();
        newer[4..8].copy_from_slice(&2_u32.to_le_bytes());
        let replacement = tempfile::NamedTempFile::new_in(store.pack_dir()).unwrap();
        fs::write(replacement.path(), &newer).unwrap();
        replacement.persist(path).unwrap();

        let reopened = ObjectStore::open(&layout).unwrap();
        incompatible(&reopened.read(&[0; 32]).unwrap_err(), kind);
        incompatible(&store.read(&id).unwrap_err(), kind);
        incompatible(&still_open.read(&[0; 32]).unwrap_err(), kind);
        incompatible(&still_open.iter_object_hashes().unwrap_err(), kind);
        incompatible(&still_open.check_local_packs(true).unwrap_err(), kind);
        let mut retry = Writer::new(&store, MAX_ENTRIES, MAX_TOTAL_PAYLOAD).unwrap();
        retry.write(&bytes).unwrap();
        incompatible(&retry.finish().unwrap_err(), kind);
        assert_eq!(fs::read(path).unwrap(), newer);

        let counterpart = if unknown_index {
            &pair.pack
        } else {
            &pair.index
        };
        fs::write(counterpart, b"damaged").unwrap();
        incompatible(&still_open.read(&[0; 32]).unwrap_err(), kind);
    }
}

#[test]
fn unknown_version_on_an_unpublished_pack_does_not_block_open() {
    let (_dir, layout, store) = fresh();
    let mut writer = writer(&store);
    writer.write(&blob(b"unpublished version")).unwrap();
    let (staged, _guard) = writer.stage().unwrap();
    let mut pack = fs::read(staged.pack.path()).unwrap();
    pack[4..8].copy_from_slice(&2_u32.to_le_bytes());
    fs::write(&staged.pair.pack, pack).unwrap();
    let reopened = ObjectStore::open(&layout).unwrap();
    assert!(reopened.iter_object_hashes().unwrap().is_empty());
}

#[test]
fn a_loose_store_skips_pack_discovery_on_a_miss() {
    let (_dir, _layout, store) = fresh();
    fs::write(store.pack_dir(), b"unrelated file").unwrap();

    assert!(matches!(
        store.read(&[0; 32]),
        Err(StoreError::ObjectNotFound(_))
    ));
    assert!(store.iter_object_hashes().unwrap().is_empty());
}

#[test]
fn a_known_pack_does_not_hide_a_newly_published_pair() {
    let (_dir, layout, store) = fresh();
    let mut first = writer(&store);
    let known = blob(b"known pack");
    let known_id = first.write(&known).unwrap();
    first.finish().unwrap();
    assert_eq!(store.read(&known_id).unwrap(), known);

    let other = ObjectStore::open(&layout).unwrap();
    let mut second = writer(&other);
    let new = blob(b"new pack");
    let new_id = second.write(&new).unwrap();
    second.finish().unwrap();

    assert_eq!(store.read(&new_id).unwrap(), new);
}

#[cfg(unix)]
#[test]
fn a_symlink_cannot_supply_the_pack_directory() {
    let (_dir, layout, store) = fresh();
    crate::store::format::activate(&store.format_path(), true).unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), store.pack_dir()).unwrap();

    let reader = ObjectStore::open(&layout).unwrap();
    assert!(matches!(
        reader.read(&[0; 32]),
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData
    ));
}

#[cfg(unix)]
#[test]
fn pack_scan_reports_filesystem_errors_other_than_absence() {
    let (_dir, layout, store) = fresh();
    crate::store::format::activate(&store.format_path(), true).unwrap();
    let objects = layout.objects_dir();
    fs::remove_dir(&objects).unwrap();
    std::os::unix::fs::symlink(&objects, &objects).unwrap();

    assert!(matches!(
        store.check_local_packs(false),
        Err(StoreError::Io(_))
    ));
}

#[test]
fn staging_stops_on_a_noncollision_error() {
    let dir = tempfile::tempdir().unwrap();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = super::stage_file(&dir.path().join("missing"), ".tmp.pack");
        let _ = result_tx.send(result);
    });
    let error = result_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap()
        .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn staging_retries_a_collision_without_replacing_the_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let occupied = dir.path().join(format!(".{:032x}.tmp.pack", 7_u128));
    fs::write(&occupied, b"existing stage").unwrap();
    let mut nonces = [7, 8].into_iter();

    let staged =
        super::stage_file_with_nonce(dir.path(), ".tmp.pack", || Ok(nonces.next().unwrap()))
            .unwrap();
    assert_ne!(staged.path(), occupied);
    assert_eq!(fs::read(occupied).unwrap(), b"existing stage");
    assert_eq!(nonces.next(), None);
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
    let row = usize::from(original[12 + 1024..12 + 1024 + 32] != id);
    for (offset, bad_value) in [
        (0, b'X'),                                                // magic
        (8, 0),                                                   // count
        (12, 9),                                                  // fanout
        (12 + 1024 + 64 + row * 8 + 7, 0xff),                     // offset outside pack
        (12 + 1024 + 80 + row * 4 + 3, 0xff),                     // payload length over cap
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
    crate::store::format::activate(&store.format_path(), true).unwrap();
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

#[test]
fn fetch_writer_requires_its_own_packed_guard_and_writes_overlapping_objects() {
    use super::writer::LocalPackWriter;

    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(a.path());
    let store = ObjectStore::init(&layout).unwrap();
    let other = ObjectStore::init(&RepoLayout::single(b.path())).unwrap();

    assert!(!store.local_packs_enabled().unwrap());
    let busy = store.prune_guard().unwrap();
    store.try_activate_local_packs().unwrap();
    assert!(!store.local_packs_active(&busy).unwrap());
    assert!(LocalPackWriter::new(&store, &busy).is_err());
    drop(busy);

    store.try_activate_local_packs().unwrap();
    let guard = store.prune_guard().unwrap();
    assert!(store.local_packs_active(&guard).unwrap());
    assert!(store.local_packs_enabled().unwrap());
    assert!(LocalPackWriter::new(&other, &guard).is_err());
    LocalPackWriter::new(&store, &guard)
        .unwrap()
        .publish()
        .unwrap();
    assert_eq!(fs::read_dir(store.pack_dir()).unwrap().count(), 0);

    let bytes = blob(b"overlap");
    let id = store.write(&bytes).unwrap();
    let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
    assert_eq!(writer.write(&bytes).unwrap(), id);
    assert_eq!(writer.write(&bytes).unwrap(), id);
    writer.publish().unwrap();
    assert_eq!(fs::read_dir(store.pack_dir()).unwrap().count(), 2);
    store.remove_object(&id).unwrap();
    assert_eq!(
        ObjectStore::open(&layout).unwrap().read(&id).unwrap(),
        bytes
    );
}

#[test]
fn the_fetch_writer_publishes_many_small_objects_in_one_pack() {
    use super::writer::LocalPackWriter;

    let (_dir, _layout, store) = fresh();
    store.try_activate_local_packs().unwrap();
    let guard = store.prune_guard().unwrap();
    let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
    let objects = (0..20).map(|n| blob(&[n; 16_000])).collect::<Vec<_>>();
    let ids: Vec<_> = objects
        .iter()
        .map(|bytes| writer.write(bytes).unwrap())
        .collect();
    writer.publish().unwrap();

    assert_eq!(fs::read_dir(store.pack_dir()).unwrap().count(), 2);
    for (id, bytes) in ids.iter().zip(objects) {
        assert_eq!(store.read(id).unwrap(), bytes);
    }
}

#[test]
fn the_fetch_batch_replaces_a_same_length_damaged_loose_copy() {
    let (_dir, _layout, store) = fresh();
    let good = blob(b"good");
    let bad = blob(b"torn");
    let id = store.write(&good).unwrap();
    fs::write(store.path_for(&id), &bad).unwrap();
    let batch = store.batch();
    assert_eq!(batch.write_fetched(&good).unwrap(), id);
    assert_eq!(fs::read(store.path_for(&id)).unwrap(), bad);
    batch.commit().unwrap();
    assert_eq!(store.read(&id).unwrap(), good);
}

fn publish_objects(store: &ObjectStore, objects: &[&[u8]]) -> (Pair, Vec<Hash>) {
    let mut writer = writer(store);
    let ids = objects
        .iter()
        .map(|bytes| writer.write(bytes).unwrap())
        .collect();
    let (staged, _guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(store).unwrap();
    (pair, ids)
}

fn set_pack_age(path: &std::path::Path, secs: u64) {
    fs::File::open(path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
        .unwrap();
}

#[test]
fn gc_counts_packed_payload_and_retires_only_wholly_dead_old_packs() {
    use crate::ops::gc::run_gc_with_pack_report;

    let (_dir, layout, store) = fresh();
    let (live, live_ids) = publish_objects(&store, &[&blob(b"live pack")]);
    let mixed_live = blob(b"mixed live entry");
    let mixed_dead = blob(b"mixed dead entry");
    let (mixed, mixed_ids) = publish_objects(&store, &[&mixed_live, &mixed_dead]);
    let dead = blob(b"all old dead entries");
    let recent = blob(b"grace protected entry");
    let (old, old_ids) = publish_objects(&store, &[&dead]);
    let (young, young_ids) = publish_objects(&store, &[&recent]);
    crate::refs::write_ref(&layout, "live", &live_ids[0]).unwrap();
    crate::refs::write_ref(&layout, "mixed", &mixed_ids[0]).unwrap();
    for pair in [&live, &mixed] {
        set_pack_age(&pair.pack, 1);
    }
    set_pack_age(&old.pack, 5);
    set_pack_age(&young.pack, 8);
    set_pack_age(&old.index, 8);

    let (preview, packed) =
        run_gc_with_pack_report(&store, &layout, 10, 5, true, &mut |_, _, _| {}).unwrap();
    assert_eq!(packed.wholly_dead_bytes, (dead.len() + recent.len()) as u64);
    assert_eq!(packed.mixed_dead_bytes, mixed_dead.len() as u64);
    assert_eq!(
        packed.eligible_dead_bytes,
        (dead.len() + mixed_dead.len()) as u64
    );
    assert_eq!(packed.survivor_bytes, mixed_live.len() as u64);
    assert_eq!(packed.packs_retired, 1);
    assert!(old.pack.exists() && old.index.exists());

    crate::atomic::testing::reset_dir_sync_calls();
    let (report, packed) =
        run_gc_with_pack_report(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
    assert_eq!(packed.packs_retired, 1);
    assert_eq!(crate::atomic::testing::dir_sync_calls(), 2);
    assert_eq!(report.bytes_reclaimed, preview.bytes_reclaimed);
    assert!(report.bytes_reclaimed > dead.len() as u64);
    assert!(!old.pack.exists() && !old.index.exists());
    assert!(!store.contains(&old_ids[0]));
    for id in live_ids.iter().chain(&mixed_ids).chain(&young_ids) {
        assert!(store.read(id).is_ok());
    }
}

#[test]
fn gc_rechecks_pack_mtime_and_leaves_a_concurrent_publication() {
    use crate::ops::gc::run_gc_with_pack_report;

    let (_dir, layout, store) = fresh();
    let (old, ids) = publish_objects(&store, &[&blob(b"reused object")]);
    set_pack_age(&old.pack, 1);
    let h = ids[0];
    let mut fresh_pack = None;
    let (_, packed) = run_gc_with_pack_report(
        &store,
        &layout,
        u64::MAX,
        0,
        false,
        &mut |phase, done, _| {
            if phase == "gc" && done == 0 && fresh_pack.is_none() {
                fresh_pack = Some(std::thread::scope(|scope| {
                    scope
                        .spawn(|| {
                            let writer = ObjectStore::open(&layout).unwrap();
                            writer.bulk_writer().reuse_object(&h).unwrap();
                            let (new, _) = publish_objects(&writer, &[&blob(b"fetch publication")]);
                            new
                        })
                        .join()
                        .unwrap()
                }));
            }
        },
    )
    .unwrap();
    assert_eq!(packed.packs_retired, 0);
    assert!(old.pack.exists() && old.index.exists());
    assert!(fresh_pack.unwrap().pack.exists());
}

#[test]
fn gc_keeps_pack_files_while_a_fetch_holds_the_prune_guard() {
    use crate::ops::gc::run_gc;

    let (_dir, layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"fetch is using this pack")]);
    let guard = store.prune_guard().unwrap();
    run_gc(&store, &layout, u64::MAX, 0, false).unwrap();
    assert!(pair.pack.exists() && pair.index.exists());
    drop(guard);
    run_gc(&store, &layout, u64::MAX, 0, false).unwrap();
    assert!(!pair.pack.exists() && !pair.index.exists());
}

#[test]
fn gc_sweeps_only_aged_recognized_pack_leftovers() {
    use crate::ops::gc::run_gc_with_pack_report;

    let (_dir, layout, store) = fresh();
    let (retired, ids) = publish_objects(&store, &[&blob(b"no pack after interruption")]);
    fs::remove_file(&retired.pack).unwrap();
    let (unpublished, _) = publish_objects(&store, &[&blob(b"no index after interruption")]);
    fs::remove_file(&unpublished.index).unwrap();
    let staging = store
        .pack_dir()
        .join(format!(".{}.tmp.idx", "a".repeat(32)));
    let recent = store
        .pack_dir()
        .join(format!(".{}.tmp.pack", "b".repeat(32)));
    let sidecar = store
        .pack_dir()
        .join(format!(".{}.tmp.idx", "C".repeat(32)));
    let non_hex = store
        .pack_dir()
        .join(format!(".{}.tmp.pack", "g".repeat(32)));
    let directory = store
        .pack_dir()
        .join(format!(".{}.tmp.pack", "d".repeat(32)));
    fs::create_dir(&directory).unwrap();
    for path in [&staging, &recent, &sidecar, &non_hex] {
        fs::write(path, b"leftover").unwrap();
    }
    for path in [
        &retired.index,
        &unpublished.pack,
        &staging,
        &sidecar,
        &non_hex,
    ] {
        set_pack_age(path, 1);
    }
    set_pack_age(&recent, 8);
    #[cfg(unix)]
    set_pack_age(&directory, 1);
    assert!(!ObjectStore::open(&layout).unwrap().contains(&ids[0]));
    assert_eq!(store.check_local_packs(true).unwrap(), 0);

    let expected_bytes: u64 = [&retired.index, &unpublished.pack, &staging]
        .iter()
        .map(|path| fs::metadata(path).unwrap().len())
        .sum();
    let (preview_totals, preview) =
        run_gc_with_pack_report(&store, &layout, 10, 5, true, &mut |_, _, _| {}).unwrap();
    assert_eq!(preview.pack_leftovers_pruned, 3);
    assert_eq!(preview_totals.bytes_reclaimed, expected_bytes);
    assert!(retired.index.exists());
    crate::atomic::testing::reset_dir_sync_calls();
    let (totals, report) =
        run_gc_with_pack_report(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
    assert_eq!(report.pack_leftovers_pruned, 3);
    assert_eq!(totals.bytes_reclaimed, expected_bytes);
    assert_eq!(crate::atomic::testing::dir_sync_calls(), 2);
    assert!(!retired.index.exists() && !unpublished.pack.exists() && !staging.exists());
    assert!(recent.exists() && sidecar.exists() && non_hex.exists() && directory.is_dir());
}

#[test]
fn gc_refuses_a_corrupt_index_before_pruning_loose_objects() {
    use crate::ops::gc::run_gc;

    let (_dir, layout, store) = fresh();
    let loose = store.write(&blob(b"loose orphan")).unwrap();
    let (pair, _) = publish_objects(&store, &[&blob(b"damaged index")]);
    let mut data = fs::read(&pair.index).unwrap();
    *data.last_mut().unwrap() ^= 1;
    fs::write(&pair.index, data).unwrap();

    for dry_run in [true, false] {
        assert!(run_gc(&store, &layout, u64::MAX, 0, dry_run).is_err());
        assert!(store.path_for(&loose).exists());
        assert!(pair.pack.exists() && pair.index.exists());
    }
}

#[test]
fn a_retirement_interrupted_after_the_pack_sync_leaves_only_the_index() {
    use crate::ops::gc::{GcReport, LiveSet, PackedGcReport, run_gc};

    let (_dir, layout, store) = fresh();
    let (pair, ids) = publish_objects(&store, &[&blob(b"retirement crash point")]);
    let mut packed = PackedGcReport::default();
    let sweep = store
        .plan_pack_sweep(&LiveSet::default(), u64::MAX, 0, &mut packed)
        .unwrap();
    crate::atomic::testing::reset_dir_sync_calls();
    let result = sweep.run_with(&store, &mut GcReport::default(), &mut packed, || {
        assert!(!pair.pack.exists());
        assert!(pair.index.is_file());
        assert_eq!(crate::atomic::testing::dir_sync_calls(), 1);
        Err(std::io::Error::other("interrupted between pack and index removal").into())
    });
    assert!(result.is_err());

    let reopened = ObjectStore::open(&layout).unwrap();
    assert!(!reopened.contains(&ids[0]));
    assert_eq!(reopened.check_local_packs(true).unwrap(), 0);
    run_gc(&reopened, &layout, u64::MAX, 0, false).unwrap();
    assert!(!pair.pack.exists() && !pair.index.exists());
}

#[test]
fn gc_drops_only_loose_duplicates_that_have_verified_packed_replacements() {
    use crate::ops::gc::run_gc_with_pack_report;

    let (_dir, layout, store) = fresh();
    for (label, loose_age, pack_age, corrupt, keep) in [
        ("old-loose", 1, 1, false, false),
        ("newer-pack", 8, 9, false, false),
        ("same-pack-mtime", 8, 8, false, false),
        ("older-pack", 8, 1, false, true),
        ("bad-pack", 1, 1, true, true),
    ] {
        let bytes = blob(label.as_bytes());
        let h = store.write(&bytes).unwrap();
        let loose = store.path_for(&h);
        let (pair, _) = publish_objects(&store, &[&bytes]);
        crate::refs::write_ref(&layout, label, &h).unwrap();
        if corrupt {
            let mut data = fs::read(&pair.pack).unwrap();
            let payload = crate::pack::HEADER_LEN + crate::pack::ENTRY_FRAME_LEN;
            data[payload + bytes.len() - 1] ^= 1;
            fs::write(&pair.pack, data).unwrap();
        }
        set_pack_age(&pair.pack, pack_age);
        set_pack_age(&loose, loose_age);

        let expected_bytes = if keep { 0 } else { bytes.len() as u64 };
        let (preview_totals, preview) =
            run_gc_with_pack_report(&store, &layout, 10, 5, true, &mut |_, _, _| {}).unwrap();
        assert_eq!(
            preview.loose_duplicates_pruned,
            usize::from(!keep),
            "{label}"
        );
        assert_eq!(preview_totals.bytes_reclaimed, expected_bytes, "{label}");
        assert!(loose.is_file());
        let guard = store.prune_guard().unwrap();
        let (_, blocked) =
            run_gc_with_pack_report(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
        assert_eq!(blocked.loose_duplicates_pruned, 0);
        assert!(loose.is_file());
        drop(guard);
        crate::atomic::testing::reset_dir_sync_calls();
        let (totals, packed) =
            run_gc_with_pack_report(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
        assert_eq!(
            packed.loose_duplicates_pruned,
            usize::from(!keep),
            "{label}"
        );
        assert_eq!(loose.is_file(), keep, "{label}");
        assert_eq!(totals.bytes_reclaimed, expected_bytes, "{label}");
        assert_eq!(
            crate::atomic::testing::dir_sync_calls(),
            if keep { 0 } else { 2 },
            "{label}"
        );
        assert_eq!(store.read(&h).unwrap(), bytes);
    }
}

#[test]
fn a_packed_leaf_probe_cannot_hide_edges_of_a_live_tree() {
    use crate::object::{EntryMode, ObjectType, Tree, TreeEntry};
    use crate::ops::gc::run_gc;

    for kind in [ObjectType::Blob, ObjectType::Delta] {
        let (_dir, layout, store) = fresh();
        let (child_pack, children) = publish_objects(&store, &[&blob(b"tree child")]);
        let tree = serialize(&Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"child".to_vec(),
                mode: EntryMode::Blob,
                object_hash: children[0],
            }],
        }))
        .unwrap();
        let root = store.write(&tree).unwrap();
        crate::refs::write_ref(&layout, "live", &root).unwrap();

        let (decoy, ids) = publish_objects(&store, &[&blob(b"incorrect leaf")]);
        let index = super::Index::open(&decoy).unwrap();
        let frame = index.find(&ids[0]).unwrap();
        if kind == ObjectType::Delta {
            let mut bytes = fs::read(&decoy.pack).unwrap();
            let offset = usize::try_from(frame.offset).unwrap();
            bytes[offset] = kind as u8;
            bytes[offset + 5] = kind.schema_version();
            fs::write(&decoy.pack, bytes).unwrap();
        }
        fs::write(&decoy.index, index::encode(decoy.key, &[(root, frame)])).unwrap();

        let gc = ObjectStore::open(&layout).unwrap();
        gc.iter_object_hashes().unwrap(); // Put the incorrect locator in the cache.
        run_gc(&gc, &layout, u64::MAX, 0, false).unwrap();
        assert!(child_pack.pack.is_file());
        assert!(gc.read(&children[0]).is_ok());
    }
}

#[test]
fn gc_preserves_a_pair_whose_missing_member_reappears_before_the_try_lock() {
    use crate::ops::gc::run_gc_with_pack_report;

    let (_dir, layout, store) = fresh();
    let bytes = blob(b"same-key publication");
    let (pair, ids) = publish_objects(&store, &[&bytes]);
    fs::remove_file(&pair.pack).unwrap();
    let mut republished = false;
    let (_, packed) = run_gc_with_pack_report(
        &store,
        &layout,
        u64::MAX,
        0,
        false,
        &mut |phase, done, _| {
            if phase == "gc" && done == 0 && !republished {
                publish_objects(&store, &[&bytes]);
                republished = true;
            }
        },
    )
    .unwrap();
    assert!(republished);
    assert_eq!(packed.pack_leftovers_pruned, 0);
    assert_eq!(packed.packs_retired, 0);
    assert!(pair.pack.is_file() && pair.index.is_file());
    assert_eq!(store.read(&ids[0]).unwrap(), bytes);
}

#[test]
fn gc_preserves_a_candidate_whose_index_inode_changes_at_the_same_mtime() {
    use crate::ops::gc::run_gc_with_pack_report;

    let (_dir, layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"changed index inode")]);
    set_pack_age(&pair.index, 1);
    let mut replaced = false;
    let (_, packed) = run_gc_with_pack_report(
        &store,
        &layout,
        u64::MAX,
        0,
        false,
        &mut |phase, done, _| {
            if phase == "gc" && done == 0 && !replaced {
                let stage = tempfile::NamedTempFile::new_in(store.pack_dir()).unwrap();
                fs::write(stage.path(), fs::read(&pair.index).unwrap()).unwrap();
                set_pack_age(stage.path(), 1);
                stage.persist(&pair.index).unwrap();
                replaced = true;
            }
        },
    )
    .unwrap();
    assert!(replaced);
    assert_eq!(packed.packs_retired, 0);
    assert!(pair.pack.is_file() && pair.index.is_file());
}

#[test]
fn same_key_publication_replaces_only_the_damaged_member_with_verified_bytes() {
    for damage_pack in [false, true] {
        let (_dir, _layout, store) = fresh();
        let bytes = blob(b"verified by the new publisher");
        let (pair, ids) = publish_objects(&store, &[&bytes]);
        let pack = fs::read(&pair.pack).unwrap();
        let index = fs::read(&pair.index).unwrap();
        let (mut corrupt, member) = if damage_pack {
            (pack.clone(), &pair.pack)
        } else {
            (index.clone(), &pair.index)
        };
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(member, corrupt).unwrap();
        assert!(store.check_local_packs(false).is_err());

        let (published, _) = publish_objects(&store, &[&bytes]);
        assert_eq!(pair.key, published.key);
        assert_eq!(fs::read(&pair.pack).unwrap(), pack);
        assert_eq!(fs::read(&pair.index).unwrap(), index);
        assert_eq!(store.check_local_packs(false).unwrap(), 0);
        assert_eq!(store.read(&ids[0]).unwrap(), bytes);
    }
}

#[test]
fn a_damaged_dead_pack_does_not_block_collection_of_verified_garbage() {
    use crate::ops::gc::run_gc_with_pack_report;

    let (_dir, layout, store) = fresh();
    let (damaged, _) = publish_objects(&store, &[&blob(b"damaged dead pack")]);
    let (good, _) = publish_objects(&store, &[&blob(b"verified dead pack")]);
    let loose = store.write(&blob(b"unrelated loose garbage")).unwrap();
    let mut bytes = fs::read(&damaged.pack).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&damaged.pack, bytes).unwrap();

    for dry_run in [true, false] {
        let (report, packed) =
            run_gc_with_pack_report(&store, &layout, u64::MAX, 0, dry_run, &mut |_, _, _| {})
                .unwrap();
        assert_eq!(packed.skipped_pack_errors.len(), 1);
        assert!(packed.skipped_pack_errors[0].contains("invalid pack trailer"));
        assert_eq!(packed.packs_retired, 1);
        assert_eq!(report.pruned, 1);
        assert!(damaged.pack.is_file() && damaged.index.is_file());
        assert_eq!(good.pack.is_file(), dry_run);
        assert_eq!(store.path_for(&loose).is_file(), dry_run);
    }
}

#[test]
fn publishing_an_existing_pack_refreshes_its_mtime() {
    let (_dir, _layout, store) = fresh();
    let bytes = blob(b"reuse on publication");
    let (pair, _) = publish_objects(&store, &[&bytes]);
    set_pack_age(&pair.pack, 1);

    let (republished, _) = publish_objects(&store, &[&bytes]);
    assert_eq!(pair.key, republished.key);
    assert!(
        fs::metadata(&pair.pack).unwrap().modified().unwrap()
            > std::time::UNIX_EPOCH + std::time::Duration::from_secs(1)
    );
}

#[test]
fn a_recent_loose_copy_replaced_by_a_newer_pack_is_not_counted_as_kept() {
    use crate::ops::gc::run_gc_with_pack_report;

    let (_dir, layout, store) = fresh();
    let bytes = blob(b"recent dead duplicate");
    let h = store.write(&bytes).unwrap();
    let loose = store.path_for(&h);
    let (pair, _) = publish_objects(&store, &[&bytes]);
    set_pack_age(&loose, 8);
    set_pack_age(&pair.pack, 9);

    for dry_run in [true, false] {
        let (report, packed) =
            run_gc_with_pack_report(&store, &layout, 10, 5, dry_run, &mut |_, _, _| {}).unwrap();
        assert_eq!(report.kept_recent, 0);
        assert_eq!(packed.loose_duplicates_pruned, 1);
        assert_eq!(loose.exists(), dry_run);
        assert_eq!(store.read(&h).unwrap(), bytes);
    }
}

#[test]
fn gc_previews_each_loose_duplicate_once_when_two_packs_hold_it() {
    use crate::ops::gc::run_gc_with_pack_report;

    let (_dir, layout, store) = fresh();
    let live = blob(b"shared packed object");
    let id = store.write(&live).unwrap();
    crate::refs::write_ref(&layout, "live", &id).unwrap();
    publish_objects(&store, &[&live, &blob(b"first extra entry")]);
    publish_objects(&store, &[&live, &blob(b"second extra entry")]);

    let (report, packed) =
        run_gc_with_pack_report(&store, &layout, u64::MAX, 0, true, &mut |_, _, _| {}).unwrap();
    assert_eq!(packed.packs_retired, 0);
    assert_eq!(packed.loose_duplicates_pruned, 1);
    assert_eq!(report.bytes_reclaimed, live.len() as u64);
    assert!(store.path_for(&id).exists());
}

thread_local! {
    static BEFORE_DUPLICATE_TRY_LOCK: std::cell::Cell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::Cell::new(None) };
    static PACK_SCAN_ERROR: std::cell::Cell<Option<(Hash, std::io::ErrorKind)>> =
        const { std::cell::Cell::new(None) };
}

pub(super) fn before_duplicate_try_lock() {
    if let Some(change) = BEFORE_DUPLICATE_TRY_LOCK.take() {
        change();
    }
}

pub(super) fn pack_scan_error(key: Hash) -> std::io::Result<()> {
    if let Some((target, kind)) = PACK_SCAN_ERROR.get()
        && target == key
    {
        PACK_SCAN_ERROR.set(None);
        return Err(kind.into());
    }
    Ok(())
}

#[test]
fn gc_keeps_a_loose_duplicate_when_any_member_changes_before_the_try_lock() {
    use crate::ops::gc::run_gc_with_pack_report;

    for member in ["pack", "index", "loose"] {
        let (_dir, layout, store) = fresh();
        let bytes = blob(b"loose duplicate of a live packed object");
        let id = store.write(&bytes).unwrap();
        crate::refs::write_ref(&layout, "live", &id).unwrap();
        let loose = store.path_for(&id);
        let (pair, _) = publish_objects(&store, &[&bytes]);
        set_pack_age(&pair.pack, 9);
        set_pack_age(&pair.index, 1);
        set_pack_age(&loose, 8);

        let path = match member {
            "pack" => pair.pack,
            "index" => pair.index,
            _ => loose.clone(),
        };
        let pack_dir = store.pack_dir();
        BEFORE_DUPLICATE_TRY_LOCK.set(Some(Box::new(move || match member {
            "pack" => set_pack_age(&path, 1),
            "index" => {
                // Keep the locator bytes and mtime identical while replacing
                // its file identity.
                let replacement = tempfile::NamedTempFile::new_in(pack_dir).unwrap();
                fs::write(replacement.path(), fs::read(&path).unwrap()).unwrap();
                set_pack_age(replacement.path(), 1);
                replacement.persist(&path).unwrap();
            }
            _ => set_pack_age(&path, 10),
        })));

        let (report, packed) =
            run_gc_with_pack_report(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
        assert!(BEFORE_DUPLICATE_TRY_LOCK.take().is_none());
        assert_eq!(packed.loose_duplicates_pruned, 0, "{member} changed");
        assert_eq!(report.bytes_reclaimed, 0, "{member} changed");
        assert_eq!(fs::read(loose).unwrap(), bytes, "{member} changed");
    }
}

#[test]
fn a_pack_scan_io_error_aborts_gc_without_removing_other_garbage() {
    use crate::ops::gc::{GcRootsError, run_gc};

    let (_dir, layout, store) = fresh();
    let (unreadable, _) = publish_objects(&store, &[&blob(b"unreadable dead pack")]);
    let (other, _) = publish_objects(&store, &[&blob(b"other dead pack")]);
    let loose = store.write(&blob(b"unrelated loose garbage")).unwrap();
    let kind = std::io::ErrorKind::PermissionDenied;
    PACK_SCAN_ERROR.set(Some((unreadable.key, kind)));

    let result = run_gc(&store, &layout, u64::MAX, 0, false);
    assert!(PACK_SCAN_ERROR.get().is_none());
    assert!(matches!(
        result,
        Err(GcRootsError::Store(StoreError::Io(error))) if error.kind() == kind
    ));
    assert!(unreadable.pack.is_file() && unreadable.index.is_file());
    assert!(other.pack.is_file() && other.index.is_file());
    assert!(store.path_for(&loose).is_file());
}

#[test]
fn a_same_key_pack_scan_io_error_leaves_the_existing_pair_untouched() {
    use std::time::{Duration, UNIX_EPOCH};

    let (_dir, _layout, store) = fresh();
    let bytes = blob(b"same-key pack scan I/O error");
    let (pair, _) = publish_objects(&store, &[&bytes]);
    let original_pack = fs::read(&pair.pack).unwrap();
    let original_index = fs::read(&pair.index).unwrap();
    set_pack_age(&pair.pack, 1);
    let mut retry = writer(&store);
    retry.write(&bytes).unwrap();
    let kind = std::io::ErrorKind::PermissionDenied;
    PACK_SCAN_ERROR.set(Some((pair.key, kind)));

    let result = retry.finish();
    assert!(PACK_SCAN_ERROR.get().is_none());
    assert!(matches!(result, Err(StoreError::Io(error)) if error.kind() == kind));
    assert_eq!(fs::read(&pair.pack).unwrap(), original_pack);
    assert_eq!(fs::read(&pair.index).unwrap(), original_index);
    assert_eq!(
        fs::metadata(&pair.pack).unwrap().modified().unwrap(),
        UNIX_EPOCH + Duration::from_secs(1)
    );
}

#[test]
fn reads_and_misses_reuse_indexes_past_sixty_four_packs() {
    use std::sync::atomic::Ordering;

    let (_dir, layout, store) = fresh();
    let dir = store.pack_dir();
    fs::create_dir(&dir).unwrap();
    store.try_activate_local_packs().unwrap();
    let objects: Vec<_> = (0..104)
        .map(|n| {
            let bytes = blob(&[n]);
            let id = index::canonical_id(&bytes).unwrap();
            let len = u32::try_from(bytes.len()).unwrap();
            let mut pack = crate::pack::MAGIC.to_vec();
            pack.extend_from_slice(&1_u32.to_le_bytes());
            pack.extend_from_slice(&1_u32.to_le_bytes());
            pack.push(0);
            pack.extend_from_slice(&len.to_le_bytes());
            let frame = index::Frame {
                offset: pack.len() as u64,
                len,
            };
            pack.extend_from_slice(&bytes);
            let trailer = blake3::hash(&pack);
            pack.extend_from_slice(trailer.as_bytes());
            let key = *blake3::hash(&pack).as_bytes();
            let pair = Pair::new(&dir, key);
            fs::write(&pair.pack, pack).unwrap();
            fs::write(&pair.index, index::encode(key, &[(id, frame)])).unwrap();
            (id, bytes)
        })
        .collect();

    let reader = ObjectStore::open(&layout).unwrap();
    let loads = || reader.packs.index_loads.load(Ordering::Relaxed);
    assert!(matches!(
        reader.read(&[0; 32]),
        Err(StoreError::ObjectNotFound(_))
    ));
    assert_eq!(loads(), objects.len());
    {
        let discovery = reader.packs.discovery.lock().unwrap();
        assert_eq!(discovery.catalog.routes.len(), objects.len());
        assert!(
            discovery
                .catalog
                .packs
                .iter()
                .all(|pack| pack.row_charge() == index::INDEX_ROW_LEN)
        );
    }

    for (id, bytes) in objects.iter().rev() {
        assert_eq!(reader.read(id).unwrap(), *bytes);
    }
    for n in 1..8 {
        assert!(matches!(
            reader.read(&[n; 32]),
            Err(StoreError::ObjectNotFound(_))
        ));
    }
    assert_eq!(loads(), objects.len());
    assert_eq!(reader.packs.handles.cached(), 96);
}

#[test]
fn lookups_check_the_selected_extent_and_scans_check_the_checksum() {
    let (_dir, layout, store) = fresh();
    let bytes = blob(b"indexed bytes");
    let mut writer = writer(&store);
    let id = writer.write(&bytes).unwrap();
    let (staged, _guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();

    let mut idx = fs::read(&pair.index).unwrap();
    *idx.last_mut().unwrap() ^= 1;
    fs::write(&pair.index, &idx).unwrap();
    let reader = ObjectStore::open(&layout).unwrap();
    assert_eq!(reader.read(&id).unwrap(), bytes);
    assert!(reader.check_local_packs(false).is_err());

    let offset_at = 12 + 1024 + 32;
    idx[offset_at..offset_at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&pair.index, idx).unwrap();
    let error = reader.read(&id).unwrap_err();
    assert!(error.to_string().contains("extent"), "{error}");
}

#[test]
fn cached_pack_handles_do_not_keep_unpublished_locations_visible() {
    for pack_removed in [false, true] {
        let (_dir, layout, store) = fresh();
        let bytes = blob(b"retired object");
        let mut writer = writer(&store);
        let id = writer.write(&bytes).unwrap();
        let (staged, _guard) = writer.stage().unwrap();
        let pair = staged.pair.clone();
        staged.publish(&store).unwrap();
        let reader = ObjectStore::open(&layout).unwrap();
        assert_eq!(reader.read(&id).unwrap(), bytes);

        fs::remove_file(if pack_removed {
            &pair.pack
        } else {
            &pair.index
        })
        .unwrap();
        assert!(matches!(
            reader.read(&id),
            Err(StoreError::ObjectNotFound(_))
        ));
        store.write(&bytes).unwrap();
        assert_eq!(reader.read(&id).unwrap(), bytes);
        store.remove_object(&id).unwrap();

        let mut replacement = Writer::new(&store, MAX_ENTRIES, MAX_TOTAL_PAYLOAD).unwrap();
        replacement.write(&bytes).unwrap();
        replacement.write(&blob(b"new pack key")).unwrap();
        replacement.finish().unwrap();
        assert_eq!(reader.read(&id).unwrap(), bytes);
    }
}

#[test]
fn an_index_outside_the_row_budget_routes_without_reopening_on_misses() {
    use super::reader::{Handles, Locator, prefix};

    let (_dir, _layout, store) = fresh();
    let bytes = blob(b"read rows from disk");
    let mut writer = writer(&store);
    let id = writer.write(&bytes).unwrap();
    let (staged, _guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();

    let locator = std::sync::Arc::new(Locator::open(&pair, 0, 64).unwrap());
    assert_eq!(locator.row_charge(), 0);
    let catalog = super::Catalog::from_packs(vec![std::sync::Arc::clone(&locator)], None);
    let routes: Vec<_> = catalog.candidates(&id).collect();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].1, Some(0));
    let mut absent = id;
    absent[0] ^= 1;
    assert_ne!(prefix(&absent), prefix(&id));
    assert!(catalog.candidates(&absent).next().is_none());
    let handles = Handles::default();
    assert!(locator.find(&handles, &id, routes[0].1).unwrap().is_some());
    let mut different = id;
    different[31] ^= 1;
    assert!(
        locator
            .find(&handles, &different, routes[0].1)
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn pack_discovery_notices_publication_with_restored_directory_mtime() {
    let (_dir, layout, store) = fresh();
    let mut writer = writer(&store);
    writer.write(&blob(b"known object")).unwrap();
    writer.finish().unwrap();
    let reader = ObjectStore::open(&layout).unwrap();
    assert!(!reader.contains(&[0; 32]));
    let dir = fs::File::open(store.pack_dir()).unwrap();
    let mtime = dir.metadata().unwrap().modified().unwrap();

    let bytes = blob(b"published with unchanged directory mtime");
    let mut writer = Writer::new(&store, MAX_ENTRIES, MAX_TOTAL_PAYLOAD).unwrap();
    let id = writer.write(&bytes).unwrap();
    writer.finish().unwrap();
    dir.set_modified(mtime).unwrap();
    assert_eq!(dir.metadata().unwrap().modified().unwrap(), mtime);
    assert_eq!(reader.read(&id).unwrap(), bytes);
}

#[test]
fn budget_boundaries_preserve_lookup_in_all_three_index_storage_modes() {
    use std::sync::Arc;

    use super::reader::{Handles, Locator, Route};

    let (_dir, _layout, store) = fresh();
    let mut objects: Vec<_> = (0..300_u16).map(|n| blob(&n.to_le_bytes())).collect();
    let first_bucket = (0..=u16::MAX)
        .map(|n| {
            let [lo, hi] = n.to_le_bytes();
            blob(&[lo, hi, 0])
        })
        .find(|bytes| index::canonical_id(bytes).unwrap()[0] == 0)
        .unwrap();
    objects.push(first_bucket);
    let objects: Vec<_> = objects.iter().map(Vec::as_slice).collect();
    let (pair, mut ids) = publish_objects(&store, &objects);
    ids.sort_unstable();
    let strict = index::Index::open(&pair).unwrap();
    let row_bytes = index::INDEX_ROW_LEN * ids.len();
    let route_bytes = (size_of::<Route>() + size_of::<u32>()) * ids.len();

    for (rows, routes, expected_rows, expected_routes) in [
        (row_bytes, route_bytes, row_bytes, ids.len()),
        (row_bytes - 1, route_bytes, 0, ids.len()),
        (row_bytes, route_bytes - 1, 0, 0),
    ] {
        let locator = Arc::new(Locator::open(&pair, rows, routes).unwrap());
        assert_eq!(locator.row_charge(), expected_rows);
        assert_eq!(locator.route_count(), expected_routes);
        assert_eq!(
            locator.route_charge(),
            expected_routes * (size_of::<Route>() + size_of::<u32>())
        );
        let catalog = super::Catalog::from_packs(vec![Arc::clone(&locator)], None);
        let handles = Handles::default();
        for id in &ids {
            let frames: Vec<_> = catalog
                .candidates(id)
                .filter_map(|(pack, row)| pack.find(&handles, id, row).unwrap())
                .collect();
            assert_eq!(frames, [strict.find(id).unwrap()]);
        }
        for first in 0..=u8::MAX {
            for trailing in [0, u8::MAX] {
                let mut absent = [trailing; 32];
                absent[0] = first;
                assert!(
                    catalog
                        .candidates(&absent)
                        .all(|(pack, row)| pack.find(&handles, &absent, row).unwrap().is_none())
                );
            }
        }
    }
}

#[test]
fn cached_pack_stream_advances_and_stops_at_the_selected_frame() {
    use std::io::Read;

    let (_dir, layout, store) = fresh();
    let bytes = blob(b"split the selected frame into short reads");
    let next = blob(b"following frame");
    let (_, ids) = publish_objects(&store, &[&bytes, &next]);
    let reader = ObjectStore::open(&layout).unwrap();
    let mut contents = reader
        .packs
        .lookup(&reader, &ids[0], true, |location| location.open())
        .unwrap();
    let mut buffer = [0; 7];
    for expected in bytes.chunks(buffer.len()) {
        let n = contents.read(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], expected);
    }
    assert_eq!(contents.read(&mut buffer).unwrap(), 0);
}

#[cfg(unix)]
#[test]
fn handles_reuse_only_the_requested_member_and_close_removed_entries() {
    use std::sync::Arc;

    use super::reader::{Handles, Locator, Member};

    let (_dir, _layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"two file handles")]);
    let locator = Arc::new(Locator::open(&pair, 0, 0).unwrap());
    let handles = Handles::default();
    let pack = handles.get(&locator, Member::Pack).unwrap();
    let index = handles.get(&locator, Member::Index).unwrap();
    assert!(!Arc::ptr_eq(&pack, &index));
    assert!(Arc::ptr_eq(
        &pack,
        &handles.get(&locator, Member::Pack).unwrap()
    ));
    assert!(Arc::ptr_eq(
        &index,
        &handles.get(&locator, Member::Index).unwrap()
    ));
    assert_eq!(handles.cached(), 2);
    handles.retain(|candidate| !Arc::ptr_eq(candidate, &locator));
    assert_eq!(handles.cached(), 0);

    for (path, member) in [(&pair.pack, Member::Pack), (&pair.index, Member::Index)] {
        let bytes = fs::read(path).unwrap();
        let replacement = tempfile::NamedTempFile::new_in(store.pack_dir()).unwrap();
        fs::write(replacement.path(), bytes).unwrap();
        replacement.persist(path).unwrap();
        assert!(matches!(
            handles.get(&locator, member),
            Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
        ));
    }
}

#[test]
fn a_verified_collection_location_rechecks_the_index_version() {
    use std::sync::Arc;

    let (_dir, _layout, store) = fresh();
    let (pair, ids) = publish_objects(&store, &[&blob(b"verified collection location")]);
    let index = Arc::new(index::Index::open(&pair).unwrap());
    let frame = index.find(&ids[0]).unwrap();
    let location = super::Location::Packed(index, frame);
    assert!(location.open().is_ok());
    let mut bytes = fs::read(&pair.index).unwrap();
    bytes[4..8].copy_from_slice(&2_u32.to_le_bytes());
    fs::write(&pair.index, bytes).unwrap();
    set_pack_age(&pair.index, 1);
    assert!(matches!(
        location.open(),
        Err(StoreError::IncompatibleRepoFormat { .. })
    ));
}

#[test]
fn forgetting_a_pack_evicts_only_its_handles_and_invalidates_discovery() {
    use std::sync::Arc;

    use super::reader::Member;

    let (_dir, _layout, store) = fresh();
    let (first, _) = publish_objects(&store, &[&blob(b"first handle")]);
    let (last, _) = publish_objects(&store, &[&blob(b"last handle")]);
    let catalog = store.packs.discover(&store.pack_dir(), true).unwrap();
    let first_locator = catalog
        .packs
        .iter()
        .find(|p| p.pair.key == first.key)
        .unwrap();
    let last_locator = catalog
        .packs
        .iter()
        .find(|p| p.pair.key == last.key)
        .unwrap();
    store
        .packs
        .handles
        .get(first_locator, Member::Pack)
        .unwrap();
    let last_handle = store.packs.handles.get(last_locator, Member::Pack).unwrap();
    store.packs.remember_publication(&last);
    store.packs.discovery.lock().unwrap().scanned = true;
    store.packs.forget(&first.key);
    assert_eq!(store.packs.handles.cached(), 1);
    let after_forget = store.packs.handles.get(last_locator, Member::Pack).unwrap();
    assert!(Arc::ptr_eq(&last_handle, &after_forget));
    {
        let discovery = store.packs.discovery.lock().unwrap();
        assert!(!discovery.scanned);
        assert_eq!(discovery.latest.as_ref().unwrap().pair.key, last.key);
    }
    store.packs.forget(&last.key);
    assert_eq!(store.packs.handles.cached(), 0);
    assert!(store.packs.discovery.lock().unwrap().latest.is_none());
}

#[test]
fn forced_discovery_rechecks_an_index_even_with_the_same_directory_stamp() {
    use std::sync::Arc;

    let (_dir, _layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"force a rescan")]);
    let dir = store.pack_dir();
    let first = store.packs.discover(&dir, true).unwrap();
    // Model a directory whose status time has already settled.
    store.packs.discovery.lock().unwrap().scanned = true;
    fs::write(pair.index, b"damaged index").unwrap();
    assert!(Arc::ptr_eq(
        &first,
        &store.packs.discover(&dir, false).unwrap()
    ));
    let second = store.packs.discover(&dir, true).unwrap();
    assert!(second.packs.is_empty());
    assert!(second.error.is_some());
}

#[cfg(unix)]
#[test]
fn cached_absence_does_not_hide_filesystem_errors_in_discovery() {
    let (dir, _, store) = fresh();
    let path = dir.path().join("missing").join("pack");
    assert!(store.packs.discover(&path, false).unwrap().packs.is_empty());
    let missing = path.parent().unwrap();
    std::os::unix::fs::symlink(missing, missing).unwrap();
    assert!(matches!(
        store.packs.discover(&path, false),
        Err(StoreError::Io(error)) if error.kind() != std::io::ErrorKind::NotFound
    ));
}

#[test]
fn a_loose_location_keeps_its_distinct_verification_policy() {
    let (_dir, _layout, store) = fresh();
    let id = store.write(&blob(b"loose location")).unwrap();
    let packed = store
        .packs
        .lookup(&store, &id, true, |location| Ok(location.is_packed()))
        .unwrap();
    assert!(!packed);
}

#[test]
fn discovery_accounts_for_new_retained_and_replaced_indexes_within_each_budget() {
    use super::reader::Route;

    let row_bytes = index::INDEX_ROW_LEN;
    let route_bytes = size_of::<Route>() + size_of::<u32>();
    for routed_packs in [1, 3] {
        let (_dir, _layout, store) = fresh();
        publish_objects(&store, &[&blob(b"first candidate")]);
        publish_objects(&store, &[&blob(b"second candidate")]);
        store.packs.discovery.lock().unwrap().budgets =
            Some((row_bytes, route_bytes * routed_packs));
        let dir = store.pack_dir();
        let first = store.packs.discover(&dir, true).unwrap();
        let resident = &first.packs[0];
        assert_eq!(resident.row_charge(), row_bytes);
        assert_eq!(resident.route_charge(), route_bytes);
        assert_eq!(first.packs[1].row_charge(), 0);
        assert_eq!(
            first.packs[1].route_charge(),
            if routed_packs == 1 { 0 } else { route_bytes }
        );

        let (extra, _) = publish_objects(&store, &[&blob(b"another candidate")]);
        let second = store.packs.discover(&dir, true).unwrap();
        let added = second
            .packs
            .iter()
            .find(|p| p.pair.key == extra.key)
            .unwrap();
        assert_eq!(added.row_charge(), 0);
        assert_eq!(
            added.route_charge(),
            if routed_packs == 1 { 0 } else { route_bytes }
        );

        let replacement = tempfile::NamedTempFile::new_in(&dir).unwrap();
        fs::copy(&resident.pair.index, replacement.path()).unwrap();
        replacement.persist(&resident.pair.index).unwrap();
        let third = store.packs.discover(&dir, true).unwrap();
        let reloaded = third
            .packs
            .iter()
            .find(|p| p.pair.key == resident.pair.key)
            .unwrap();
        assert_eq!(reloaded.row_charge(), row_bytes);
        assert_eq!(reloaded.route_charge(), route_bytes);
    }
}

#[test]
fn a_pack_retired_between_listing_and_open_is_absent() {
    let (_dir, layout, store) = fresh();
    let (pair, ids) = publish_objects(&store, &[&blob(b"retired during discovery")]);
    let reader = ObjectStore::open(&layout).unwrap();
    reader.packs.discovery.lock().unwrap().retire_after_listing = Some(pair.pack);
    assert!(matches!(
        reader.read(&ids[0]),
        Err(StoreError::ObjectNotFound(_))
    ));
}
