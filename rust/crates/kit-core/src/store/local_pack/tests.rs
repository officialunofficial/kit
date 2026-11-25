use std::fmt::Write as _;
use std::fs;
use std::io::{Seek, SeekFrom, Write};

use crate::hash::Hash;
use crate::layout::RepoLayout;
use crate::object::{Blob, Object, ObjectType};
use crate::pack::{MAX_ENTRIES, MAX_TOTAL_PAYLOAD};
use crate::serialize::serialize;
use crate::store::{ObjectStore, StoreError};

use super::writer::PackFixture;
use super::{Pair, index};

pub(super) fn fresh() -> (tempfile::TempDir, RepoLayout, ObjectStore) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    (dir, layout, store)
}

pub(super) fn blob(data: &[u8]) -> Vec<u8> {
    serialize(&Object::Blob(Blob {
        data: data.to_vec(),
    }))
    .unwrap()
}

fn writer(store: &ObjectStore) -> PackFixture<'_> {
    PackFixture::new(store, MAX_ENTRIES, MAX_TOTAL_PAYLOAD).unwrap()
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

    let mut retry = PackFixture::new(&store, MAX_ENTRIES, MAX_TOTAL_PAYLOAD).unwrap();
    retry.write(&bytes).unwrap();
    retry.finish().unwrap();
    assert_eq!(reader.read(&id).unwrap(), bytes);
}

#[test]
fn pack_scan_keeps_every_read_error_a_read_error() {
    use std::io::{Error, ErrorKind};

    let (_dir, _layout, store) = fresh();
    let mut writer = writer(&store);
    writer.write(&blob(b"checkpoint")).unwrap();
    let (staged, _guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();

    for (input, expected) in [
        (ErrorKind::Interrupted, ErrorKind::Interrupted),
        (ErrorKind::TimedOut, ErrorKind::TimedOut),
        (ErrorKind::PermissionDenied, ErrorKind::PermissionDenied),
        (ErrorKind::ConnectionReset, ErrorKind::ConnectionReset),
    ] {
        let result = super::scan_pair_checked(&pair, &|| Err(Error::from(input).into()));
        let Err(StoreError::Io(error)) = result else {
            panic!("expected an I/O error from the pack scan");
        };
        assert_eq!(error.kind(), expected);
    }
}

#[test]
fn an_orphan_plan_keeps_a_pack_whose_index_is_published_before_the_lock() {
    let (_dir, _layout, store) = fresh();
    let mut writer = writer(&store);
    let bytes = blob(b"publication finished after orphan planning");
    let id = writer.write(&bytes).unwrap();
    let (staged, guard) = writer.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();

    let index = fs::read(&pair.index).unwrap();
    fs::remove_file(&pair.index).unwrap();
    let (sweep, pairs) = store.plan_pack_leftovers(u64::MAX, 0).unwrap();
    assert_eq!(pairs, 0);
    assert!(sweep.is_empty(), "the sweep alone leaves a lone pack");
    let plan = store.plan_lone_packs(u64::MAX, 0).unwrap();
    assert!(!plan.is_empty());
    fs::write(&pair.index, index).unwrap();
    drop(guard);

    let mut report = crate::ops::gc::GcReport::default();
    assert!(plan.run_with(&store, &mut report, || Ok(())).unwrap());
    assert_eq!(report.pack_leftovers_pruned, 0);
    assert!(pair.pack.is_file() && pair.index.is_file());
    assert_eq!(store.read(&id).unwrap(), bytes);
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

fn set_version(path: &std::path::Path, version: u32) {
    let mut bytes = fs::read(path).unwrap();
    bytes[4..8].copy_from_slice(&version.to_le_bytes());
    let replacement = tempfile::NamedTempFile::new_in(path.parent().unwrap()).unwrap();
    fs::write(replacement.path(), &bytes).unwrap();
    replacement.persist(path).unwrap();
}

#[test]
fn a_pair_written_at_a_newer_version_refuses_lookup_and_repair() {
    fn incompatible(error: &StoreError) {
        assert!(matches!(error, StoreError::IncompatibleRepoFormat { .. }));
        let text = error.to_string();
        assert!(text.contains("Update kit"), "{text}");
        assert!(text.contains("version 2"), "{text}");
    }

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

    set_version(&pair.pack, 2);
    set_version(&pair.index, 2);
    let newer = fs::read(&pair.pack).unwrap();

    let reopened = ObjectStore::open(&layout).unwrap();
    incompatible(&reopened.read(&[0; 32]).unwrap_err());
    incompatible(&store.read(&id).unwrap_err());
    incompatible(&still_open.read(&[0; 32]).unwrap_err());
    incompatible(&still_open.iter_object_hashes().unwrap_err());
    incompatible(&still_open.check_local_packs(true).unwrap_err());
    let mut retry = PackFixture::new(&store, MAX_ENTRIES, MAX_TOTAL_PAYLOAD).unwrap();
    retry.write(&bytes).unwrap();
    incompatible(&retry.finish().unwrap_err());
    assert_eq!(fs::read(&pair.pack).unwrap(), newer);
}

#[test]
fn a_wrong_version_in_one_file_is_damage_to_that_pair_and_repair_rebuilds_the_index() {
    for index_is_wrong in [true, false] {
        let (_dir, layout, pairs) = packed_store(&[vec![1, 2, 3], vec![4]]);
        let wrong = if index_is_wrong {
            &pairs[0].index
        } else {
            &pairs[0].pack
        };
        set_version(wrong, 2);

        let reader = ObjectStore::open(&layout).unwrap();
        let error = reader.read(&packed_blob(1).0).unwrap_err();
        let text = error.to_string();
        assert!(
            matches!(error, StoreError::LocalPackDamaged { .. }),
            "{text}"
        );
        assert!(
            text.contains(&pairs[0].pack.display().to_string()),
            "{text}"
        );
        assert!(text.contains("version 2"), "{text}");
        assert!(
            text.contains("does not match the other file of the pair"),
            "{text}"
        );
        let named = if index_is_wrong {
            "local index"
        } else {
            "local pack"
        };
        assert!(text.contains(named), "the differing file is named: {text}");
        assert!(!text.contains("Update kit"), "{text}");
        assert_eq!(
            text.contains("repair-indexes"),
            index_is_wrong,
            "the hint names the damaged file: {text}"
        );
        assert_eq!(reader.read(&packed_blob(4).0).unwrap(), packed_blob(4).1);

        if index_is_wrong {
            assert_eq!(reader.check_local_packs(true).unwrap(), 1);
            assert_eq!(reader.read(&packed_blob(1).0).unwrap(), packed_blob(1).1);
        } else {
            let error = reader.check_local_packs(true).unwrap_err();
            assert!(
                matches!(error, StoreError::LocalPackDamaged { .. }),
                "{error}"
            );
        }
    }
}

#[test]
fn a_version_error_on_a_pair_with_valid_versions_keeps_its_own_reason() {
    let (_dir, _layout, pairs) = packed_store(&[vec![1]]);
    for (found, reason) in [
        (Some("odd version".to_owned()), "odd version"),
        (None, "unknown"),
    ] {
        let error = pairs[0].context(StoreError::IncompatibleRepoFormat { found });
        assert_damage(&error, &pairs[0], reason);
        let StoreError::LocalPackDamaged { reason: text, .. } = &error else {
            unreachable!("asserted above");
        };
        assert!(!text.contains("does not match"), "{text}");
        assert!(!text.contains("not one this kit reads"), "{text}");
    }
}

#[test]
fn a_pair_with_an_unknown_index_version_does_not_hide_the_other_pairs() {
    let (_dir, layout, store) = fresh();
    let mut first = writer(&store);
    first.write(&blob(b"object in the newer pair")).unwrap();
    let (staged, guard) = first.stage().unwrap();
    let newer = staged.pair.clone();
    staged.publish(&store).unwrap();
    drop(guard);

    let kept = blob(b"object in the readable pair");
    let mut second = writer(&store);
    let id = second.write(&kept).unwrap();
    second.finish().unwrap();

    let mut index = fs::read(&newer.index).unwrap();
    index[4..8].copy_from_slice(&2_u32.to_le_bytes());
    fs::write(&newer.index, index).unwrap();

    let reopened = ObjectStore::open(&layout).unwrap();
    let read = reopened.read(&id);
    assert!(
        read.as_ref().is_ok_and(|bytes| *bytes == kept),
        "an unknown index version stops lookup on that pair only, got {read:?}"
    );
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
    let dir = tempfile::tempdir().unwrap();
    let store = ObjectStore::init_loose(&RepoLayout::single(dir.path())).unwrap();
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
    crate::store::format::activate(&store.format_path()).unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), store.pack_dir()).unwrap();

    let reader = ObjectStore::open(&layout).unwrap();
    assert!(matches!(
        reader.read(&[0; 32]),
        Err(StoreError::LocalPackDamaged { .. })
    ));
}

#[cfg(unix)]
#[test]
fn pack_scan_reports_filesystem_errors_other_than_absence() {
    let (_dir, layout, store) = fresh();
    crate::store::format::activate(&store.format_path()).unwrap();
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

fn assert_damage(error: &StoreError, pair: &Pair, reason: &str) {
    let StoreError::LocalPackDamaged {
        pack,
        reason: found,
    } = error
    else {
        panic!("expected local pack damage, got {error:?}");
    };
    assert_eq!(&**pack, pair.pack.display().to_string());
    assert!(found.contains(reason), "{found}");
}

#[test]
fn every_kind_of_damage_is_a_typed_error_with_the_pack_name() {
    type Damage = fn(&[u8], &[u8]) -> (Vec<u8>, Vec<u8>);

    let (_dir, layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"first"), &blob(b"second")]);
    let pack = fs::read(&pair.pack).unwrap();
    let index = fs::read(&pair.index).unwrap();

    let verified = "does not match verified pack";
    let cases: [(&str, Damage, &str); 6] = [
        (
            "corrupt index checksum",
            |p, i| {
                let mut i = i.to_vec();
                *i.last_mut().unwrap() ^= 1;
                (p.to_vec(), i)
            },
            verified,
        ),
        (
            "corrupt pack frame",
            |p, i| {
                let mut p = p.to_vec();
                *p.last_mut().unwrap() ^= 1;
                (p, i.to_vec())
            },
            "trailer",
        ),
        (
            "truncated pack",
            |p, i| (p[..p.len() - 40].to_vec(), i.to_vec()),
            "size disagrees",
        ),
        (
            "truncated index",
            |p, i| (p.to_vec(), i[..i.len() - 40].to_vec()),
            verified,
        ),
        (
            "truncated pack header",
            |p, i| (p[..5].to_vec(), i.to_vec()),
            "header ends early",
        ),
        (
            "truncated index header",
            |p, i| (p.to_vec(), i[..5].to_vec()),
            verified,
        ),
    ];
    for (label, damage, reason) in cases {
        let (damaged_pack, damaged_index) = damage(&pack, &index);
        fs::write(&pair.pack, damaged_pack).unwrap();
        fs::write(&pair.index, damaged_index).unwrap();
        let reader = ObjectStore::open(&layout).unwrap();
        let error = reader.check_local_packs(false).unwrap_err();
        assert!(
            matches!(error, StoreError::LocalPackDamaged { .. }),
            "{label}: {error:?}"
        );
        assert_damage(&error, &pair, reason);
    }
}

#[test]
fn a_non_regular_member_is_damage_and_an_unreadable_one_is_not() {
    let (_dir, layout, store) = fresh();
    let (pair, ids) = publish_objects(&store, &[&blob(b"index kinds")]);

    let other = pair.index.with_extension("other");
    fs::create_dir(&other).unwrap();
    assert!(matches!(
        index::open_regular(&other),
        Err(StoreError::LocalPackDamaged { pack, .. }) if *pack == *other.display().to_string()
    ));
    fs::remove_dir(&other).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pair.index, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&pair.index).is_err() {
            let reader = ObjectStore::open(&layout).unwrap();
            for error in [
                reader.check_local_packs(false).unwrap_err(),
                reader.check_presence(&ids[0]).unwrap_err(),
            ] {
                assert!(
                    matches!(&error, StoreError::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
                    "{error:?}"
                );
            }
        }
        fs::set_permissions(&pair.index, fs::Permissions::from_mode(0o644)).unwrap();
    }
}

#[test]
fn damage_without_a_pack_takes_the_name_of_the_file_being_read() {
    use std::io::{Error, ErrorKind};
    use std::path::Path;

    let path = Path::new("staged.pack");
    for error in [
        index::invalid("bad frame"),
        StoreError::Io(Error::from(ErrorKind::UnexpectedEof)),
    ] {
        let StoreError::LocalPackDamaged { pack, .. } = index::named(path, error) else {
            panic!("expected damage");
        };
        assert_eq!(&*pack, "staged.pack");
    }
    assert!(matches!(
        index::named(path, index::invalid_at(Path::new("other.pack"), "bad frame")),
        StoreError::LocalPackDamaged { pack, .. } if &*pack == "other.pack"
    ));
    assert!(matches!(
        index::named(path, StoreError::Io(Error::from(ErrorKind::TimedOut))),
        StoreError::Io(e) if e.kind() == ErrorKind::TimedOut
    ));
}

#[test]
fn a_read_that_ends_early_is_damage_and_other_read_errors_are_not() {
    use std::io::{Error, ErrorKind};

    let (_dir, _layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"classification")]);

    assert_damage(
        &pair.context(Error::from(ErrorKind::UnexpectedEof)),
        &pair,
        "ends early",
    );
    assert_damage(
        &pair.context(index::invalid("bad frame")),
        &pair,
        "bad frame",
    );
    // An index that ends early is damage to the index, so it names the repair;
    // a file that ends early elsewhere in the pair does not.
    let early = pair.index_context(Error::from(ErrorKind::UnexpectedEof));
    assert_damage(&early, &pair, "ends early");
    assert!(early.to_string().contains("repair-indexes"), "{early}");
    assert!(
        !pair
            .context(Error::from(ErrorKind::UnexpectedEof))
            .to_string()
            .contains("repair-indexes")
    );
    let other = index::invalid_at(std::path::Path::new("other.pack"), "named elsewhere");
    assert!(matches!(
        pair.context(other),
        StoreError::LocalPackDamaged { pack, .. } if &*pack == "other.pack"
    ));
    for kind in [
        ErrorKind::Interrupted,
        ErrorKind::TimedOut,
        ErrorKind::PermissionDenied,
        ErrorKind::NotFound,
        ErrorKind::Other,
    ] {
        for error in [
            pair.context(Error::from(kind)),
            pair.index_context(Error::from(kind)),
        ] {
            assert!(
                matches!(&error, StoreError::Io(e) if e.kind() == kind),
                "{kind:?}: {error:?}"
            );
        }
    }
}

#[test]
fn rebuild_an_index_from_a_verified_pack() {
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
    // A pack that lost its index is verified whole and gets its index back.
    fs::remove_file(&pair.index).unwrap();
    assert_eq!(reopened.check_local_packs(false).unwrap(), 0);
    assert!(!pair.index.exists());
    assert_eq!(reopened.check_local_packs(true).unwrap(), 1);
    assert_eq!(fs::read(&pair.index).unwrap(), idx);
    assert_eq!(reopened.read(&id).unwrap(), bytes);
}

#[test]
fn the_sweep_plan_counts_whole_pairs_and_plans_only_a_lone_index() {
    let (_dir, layout, pairs) = packed_store(&[vec![1, 2, 3], vec![4, 5, 6]]);
    let store = ObjectStore::open(&layout).unwrap();
    let (sweep, count) = store.plan_pack_leftovers(u64::MAX, 0).unwrap();
    assert_eq!(count, 2);
    assert!(sweep.is_empty());

    // Losing the pack leaves a lone index, which the sweep plans to remove.
    fs::remove_file(&pairs[1].pack).unwrap();
    let (sweep, count) = store.plan_pack_leftovers(u64::MAX, 0).unwrap();
    assert_eq!(count, 1);
    assert!(!sweep.is_empty());
}

#[test]
fn repair_leaves_healthy_pairs_alone_and_takes_no_lock_for_them() {
    let (_dir, layout, pairs) = packed_store(&[vec![1, 2, 3], vec![4, 5, 6]]);
    let store = ObjectStore::open(&layout).unwrap();
    let before: Vec<_> = pairs
        .iter()
        .map(|pair| fs::read(&pair.index).unwrap())
        .collect();
    // A busy fetch holds the shared guard: repair would fail if it tried to
    // rebuild anything, so it must repair nothing here.
    let guard = store.prune_guard().unwrap();
    assert_eq!(store.check_local_packs(true).unwrap(), 0);
    drop(guard);
    for (pair, idx) in pairs.iter().zip(&before) {
        assert_eq!(&fs::read(&pair.index).unwrap(), idx);
    }
}

#[test]
fn a_lone_pack_that_fails_verification_is_not_given_an_index() {
    let (_dir, layout, pairs) = packed_store(&[vec![1, 2, 3]]);
    fs::remove_file(&pairs[0].index).unwrap();
    let mut bytes = fs::read(&pairs[0].pack).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(&pairs[0].pack, bytes).unwrap();

    let store = ObjectStore::open(&layout).unwrap();
    assert!(store.check_local_packs(true).is_err());
    assert!(!pairs[0].index.exists());
}

fn flip_middle_byte(path: &std::path::Path) {
    let mut bytes = fs::read(path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(path, bytes).unwrap();
}

#[test]
fn one_damaged_pair_does_not_stop_repair_of_the_others() {
    // Directory order is not fixed, so each pair takes a turn as the damaged one.
    for damaged in 0..3 {
        let (_dir, layout, pairs) = packed_store(&[vec![1], vec![2], vec![3]]);
        let indexes: Vec<_> = pairs
            .iter()
            .map(|pair| fs::read(&pair.index).unwrap())
            .collect();
        for (n, pair) in pairs.iter().enumerate() {
            if n != damaged {
                fs::write(&pair.index, b"damaged").unwrap();
            }
        }
        flip_middle_byte(&pairs[damaged].pack);
        let broken_pack = fs::read(&pairs[damaged].pack).unwrap();

        let store = ObjectStore::open(&layout).unwrap();
        let error = store.check_local_packs(true).unwrap_err();
        assert!(
            matches!(error, StoreError::LocalPackDamaged { .. }),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains(&pairs[damaged].pack.display().to_string()),
            "{error}"
        );
        for (n, pair) in pairs.iter().enumerate() {
            if n != damaged {
                assert_eq!(fs::read(&pair.index).unwrap(), indexes[n], "pair {n}");
            }
        }
        assert_eq!(fs::read(&pairs[damaged].pack).unwrap(), broken_pack);
        assert_eq!(fs::read(&pairs[damaged].index).unwrap(), indexes[damaged]);
    }
}

#[test]
fn a_damaged_live_pair_does_not_hide_a_damaged_lone_pack() {
    let (_dir, layout, pairs) = packed_store(&[vec![1], vec![2], vec![3]]);
    fs::remove_file(&pairs[0].index).unwrap();
    flip_middle_byte(&pairs[0].pack);
    flip_middle_byte(&pairs[1].pack);
    let healthy = fs::read(&pairs[2].index).unwrap();
    fs::write(&pairs[2].index, b"damaged").unwrap();

    let store = ObjectStore::open(&layout).unwrap();
    let error = store.check_local_packs(true).unwrap_err();
    let text = error.to_string();
    assert!(
        matches!(error, StoreError::LocalPackDamaged { .. }),
        "{text}"
    );
    for damaged in &pairs[..2] {
        assert!(
            text.contains(&damaged.pack.display().to_string()),
            "{text}"
        );
    }
    assert!(!pairs[0].index.exists());
    assert_eq!(fs::read(&pairs[2].index).unwrap(), healthy);

    // Without repair, the damaged live pair still shows.
    let error = store.check_local_packs(false).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&pairs[1].pack.display().to_string()),
        "{error}"
    );
}

#[test]
fn a_flipped_payload_byte_names_the_local_pack() {
    let (_dir, _layout, store) = fresh();
    let bytes = blob(b"pack damage");
    let mut w = writer(&store);
    let id = w.write(&bytes).unwrap();
    let (staged, _guard) = w.stage().unwrap();
    let pair = staged.pair.clone();
    staged.publish(&store).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&pair.pack).unwrap();
    file.seek(SeekFrom::Start(12 + 5 + 10)).unwrap();
    file.write_all(b"x").unwrap();

    let named = pair.pack.display().to_string();
    for error in [
        store.read(&id).unwrap_err(),
        store.read_object(&id).unwrap_err(),
        store.read_unverified(&id).unwrap_err(),
    ] {
        match &error {
            StoreError::HashMismatch { pack, .. } => {
                assert_eq!(pack.as_deref(), Some(named.as_str()));
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        assert!(error.to_string().contains(&named), "{error}");
    }
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
fn the_writer_limits_are_the_ones_the_spec_states() {
    // SPEC-OBJECTS §10.1: 65,536 entries and 64 MiB of payload per pack, for
    // the batch, fetch windows and gc outputs alike.
    assert_eq!(super::PACK_SEAL_ENTRIES, 65_536);
    assert_eq!(super::PACK_SEAL_BYTES, 64 << 20);
    assert_eq!(super::copy::OUTPUT_ENTRIES, super::PACK_SEAL_ENTRIES);
    assert_eq!(super::copy::OUTPUT_PAYLOAD, super::PACK_SEAL_BYTES as u64);
}

#[test]
fn rolls_over_at_count_and_payload_caps() {
    for (max_entries, max_payload) in [(1, 1024), (2, 12)] {
        let (_dir, _layout, store) = fresh();
        let mut writer = PackFixture::new(&store, max_entries, max_payload).unwrap();
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
    let store = ObjectStore::init_loose(&layout).unwrap();
    let other = ObjectStore::init_loose(&RepoLayout::single(b.path())).unwrap();

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

pub(super) fn publish_objects(store: &ObjectStore, objects: &[&[u8]]) -> (Pair, Vec<Hash>) {
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

pub(super) fn set_pack_age(path: &std::path::Path, secs: u64) {
    fs::File::open(path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
        .unwrap();
}

#[test]
fn gc_counts_packed_payload_and_retires_only_wholly_dead_old_packs() {
    use crate::ops::gc::run_gc;

    let (_dir, layout, store) = fresh();
    let (live, live_ids) = publish_objects(&store, &[&blob(b"live pack")]);
    // Dead bytes stay under a quarter of the pack, so only the wholly dead
    // retirement applies here.
    let mixed_live = blob(&[b'l'; 200]);
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

    let preview = run_gc(&store, &layout, 10, 5, true, &mut |_, _, _| {}).unwrap();
    assert_eq!(
        preview.wholly_dead_bytes,
        (dead.len() + recent.len()) as u64
    );
    assert_eq!(preview.mixed_dead_bytes, mixed_dead.len() as u64);
    assert_eq!(
        preview.eligible_dead_bytes,
        (dead.len() + mixed_dead.len()) as u64
    );
    assert_eq!(preview.survivor_bytes, mixed_live.len() as u64);
    assert_eq!(preview.packs_retired, 1);
    assert!(old.pack.exists() && old.index.exists());

    crate::durable::testing::reset_dir_sync_calls();
    let report = run_gc(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
    assert_eq!(report.packs_retired, 1);
    assert_eq!(crate::durable::testing::dir_sync_calls(), 2);
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
    use crate::ops::gc::run_gc;

    let (_dir, layout, store) = fresh();
    let (old, ids) = publish_objects(&store, &[&blob(b"reused object")]);
    set_pack_age(&old.pack, 1);
    let h = ids[0];
    let mut fresh_pack = None;
    let packed = run_gc(
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
    run_gc(&store, &layout, u64::MAX, 0, false, &mut |_, _, _| {}).unwrap();
    assert!(pair.pack.exists() && pair.index.exists());
    drop(guard);
    run_gc(&store, &layout, u64::MAX, 0, false, &mut |_, _, _| {}).unwrap();
    assert!(!pair.pack.exists() && !pair.index.exists());
}

#[test]
fn gc_sweeps_only_aged_recognized_pack_leftovers() {
    use crate::ops::gc::run_gc;

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
    assert_eq!(store.check_local_packs(false).unwrap(), 0);

    let expected_bytes: u64 = [&retired.index, &unpublished.pack, &staging]
        .iter()
        .map(|path| fs::metadata(path).unwrap().len())
        .sum();
    let preview_totals = run_gc(&store, &layout, 10, 5, true, &mut |_, _, _| {}).unwrap();
    assert_eq!(preview_totals.pack_leftovers_pruned, 3);
    assert_eq!(preview_totals.bytes_reclaimed, expected_bytes);
    assert!(retired.index.exists());
    crate::durable::testing::reset_dir_sync_calls();
    let totals = run_gc(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
    assert_eq!(totals.pack_leftovers_pruned, 3);
    assert_eq!(totals.bytes_reclaimed, expected_bytes);
    assert_eq!(crate::durable::testing::dir_sync_calls(), 2);
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
        assert!(run_gc(&store, &layout, u64::MAX, 0, dry_run, &mut |_, _, _| {}).is_err());
        assert!(store.path_for(&loose).exists());
        assert!(pair.pack.exists() && pair.index.exists());
    }
}

#[test]
fn a_retirement_interrupted_after_the_pack_sync_leaves_only_the_index() {
    use crate::ops::gc::{GcReport, LiveSet, maintain_packs};

    let (_dir, layout, store) = fresh();
    let _ = maintain_packs(&layout, &store, &|| false);
    let (pair, ids) = publish_objects(&store, &[&blob(b"retirement crash point")]);
    set_pack_age(&pair.index, 1);
    let mut report = GcReport::default();
    let sweep = store
        .plan_pack_sweep(&LiveSet::default(), u64::MAX, 0, &mut report)
        .unwrap();
    crate::durable::testing::reset_dir_sync_calls();
    let result = sweep.run_with(&store, &mut report, || {
        assert!(!pair.pack.exists());
        assert!(pair.index.is_file());
        assert_eq!(crate::durable::testing::dir_sync_calls(), 1);
        Err(std::io::Error::other("interrupted between pack and index removal").into())
    });
    assert!(result.is_err());

    let reopened = ObjectStore::open(&layout).unwrap();
    assert!(!reopened.contains(&ids[0]));
    assert_eq!(reopened.check_local_packs(true).unwrap(), 0);
    assert_eq!(
        maintain_packs(&layout, &reopened, &|| false).leftovers_removed,
        1
    );
    assert!(!pair.pack.exists() && !pair.index.exists());
}

#[test]
fn gc_drops_only_loose_duplicates_that_have_verified_packed_replacements() {
    use crate::ops::gc::run_gc;

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
        let preview_totals = run_gc(&store, &layout, 10, 5, true, &mut |_, _, _| {}).unwrap();
        assert_eq!(
            preview_totals.loose_duplicates_pruned,
            usize::from(!keep),
            "{label}"
        );
        assert_eq!(preview_totals.bytes_reclaimed, expected_bytes, "{label}");
        assert!(loose.is_file());
        let guard = store.prune_guard().unwrap();
        let blocked = run_gc(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
        assert_eq!(blocked.loose_duplicates_pruned, 0);
        assert!(loose.is_file());
        drop(guard);
        crate::durable::testing::reset_dir_sync_calls();
        let totals = run_gc(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
        assert_eq!(
            totals.loose_duplicates_pruned,
            usize::from(!keep),
            "{label}"
        );
        assert_eq!(loose.is_file(), keep, "{label}");
        assert_eq!(totals.bytes_reclaimed, expected_bytes, "{label}");
        assert_eq!(
            crate::durable::testing::dir_sync_calls(),
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
        run_gc(&gc, &layout, u64::MAX, 0, false, &mut |_, _, _| {}).unwrap();
        assert!(child_pack.pack.is_file());
        assert!(gc.read(&children[0]).is_ok());
    }
}

#[test]
fn gc_preserves_a_pair_whose_missing_member_reappears_before_the_try_lock() {
    use crate::ops::gc::run_gc;

    let (_dir, layout, store) = fresh();
    let bytes = blob(b"same-key publication");
    let (pair, ids) = publish_objects(&store, &[&bytes]);
    fs::remove_file(&pair.pack).unwrap();
    let mut republished = false;
    let packed = run_gc(
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
    use crate::ops::gc::run_gc;

    let (_dir, layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"changed index inode")]);
    set_pack_age(&pair.index, 1);
    let mut replaced = false;
    let packed = run_gc(
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
    use crate::ops::gc::run_gc;

    let (_dir, layout, store) = fresh();
    let (damaged, _) = publish_objects(&store, &[&blob(b"damaged dead pack")]);
    let (good, _) = publish_objects(&store, &[&blob(b"verified dead pack")]);
    let loose = store.write(&blob(b"unrelated loose garbage")).unwrap();
    let mut bytes = fs::read(&damaged.pack).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&damaged.pack, bytes).unwrap();

    for dry_run in [true, false] {
        let report = run_gc(&store, &layout, u64::MAX, 0, dry_run, &mut |_, _, _| {}).unwrap();
        assert_eq!(report.skipped_pack_errors.len(), 1);
        assert!(report.skipped_pack_errors[0].contains("invalid pack trailer"));
        assert_eq!(report.packs_retired, 1);
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
    use crate::ops::gc::run_gc;

    let (_dir, layout, store) = fresh();
    let bytes = blob(b"recent dead duplicate");
    let h = store.write(&bytes).unwrap();
    let loose = store.path_for(&h);
    let (pair, _) = publish_objects(&store, &[&bytes]);
    set_pack_age(&loose, 8);
    set_pack_age(&pair.pack, 9);

    for dry_run in [true, false] {
        let report = run_gc(&store, &layout, 10, 5, dry_run, &mut |_, _, _| {}).unwrap();
        assert_eq!(report.kept_recent, 0);
        assert_eq!(report.loose_duplicates_pruned, 1);
        assert_eq!(loose.exists(), dry_run);
        assert_eq!(store.read(&h).unwrap(), bytes);
    }
}

#[test]
fn gc_previews_each_loose_duplicate_once_when_two_packs_hold_it() {
    use crate::ops::gc::run_gc;

    let (_dir, layout, store) = fresh();
    let live = blob(b"shared packed object");
    let id = store.write(&live).unwrap();
    crate::refs::write_ref(&layout, "live", &id).unwrap();
    publish_objects(&store, &[&live, &blob(b"first extra entry")]);
    publish_objects(&store, &[&live, &blob(b"second extra entry")]);

    let report = run_gc(&store, &layout, u64::MAX, 0, true, &mut |_, _, _| {}).unwrap();
    assert_eq!(report.packs_retired, 0);
    assert_eq!(report.loose_duplicates_pruned, 1);
    // The preview also counts what rewriting the two packs would reclaim.
    assert!(report.bytes_reclaimed >= live.len() as u64);
    assert!(store.path_for(&id).exists());
}

type AfterCopy = Box<dyn FnOnce() -> crate::store::StoreResult<()>>;
type AfterBatch = Box<dyn FnMut(usize) -> crate::store::StoreResult<()>>;

thread_local! {
    static RETIRE_BATCH: std::cell::Cell<Option<(usize, u64)>> = const { std::cell::Cell::new(None) };
    static AFTER_RETIRE_BATCH: std::cell::RefCell<Option<AfterBatch>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_COPY_PUBLISH: std::cell::Cell<Option<AfterCopy>> =
        const { std::cell::Cell::new(None) };
    static IO_LOG: std::cell::RefCell<Option<Vec<(&'static str, std::path::PathBuf)>>> =
        const { std::cell::RefCell::new(None) };
    static BEFORE_DUPLICATE_TRY_LOCK: std::cell::Cell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::Cell::new(None) };
    static PACK_SCAN_ERROR: std::cell::Cell<Option<(Hash, std::io::ErrorKind)>> =
        const { std::cell::Cell::new(None) };
}

/// Test override of the batch limits; reset when the guard drops.
pub(super) struct RetireBatch;

pub(super) fn set_retire_batch(size: usize) -> RetireBatch {
    set_retire_batch_limits(size, super::gc::RETIRE_BATCH_BYTES)
}

pub(super) fn set_retire_batch_limits(size: usize, bytes: u64) -> RetireBatch {
    RETIRE_BATCH.set(Some((size, bytes)));
    RetireBatch
}

impl Drop for RetireBatch {
    fn drop(&mut self) {
        RETIRE_BATCH.set(None);
        AFTER_RETIRE_BATCH.with(|hook| *hook.borrow_mut() = None);
    }
}

pub(super) fn retire_batch() -> Option<(usize, u64)> {
    RETIRE_BATCH.get()
}

/// Runs after each batch released the exclusive lock, with the number of
/// batches done so far. An error stands for a crash.
pub(super) fn after_retire_batch(done: usize) -> crate::store::StoreResult<()> {
    AFTER_RETIRE_BATCH.with(|hook| match hook.borrow_mut().as_mut() {
        Some(hook) => hook(done),
        None => Ok(()),
    })
}

pub(super) fn set_after_retire_batch(
    hook: impl FnMut(usize) -> crate::store::StoreResult<()> + 'static,
) {
    AFTER_RETIRE_BATCH.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Runs after copy-then-retire published its outputs and dropped the shared
/// guard, before the exclusive try. An error stands for a crash.
pub(super) fn after_copy_publish() -> crate::store::StoreResult<()> {
    match AFTER_COPY_PUBLISH.take() {
        Some(hook) => hook(),
        None => Ok(()),
    }
}

pub(super) fn set_after_copy_publish(
    hook: impl FnOnce() -> crate::store::StoreResult<()> + 'static,
) {
    AFTER_COPY_PUBLISH.set(Some(Box::new(hook)));
}

pub(super) fn record_io() {
    IO_LOG.with(|log| *log.borrow_mut() = Some(Vec::new()));
}

pub(super) fn take_io() -> Vec<(&'static str, std::path::PathBuf)> {
    IO_LOG.with(|log| log.borrow_mut().take().unwrap_or_default())
}

/// Record a flush or unlink of the retirement section while a test records.
pub(super) fn note_io(kind: &'static str, path: &std::path::Path) {
    IO_LOG.with(|log| {
        if let Some(log) = log.borrow_mut().as_mut() {
            log.push((kind, path.to_path_buf()));
        }
    });
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
    use crate::ops::gc::run_gc;

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

        let report = run_gc(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
        assert!(BEFORE_DUPLICATE_TRY_LOCK.take().is_none());
        assert_eq!(report.loose_duplicates_pruned, 0, "{member} changed");
        assert_eq!(report.bytes_reclaimed, 0, "{member} changed");
        assert_eq!(fs::read(loose).unwrap(), bytes, "{member} changed");
    }
}

/// A pair that packs five live objects whose loose copies are duplicates.
fn five_loose_duplicates() -> (
    tempfile::TempDir,
    RepoLayout,
    ObjectStore,
    Vec<(Hash, Vec<u8>)>,
) {
    let (dir, layout, store) = fresh();
    let objects: Vec<_> = (0..5)
        .map(|n| {
            let bytes = blob(format!("loose duplicate {n}").as_bytes());
            let id = store.write(&bytes).unwrap();
            crate::refs::write_ref(&layout, &format!("live{n}"), &id).unwrap();
            set_pack_age(&store.path_for(&id), 8);
            (id, bytes)
        })
        .collect();
    let bytes: Vec<&[u8]> = objects.iter().map(|(_, bytes)| bytes.as_slice()).collect();
    let (pair, _) = publish_objects(&store, &bytes);
    set_pack_age(&pair.pack, 9);
    set_pack_age(&pair.index, 1);
    (dir, layout, store, objects)
}

#[test]
fn dropping_loose_duplicates_takes_the_lock_in_batches_and_counts_the_holds() {
    use crate::ops::gc::run_gc;

    let (_dir, layout, store, objects) = five_loose_duplicates();
    let _batch = set_retire_batch(2);
    let loose = |objects: &[(Hash, Vec<u8>)]| {
        objects
            .iter()
            .filter(|(id, _)| store.path_for(id).exists())
            .count()
    };
    let lock_path = store.format_path();
    let objects_for_hook = objects.clone();
    let root = store.objects_root().to_path_buf();
    set_after_retire_batch(move |done| {
        // The exclusive lock is free between batches, and each batch dropped
        // at most two copies.
        let file = fs::File::open(&lock_path).unwrap();
        assert!(file.try_lock().is_ok(), "batch {done} kept the lock");
        let left = objects_for_hook
            .iter()
            .filter(|(id, _)| {
                let hex = crate::hash::to_hex(id);
                root.join(&hex[..2]).join(&hex[2..]).exists()
            })
            .count();
        assert_eq!(left, 5_usize.saturating_sub(2 * done), "batch {done}");
        Ok(())
    });

    let report = run_gc(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
    assert_eq!(report.loose_duplicates_pruned, 5);
    assert_eq!(report.retire_batches, 3, "two, two and one");
    assert_eq!(loose(&objects), 0);
    for (id, bytes) in &objects {
        assert_eq!(&store.read(id).unwrap(), bytes);
    }
}

#[test]
fn checking_the_buckets_of_a_short_fanout_reports_damage() {
    use super::reader::check_buckets;

    let fanout = |ends: &dyn Fn(usize) -> u32| -> Vec<u8> {
        (0..256)
            .flat_map(|shard| ends(shard).to_le_bytes())
            .collect()
    };
    // Every bucket ends at 2 rows: ids that start with 0 fit, others do not.
    let whole = fanout(&|_| 2);
    check_buckets(&whole, [0, 0].into_iter()).unwrap();
    assert!(check_buckets(&whole, [0, 1].into_iter()).is_err());
    // No bucket reaches the first row: damage, with no bucket left to read.
    let short = fanout(&|_| 0);
    assert!(check_buckets(&short, [0].into_iter()).is_err());
}

#[test]
fn a_batch_of_loose_duplicates_stops_at_its_byte_cap() {
    use crate::ops::gc::run_gc;

    let (_dir, layout, store, objects) = five_loose_duplicates();
    let largest = objects
        .iter()
        .map(|(id, _)| fs::metadata(store.path_for(id)).unwrap().len())
        .max()
        .unwrap();
    // Room for one copy but never for two, whatever the count limit: each
    // batch takes its first copy and stops there.
    let _batch = set_retire_batch_limits(32, largest);

    let report = run_gc(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
    assert_eq!(report.loose_duplicates_pruned, 5);
    assert_eq!(report.retire_batches, 5, "one copy per batch");
}

#[test]
fn a_crash_between_loose_duplicate_batches_loses_nothing() {
    use crate::ops::gc::run_gc;

    let (_dir, layout, store, objects) = five_loose_duplicates();
    let batch = set_retire_batch(2);
    set_after_retire_batch(|done| {
        if done == 1 {
            Err(std::io::Error::other("crash after the first batch").into())
        } else {
            Ok(())
        }
    });

    assert!(run_gc(&store, &layout, 10, 5, false, &mut |_, _, _| {}).is_err());
    let left = objects
        .iter()
        .filter(|(id, _)| store.path_for(id).exists())
        .count();
    assert_eq!(left, 3, "only the first batch dropped its copies");
    for (id, bytes) in &objects {
        assert_eq!(&store.read(id).unwrap(), bytes);
    }
    // The next run drops the rest.
    drop(batch);
    let report = run_gc(&store, &layout, 10, 5, false, &mut |_, _, _| {}).unwrap();
    assert_eq!(report.loose_duplicates_pruned, 3);
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

    let result = run_gc(&store, &layout, u64::MAX, 0, false, &mut |_, _, _| {});
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
    let handles = &reader.packs.handles;
    assert!(handles.limit() >= super::reader::HANDLE_FLOOR);
    assert_eq!(handles.cached(), objects.len().min(handles.limit()));
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

        let mut replacement = PackFixture::new(&store, MAX_ENTRIES, MAX_TOTAL_PAYLOAD).unwrap();
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
    let catalog =
        super::Catalog::from_packs(vec![std::sync::Arc::clone(&locator)], Vec::new(), false);
    let routes: Vec<_> = catalog.candidates(&id).collect();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].1, Some(0));
    let mut absent = id;
    absent[0] ^= 1;
    assert_ne!(prefix(&absent), prefix(&id));
    assert!(catalog.candidates(&absent).next().is_none());
    let handles = Handles::default();
    assert!(
        locator
            .find(&handles, &id, routes[0].1, None)
            .unwrap()
            .is_some()
    );
    let mut different = id;
    different[31] ^= 1;
    assert!(
        locator
            .find(&handles, &different, routes[0].1, None)
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
    let mut writer = PackFixture::new(&store, MAX_ENTRIES, MAX_TOTAL_PAYLOAD).unwrap();
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
        let catalog = super::Catalog::from_packs(vec![Arc::clone(&locator)], Vec::new(), false);
        let handles = Handles::default();
        for id in &ids {
            let frames: Vec<_> = catalog
                .candidates(id)
                .filter_map(|(pack, row)| pack.find(&handles, id, row, None).unwrap())
                .collect();
            assert_eq!(frames, [strict.find(id).unwrap()]);
        }
        for first in 0..=u8::MAX {
            for trailing in [0, u8::MAX] {
                let mut absent = [trailing; 32];
                absent[0] = first;
                assert!(
                    catalog.candidates(&absent).all(|(pack, row)| pack
                        .find(&handles, &absent, row, None)
                        .unwrap()
                        .is_none())
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
fn concurrent_probes_of_one_uncached_pack_end_with_one_cached_handle() {
    use std::sync::{Arc, Barrier};

    use super::reader::{Handles, Locator, Member};

    const THREADS: usize = 16;
    let (_dir, _layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"racing probes")]);
    let locator = Arc::new(Locator::open(&pair, 0, 0).unwrap());
    for _ in 0..20 {
        let handles = Handles::default();
        let barrier = Barrier::new(THREADS);
        let got: Vec<_> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        handles.get(&locator, Member::Pack).unwrap()
                    })
                })
                .collect();
            workers.into_iter().map(|w| w.join().unwrap()).collect()
        });
        assert_eq!(handles.cached(), 1);
        assert!((1..=THREADS).contains(&handles.opens()));
        let cached = handles.get(&locator, Member::Pack).unwrap();
        assert!(got.iter().all(|h| Arc::ptr_eq(h, &cached)));
    }
}

#[test]
fn a_probe_that_loses_the_open_race_keeps_the_cached_handle() {
    use std::sync::Arc;

    use super::reader::{Handles, Locator, Member};

    let (_dir, _layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"lost open race")]);
    let locator = Arc::new(Locator::open(&pair, 0, 0).unwrap());
    let handles = Handles::default();
    let winner = Arc::new(std::sync::Mutex::new(None));
    let slot = Arc::clone(&winner);
    let rival = Arc::clone(&locator);
    handles.once_after_open(move |handles| {
        *slot.lock().unwrap() = Some(handles.get(&rival, Member::Pack).unwrap());
    });
    let loser = handles.get(&locator, Member::Pack).unwrap();
    let winner = winner.lock().unwrap().take().unwrap();
    assert!(Arc::ptr_eq(&loser, &winner));
    assert_eq!(handles.cached(), 1);
    assert_eq!(handles.opens(), 2);
}

#[cfg(unix)]
#[test]
fn a_pack_retired_during_an_open_is_not_cached() {
    use std::io::Read;
    use std::sync::Arc;

    use super::reader::{Handles, Locator, Member};

    let (_dir, _layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"retired during open")]);
    let locator = Arc::new(Locator::open(&pair, 0, 0).unwrap());
    let handles = Handles::default();
    let retired = Arc::clone(&locator);
    handles.once_after_open(move |handles| {
        handles.retain(|candidate| !Arc::ptr_eq(candidate, &retired));
        fs::remove_file(&retired.pair.pack).unwrap();
    });
    // The caller still gets a handle to the file it opened and checked.
    let handle = handles.get(&locator, Member::Pack).unwrap();
    let mut magic = [0; 4];
    let mut file = &*handle;
    file.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, crate::pack::MAGIC);
    // Nothing keeps the deleted file open, and a later probe sees it gone.
    assert_eq!(handles.cached(), 0);
    assert!(matches!(
        handles.get(&locator, Member::Pack),
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
}

#[cfg(unix)]
#[test]
fn a_pack_replaced_before_its_open_is_absent_and_is_not_cached() {
    use std::sync::Arc;

    use super::reader::{Handles, Locator, Member};

    let (_dir, _layout, store) = fresh();
    let (pair, _) = publish_objects(&store, &[&blob(b"replaced before open")]);
    let locator = Arc::new(Locator::open(&pair, 0, 0).unwrap());
    let handles = Handles::default();
    let bytes = fs::read(&pair.pack).unwrap();
    let replacement = tempfile::NamedTempFile::new_in(store.pack_dir()).unwrap();
    fs::write(replacement.path(), bytes).unwrap();
    replacement.persist(&pair.pack).unwrap();
    assert!(matches!(
        handles.get(&locator, Member::Pack),
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert_eq!(handles.cached(), 0);
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
        Err(StoreError::LocalPackDamaged { .. })
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
    assert!(!second.errors.is_empty());
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

/// A ref that names a manifest of `chunks`.
pub(super) fn manifest_root(
    store: &ObjectStore,
    layout: &RepoLayout,
    name: &str,
    chunks: &[Hash],
) -> Hash {
    let manifest = serialize(&Object::ChunkedBlob(
        crate::object::testing::spread(chunks.len() as u64, 0, chunks.to_vec()).unwrap(),
    ))
    .unwrap();
    let root = store.write(&manifest).unwrap();
    crate::refs::write_ref(layout, name, &root).unwrap();
    root
}

/// Change one byte of an object's frame, `at` bytes into its bytes.
pub(super) fn damage_frame(pair: &Pair, id: &Hash, at: usize, change: impl FnOnce(&mut u8)) {
    let frame = super::Index::open(pair).unwrap().find(id).unwrap();
    let mut bytes = fs::read(&pair.pack).unwrap();
    change(&mut bytes[usize::try_from(frame.offset).unwrap() + at]);
    fs::write(&pair.pack, bytes).unwrap();
}

/// Change one byte of an object's five-byte frame header.
pub(super) fn damage_header(pair: &Pair, id: &Hash, at: usize, change: impl FnOnce(&mut u8)) {
    let frame = super::Index::open(pair).unwrap().find(id).unwrap();
    let mut bytes = fs::read(&pair.pack).unwrap();
    change(&mut bytes[usize::try_from(frame.offset).unwrap() - 5 + at]);
    fs::write(&pair.pack, bytes).unwrap();
}

#[test]
fn the_mark_checks_a_packed_chunk_by_its_head_and_hashes_none_of_it() {
    let (_dir, layout, store) = fresh();
    let (_, chunks) = publish_objects(&store, &[&blob(&[1; 4096]), &blob(&[2; 4096])]);
    let root = manifest_root(&store, &layout, "live", &chunks);

    let gc = ObjectStore::open(&layout).unwrap();
    assert!(
        chunks.iter().all(|c| !gc.path_for(c).exists()),
        "chunks are packed"
    );
    let live = crate::ops::gc::live_objects(&gc, &layout).unwrap();
    assert!(live.contains(&root) && chunks.iter().all(|c| live.contains(c)));
    assert_eq!(gc.gc_hashed_byte_count(), 0);
}

#[test]
fn a_packed_chunk_with_a_bad_payload_passes_the_mark_and_is_reported_by_the_scan() {
    let (_dir, layout, store) = fresh();
    let (pair, chunks) = publish_objects(&store, &[&blob(&[3; 4096])]);
    manifest_root(&store, &layout, "live", &chunks);
    let orphan = store.write(&blob(b"unreachable")).unwrap();
    damage_frame(&pair, &chunks[0], 10, |byte| *byte ^= 1);

    let gc = ObjectStore::open(&layout).unwrap();
    assert!(crate::ops::gc::live_objects(&gc, &layout).is_ok());
    assert!(matches!(
        gc.check_local_packs(false),
        Err(StoreError::LocalPackDamaged { .. })
    ));
    assert!(gc.read(&chunks[0]).is_err());

    // Gc runs, keeps the live pack, and removes only what nothing reaches.
    crate::ops::gc::run_gc(&gc, &layout, u64::MAX, 0, false, &mut |_, _, _| {}).unwrap();
    assert!(pair.pack.is_file() && pair.index.is_file());
    assert!(!gc.contains(&orphan));
}

#[test]
fn an_index_row_that_locates_another_kind_of_object_is_not_a_chunk() {
    use crate::object::Tree;
    use crate::ops::gc::GcRootsError;

    let (_dir, layout, store) = fresh();
    let chunk = index::canonical_id(&blob(&[4; 4096])).unwrap();
    let root = manifest_root(&store, &layout, "live", &[chunk]);
    let tree = serialize(&Object::Tree(Tree { entries: vec![] })).unwrap();
    let (decoy, ids) = publish_objects(&store, &[&tree]);
    let frame = super::Index::open(&decoy).unwrap().find(&ids[0]).unwrap();
    fs::write(&decoy.index, index::encode(decoy.key, &[(chunk, frame)])).unwrap();

    let gc = ObjectStore::open(&layout).unwrap();
    let error = crate::ops::gc::live_objects(&gc, &layout).unwrap_err();
    assert!(
        matches!(error, GcRootsError::ChunkNotBlob { chunk: c, manifest } if c == chunk && manifest == root),
        "{error:?}"
    );
}

#[test]
fn a_packed_chunk_whose_head_disagrees_with_its_frame_length_fails_the_mark() {
    use crate::ops::gc::GcRootsError;

    let (_dir, layout, store) = fresh();
    let (pair, chunks) = publish_objects(&store, &[&blob(&[5; 4096])]);
    manifest_root(&store, &layout, "live", &chunks);
    let orphan = store.write(&blob(b"kept after a failed mark")).unwrap();
    damage_frame(&pair, &chunks[0], 6, |byte| *byte ^= 1);

    let gc = ObjectStore::open(&layout).unwrap();
    let error = crate::ops::gc::live_objects(&gc, &layout).unwrap_err();
    assert!(
        matches!(&error, GcRootsError::Store(StoreError::LocalPackDamaged { reason, .. }) if reason.contains("blob header")),
        "{error:?}"
    );
    assert!(crate::ops::gc::run_gc(&gc, &layout, u64::MAX, 0, false, &mut |_, _, _| {}).is_err());
    assert!(pair.pack.is_file() && gc.contains(&orphan));
}

#[test]
fn an_id_reached_as_a_file_and_as_a_chunk_is_still_hashed() {
    use crate::object::{EntryMode, Tree, TreeEntry};
    use crate::ops::gc::GcRootsError;

    let bytes = blob(&[6; 4096]);
    for damaged in [false, true] {
        let (_dir, layout, store) = fresh();
        let (pair, ids) = publish_objects(&store, &[&bytes]);
        let tree = serialize(&Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"file".to_vec(),
                mode: EntryMode::Blob,
                object_hash: ids[0],
            }],
        }))
        .unwrap();
        let root = store.write(&tree).unwrap();
        crate::refs::write_ref(&layout, "files", &root).unwrap();
        manifest_root(&store, &layout, "chunked", &ids);
        if damaged {
            damage_frame(&pair, &ids[0], 10, |byte| *byte ^= 1);
        }

        let gc = ObjectStore::open(&layout).unwrap();
        let result = crate::ops::gc::live_objects(&gc, &layout);
        if damaged {
            assert!(
                matches!(
                    result,
                    Err(GcRootsError::Store(StoreError::HashMismatch { .. }))
                ),
                "{result:?}"
            );
        } else {
            result.unwrap();
        }
        // The file probe hashes the blob once. The chunk pass skips it.
        assert_eq!(gc.gc_hashed_byte_count(), bytes.len() as u64);
    }
}

/// A ref whose tree lists each of `ids` as a file.
fn files_root(store: &ObjectStore, layout: &RepoLayout, ids: &[Hash]) -> Hash {
    use crate::object::{EntryMode, Tree, TreeEntry};

    let entries = ids
        .iter()
        .enumerate()
        .map(|(n, id)| TreeEntry {
            name: format!("f{n}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: *id,
        })
        .collect();
    let root = store
        .write(&serialize(&Object::Tree(Tree { entries })).unwrap())
        .unwrap();
    crate::refs::write_ref(layout, "files", &root).unwrap();
    root
}

#[derive(Clone, Copy, Debug)]
enum Damage {
    None,
    Payload,
    Prologue,
    TypeTag,
    FrameHeader,
}

/// The mark of the store at `layout`, through the one-read probe or the
/// streaming probe: its result as text, and the bytes the probes hashed.
fn marked(layout: &RepoLayout, streaming: bool) -> (String, u64) {
    let gc = ObjectStore::open(layout).unwrap();
    if streaming {
        gc.gc_probe_streaming_only();
    }
    let result = crate::ops::gc::live_objects(&gc, layout);
    (format!("{result:?}"), gc.gc_hashed_byte_count())
}

#[test]
fn the_one_read_probe_marks_what_the_streaming_probe_marks() {
    let limit = crate::store::GC_SMALL_FRAME;
    // A frame is ten bytes longer than its payload. These payloads put the
    // frame below, at and above the largest frame the probe reads whole.
    for payload in [0, 1, 4096, limit - 11, limit - 10, limit - 9, 3 * limit] {
        for as_chunk in [false, true] {
            for damage in [
                Damage::None,
                Damage::Payload,
                Damage::Prologue,
                Damage::TypeTag,
                Damage::FrameHeader,
            ] {
                if payload == 0 && matches!(damage, Damage::Payload) {
                    continue;
                }
                let (_dir, layout, store) = fresh();
                let bytes = blob(&vec![0x5a; payload]);
                let (pair, ids) = publish_objects(&store, &[&bytes]);
                if as_chunk {
                    manifest_root(&store, &layout, "chunked", &ids);
                } else {
                    files_root(&store, &layout, &ids);
                }
                match damage {
                    Damage::None => {}
                    Damage::Payload => damage_frame(&pair, &ids[0], 10 + payload / 2, |b| *b ^= 1),
                    Damage::Prologue => damage_frame(&pair, &ids[0], 6, |b| *b ^= 1),
                    Damage::TypeTag => damage_frame(&pair, &ids[0], 0, |b| *b = 0xee),
                    Damage::FrameHeader => damage_header(&pair, &ids[0], 1, |b| *b ^= 1),
                }

                let streamed = marked(&layout, true);
                let one_read = marked(&layout, false);
                let case = format!("payload {payload}, chunk {as_chunk}, {damage:?}");
                assert_eq!(one_read, streamed, "{case}");
                // A chunk is checked by its head only, so a bad payload passes.
                let passes = matches!(damage, Damage::None)
                    || (as_chunk && matches!(damage, Damage::Payload));
                assert_eq!(
                    streamed.0.starts_with("Ok("),
                    passes,
                    "{case}: {}",
                    streamed.0
                );
            }
        }
    }
}

#[test]
fn the_one_read_probe_answers_a_head_of_any_size_and_a_whole_frame_up_to_its_limit() {
    let limit = crate::store::GC_SMALL_FRAME;
    // A frame is ten bytes longer than its payload. 4096 is a fixed size, so
    // that a limit changed to another value moves the answer.
    for payload in [0, 1, 4096, limit - 11, limit - 10, limit - 9, 3 * limit] {
        for as_chunk in [false, true] {
            let (_dir, layout, store) = fresh();
            let bytes = blob(&vec![0x33; payload]);
            let (_, ids) = publish_objects(&store, &[&bytes]);
            if as_chunk {
                manifest_root(&store, &layout, "chunked", &ids);
            } else {
                files_root(&store, &layout, &ids);
            }

            let gc = ObjectStore::open(&layout).unwrap();
            crate::ops::gc::live_objects(&gc, &layout).unwrap();
            // A chunk is probed by its head, so its frame is never too large.
            // A file is hashed, so its frame is read whole only up to 16 KiB.
            let whole = payload + 10 <= 16 * 1024;
            let expected = u64::from(as_chunk || whole);
            assert_eq!(
                gc.gc_one_read_probe_count(),
                expected,
                "payload {payload}, chunk {as_chunk}"
            );
        }
    }
}

#[test]
fn a_packed_blob_above_the_one_read_limit_is_hashed_by_streaming() {
    let limit = crate::store::GC_SMALL_FRAME;
    for payload in [limit - 10, limit - 9] {
        let (_dir, layout, store) = fresh();
        let bytes = blob(&vec![7; payload]);
        let (_, ids) = publish_objects(&store, &[&bytes]);
        files_root(&store, &layout, &ids);

        let gc = ObjectStore::open(&layout).unwrap();
        crate::ops::gc::live_objects(&gc, &layout).unwrap();
        assert_eq!(gc.gc_hashed_byte_count(), bytes.len() as u64);
    }
}

#[test]
fn a_delta_frame_in_a_local_pack_stops_the_mark_through_either_probe() {
    for as_chunk in [false, true] {
        let (_dir, layout, store) = fresh();
        let (pair, ids) = publish_objects(&store, &[&blob(&[9; 64])]);
        if as_chunk {
            manifest_root(&store, &layout, "chunked", &ids);
        } else {
            files_root(&store, &layout, &ids);
        }
        // The type byte now names a delta, which a local pack never holds.
        damage_frame(&pair, &ids[0], 0, |b| *b = 0x06);

        let streamed = marked(&layout, true);
        let one_read = marked(&layout, false);
        assert_eq!(one_read, streamed, "chunk {as_chunk}");
        assert!(
            one_read.0.contains("delta object in local pack"),
            "chunk {as_chunk}: {}",
            one_read.0
        );
    }
}

#[test]
fn the_one_read_probe_marks_non_blob_frames_as_the_streaming_probe_does() {
    use crate::object::{EntryMode, Tree, TreeEntry};

    // A tree is probed by its type and read afterwards. The frame is small
    // enough to arrive whole, and no byte of it counts as hashed by the probe.
    let (_dir, layout, store) = fresh();
    let (_, ids) = publish_objects(&store, &[&blob(b"inner")]);
    let inner = serialize(&Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"leaf".to_vec(),
            mode: EntryMode::Blob,
            object_hash: ids[0],
        }],
    }))
    .unwrap();
    let (_, trees) = publish_objects(&store, &[&inner]);
    let outer = serialize(&Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"dir".to_vec(),
            mode: EntryMode::Tree,
            object_hash: trees[0],
        }],
    }))
    .unwrap();
    let root = store.write(&outer).unwrap();
    crate::refs::write_ref(&layout, "nested", &root).unwrap();

    let streamed = marked(&layout, true);
    let one_read = marked(&layout, false);
    assert_eq!(one_read, streamed);
    assert!(one_read.0.starts_with("Ok("), "{}", one_read.0);
}

#[cfg(unix)]
#[test]
fn the_handle_limit_is_a_quarter_of_the_open_file_limit_within_its_bounds() {
    use super::reader::{HANDLE_CEILING, HANDLE_FLOOR, handle_limit_for};

    assert_eq!(handle_limit_for(0), HANDLE_FLOOR);
    assert_eq!(handle_limit_for(256), HANDLE_FLOOR);
    assert_eq!(handle_limit_for(1024), 256);
    assert_eq!(handle_limit_for(2048), 512);
    assert_eq!(handle_limit_for(1 << 20), HANDLE_CEILING);
    assert_eq!(handle_limit_for(u64::MAX), HANDLE_CEILING);
}

#[test]
fn a_full_handle_cache_drops_the_least_recently_used_file() {
    use std::sync::Arc;

    use super::reader::{Handles, Locator, Member};

    let (_dir, _layout, store) = fresh();
    let locators: Vec<_> = (0..3_u8)
        .map(|n| {
            let (pair, _) = publish_objects(&store, &[&blob(&[n; 64])]);
            Arc::new(Locator::open(&pair, 0, 0).unwrap())
        })
        .collect();
    let handles = Handles::limited(2);
    let a = handles.get(&locators[0], Member::Pack).unwrap();
    let b = handles.get(&locators[1], Member::Pack).unwrap();
    // A is used again, so B is the least recently used.
    assert!(Arc::ptr_eq(
        &a,
        &handles.get(&locators[0], Member::Pack).unwrap()
    ));
    assert_eq!(handles.opens(), 2);

    handles.get(&locators[2], Member::Pack).unwrap();
    assert_eq!(handles.cached(), 2);
    assert_eq!(Arc::strong_count(&b), 1, "the cache let go of B");
    assert!(Arc::ptr_eq(
        &a,
        &handles.get(&locators[0], Member::Pack).unwrap()
    ));
    assert_eq!(handles.opens(), 3);

    let reopened = handles.get(&locators[1], Member::Pack).unwrap();
    assert!(!Arc::ptr_eq(&b, &reopened));
    assert_eq!(handles.opens(), 4);
    assert_eq!(handles.cached(), 2);
}

#[test]
fn each_use_of_a_cached_file_makes_it_newer_than_every_use_before() {
    use std::sync::Arc;

    use super::reader::{Handles, Locator, Member};

    let (_dir, _layout, store) = fresh();
    let locators: Vec<_> = (0..2_u8)
        .map(|n| {
            let (pair, _) = publish_objects(&store, &[&blob(&[n; 64])]);
            Arc::new(Locator::open(&pair, 0, 0).unwrap())
        })
        .collect();
    let handles = Handles::limited(8);
    let used = |n: usize| handles.used(&locators[n], Member::Pack).unwrap();

    handles.get(&locators[0], Member::Pack).unwrap();
    let first = used(0);
    handles.get(&locators[1], Member::Pack).unwrap();
    let second = used(1);
    assert!(second > first, "a file opened later is newer");

    handles.get(&locators[0], Member::Pack).unwrap();
    assert!(used(0) > second, "a hit makes the file the newest");
    assert_eq!(used(1), second, "and leaves the others as they were");
    assert_eq!(handles.used(&locators[0], Member::Index), None);
}

pub(super) fn cut_pack_short(pair: &Pair) {
    let cut = fs::metadata(&pair.pack).unwrap().len() - 100;
    fs::OpenOptions::new()
        .write(true)
        .open(&pair.pack)
        .unwrap()
        .set_len(cut)
        .unwrap();
}

#[test]
fn a_pack_cut_short_before_a_read_is_damage_on_every_read_path() {
    let (_dir, layout, store) = fresh();
    let bytes = blob(&[7; 4096]);
    let (pair, ids) = publish_objects(&store, &[&bytes]);
    let reader = ObjectStore::open(&layout).unwrap();
    assert_eq!(reader.read(&ids[0]).unwrap(), bytes);
    cut_pack_short(&pair);

    for error in [
        reader.read(&ids[0]).unwrap_err(),
        reader.read_unverified(&ids[0]).unwrap_err(),
        reader
            .read_with_allocator::<StoreError>(&ids[0], |size| Ok(Vec::with_capacity(size)))
            .unwrap_err(),
        reader.read_object(&ids[0]).unwrap_err(),
    ] {
        assert!(
            matches!(&error, StoreError::LocalPackDamaged { pack, .. } if **pack == *pair.pack.display().to_string()),
            "{error:?}"
        );
    }
}

#[test]
fn a_pack_cut_short_after_its_handle_is_cached_is_damage_and_a_read_error_is_not() {
    use std::io::Read;

    let (_dir, layout, store) = fresh();
    let bytes = blob(&[8; 4096]);
    let (pair, ids) = publish_objects(&store, &[&bytes]);
    let reader = ObjectStore::open(&layout).unwrap();
    assert_eq!(reader.read(&ids[0]).unwrap(), bytes); // Caches the locator and handle.

    // The pack ends early after the frame was opened and before it is read.
    let error = reader
        .packs
        .lookup(&reader, &ids[0], false, |location| {
            let mut contents = location.open()?;
            cut_pack_short(&pair);
            let mut read = vec![0; bytes.len()];
            contents.read_exact(&mut read)?;
            Ok(read)
        })
        .unwrap_err();
    assert_damage(&error, &pair, "ends early");

    for kind in [
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::PermissionDenied,
    ] {
        let error = reader
            .packs
            .lookup(&reader, &ids[0], false, |_| -> Result<(), StoreError> {
                Err(std::io::Error::from(kind).into())
            })
            .unwrap_err();
        assert!(
            matches!(&error, StoreError::Io(e) if e.kind() == kind),
            "{error:?}"
        );
    }
}

#[test]
fn a_good_loose_chunk_survives_gc_when_its_packed_copy_has_a_bad_payload() {
    let (_dir, layout, store) = fresh();
    let bytes = blob(&[9; 4096]);
    let (pair, chunks) = publish_objects(&store, &[&bytes]);
    manifest_root(&store, &layout, "live", &chunks);
    // The mark accepts the packed copy by its head, so only the duplicate
    // check protects the loose copy.
    let loose = store.path_for(&chunks[0]);
    fs::create_dir_all(loose.parent().unwrap()).unwrap();
    fs::write(&loose, &bytes).unwrap();
    damage_frame(&pair, &chunks[0], 10, |byte| *byte ^= 1);

    let gc = ObjectStore::open(&layout).unwrap();
    let report =
        crate::ops::gc::run_gc(&gc, &layout, u64::MAX, 0, false, &mut |_, _, _| {}).unwrap();
    assert_eq!(report.loose_duplicates_pruned, 0);
    assert_eq!(fs::read(&loose).unwrap(), bytes);
    assert!(pair.pack.is_file());
}

#[test]
fn the_soft_classification_hashes_an_id_it_reached_as_a_chunk_and_as_a_node() {
    use crate::object::{EntryMode, Tree, TreeEntry};

    let bytes = blob(&[10; 4096]);
    // The tree lists the manifest before and after the blob in turn, so the
    // blob is seen first as a chunk in one run and first as a node in the other.
    for (manifest_name, blob_name) in [("a", "b"), ("b", "a")] {
        let (_dir, layout, store) = fresh();
        let (pair, ids) = publish_objects(&store, &[&bytes]);
        let manifest = serialize(&Object::ChunkedBlob(
            crate::object::testing::spread(1, 0, ids.clone()).unwrap(),
        ))
        .unwrap();
        let manifest = store.write(&manifest).unwrap();
        let mut entries = vec![
            TreeEntry {
                name: manifest_name.into(),
                mode: EntryMode::Blob,
                object_hash: manifest,
            },
            TreeEntry {
                name: blob_name.into(),
                mode: EntryMode::Blob,
                object_hash: ids[0],
            },
        ];
        entries.sort_by(|x, y| x.name.cmp(&y.name));
        let tree = store
            .write(&serialize(&Object::Tree(Tree { entries })).unwrap())
            .unwrap();
        damage_frame(&pair, &ids[0], 10, |byte| *byte ^= 1);

        let gc = ObjectStore::open(&layout).unwrap();
        let result = crate::ops::gc::classify_soft_root(&gc, tree);
        assert!(
            matches!(
                result,
                Err(crate::ops::gc::GcRootsError::Store(
                    StoreError::HashMismatch { .. }
                ))
            ),
            "{manifest_name}/{blob_name}: {result:?}"
        );
    }
}

#[test]
fn the_seal_limits_are_the_fetch_window_and_fit_the_pack_format() {
    assert_eq!(super::PACK_SEAL_BYTES, 64 * 1024 * 1024);
    assert_eq!(super::PACK_SEAL_ENTRIES, 65_536);
    assert!(super::PACK_SEAL_BYTES as u64 <= MAX_TOTAL_PAYLOAD);
    assert!(super::PACK_SEAL_ENTRIES <= MAX_ENTRIES as usize);
}

/// Hand-built pair holding `objects` as `(id, bytes)`. The ids need not be
/// the hashes of the bytes unless a test reads the objects back.
fn hand_pack(dir: &std::path::Path, objects: &[(Hash, Vec<u8>)]) -> Pair {
    let mut objects = objects.to_vec();
    objects.sort_by_key(|(id, _)| *id);
    objects.dedup_by_key(|(id, _)| *id);
    let mut pack = crate::pack::MAGIC.to_vec();
    pack.extend_from_slice(&1_u32.to_le_bytes());
    pack.extend_from_slice(&u32::try_from(objects.len()).unwrap().to_le_bytes());
    let mut rows = Vec::new();
    for (id, bytes) in &objects {
        let len = u32::try_from(bytes.len()).unwrap();
        pack.push(0);
        pack.extend_from_slice(&len.to_le_bytes());
        rows.push((
            *id,
            index::Frame {
                offset: pack.len() as u64,
                len,
            },
        ));
        pack.extend_from_slice(bytes);
    }
    let trailer = blake3::hash(&pack);
    pack.extend_from_slice(trailer.as_bytes());
    let key = *blake3::hash(&pack).as_bytes();
    let pair = Pair::new(dir, key);
    fs::write(&pair.pack, pack).unwrap();
    fs::write(&pair.index, index::encode(key, &rows)).unwrap();
    pair
}

/// A packed store whose pairs hold the blobs `sets` name, a blob per byte.
fn packed_store(sets: &[Vec<u8>]) -> (tempfile::TempDir, RepoLayout, Vec<Pair>) {
    let (dir, layout, store) = fresh();
    let packs = store.pack_dir();
    fs::create_dir(&packs).unwrap();
    store.try_activate_local_packs().unwrap();
    let pairs = sets
        .iter()
        .map(|set| {
            let objects: Vec<_> = set.iter().map(|&n| packed_blob(n)).collect();
            hand_pack(&packs, &objects)
        })
        .collect();
    (dir, layout, pairs)
}

fn packed_blob(n: u8) -> (Hash, Vec<u8>) {
    let bytes = blob(&[n, 7]);
    (index::canonical_id(&bytes).unwrap(), bytes)
}

/// The pack that serves `id`, or the debug text of the failure.
fn serving_pack(store: &ObjectStore, id: &Hash) -> Result<std::path::PathBuf, String> {
    store
        .packs
        .lookup(store, id, true, |location| {
            if matches!(location, super::Location::Loose(_)) {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
            }
            Ok(location.path().to_path_buf())
        })
        .map_err(|error| format!("{error:?}"))
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn is_lazy(store: &ObjectStore) -> bool {
    store.packs.discovery.lock().unwrap().catalog.lazy
}

#[test]
fn lazy_full_and_promoted_catalogs_return_the_same_location_for_every_id() {
    let mut state = 0x9e37_79b9_7f4a_7c15;
    // Duplicates across pairs, empty pairs and ids that no pair holds.
    let sets: Vec<Vec<u8>> = (0..14)
        .map(|n| {
            let size = if n == 3 { 0 } else { 1 + next(&mut state) % 30 };
            (0..size)
                .map(|_| u8::try_from(next(&mut state) % 60).unwrap())
                .collect()
        })
        .collect();
    let (_dir, layout, _pairs) = packed_store(&sets);
    let ids: Vec<_> = (0..=255).map(|n| packed_blob(n).0).collect();

    let open = |full: bool, budgets: Option<(usize, usize)>| {
        let store = ObjectStore::open(&layout).unwrap();
        let mut discovery = store.packs.discovery.lock().unwrap();
        discovery.full = full;
        discovery.budgets = budgets;
        drop(discovery);
        store
    };
    let lazy = open(false, None);
    let full = open(true, None);
    let prefixes = open(true, Some((0, usize::MAX)));
    let on_disk = open(true, Some((0, 0)));
    let promoted = open(false, None);
    // Spend the probe budget on misses so the next lookups promote.
    for _ in 0..super::LAZY_PROBE_BUDGET {
        let _ = promoted.check_presence(&[0xff; 32]);
    }
    promoted.check_presence(&ids[0]).ok();
    assert!(promoted.packs.discovery.lock().unwrap().full);
    assert!(!is_lazy(&promoted));

    serving_pack(&lazy, &ids[0]).ok();
    assert!(is_lazy(&lazy));
    for (at, id) in ids.iter().enumerate() {
        if at == 60 {
            // Every object that a pair holds was answered by probing.
            assert!(is_lazy(&lazy));
        }
        let expected = serving_pack(&full, id);
        for (name, store) in [
            ("lazy", &lazy),
            ("prefixes", &prefixes),
            ("on disk", &on_disk),
            ("promoted", &promoted),
        ] {
            assert_eq!(serving_pack(store, id), expected, "{name} {id:?}");
        }
        assert_eq!(
            lazy.check_presence(id).is_ok(),
            expected.is_ok(),
            "presence {id:?}"
        );
    }
    assert!(!is_lazy(&full));
}

#[test]
fn a_catalog_stays_lazy_up_to_the_pair_limit_and_loads_rows_above_it() {
    let limit = u8::try_from(super::LAZY_PAIR_LIMIT).unwrap();
    let sets: Vec<Vec<u8>> = (0..limit).map(|n| vec![n]).collect();
    let (_dir, layout, _pairs) = packed_store(&sets);
    let reader = ObjectStore::open(&layout).unwrap();
    assert!(reader.check_presence(&packed_blob(0).0).is_ok());
    {
        let discovery = reader.packs.discovery.lock().unwrap();
        assert!(discovery.catalog.lazy && !discovery.full);
        assert!(discovery.catalog.routes.is_empty());
        assert_eq!(discovery.catalog.on_disk.len(), sets.len());
    }
    // Index and pack handles of every pair fit the cache together.
    for n in 0..limit {
        assert!(reader.check_presence(&packed_blob(n).0).is_ok());
    }
    // No handle was opened twice, so the cache held every member.
    assert!(reader.packs.handles.opens() <= 2 * sets.len());

    // One more pair crosses the limit, and every pair loads its rows.
    hand_pack(&reader.pack_dir(), &[packed_blob(200)]);
    assert!(reader.check_presence(&packed_blob(200).0).is_ok());
    let discovery = reader.packs.discovery.lock().unwrap();
    assert!(discovery.full && !discovery.catalog.lazy);
    assert_eq!(discovery.catalog.routes.len(), sets.len() + 1);
    assert!(discovery.catalog.on_disk.is_empty());
}

#[test]
fn a_write_session_gets_the_routes() {
    let (_dir, layout, _pairs) = packed_store(&[vec![1, 2], vec![3]]);
    let reader = ObjectStore::open(&layout).unwrap();
    assert!(reader.check_presence(&packed_blob(1).0).is_ok());
    assert!(is_lazy(&reader));
    let (_guard, catalog) = reader.discover_write_packs().unwrap();
    assert!(!catalog.lazy);
    assert_eq!(catalog.routes.len(), 3);
    assert!(!catalog.may_contain(&packed_blob(99).0));
}

#[test]
fn a_command_promotes_the_catalog_in_the_middle_of_its_lookups() {
    let (_dir, layout, _pairs) = packed_store(&[vec![1, 2], vec![2, 3], vec![4]]);
    let reader = ObjectStore::open(&layout).unwrap();
    let mut promoted_at = None;
    for round in 0..super::LAZY_PROBE_BUDGET {
        // Misses probe every pair. Hits keep returning the right bytes.
        assert!(matches!(
            reader.read(&[0xee; 32]),
            Err(StoreError::ObjectNotFound(_))
        ));
        for n in [1, 2, 3, 4] {
            let (id, bytes) = packed_blob(n);
            assert_eq!(reader.read(&id).unwrap(), bytes);
        }
        if promoted_at.is_none() && !is_lazy(&reader) {
            promoted_at = Some(round);
        }
    }
    assert!(promoted_at.is_some_and(|round| round > 0));
    assert_eq!(
        reader.packs.discovery.lock().unwrap().catalog.routes.len(),
        5
    );
}

#[test]
fn a_pair_retired_after_a_lazy_probe_goes_stale_and_is_found_elsewhere() {
    let (_dir, layout, pairs) = packed_store(&[vec![1, 2], vec![2, 3]]);
    let reader = ObjectStore::open(&layout).unwrap();
    for n in [1, 2, 3] {
        assert!(reader.check_presence(&packed_blob(n).0).is_ok());
    }
    assert!(is_lazy(&reader));
    let first = serving_pack(&reader, &packed_blob(2).0).unwrap();
    let retired = pairs.iter().find(|pair| pair.pack == first).unwrap();
    let other = pairs.iter().find(|pair| pair.pack != first).unwrap();
    fs::remove_file(&retired.pack).unwrap();
    fs::remove_file(&retired.index).unwrap();

    assert_eq!(
        serving_pack(&reader, &packed_blob(2).0).unwrap(),
        other.pack
    );
    let only_there = if retired.pack == pairs[0].pack { 1 } else { 3 };
    assert!(matches!(
        reader.read(&packed_blob(only_there).0),
        Err(StoreError::ObjectNotFound(_))
    ));
}

#[cfg(unix)]
#[test]
fn a_symlinked_or_irregular_member_hides_its_pair_without_damage() {
    for full in [false, true] {
        let (dir, layout, pairs) = packed_store(&[vec![1], vec![2], vec![3], vec![4]]);
        let (linked, directory, healthy, pipe) = (&pairs[0], &pairs[1], &pairs[2], &pairs[3]);
        let elsewhere = dir.path().join("elsewhere.idx");
        fs::rename(&linked.index, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &linked.index).unwrap();
        fs::remove_file(&directory.pack).unwrap();
        fs::create_dir(&directory.pack).unwrap();
        // Opening a pipe for reading would wait for a writer.
        fs::remove_file(&pipe.index).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&pipe.index)
                .status()
                .unwrap()
                .success()
        );

        let reader = ObjectStore::open(&layout).unwrap();
        reader.packs.discovery.lock().unwrap().full = full;
        for n in [1, 2, 4] {
            assert!(
                matches!(
                    reader.read(&packed_blob(n).0),
                    Err(StoreError::ObjectNotFound(_))
                ),
                "full {full}, object {n}"
            );
        }
        assert_eq!(
            serving_pack(&reader, &packed_blob(3).0).unwrap(),
            healthy.pack
        );
        let discovery = reader.packs.discovery.lock().unwrap();
        assert!(discovery.catalog.errors.is_empty());
        assert_eq!(discovery.catalog.packs.len(), 1);
    }
}

#[test]
fn damage_to_an_index_header_or_fanout_reads_the_same_in_every_catalog_mode() {
    let (_dir, layout, pairs) = packed_store(&[vec![1, 2, 3]]);
    let mut bytes = fs::read(&pairs[0].index).unwrap();
    let mut damaged = bytes.clone();
    // The first fanout entry says more ids than the pack holds.
    damaged[12..16].copy_from_slice(&200_u32.to_le_bytes());
    fs::write(&pairs[0].index, &damaged).unwrap();

    let mut errors = Vec::new();
    for full in [false, true] {
        let reader = ObjectStore::open(&layout).unwrap();
        reader.packs.discovery.lock().unwrap().full = full;
        let error = reader.check_presence(&packed_blob(1).0).unwrap_err();
        assert!(
            matches!(error, StoreError::LocalPackDamaged { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains("repair-indexes"), "{error}");
        errors.push(error.to_string());
        let miss = reader.check_presence(&packed_blob(90).0).unwrap_err();
        assert_eq!(miss.to_string(), error.to_string());
    }
    assert_eq!(errors[0], errors[1]);

    bytes[0] ^= 1;
    fs::write(&pairs[0].index, &bytes).unwrap();
    let reader = ObjectStore::open(&layout).unwrap();
    assert!(matches!(
        reader.check_presence(&packed_blob(1).0),
        Err(StoreError::LocalPackDamaged { .. })
    ));
}

#[test]
fn a_shard_listing_matches_the_full_listing_in_every_catalog_mode() {
    let mut state = 0x1234_5678_9abc_def1;
    let sets: Vec<Vec<u8>> = (0..6)
        .map(|_| {
            (0..40)
                .map(|_| u8::try_from(next(&mut state) % 90).unwrap())
                .collect()
        })
        .collect();
    let (_dir, layout, _pairs) = packed_store(&sets);
    let reference = ObjectStore::open(&layout)
        .unwrap()
        .iter_object_hashes()
        .unwrap();
    assert!(!reference.is_empty());
    for (full, budgets) in [
        (false, None),
        (true, None),
        (true, Some((0, usize::MAX))),
        (true, Some((0, 0))),
    ] {
        let reader = ObjectStore::open(&layout).unwrap();
        {
            let mut discovery = reader.packs.discovery.lock().unwrap();
            discovery.full = full;
            discovery.budgets = budgets;
        }
        let mut listed = Vec::new();
        for shard in 0..=255 {
            let ids = reader.list_shard(shard).unwrap();
            assert!(ids.iter().all(|id| id[0] == shard));
            listed.extend(ids);
        }
        assert_eq!(listed, reference, "full {full} budgets {budgets:?}");
    }
}

#[test]
fn a_shard_listing_checks_an_index_like_a_lookup_and_the_scans_still_check_the_checksum() {
    let (_dir, layout, pairs) = packed_store(&[vec![1, 2, 3]]);
    let mut bytes = fs::read(&pairs[0].index).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&pairs[0].index, &bytes).unwrap();

    let reader = ObjectStore::open(&layout).unwrap();
    let id = packed_blob(1).0;
    assert_eq!(reader.list_shard(id[0]).unwrap(), [id]);
    assert!(reader.check_local_packs(false).is_err());
    assert!(reader.iter_object_hashes().is_err());

    // Damage that a lookup would report fails the listing too.
    bytes[0] ^= 1;
    fs::write(&pairs[0].index, &bytes).unwrap();
    let reader = ObjectStore::open(&layout).unwrap();
    assert!(matches!(
        reader.list_shard(id[0]),
        Err(StoreError::LocalPackDamaged { .. })
    ));
}

#[test]
fn a_repaired_pair_loads_again_in_a_lazy_catalog() {
    let (_dir, layout, pairs) = packed_store(&[vec![1, 2], vec![3]]);
    let reader = ObjectStore::open(&layout).unwrap();
    for n in [1, 2, 3] {
        assert!(reader.check_presence(&packed_blob(n).0).is_ok());
    }
    assert!(is_lazy(&reader));
    let before = reader.packs.discovery.lock().unwrap().catalog.packs.clone();
    // Damage the index body so the checksum fails, then repair it in place.
    let mut bytes = fs::read(&pairs[0].index).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&pairs[0].index, &bytes).unwrap();
    assert_eq!(reader.check_local_packs(true).unwrap(), 1);

    assert!(reader.check_presence(&packed_blob(1).0).is_ok());
    let after = reader.packs.discovery.lock().unwrap().catalog.packs.clone();
    let key = |packs: &[std::sync::Arc<super::Locator>]| {
        packs
            .iter()
            .find(|pack| pack.pair.key == pairs[0].key)
            .map(std::sync::Arc::as_ptr)
    };
    assert_ne!(key(&before), key(&after));
}

#[test]
fn routes_come_out_in_prefix_then_pair_order_with_ties_and_crowded_buckets() {
    use super::reader::Locator;

    let mut state = 7;
    let mut id = |lead: &[u8]| {
        let mut id = [0; 32];
        for byte in &mut id {
            *byte = u8::try_from(next(&mut state) % 256).unwrap();
        }
        id[..lead.len()].copy_from_slice(lead);
        id
    };
    for (name, leads) in [
        ("spread", vec![vec![], vec![], vec![]]),
        ("one bucket", vec![vec![0xab, 0xcd]]),
        ("one prefix", vec![vec![1, 2, 3, 4]]),
        ("two prefixes", vec![vec![9, 9, 9, 1], vec![9, 9, 9, 2]]),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let locators: Vec<_> = (0..5)
            .map(|_| {
                let objects: Vec<_> = (0..300)
                    .map(|n| {
                        let lead = &leads[n % leads.len()];
                        (id(lead), vec![0; 6])
                    })
                    .collect();
                let pair = hand_pack(dir.path(), &objects);
                std::sync::Arc::new(Locator::open(&pair, usize::MAX, usize::MAX).unwrap())
            })
            .collect();
        let mut expected: Vec<_> = locators
            .iter()
            .enumerate()
            .flat_map(|(pack, locator)| {
                locator.prefixes().enumerate().map(move |(row, prefix)| {
                    (
                        prefix,
                        u32::try_from(pack).unwrap(),
                        u32::try_from(row).unwrap(),
                    )
                })
            })
            .collect();
        expected.sort_unstable();
        let routes = super::sorted_routes(&locators);
        assert!(
            routes
                .windows(2)
                .all(|w| (w[0].prefix, w[0].pack) <= (w[1].prefix, w[1].pack)),
            "{name}"
        );
        let mut got: Vec<_> = routes.iter().map(|r| (r.prefix, r.pack, r.row)).collect();
        got.sort_unstable();
        assert_eq!(got, expected, "{name}");
    }
}

#[test]
fn a_bad_first_copy_gives_way_to_a_good_one_and_errors_rank_the_same_in_every_mode() {
    let (id, bytes) = packed_blob(9);
    let decoy = (id, blob(b"not the object"));
    // The cut copy needs `id` as its first frame.
    let filler = (10..=255)
        .map(packed_blob)
        .find(|(other, _)| *other > id)
        .unwrap();
    // A copy whose frame length disagrees with its index.
    let cut = |dir: &std::path::Path| {
        let pair = hand_pack(dir, &[(id, bytes.clone()), filler.clone()]);
        let mut pack = fs::read(&pair.pack).unwrap();
        pack[crate::pack::HEADER_LEN + 1] ^= 1;
        fs::write(&pair.pack, pack).unwrap();
        pair
    };
    // Pairs are probed in key order: the good copy must come after the bad ones.
    let good = |dir: &std::path::Path, after: &[Hash]| {
        for n in 11..=255 {
            let pair = hand_pack(dir, &[(id, bytes.clone()), packed_blob(n)]);
            if after.iter().all(|key| *key < pair.key) {
                return;
            }
            fs::remove_file(&pair.pack).unwrap();
            fs::remove_file(&pair.index).unwrap();
        }
        panic!("no good copy sorts after the bad ones");
    };
    let mut by_mode = Vec::new();
    for full in [false, true] {
        let mut outcomes = Vec::new();
        for (decoys, cuts, good_copy) in [
            (true, false, true),
            (true, true, true),
            (true, false, false),
            (true, true, false),
            (false, true, false),
        ] {
            let (_dir, layout, store) = fresh();
            let dir = store.pack_dir();
            fs::create_dir(&dir).unwrap();
            store.try_activate_local_packs().unwrap();
            let mut bad = Vec::new();
            if decoys {
                bad.push(hand_pack(&dir, std::slice::from_ref(&decoy)).key);
            }
            if cuts {
                bad.push(cut(&dir).key);
            }
            if good_copy {
                good(&dir, &bad);
            }
            let reader = ObjectStore::open(&layout).unwrap();
            reader.packs.discovery.lock().unwrap().full = full;
            outcomes.push(match reader.read(&id) {
                Ok(read) => format!("ok {}", read == bytes),
                Err(error) => format!("{error:?}")
                    .chars()
                    .take_while(|c| c.is_alphanumeric())
                    .collect(),
            });
        }
        by_mode.push(outcomes);
    }
    assert_eq!(by_mode[0], by_mode[1]);
    assert_eq!(
        by_mode[0],
        [
            "ok true",
            "ok true",
            "HashMismatch",
            // A mismatch outranks the damage of another copy.
            "HashMismatch",
            "LocalPackDamaged",
        ]
    );
}

/// Hands out its bytes a few at a time, after one interrupted call.
struct Trickle {
    bytes: Vec<u8>,
    interrupted: bool,
    failure: Option<std::io::ErrorKind>,
}

impl std::io::Read for Trickle {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(kind) = self.failure {
            return Err(kind.into());
        }
        if !std::mem::replace(&mut self.interrupted, true) {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        let len = buffer.len().min(self.bytes.len()).min(3);
        buffer[..len].copy_from_slice(&self.bytes[..len]);
        self.bytes.drain(..len);
        Ok(len)
    }
}

#[test]
fn a_vectored_read_fills_every_buffer_across_short_and_interrupted_reads() {
    use std::io::IoSliceMut;

    let fill = |reader: &mut Trickle| {
        let (mut head, mut rows, mut empty, mut tail) = ([0; 4], vec![0; 7], [0; 0], [0; 5]);
        let result = super::reader::read_exact_vectored(
            reader,
            &mut [
                IoSliceMut::new(&mut head),
                IoSliceMut::new(&mut rows),
                IoSliceMut::new(&mut empty),
                IoSliceMut::new(&mut tail),
            ],
        );
        (result, [head.to_vec(), rows, tail.to_vec()].concat())
    };
    let bytes: Vec<u8> = (1..=16).collect();
    let mut reader = Trickle {
        bytes: bytes.clone(),
        interrupted: false,
        failure: None,
    };
    let (result, filled) = fill(&mut reader);
    result.unwrap();
    assert_eq!(filled, bytes);

    let mut short = Trickle {
        bytes: bytes[..9].to_vec(),
        interrupted: false,
        failure: None,
    };
    let error = fill(&mut short).0.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);

    let mut broken = Trickle {
        bytes,
        interrupted: false,
        failure: Some(std::io::ErrorKind::PermissionDenied),
    };
    let error = fill(&mut broken).0.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

/// Every way a catalog can hold a pair: probing index files, rows in memory,
/// ids routed from the file, and nothing cached.
const CATALOG_MODES: [(bool, Option<(usize, usize)>); 4] = [
    (false, None),
    (true, None),
    (true, Some((0, usize::MAX))),
    (true, Some((0, 0))),
];

fn reopen(layout: &RepoLayout, full: bool, budgets: Option<(usize, usize)>) -> ObjectStore {
    let reader = ObjectStore::open(layout).unwrap();
    {
        let mut discovery = reader.packs.discovery.lock().unwrap();
        discovery.full = full;
        discovery.budgets = budgets;
    }
    reader
}

#[test]
fn an_id_column_that_leaves_its_fanout_bucket_is_damage_naming_the_pair() {
    let (_dir, layout, pairs) = packed_store(&[(1..=30).collect(), vec![100]]);
    let (held, held_bytes) = (1..=30)
        .map(packed_blob)
        .find(|(id, _)| id[0] != 0)
        .unwrap();
    let mut bytes = fs::read(&pairs[0].index).unwrap();
    bytes[index::FANOUT_END..index::FANOUT_END + 32 * 30].fill(0);
    fs::write(&pairs[0].index, &bytes).unwrap();

    for (full, budgets) in CATALOG_MODES {
        let reader = reopen(&layout, full, budgets);
        let error = reader.read(&held).unwrap_err();
        let text = error.to_string();
        assert!(
            matches!(error, StoreError::LocalPackDamaged { .. }),
            "full {full}, budgets {budgets:?}: {text}"
        );
        assert!(
            text.contains(&pairs[0].pack.display().to_string()),
            "{text}"
        );
        assert!(text.contains("repair-indexes"), "{text}");
        assert!(matches!(
            reader.list_shard(held[0]),
            Err(StoreError::LocalPackDamaged { .. })
        ));
    }
    let reader = ObjectStore::open(&layout).unwrap();
    assert_eq!(reader.check_local_packs(true).unwrap(), 1);
    assert_eq!(reader.read(&held).unwrap(), held_bytes);
}

#[test]
fn a_damaged_pair_fails_only_the_shards_it_can_hold() {
    let (_dir, layout, pairs) = packed_store(&[(1..=30).collect(), vec![100]]);
    let held: Vec<u8> = (1..=30).map(|n| packed_blob(n).0[0]).collect();
    let bytes = fs::read(&pairs[0].index).unwrap();
    fs::write(&pairs[0].index, &bytes[..bytes.len() / 2]).unwrap();
    let (elsewhere, elsewhere_bytes) = (101..=255)
        .map(packed_blob)
        .find(|(id, _)| !held.contains(&id[0]))
        .unwrap();

    for (full, budgets) in CATALOG_MODES {
        let reader = reopen(&layout, full, budgets);
        let id = reader.write(&elsewhere_bytes).unwrap();
        assert_eq!(id, elsewhere);
        assert_eq!(reader.list_shard(elsewhere[0]).unwrap(), [elsewhere]);
        assert!(matches!(
            reader.read(&[elsewhere[0]; 32]),
            Err(StoreError::ObjectNotFound(_))
        ));
        for shard in held.iter().copied() {
            let error = reader.list_shard(shard).unwrap_err();
            let text = error.to_string();
            assert!(
                matches!(error, StoreError::LocalPackDamaged { .. }),
                "{text}"
            );
            assert!(
                text.contains(&pairs[0].pack.display().to_string()),
                "{text}"
            );
        }
    }
}

#[test]
fn a_cut_index_narrows_the_failing_shards_only_while_its_head_is_trusted() {
    let (_dir, _layout, pairs) = packed_store(&[vec![1, 2, 3]]);
    let pair = &pairs[0];
    let full = fs::read(&pair.index).unwrap();
    let shards_of = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = full[..full.len() - 32].to_vec();
        edit(&mut bytes);
        fs::write(&pair.index, bytes).unwrap();
        pair.shards()
    };
    let held = shards_of(&|_| {}).expect("a cut index with an agreeing head narrows");
    assert!(held.iter().any(|&shard| shard));
    assert!(
        shards_of(&|bytes| bytes[0] ^= 1).is_none(),
        "a wrong magic leaves the head untrusted"
    );
    assert!(
        shards_of(&|bytes| bytes[8] ^= 1).is_none(),
        "a count that differs from the pack's leaves the head untrusted"
    );
}

#[test]
fn damage_to_the_pack_is_not_blamed_on_the_index() {
    let (_dir, layout, pairs) = packed_store(&[vec![1, 2, 3]]);
    let mut bytes = fs::read(&pairs[0].pack).unwrap();
    bytes[0] ^= 1;
    fs::write(&pairs[0].pack, &bytes).unwrap();
    let pack = pairs[0].pack.display().to_string();

    let reader = ObjectStore::open(&layout).unwrap();
    for error in [
        reader.read(&packed_blob(1).0).unwrap_err(),
        reader.list_shard(packed_blob(1).0[0]).unwrap_err(),
    ] {
        let text = error.to_string();
        assert!(
            matches!(error, StoreError::LocalPackDamaged { .. }),
            "{text}"
        );
        assert!(text.contains(&pack), "{text}");
        assert!(!text.contains("repair-indexes"), "{text}");
    }
}

#[test]
fn an_index_borrowed_from_another_pair_does_not_hide_the_pair_it_replaced() {
    let (_dir, layout, pairs) = packed_store(&[vec![1, 2, 3], vec![4, 5, 6]]);
    fs::copy(&pairs[1].index, &pairs[0].index).unwrap();
    let held = packed_blob(1).0;

    for (full, budgets) in CATALOG_MODES {
        let reader = reopen(&layout, full, budgets);
        let error = reader.read(&held).unwrap_err();
        assert!(
            matches!(error, StoreError::LocalPackDamaged { .. }),
            "full {full}, budgets {budgets:?}: {error}"
        );
        assert!(matches!(
            reader.list_shard(held[0]),
            Err(StoreError::LocalPackDamaged { .. })
        ));
    }
}

#[test]
fn repair_gives_a_lone_pack_its_index_although_another_pair_cannot_be_repaired() {
    let (_dir, layout, pairs) = packed_store(&[vec![1, 2, 3], vec![4, 5, 6]]);
    let mut bytes = fs::read(&pairs[0].pack).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::write(&pairs[0].pack, bytes).unwrap();
    fs::remove_file(&pairs[1].index).unwrap();

    let store = ObjectStore::open(&layout).unwrap();
    assert!(store.check_local_packs(true).is_err());
    assert!(pairs[1].index.exists());
    assert_eq!(store.read(&packed_blob(4).0).unwrap(), packed_blob(4).1);
}
