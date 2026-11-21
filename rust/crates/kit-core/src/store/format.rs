use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use super::{FORMAT_MAX_BYTES, FORMAT_VALUE, StoreError, StoreResult};

const LEGACY: &[u8] = b"bmt-v2\n";
pub(super) const PACKED: &[u8] = b"bmt-v2\nP";
const LOST_APPEND: &[u8] = b"bmt-v2\n\0";

fn incompatible(found: Option<String>) -> StoreError {
    StoreError::IncompatibleRepoFormat { found }
}

fn read_marker(file: &File) -> StoreResult<Vec<u8>> {
    match crate::bounded_read::read_capped_from(file, FORMAT_MAX_BYTES) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            Err(incompatible(Some("unreadable".into())))
        }
        Err(e) => Err(e.into()),
    }
}

/// The marker is exactly one of three byte strings. Any other bytes, such as
/// trailing whitespace, refuse the store.
fn parse(bytes: &[u8]) -> StoreResult<bool> {
    if bytes == PACKED {
        return Ok(true);
    }
    if bytes == LEGACY || bytes == LOST_APPEND {
        return Ok(false);
    }
    match std::str::from_utf8(bytes) {
        // Padding around the right value shows in the report.
        Ok(text) if text.trim() == FORMAT_VALUE => Err(incompatible(Some(text.into()))),
        Ok(text) => Err(incompatible(Some(text.trim().into()))),
        Err(_) => Err(incompatible(Some("unreadable".into()))),
    }
}

fn open_marker(path: &Path, writable: bool) -> StoreResult<File> {
    match OpenOptions::new().read(true).write(writable).open(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(incompatible(None)),
        other => Ok(other?),
    }
}

/// Read the marker using a shared lock on its existing inode.
pub(super) fn check(path: &Path) -> StoreResult<bool> {
    let file = open_marker(path, false)?;
    file.lock_shared()?;
    parse(&read_marker(&file)?)
}

/// Read the marker only if its shared lock is immediately available.
pub(super) fn try_check(path: &Path) -> StoreResult<bool> {
    let file = open_marker(path, false)?;
    file.try_lock_shared().map_err(io::Error::from)?;
    parse(&read_marker(&file)?)
}

/// The marker a new store starts with.
pub(super) fn init_marker(path: &Path) -> &'static [u8] {
    #[cfg(feature = "fault-injection")]
    if crate::fault::keeps_loose(path) {
        return LEGACY;
    }
    #[cfg(not(feature = "fault-injection"))]
    let _ = path;
    PACKED
}

/// Try the one-way activation without blocking. Returns whether this call
/// left the marker packed. A busy lock leaves the store loose, and so does a
/// marker this user cannot write, so objects stay writable in a shared
/// repository. Any other error is returned.
pub(super) fn try_activate(path: &Path) -> StoreResult<bool> {
    #[cfg(feature = "fault-injection")]
    if crate::fault::keeps_loose(path) {
        return Ok(false);
    }
    match activate(path) {
        Ok(()) => Ok(true),
        Err(StoreError::Io(e))
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock
                    | io::ErrorKind::PermissionDenied
                    | io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

pub(super) fn activate(path: &Path) -> StoreResult<()> {
    let file = open_marker(path, true)?;
    file.try_lock().map_err(io::Error::from)?;
    if !parse(&read_marker(&file)?)? {
        crate::pack::write_at(&file, LEGACY.len() as u64, b"P")?;
    }
    file.sync_all()?;
    Ok(())
}

pub(super) fn packed_under_guard(guard: &super::PruneGuard) -> StoreResult<bool> {
    let len = guard.format.metadata()?.len();
    if len > FORMAT_MAX_BYTES {
        return Err(incompatible(Some("unreadable".into())));
    }
    let mut bytes = [0; 64];
    let marker = &mut bytes[..usize::try_from(len).expect("bounded marker length")];
    crate::pack::read_spooled(&guard.format, 0, marker)?;
    parse(marker)
}

pub(super) fn sync_packed(path: &Path, guard: &super::PruneGuard) -> StoreResult<()> {
    if !packed_under_guard(guard)? {
        return Err(incompatible(Some(
            "local packs require capability P".into(),
        )));
    }
    guard.format.sync_all()?;
    crate::atomic::sync_dir(path.parent().expect("format marker has a parent"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LEGACY, LOST_APPEND, PACKED, activate, check, try_activate};
    use crate::layout::RepoLayout;
    use crate::store::{ObjectStore, StoreError};
    use std::fs::{self, File};
    use std::io::{self, Read};

    #[test]
    fn lost_append_keeps_loose_reads_under_the_shared_lock() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let bytes = b"loose object";
        let id = store.write(bytes).unwrap();
        let marker = layout.format_file();

        for state in [LEGACY, LOST_APPEND] {
            fs::write(&marker, state).unwrap();
            let guard = store.prune_guard().unwrap();
            assert!(!check(&marker).unwrap());
            let reopened = ObjectStore::open(&layout).unwrap();
            assert_eq!(reopened.read(&id).unwrap(), bytes);
            assert_eq!(fs::read(&marker).unwrap(), state);
            drop(guard);
        }
    }

    #[test]
    fn activation_writes_only_the_tail_of_the_existing_inode() {
        for state in [LEGACY, LOST_APPEND] {
            let dir = tempfile::tempdir().unwrap();
            let layout = RepoLayout::single(dir.path());
            ObjectStore::init(&layout).unwrap();
            let marker = layout.format_file();
            fs::write(&marker, state).unwrap();
            let mut original = File::open(&marker).unwrap();

            activate(&marker).unwrap();
            activate(&marker).unwrap();
            assert!(check(&marker).unwrap());
            let mut current = Vec::new();
            original.read_to_end(&mut current).unwrap();
            assert_eq!(current, PACKED);
            assert_eq!(fs::read(&marker).unwrap(), PACKED);
        }
    }

    #[test]
    fn busy_activation_leaves_the_marker_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let marker = layout.format_file();
        fs::write(&marker, LOST_APPEND).unwrap();

        let guard = store.prune_guard().unwrap();
        assert!(
            matches!(activate(&marker), Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(fs::read(&marker).unwrap(), LOST_APPEND);
        drop(guard);
        activate(&marker).unwrap();
        assert_eq!(fs::read(&marker).unwrap(), PACKED);
    }

    #[test]
    fn the_guard_refuses_every_marker_but_the_three_exact_ones() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let mut padded = b"bmt-v2".to_vec();
        padded.resize(64, b' ');
        let mut too_long = padded.clone();
        too_long.push(b' ');

        for (bytes, active) in [
            (LEGACY.to_vec(), Some(false)),
            (LOST_APPEND.to_vec(), Some(false)),
            (PACKED.to_vec(), Some(true)),
            (b"bmt-v2\n\n".to_vec(), None),
            (b"bmt-v2".to_vec(), None),
            (b"bmt-v2\r\n".to_vec(), None),
            (b" bmt-v2\n".to_vec(), None),
            (padded, None),
            (too_long, None),
        ] {
            fs::write(layout.format_file(), &bytes).unwrap();
            let guard = store.prune_guard().unwrap();
            match active {
                Some(active) => {
                    assert_eq!(
                        store.local_packs_active(&guard).unwrap(),
                        active,
                        "{bytes:?}"
                    );
                }
                None => assert!(
                    matches!(
                        store.local_packs_active(&guard),
                        Err(StoreError::IncompatibleRepoFormat { .. })
                    ),
                    "{bytes:?}"
                ),
            }
        }
    }

    #[test]
    fn a_refused_marker_is_reported_with_its_padding_only_for_the_known_value() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("format");
        for (bytes, found) in [
            (b"bmt-v2\n\n".as_slice(), "bmt-v2\n\n"),
            (b"bmt-v2 ".as_slice(), "bmt-v2 "),
            (b"bmt-v1\n".as_slice(), "bmt-v1"),
        ] {
            fs::write(&marker, bytes).unwrap();
            assert!(
                matches!(
                    check(&marker),
                    Err(StoreError::IncompatibleRepoFormat { found: Some(ref got) }) if got == found
                ),
                "{bytes:?}"
            );
        }
    }

    #[test]
    fn activation_propagates_io_errors_other_than_contention() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(try_activate(dir.path()), Err(StoreError::Io(_))));
    }

    #[test]
    fn unknown_required_capabilities_refuse_open_with_an_update_hint() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();

        for bytes in [b"bmt-v2\nX".as_slice(), b"bmt-v2\nPX"] {
            fs::write(layout.format_file(), bytes).unwrap();
            let error = ObjectStore::open(&layout).unwrap_err();
            assert!(matches!(error, StoreError::IncompatibleRepoFormat { .. }));
            assert!(error.to_string().contains("Update kit"));
        }
    }

    #[test]
    fn activation_refuses_other_tails_and_missing_markers() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        let marker = layout.format_file();

        for malformed in [
            b"bmt-v2\nX".as_slice(),
            b"bmt-v2\n\0\0",
            b"bmt-v2\nP\n",
            b"bmt-v2\n\n",
            b"bmt-v2",
        ] {
            fs::write(&marker, malformed).unwrap();
            assert!(matches!(
                check(&marker),
                Err(StoreError::IncompatibleRepoFormat { .. })
            ));
            assert!(matches!(
                activate(&marker),
                Err(StoreError::IncompatibleRepoFormat { .. })
            ));
            assert_eq!(fs::read(&marker).unwrap(), malformed);
        }
        fs::remove_file(&marker).unwrap();
        assert!(matches!(
            activate(&marker),
            Err(StoreError::IncompatibleRepoFormat { found: None })
        ));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn marker_open_preserves_filesystem_errors_other_than_absence() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        let marker = layout.format_file();
        fs::remove_file(&marker).unwrap();
        std::os::unix::fs::symlink(&marker, &marker).unwrap();

        assert!(matches!(ObjectStore::open(&layout), Err(StoreError::Io(_))));
    }

    fn loose_store(state: &[u8]) -> (tempfile::TempDir, RepoLayout, ObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        fs::write(layout.format_file(), state).unwrap();
        let store = ObjectStore::open(&layout).unwrap();
        (dir, layout, store)
    }

    #[test]
    fn init_writes_the_packed_marker_through_a_synced_rename() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        crate::atomic::testing::reset_dir_sync_calls();

        let store = ObjectStore::init(&layout).unwrap();

        assert!(crate::atomic::testing::dir_sync_calls() >= 1);
        assert_eq!(fs::read(layout.format_file()).unwrap(), PACKED);
        assert!(store.local_packs_enabled().unwrap());
        assert!(
            ObjectStore::open(&layout)
                .unwrap()
                .local_packs_enabled()
                .unwrap()
        );
        let mut names: Vec<_> = fs::read_dir(layout.common_dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["format", "objects"], "no temporary marker is left");
    }

    #[test]
    fn the_first_write_of_any_kind_activates_a_loose_store() {
        for state in [LEGACY, LOST_APPEND] {
            let (_dir, layout, store) = loose_store(state);
            let batch = store.batch();
            assert_eq!(fs::read(layout.format_file()).unwrap(), state);
            batch.write(b"staged").unwrap();
            assert_eq!(fs::read(layout.format_file()).unwrap(), PACKED);
            batch.commit().unwrap();

            let (_dir, layout, store) = loose_store(state);
            store.write(b"direct").unwrap();
            assert_eq!(fs::read(layout.format_file()).unwrap(), PACKED);

            let (_dir, layout, store) = loose_store(state);
            let mut bulk = store.bulk_writer();
            assert_eq!(fs::read(layout.format_file()).unwrap(), state);
            bulk.write(b"bulk").unwrap();
            assert_eq!(fs::read(layout.format_file()).unwrap(), PACKED);
            bulk.commit().unwrap();
        }
    }

    #[test]
    fn a_reader_and_an_empty_batch_leave_a_loose_store_loose() {
        for state in [LEGACY, LOST_APPEND] {
            let (_dir, layout, store) = loose_store(state);
            let id = crate::object::object_id_from_bytes(b"absent");

            assert!(store.read(&id).is_err());
            assert!(store.object_size(&id).is_err());
            assert!(store.check_presence(&id).is_err());
            store.batch().commit().unwrap();
            store.sync_shards([]).unwrap();
            drop(store.bulk_writer());

            assert_eq!(fs::read(layout.format_file()).unwrap(), state);
        }
    }

    #[test]
    fn a_batch_that_activates_the_store_gets_its_pack_catalog_afterwards() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let publisher = ObjectStore::init(&layout).unwrap();
        let bytes =
            crate::serialize::serialize(&crate::object::Object::Blob(crate::object::Blob {
                data: b"already in a pack".to_vec(),
            }))
            .unwrap();
        let guard = publisher.prune_guard().unwrap();
        let mut pack = crate::store::LocalPackWriter::new(&publisher, &guard).unwrap();
        let id = pack.write(&bytes).unwrap();
        pack.publish().unwrap();
        drop(guard);
        fs::write(layout.format_file(), LEGACY).unwrap();

        let writer = ObjectStore::open(&layout).unwrap();
        let batch = writer.batch();
        assert_eq!(batch.write(&bytes).unwrap(), id);
        batch.commit().unwrap();

        assert_eq!(fs::read(layout.format_file()).unwrap(), PACKED);
        assert!(
            !writer.path_for(&id).exists(),
            "reused from the pack, not rewritten loose"
        );
    }

    #[test]
    fn a_missed_activation_writes_loose_and_the_handle_does_not_try_again() {
        for state in [LEGACY, LOST_APPEND] {
            let (_dir, layout, store) = loose_store(state);
            let guard = store.prune_guard().unwrap();

            let batch = store.batch();
            let first = batch.write(b"first").unwrap();
            batch.commit().unwrap();
            let direct = store.write(b"second").unwrap();
            assert_eq!(fs::read(layout.format_file()).unwrap(), state);
            assert!(store.path_for(&first).exists());
            assert!(store.path_for(&direct).exists());

            drop(guard);
            let batch = store.batch();
            let third = batch.write(b"third").unwrap();
            batch.commit().unwrap();
            assert_eq!(fs::read(layout.format_file()).unwrap(), state);
            assert!(store.path_for(&third).exists());

            // A new handle tries again.
            let fresh = ObjectStore::open(&layout).unwrap();
            fresh.write(b"fourth").unwrap();
            assert_eq!(fs::read(layout.format_file()).unwrap(), PACKED);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_that_cannot_be_written_leaves_writes_loose() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, layout, store) = loose_store(LEGACY);
        let marker = layout.format_file();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o444)).unwrap();
        if std::fs::OpenOptions::new()
            .write(true)
            .open(&marker)
            .is_ok()
        {
            return; // running as a user that ignores the mode bits
        }

        let batch = store.batch();
        let staged = batch.write(b"staged").unwrap();
        batch.commit().unwrap();
        let direct = store.write(b"direct").unwrap();
        let mut bulk = store.bulk_writer();
        bulk.write(b"bulk").unwrap();
        bulk.commit().unwrap();

        assert_eq!(fs::read(&marker).unwrap(), LEGACY);
        assert!(store.path_for(&staged).exists());
        assert!(store.path_for(&direct).exists());
        assert!(matches!(try_activate(&marker), Ok(false)));
    }

    #[test]
    fn a_failure_other_than_contention_or_a_read_only_marker_is_returned_every_time() {
        let (_dir, layout, store) = loose_store(LEGACY);
        fs::write(layout.format_file(), b"bmt-v2\nX").unwrap();
        for _ in 0..2 {
            assert!(matches!(
                store.write(b"refused"),
                Err(StoreError::IncompatibleRepoFormat { .. })
            ));
        }
        let batch = store.batch();
        assert!(matches!(
            batch.write(b"refused"),
            Err(StoreError::IncompatibleRepoFormat { .. })
        ));
    }

    #[test]
    fn a_handle_that_is_packed_never_reads_the_marker_again_to_write() {
        for state in [LEGACY, PACKED] {
            let (_dir, layout, store) = loose_store(state);
            let mut bulk = store.bulk_writer();
            bulk.write(b"first").unwrap();
            bulk.commit().unwrap();
            assert_eq!(fs::read(layout.format_file()).unwrap(), PACKED);

            // Neither the handle that activated the store nor one opened packed
            // looks at the marker again, so a bad one does not stop a writer.
            fs::write(layout.format_file(), b"bmt-v2\nX").unwrap();
            let mut bulk = store.bulk_writer();
            bulk.write(b"second").unwrap();
            bulk.commit().unwrap();
            fs::write(layout.format_file(), PACKED).unwrap();
            let packed = ObjectStore::open(&layout).unwrap();
            fs::write(layout.format_file(), b"bmt-v2\nX").unwrap();
            let mut bulk = packed.bulk_writer();
            bulk.write(b"third").unwrap();
            bulk.commit().unwrap();
        }
    }

    #[test]
    fn each_marker_state_a_crash_at_the_byte_can_leave_reopens_and_the_next_write_activates() {
        for state in [LEGACY, LOST_APPEND, PACKED] {
            let (_dir, layout, store) = loose_store(state);
            let id = store.write(b"before").unwrap();
            assert_eq!(fs::read(layout.format_file()).unwrap(), PACKED);

            let reopened = ObjectStore::open(&layout).unwrap();
            assert_eq!(reopened.read(&id).unwrap(), b"before");
        }
    }
}
