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

pub(super) fn try_activate(path: &Path) -> StoreResult<()> {
    #[cfg(feature = "fault-injection")]
    if crate::fault::keeps_loose(path) {
        return Ok(());
    }
    match activate(path) {
        Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
        result => result,
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
}
