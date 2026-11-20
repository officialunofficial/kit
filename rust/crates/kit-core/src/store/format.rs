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

fn parse(bytes: &[u8]) -> StoreResult<bool> {
    if bytes == PACKED {
        return Ok(true);
    }
    if bytes == LOST_APPEND {
        return Ok(false);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) if text.trim() == FORMAT_VALUE => Ok(false),
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
    match activate(path, false) {
        Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
        result => result,
    }
}

pub(super) fn activate(path: &Path, strict: bool) -> StoreResult<()> {
    let file = open_marker(path, true)?;
    file.try_lock().map_err(io::Error::from)?;
    let bytes = read_marker(&file)?;
    if !parse(&bytes)? {
        if bytes != LEGACY && bytes != LOST_APPEND {
            return if strict {
                Err(incompatible(Some("noncanonical legacy marker".into())))
            } else {
                Ok(())
            };
        }
        crate::pack::write_spooled(&file, LEGACY.len() as u64, b"P")?;
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
    use super::{LEGACY, LOST_APPEND, PACKED, activate, check};
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

            activate(&marker, true).unwrap();
            activate(&marker, true).unwrap();
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
            matches!(activate(&marker, true), Err(StoreError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(fs::read(&marker).unwrap(), LOST_APPEND);
        drop(guard);
        activate(&marker, true).unwrap();
        assert_eq!(fs::read(&marker).unwrap(), PACKED);
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

        for malformed in [b"bmt-v2\nX".as_slice(), b"bmt-v2\n\0\0", b"bmt-v2\nP\n"] {
            fs::write(&marker, malformed).unwrap();
            assert!(matches!(
                check(&marker),
                Err(StoreError::IncompatibleRepoFormat { .. })
            ));
            assert!(matches!(
                activate(&marker, true),
                Err(StoreError::IncompatibleRepoFormat { .. })
            ));
            assert_eq!(fs::read(&marker).unwrap(), malformed);
        }
        let noncanonical = b"bmt-v2\n\n";
        fs::write(&marker, noncanonical).unwrap();
        assert!(!check(&marker).unwrap());
        assert!(matches!(
            activate(&marker, true),
            Err(StoreError::IncompatibleRepoFormat { .. })
        ));
        assert_eq!(fs::read(&marker).unwrap(), noncanonical);

        fs::remove_file(&marker).unwrap();
        assert!(matches!(
            activate(&marker, true),
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
