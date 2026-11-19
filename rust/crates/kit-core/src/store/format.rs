use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, Write};
use std::path::Path;

use super::{FORMAT_MAX_BYTES, FORMAT_VALUE, StoreError, StoreResult};

#[cfg(test)]
const LEGACY: &[u8] = b"bmt-v2\n";
pub(super) const PACKED: &[u8] = b"bmt-v2\nP";
const INTENT: &str = "format.activate";

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

fn intent(path: &Path) -> StoreResult<Option<File>> {
    let path = path.with_file_name(INTENT);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Ok(meta) if !meta.is_file() => {
            return Err(incompatible(Some(
                "invalid format activation intent".into(),
            )));
        }
        result => {
            result?;
        }
    }
    let file = File::open(path)?;
    if !matches!(read_marker(&file), Ok(bytes) if bytes == PACKED) {
        return Err(incompatible(Some(
            "invalid format activation intent".into(),
        )));
    }
    Ok(Some(file))
}

fn parent(path: &Path) -> &Path {
    path.parent().expect("format marker has a parent")
}

fn finish(path: &Path, file: &File) -> StoreResult<()> {
    file.sync_all()?;
    fs::remove_file(path.with_file_name(INTENT))?;
    crate::atomic::sync_dir(parent(path))?;
    Ok(())
}

fn recover(path: &Path, file: &mut File, intent: File) -> StoreResult<()> {
    intent.sync_all()?;
    drop(intent);
    crate::atomic::sync_dir(parent(path))?;
    file.rewind()?;
    file.write_all(PACKED)?;
    file.set_len(PACKED.len() as u64)?;
    finish(path, file)
}

fn checked_under_shared(path: &Path, file: &File) -> StoreResult<bool> {
    let pending = intent(path)?.is_some();
    let packed = parse(&read_marker(file)?)?;
    if pending && packed {
        return Err(incompatible(Some(
            "format activation needs recovery".into(),
        )));
    }
    Ok(packed)
}

/// Read with the shared lock. Only a fresh open attempts recovery.
pub(super) fn check(path: &Path, recover_pending: bool) -> StoreResult<bool> {
    let shared = open_marker(path, false)?;
    shared.lock_shared()?;
    if !recover_pending {
        return checked_under_shared(path, &shared);
    }
    if intent(path)?.is_none() {
        return parse(&read_marker(&shared)?);
    }
    drop(shared);

    match open_marker(path, true) {
        Ok(mut exclusive) => match exclusive.try_lock() {
            Ok(()) => {
                if let Some(intent) = intent(path)? {
                    recover(path, &mut exclusive, intent)?;
                    return Ok(true);
                }
                return parse(&read_marker(&exclusive)?);
            }
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        },
        Err(StoreError::Io(e))
            if matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
            ) => {}
        Err(e) => return Err(e),
    }

    let shared = open_marker(path, false)?;
    shared.lock_shared()?;
    checked_under_shared(path, &shared)
}

#[cfg(test)]
pub(super) fn activate(path: &Path) -> StoreResult<()> {
    let mut file = open_marker(path, true)?;
    file.try_lock().map_err(io::Error::from)?;
    if let Some(intent) = intent(path)? {
        return recover(path, &mut file, intent);
    }
    let bytes = read_marker(&file)?;
    if parse(&bytes)? {
        return Ok(());
    }
    if bytes != LEGACY {
        return Err(incompatible(Some("noncanonical legacy marker".into())));
    }
    crate::atomic::write_atomic(&path.with_file_name(INTENT), PACKED, false)?;
    file.seek(std::io::SeekFrom::Start(LEGACY.len() as u64))?;
    file.write_all(b"P")?;
    finish(path, &file)
}

#[cfg(test)]
pub(super) fn sync_packed(path: &Path, guard: &super::PruneGuard) -> StoreResult<()> {
    if intent(path)?.is_some() || !parse(&read_marker(&guard.format)?)? {
        return Err(incompatible(Some(
            "format activation needs recovery".into(),
        )));
    }
    guard.format.sync_all()?;
    crate::atomic::sync_dir(parent(path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{INTENT, LEGACY, PACKED, activate};
    use crate::layout::RepoLayout;
    use crate::store::{ObjectStore, StoreError};
    use std::fs::{self, File};
    use std::io::Read;

    #[test]
    fn marker_recovers_from_every_intent_boundary() {
        let cases: &[(&[u8], bool, bool)] = &[
            (LEGACY, false, false),      // Before staging, or rename not retained.
            (LEGACY, true, true),        // Intent rename survives. Append hasn't started.
            (b"bmt-v2\n\0", true, true), // Length survives the torn append.
            (PACKED, true, true),        // Append survives before or after sync.
            (PACKED, false, true),       // Intent unlink survives.
            (b"bmt-\xff", true, true),   // The marker rewrite tears too.
        ];
        for &(bytes, intent, packed) in cases {
            let dir = tempfile::tempdir().unwrap();
            let layout = RepoLayout::single(dir.path());
            let _store = ObjectStore::init(&layout).unwrap();
            let marker = layout.format_file();
            fs::write(&marker, bytes).unwrap();
            let original = File::open(&marker).unwrap();
            if intent {
                fs::write(marker.with_file_name(INTENT), PACKED).unwrap();
            }
            fs::write(marker.with_file_name(".kit.tmp.marker"), b"partial").unwrap();

            ObjectStore::open(&layout).unwrap();
            let mut current = Vec::new();
            (&original).read_to_end(&mut current).unwrap();
            assert_eq!(current, if packed { PACKED } else { LEGACY });
            assert!(!marker.with_file_name(INTENT).exists());
            activate(&marker).unwrap();
            ObjectStore::open(&layout).unwrap();
            assert_eq!(fs::read(&marker).unwrap(), PACKED);
        }
    }

    #[test]
    fn recovery_requires_an_exact_intent_and_an_existing_inode() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let _store = ObjectStore::init(&layout).unwrap();
        let marker = layout.format_file();
        let intent = marker.with_file_name(INTENT);
        fs::write(&marker, b"torn").unwrap();
        assert!(matches!(
            ObjectStore::open(&layout),
            Err(StoreError::IncompatibleRepoFormat { .. })
        ));
        fs::write(&intent, b"torn").unwrap();
        assert!(matches!(
            ObjectStore::open(&layout),
            Err(StoreError::IncompatibleRepoFormat { .. })
        ));
        fs::write(&intent, PACKED).unwrap();
        fs::remove_file(&marker).unwrap();
        assert!(matches!(
            ObjectStore::open(&layout),
            Err(StoreError::IncompatibleRepoFormat { found: None })
        ));
        assert!(!marker.exists());
    }

    #[test]
    fn recovery_try_lock_contends_and_accepts_only_a_legacy_marker() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        let marker = layout.format_file();
        let guard = store.prune_guard().unwrap();
        fs::write(marker.with_file_name(INTENT), PACKED).unwrap();
        ObjectStore::open(&layout).unwrap();
        fs::write(&marker, PACKED).unwrap();
        assert!(matches!(
            ObjectStore::open(&layout),
            Err(StoreError::IncompatibleRepoFormat { .. })
        ));
        drop(guard);
        ObjectStore::open(&layout).unwrap();
        assert!(!marker.with_file_name(INTENT).exists());
        assert_eq!(fs::read(&marker).unwrap(), PACKED);
    }
}
