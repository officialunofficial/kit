//! Drop fetch shortcuts for a remote whose tracking history has a hole.

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use kit_core::hash::{Hash, Hasher, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::ops::check_closure_present;
use kit_core::refs;
use kit_core::store::{ObjectStore, StoreError};
use kit_sync::AppliedPacks;

/// Schedule a full fetch after a diagnostic found a missing object.
/// A verified closure report can name its incomplete root, saving a walk
/// when that root is a tracking tip. Other callers discover affected remotes
/// by checking their tracking histories.
pub(super) fn note_missing(layout: &RepoLayout, store: &ObjectStore, broken_root: Option<Hash>) {
    warn_on_clear_error(forget_broken_remotes(layout, store, broken_root));
}

fn forget_broken_remotes(
    layout: &RepoLayout,
    store: &ObjectStore,
    broken_root: Option<Hash>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = crate::config::read_layered(layout)?;
    let mut affected = Vec::new();
    for remote in crate::config::configured_remote_names(&cfg) {
        let tracking = refs::list_remote_refs(layout, &remote)?;
        if broken_root.is_some_and(|root| tracking.iter().any(|r| r.hash == Some(root)))
            || matches!(
                check_closure_present(store, tracking.iter().filter_map(|r| r.hash.as_ref())),
                Err(StoreError::ObjectNotFound(_))
            )
        {
            affected.push((remote, tracking));
        }
    }
    if affected.is_empty() {
        return Ok(());
    }

    // Fetch holds a shared prune guard while reading and writing these
    // records. Try the exclusive lock only after the scans and never wait
    // for it. Restore and gc can still hold a worktree lock.
    let _format = lock_fetch_records(layout)?;
    let records = checked_records_root(layout)?;
    forget_fetch_shortcuts(&records)?;
    for (remote, tracking) in affected {
        for r in tracking {
            // The verified-tip filename is the hash of the length-prefixed
            // remote and branch names, as written by the fetch.
            let mut key = Hasher::new();
            for part in [&remote, &r.name] {
                key.update(&(part.len() as u64).to_le_bytes())
                    .update(part.as_bytes());
            }
            let path = records.join(".verified").join(to_hex(&key.finalize()));
            match fs::remove_file(path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                result => result?,
            }
        }
        AppliedPacks::remove_record(layout, &remote)?;
    }
    Ok(())
}

/// Pack coverage is unknown, so drop every data-pack hint and history
/// shortcut while fetch is excluded. Attestation records have their own
/// lifetime and are independent of object pack keys.
pub(super) fn note_bad_pack(layout: &RepoLayout) {
    warn_on_clear_error(forget_all_data_records(layout));
}

fn warn_on_clear_error(result: Result<(), impl std::fmt::Display>) {
    if let Err(error) = result {
        let _ = writeln!(
            io::stderr().lock(),
            "warning: could not clear fetch records: {error}; rerun the diagnostic before fetching"
        );
    }
}

fn forget_all_data_records(layout: &RepoLayout) -> io::Result<()> {
    let _format = lock_fetch_records(layout)?;
    let records = checked_records_root(layout)?;
    forget_fetch_shortcuts(&records)?;
    remove_dir_if_present(&records.join(".verified"))?;
    let Some(entries) = read_cache_dir(&records)? else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry?;
        // AppliedPacks flattens a remote name by encoding slashes as %2F.
        if entry.file_type()?.is_file()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| refs::validate_ref_name(&name.replace("%2F", "/")))
        {
            fs::remove_file(entry.path())?;
        }
    }
    kit_transport_file::sync_dir(&records)
}

fn checked_records_root(layout: &RepoLayout) -> io::Result<std::path::PathBuf> {
    let records = layout.applied_packs_dir();
    check_cache_dir(layout.common_dir())?;
    check_cache_dir(&records)?;
    Ok(records)
}

fn check_cache_dir(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a directory", path.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn read_cache_dir(path: &Path) -> io::Result<Option<fs::ReadDir>> {
    if check_cache_dir(path)? {
        fs::read_dir(path).map(Some)
    } else {
        Ok(None)
    }
}

fn lock_fetch_records(layout: &RepoLayout) -> io::Result<fs::File> {
    let format = fs::File::open(layout.format_file())?;
    format.try_lock()?;
    Ok(format)
}

fn forget_fetch_shortcuts(records: &Path) -> io::Result<()> {
    // These filenames include a repository address that can change between
    // fetches. Drop every address's shortcuts.
    forget_cursors(&records.join(".cursors"))?;
    remove_dir_if_present(&records.join(".heads"))
}

fn remove_dir_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// Fetch cursors use a bare digest. Attestation records in this directory
/// carry an extension and have their own lifetime.
fn forget_cursors(directory: &Path) -> io::Result<()> {
    let Some(entries) = read_cache_dir(directory)? else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| kit_core::refs::parse_lowercase_hash(name.as_bytes()).is_some())
            && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
        }
    }
    kit_transport_file::sync_dir(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn cache_paths_require_a_real_directory_and_distinguish_absence() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let file = dir.path().join("file");
        fs::write(&file, b"regular file").unwrap();

        assert!(check_cache_dir(dir.path()).unwrap());
        assert!(!check_cache_dir(&missing).unwrap());
        remove_dir_if_present(&missing).unwrap();
        assert!(remove_dir_if_present(&file).is_err());
        assert!(file.is_file());
        assert_eq!(
            check_cache_dir(&file).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        #[cfg(unix)]
        {
            assert_eq!(
                check_cache_dir(&file.join("child")).unwrap_err().kind(),
                io::ErrorKind::NotADirectory
            );
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(dir.path(), &link).unwrap();
            assert_eq!(
                check_cache_dir(&link).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
