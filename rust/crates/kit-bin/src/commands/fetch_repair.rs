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
    if let Err(error) = forget_broken_remotes(layout, store, broken_root) {
        let _ = writeln!(
            io::stderr().lock(),
            "warning: could not clear fetch records: {error}; rerun the diagnostic before fetching"
        );
    }
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
    let format = fs::File::open(layout.format_file())?;
    format.try_lock()?;
    let records = layout.applied_packs_dir();
    // These filenames include a repository address that can change between
    // fetches. Drop every address's shortcuts. Only affected remotes lose
    // their digest records and signature anchors.
    forget_cursors(&records.join(".cursors"))?;
    match fs::remove_dir_all(records.join(".heads")) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        result => result?,
    }
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

/// Fetch cursors use a bare digest. Attestation records in this directory
/// carry an extension and have their own lifetime.
fn forget_cursors(directory: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
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
    Ok(())
}
