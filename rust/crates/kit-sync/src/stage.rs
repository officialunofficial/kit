//! Private staging of downloaded packs, and applying them.
//!
//! Packs are downloaded to files in a private directory without any repo
//! lock held, up to the staging budget, then unpacked into the object store
//! under the lock. The packs past the budget are applied as they arrive, with
//! the lock held: each is downloaded, checked, unpacked and recorded, then
//! dropped, so a chain of any size stages at most the budget. Success,
//! cancellation and every error remove the private directory.

use std::io::{Read as _, Write as _};

use kit_core::hash::Hash;
use kit_core::pack::PackReader;
use kit_core::protocol::PackKey;
use kit_core::store::ObjectStore;

use crate::applied_packs::AppliedPacks;
use crate::error::SyncError;
use crate::observer::{Observer, SyncEvent};
use crate::packmap::{MAX_FETCH_PACKS, branch_ref_hint};
use crate::source::RemoteSource;
use crate::verify::verify_new_object_signatures;

/// Owns all staging paths; success, cancellation and every error remove the
/// private directory. Files are closed between operations, so a large history
/// does not also require one live file descriptor per pack.
pub(crate) struct StagedPacks {
    pub(crate) directory: tempfile::TempDir,
    pub(crate) packs: Vec<StagedPack>,
    pub(crate) bytes: u64,
    /// The index in the chain of the first pack that was not staged. It is
    /// the chain length when every missing pack fit the budget.
    rest: usize,
}

pub(crate) struct StagedPack {
    key: PackKey,
    bytes: usize,
}

/// Packs a chain application downloaded and applied, and the objects they
/// wrote.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ChainApplied {
    pub(crate) packs: usize,
    pub(crate) objects: usize,
}

/// Download to private files without holding the repo lock, until the next
/// pack would take the staged bytes past `disk_limit`. That pack is dropped,
/// and it and the rest of the chain are left to [`apply_pack_chain`], which
/// downloads them again under the lock. Only one pack buffer exists at a
/// time, and chain metadata has an explicit aggregate limit. No
/// authoritative objects or applied records are changed.
pub(crate) fn download_pack_chain_with_limits(
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    branch: &str,
    chain: &[Hash],
    applied: &AppliedPacks,
    disk_limit: u64,
    stage_parent: Option<&std::path::Path>,
) -> Result<StagedPacks, SyncError> {
    if chain.len() > MAX_FETCH_PACKS {
        return Err(SyncError::PackChainInvalid {
            branch: branch.to_owned(),
            source: None,
        });
    }
    let directory = match stage_parent {
        Some(parent) => tempfile::Builder::new()
            .prefix("kit-fetch-")
            .tempdir_in(parent)?,
        None => tempfile::Builder::new().prefix("kit-fetch-").tempdir()?,
    };
    let mut staged = StagedPacks {
        directory,
        packs: Vec::new(),
        bytes: 0,
        rest: chain.len(),
    };
    let ref_name = branch_ref_hint(branch);
    for (index, &pk) in chain.iter().enumerate() {
        if observer.cancelled() {
            return Err(SyncError::Interrupted);
        }
        let key = PackKey::from_hash(pk);
        if applied.contains(&key) {
            continue;
        }
        let pack = download_checked_pack(source, branch, &ref_name, &key)?;
        let Some(next_bytes) = staged
            .bytes
            .checked_add(pack.len() as u64)
            .filter(|&bytes| bytes <= disk_limit)
        else {
            staged.rest = index;
            break;
        };
        let path = staged.directory.path().join(staged.packs.len().to_string());
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&pack)?;
        staged.packs.push(StagedPack {
            key,
            bytes: pack.len(),
        });
        staged.bytes = next_bytes;
        // `pack` and the file handle drop before the next download. No fsync
        // is needed for disposable staging: a crash never publishes a ref.
    }
    Ok(staged)
}

/// Download one pack and check its size and its bytes against `key`.
fn download_checked_pack(
    source: &dyn RemoteSource,
    branch: &str,
    ref_name: &str,
    key: &PackKey,
) -> Result<Vec<u8>, SyncError> {
    let pack = match source.download_pack_via_ref(key, ref_name) {
        Ok(b) => b,
        Err(error) if error.is_not_found() => {
            return Err(SyncError::AdvertisedPackMissing {
                branch: branch.to_owned(),
                pack: key.to_hex(),
                source: error,
            });
        }
        Err(e) => return Err(e.into()),
    };
    #[cfg(test)]
    observe_retained_pack_bytes(pack.capacity());
    if pack.len() as u64 > kit_core::protocol::PACK_BODY_LIMIT {
        return Err(crate::SourceError::PayloadTooLarge(pack.len()).into());
    }
    key.verify_bytes(&pack).map_err(crate::SourceError::from)?;
    Ok(pack)
}

#[cfg(test)]
std::thread_local! {
    // Tracks owned download payloads at the retention boundary. Thread-local
    // state keeps concurrently running unit tests independent.
    static PEAK_RETAINED_PACK_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn observe_retained_pack_bytes(bytes: usize) {
    PEAK_RETAINED_PACK_BYTES.with(|peak| peak.set(peak.get().max(bytes)));
}

/// Apply `chain` in order while the caller holds the repo lock through ref
/// publication: first the packs in `staged`, then each later pack of the
/// chain as it is downloaded. `staged` must come from
/// [`download_pack_chain_with_limits`] over the same `chain`; `None` applies
/// the whole chain as it arrives.
///
/// One pack is held in memory at a time. Signature checks run per pack, so
/// the full history's newly stored-object IDs are not accumulated in memory.
/// A pack is recorded as applied only after its digest, unpack and signature
/// checks succeed, and a pack already recorded is skipped.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_pack_chain(
    store: &ObjectStore,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    branch: &str,
    chain: &[Hash],
    staged: Option<StagedPacks>,
    applied: &mut AppliedPacks,
    require_signed: bool,
) -> Result<ChainApplied, SyncError> {
    let mut done = ChainApplied::default();
    let rest = match staged {
        Some(staged) => {
            apply_staged_packs(store, observer, &staged, applied, require_signed, &mut done)?;
            // Dropping the owner removes the private directory.
            staged.rest
        }
        None => 0,
    };
    let ref_name = branch_ref_hint(branch);
    for &pk in &chain[rest..] {
        if observer.cancelled() {
            return Err(SyncError::Interrupted);
        }
        let key = PackKey::from_hash(pk);
        if applied.contains(&key) {
            continue;
        }
        let pack = download_checked_pack(source, branch, &ref_name, &key)?;
        done.objects += apply_pack(store, observer, &key, &pack, applied, require_signed)?;
        done.packs += 1;
    }
    Ok(done)
}

fn apply_staged_packs(
    store: &ObjectStore,
    observer: &dyn Observer<SyncEvent>,
    staged: &StagedPacks,
    applied: &mut AppliedPacks,
    require_signed: bool,
    done: &mut ChainApplied,
) -> Result<(), SyncError> {
    for (index, entry) in staged.packs.iter().enumerate() {
        if observer.cancelled() {
            return Err(SyncError::Interrupted);
        }
        let path = staged.directory.path().join(index.to_string());
        let file = std::fs::File::open(&path)?;
        let mut pack = Vec::new();
        // Bound the read even if local temporary bytes were modified. The
        // independently requested digest is rechecked before store effects.
        file.take(entry.bytes as u64 + 1).read_to_end(&mut pack)?;
        if pack.len() != entry.bytes {
            return Err(crate::SourceError::InvalidResponse.into());
        }
        entry
            .key
            .verify_bytes(&pack)
            .map_err(crate::SourceError::from)?;
        done.objects += apply_pack(store, observer, &entry.key, &pack, applied, require_signed)?;
        done.packs += 1;
        drop(pack);
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Unpack `pack`, already checked against `key`, check the signatures of the
/// objects it stored, and record it as applied. Returns the objects it wrote.
fn apply_pack(
    store: &ObjectStore,
    observer: &dyn Observer<SyncEvent>,
    key: &PackKey,
    pack: &[u8],
    applied: &mut AppliedPacks,
    require_signed: bool,
) -> Result<usize, SyncError> {
    let report = PackReader::read(pack, store)?;
    let unpacked = (report.raw_count + report.delta_count) as usize;
    if unpacked > 0 {
        observer.event(&SyncEvent::ObjectsUnpacked { count: unpacked });
    }
    verify_new_object_signatures(store, &report.stored, require_signed)?;
    applied.insert(key);
    Ok(unpacked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::NoopObserver;
    use crate::packmap::{MAX_FETCH_STAGED_BYTES, download_packlist_node};
    use crate::source::TransportSource;
    use kit_core::hash;
    use kit_core::object::Object;
    use kit_core::pack;
    use kit_core::protocol::Transport as _;
    use kit_core::transfer;
    use kit_transport_memory::MemoryTransport;

    fn h(seed: &str) -> Hash {
        hash::hash(seed.as_bytes())
    }

    #[test]
    fn requested_pack_identity_rejects_valid_substitute_before_unpack() {
        use kit_core::layout::RepoLayout;
        use kit_core::object::Blob;
        use kit_core::pack::PackWriter;

        let objects = [
            Object::Blob(Blob {
                data: b"first".to_vec(),
            }),
            Object::Blob(Blob {
                data: b"second".to_vec(),
            }),
        ];
        let mut a = PackWriter::new();
        let mut b = PackWriter::new();
        for object in &objects {
            a.push_raw(
                object.id().unwrap(),
                &kit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
        }
        for object in objects.iter().rev() {
            b.push_raw(
                object.id().unwrap(),
                &kit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
        }
        let a = a.finish().unwrap();
        let b = b.finish().unwrap();
        let key = pack::pack_key(&a);
        assert_ne!(key, pack::pack_key(&b));
        let tx = MemoryTransport::new();
        tx.upload_pack(&b, &PackKey::from_hash(key)).unwrap();
        let td = tempfile::tempdir().unwrap();
        let applied = AppliedPacks::load(&RepoLayout::single(td.path()), "origin").unwrap();

        assert!(matches!(
            download_pack_chain_with_limits(
                &TransportSource::new(&tx),
                &NoopObserver,
                "main",
                &[key],
                &applied,
                MAX_FETCH_STAGED_BYTES,
                None
            ),
            Err(SyncError::Source(crate::SourceError::InvalidResponse))
        ));
        assert!(!applied.contains(&PackKey::from_hash(key)));
    }

    #[test]
    fn requested_packlist_identity_rejects_substitute() {
        let tx = MemoryTransport::new();
        let a = transfer::encode_packlist(None, &[h("pack-a")]).unwrap();
        let b = transfer::encode_packlist(None, &[h("pack-b")]).unwrap();
        let key = hash::hash(&a);
        tx.upload_blob(&b, &PackKey::from_hash(key)).unwrap();
        assert!(matches!(
            download_packlist_node(&TransportSource::new(&tx), key, "refs/heads/main"),
            Err(SyncError::Source(crate::SourceError::InvalidResponse))
        ));
    }

    #[test]
    fn fetch_retains_at_most_one_downloaded_pack() {
        let tx = MemoryTransport::new();
        let bytes = vec![0xAB; 1024 * 1024];
        let key = hash::hash(&bytes);
        tx.upload_pack(&bytes, &PackKey::from_hash(key)).unwrap();
        let td = tempfile::tempdir().unwrap();
        let applied =
            AppliedPacks::load(&kit_core::layout::RepoLayout::single(td.path()), "origin").unwrap();
        PEAK_RETAINED_PACK_BYTES.with(|peak| peak.set(0));
        let downloaded = download_pack_chain_with_limits(
            &TransportSource::new(&tx),
            &NoopObserver,
            "main",
            &vec![key; 32],
            &applied,
            MAX_FETCH_STAGED_BYTES,
            None,
        )
        .unwrap();
        let peak = PEAK_RETAINED_PACK_BYTES.with(std::cell::Cell::get);
        assert!(
            peak <= bytes.len(),
            "retained {peak} bytes for one-MiB packs"
        );
        drop(downloaded);
    }

    /// A pack of `blobs`, uploaded to `tx`, and its key.
    fn upload_blob_pack(tx: &MemoryTransport, blobs: &[&[u8]]) -> (Hash, usize) {
        let mut writer = pack::PackWriter::new();
        for data in blobs {
            let blob = Object::Blob(kit_core::object::Blob {
                data: data.to_vec(),
            });
            writer
                .push_raw(
                    blob.id().unwrap(),
                    &kit_core::serialize::serialize(&blob).unwrap(),
                )
                .unwrap();
        }
        let bytes = writer.finish().unwrap();
        let key = pack::pack_key(&bytes);
        tx.upload_pack(&bytes, &PackKey::from_hash(key)).unwrap();
        (key, bytes.len())
    }

    #[test]
    fn staging_stops_at_the_budget_and_drops_the_next_pack() {
        let tx = MemoryTransport::new();
        let bytes = vec![0xAB; 128];
        let key = hash::hash(&bytes);
        tx.upload_pack(&bytes, &PackKey::from_hash(key)).unwrap();
        let td = tempfile::tempdir().unwrap();
        let applied =
            AppliedPacks::load(&kit_core::layout::RepoLayout::single(td.path()), "origin").unwrap();
        let staged = download_pack_chain_with_limits(
            &TransportSource::new(&tx),
            &NoopObserver,
            "main",
            &[key, key, key],
            &applied,
            128,
            Some(td.path()),
        )
        .unwrap();
        assert_eq!(staged.packs.len(), 1);
        assert_eq!(staged.bytes, 128);
        assert_eq!(staged.rest, 1);
        assert!(!applied.contains(&PackKey::from_hash(key)));
        drop(staged);
        assert_eq!(std::fs::read_dir(td.path()).unwrap().count(), 0);
    }

    #[test]
    fn packs_past_the_budget_apply_and_skip_applied_keys() {
        use kit_core::layout::RepoLayout;

        let tx = MemoryTransport::new();
        let (a, a_len) = upload_blob_pack(&tx, &[b"first"]);
        let (b, _) = upload_blob_pack(&tx, &[b"second"]);
        let (c, _) = upload_blob_pack(&tx, &[b"third"]);
        let td = tempfile::tempdir().unwrap();
        std::fs::create_dir(td.path().join("repo")).unwrap();
        let layout = RepoLayout::single(td.path().join("repo"));
        let store = ObjectStore::init(&layout).unwrap();
        let mut applied = AppliedPacks::load(&layout, "origin").unwrap();
        let source = TransportSource::new(&tx);
        // `a` repeats where the budget runs out, so it is skipped as applied.
        let chain = [a, a, b, c];
        let staged = download_pack_chain_with_limits(
            &source,
            &NoopObserver,
            "main",
            &chain,
            &applied,
            a_len as u64,
            Some(td.path()),
        )
        .unwrap();
        assert_eq!(staged.rest, 1);

        let done = apply_pack_chain(
            &store,
            &source,
            &NoopObserver,
            "main",
            &chain,
            Some(staged),
            &mut applied,
            false,
        )
        .unwrap();

        assert_eq!(done.packs, 3);
        assert_eq!(done.objects, 3);
        for key in [a, b, c] {
            assert!(applied.contains(&PackKey::from_hash(key)));
        }
        for data in [&b"first"[..], b"second", b"third"] {
            let id = Object::Blob(kit_core::object::Blob {
                data: data.to_vec(),
            })
            .id()
            .unwrap();
            assert!(store.contains(&id));
        }
        let leftovers = std::fs::read_dir(td.path())
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name() != "repo")
            .count();
        assert_eq!(leftovers, 0, "the staging directory is removed");
    }

    #[test]
    fn fetch_staging_drop_removes_successful_downloads() {
        let tx = MemoryTransport::new();
        let bytes = b"downloaded object bytes";
        let key = hash::hash(bytes);
        tx.upload_pack(bytes, &PackKey::from_hash(key)).unwrap();
        let td = tempfile::tempdir().unwrap();
        let applied =
            AppliedPacks::load(&kit_core::layout::RepoLayout::single(td.path()), "origin").unwrap();
        let staged = download_pack_chain_with_limits(
            &TransportSource::new(&tx),
            &NoopObserver,
            "main",
            &[key],
            &applied,
            1024,
            Some(td.path()),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(staged.directory.path().join("0")).unwrap(),
            bytes
        );
        assert_eq!(staged.bytes, bytes.len() as u64);
        drop(staged);
        assert_eq!(std::fs::read_dir(td.path()).unwrap().count(), 0);
    }

    #[test]
    fn fetch_staging_digest_failure_cleans_prior_downloads() {
        let tx = MemoryTransport::new();
        let valid = b"valid first bytes";
        let first = hash::hash(valid);
        let wrong = h("missing expected bytes");
        tx.upload_pack(valid, &PackKey::from_hash(first)).unwrap();
        tx.upload_pack(b"substitute", &PackKey::from_hash(wrong))
            .unwrap();
        let td = tempfile::tempdir().unwrap();
        let applied =
            AppliedPacks::load(&kit_core::layout::RepoLayout::single(td.path()), "origin").unwrap();
        assert!(matches!(
            download_pack_chain_with_limits(
                &TransportSource::new(&tx),
                &NoopObserver,
                "main",
                &[first, wrong],
                &applied,
                1024,
                Some(td.path())
            ),
            Err(SyncError::Source(crate::SourceError::InvalidResponse))
        ));
        assert_eq!(std::fs::read_dir(td.path()).unwrap().count(), 0);
    }
}
