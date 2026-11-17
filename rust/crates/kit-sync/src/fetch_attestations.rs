//! Bounded attestation reads, isolated from object application and its caches.
use crate::{
    FetchReport, Observer, RemoteSource, SyncEvent, SyncOptions,
    attestation_records::{self, NODE_BOUND, Record, RecordKind, WALK_BYTES, WALK_LIMIT},
    lock::{LockWait, wait_for_worktree_lock},
};
use kit_core::{
    hash::Hash,
    layout::RepoLayout,
    protocol::{PACK_BODY_LIMIT, PackKey},
    refs::ATTESTMAP_REF,
    store::ObjectStore,
};
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

#[derive(Clone, Copy)]
pub(crate) enum Snapshot {
    Unavailable,
    Unsupported,
    Read(Option<Hash>),
}
impl Snapshot {
    pub(crate) fn head(self) -> Option<Hash> {
        match self {
            Self::Read(head) => head,
            Self::Unavailable | Self::Unsupported => None,
        }
    }
}

pub(crate) fn snapshot(
    source: &dyn RemoteSource,
    options: &SyncOptions,
    report: &mut FetchReport,
) -> Snapshot {
    if !options.attestations {
        return Snapshot::Read(None);
    }
    if !source.supports_attestations() {
        report
            .attestation_warnings
            .push("remote does not support attestations; skipped".into());
        return Snapshot::Unsupported;
    }
    match source.read_ref(ATTESTMAP_REF) {
        Ok(head) => Snapshot::Read(head),
        Err(error) => {
            report
                .attestation_warnings
                .push(format!("cannot read attestation log: {error}"));
            Snapshot::Unavailable
        }
    }
}

pub(crate) fn load_record(path: &Path) -> Record {
    kit_core::bounded_read::read_capped(path, 192 + 195 * WALK_LIMIT as u64)
        .ok()
        .and_then(|bytes| Record::decode(&bytes, RecordKind::Fetch))
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    store: &ObjectStore,
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    options: &SyncOptions,
    lock_wait: &LockWait,
    snapshot: Snapshot,
    report: &mut FetchReport,
) -> bool {
    if !options.attestations {
        return true;
    }
    if matches!(snapshot, Snapshot::Unsupported) {
        return true;
    }
    let Snapshot::Read(head) = snapshot else {
        return false;
    };
    let result = process(
        store, layout, source, observer, remote, options, lock_wait, head, report,
    );
    match result {
        Ok(()) => true,
        Err(error) => {
            report
                .attestation_warnings
                .push(format!("attestation fetch stopped: {error}"));
            false
        }
    }
}

type Failure = Box<dyn std::error::Error>;

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn process(
    store: &ObjectStore,
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    options: &SyncOptions,
    lock_wait: &LockWait,
    head: Option<Hash>,
    report: &mut FetchReport,
) -> Result<(), Failure> {
    let path = attestation_records::path(layout, source, remote, &options.remote_url, false);
    if options.refetch_attestations {
        match std::fs::remove_file(&path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    let mut record = load_record(&path);
    // A partial record can have no completed head. An absent remote log
    // still retires every pack of that interrupted walk.
    if head.is_none() && !record.ids.is_empty() {
        persist(&path, &Record::default())?;
        return Ok(());
    }
    let mut retry: BTreeSet<_> = record
        .pending
        .iter()
        .filter(|(_, subjects)| subjects.iter().any(|subject| store.contains(subject)))
        .map(|(pack, _)| *pack)
        .collect();
    if head == record.head && retry.is_empty() {
        return Ok(());
    }
    let mut packs = Vec::new();
    if head != record.head {
        match walk(source, observer, head, record.head) {
            Ok((new, baseline)) => {
                if baseline {
                    let listed: BTreeSet<_> = new.iter().copied().collect();
                    record.ids.retain(|id| listed.contains(id));
                    record.pending.retain(|id, _| listed.contains(id));
                    retry.retain(|id| listed.contains(id));
                }
                packs = new;
            }
            Err(error) => {
                if observer.cancelled()
                    || error.is::<std::io::Error>()
                    || error.downcast_ref::<crate::SourceError>().is_some_and(|e| {
                        !e.is_not_found() && !matches!(e, crate::SourceError::PayloadTooLarge(_))
                    })
                {
                    return Err(error);
                }
                report
                    .attestation_warnings
                    .push(format!("attestation chain skipped: {error}"));
                record.head = head;
                persist(&path, &record)?;
                return Ok(());
            }
        }
    }
    packs.extend(retry.iter().copied());
    let mut budget = kit_attest::pack::DecodeBudget::new(options.attestation_decode_bytes);
    let max = source
        .upload_limits()
        .max_pack_bytes
        .unwrap_or(PACK_BODY_LIMIT)
        .min(PACK_BODY_LIMIT);
    let mut deferred_compression = false;
    let mut pending_count: usize = record.pending.values().map(BTreeSet::len).sum();
    let mut visited = BTreeSet::new();
    for key in packs.into_iter().rev() {
        if !visited.insert(key) {
            continue;
        }
        if record.ids.contains(&key) && !retry.contains(&key) {
            continue;
        }
        if observer.cancelled() {
            persist(&path, &record)?;
            return Err("interrupted".into());
        }
        let rejected_before = report.attestations_rejected;
        let result = process_pack(
            store,
            layout,
            source,
            observer,
            lock_wait,
            key,
            max,
            &mut budget,
            report,
        );
        match result {
            Ok(missing) => {
                let others = pending_count - record.pending.get(&key).map_or(0, BTreeSet::len);
                let mut missing = missing;
                if others + missing.len() > WALK_LIMIT {
                    if !report
                        .attestation_warnings
                        .iter()
                        .any(|w| w == "attestation pending subject limit; excess subjects rejected")
                    {
                        report.attestation_warnings.push(
                            "attestation pending subject limit; excess subjects rejected".into(),
                        );
                    }
                    if report.attestations_rejected == rejected_before {
                        report.attestations_rejected += 1;
                    }
                    while missing.len() > WALK_LIMIT - others {
                        missing.pop_last();
                    }
                }
                pending_count = others + missing.len();
                record.pending.remove(&key);
                if !missing.is_empty() {
                    record.pending.insert(key, missing);
                }
                record.ids.insert(key);
            }
            Err(error) => {
                // Only a rejected payload is disposable. Network, storage and
                // budget failures must be retried with a fresh allowance.
                if let Some(error) = error.downcast_ref::<kit_attest::pack::PackError>() {
                    if matches!(
                        error,
                        kit_attest::pack::PackError::Pack(
                            kit_core::pack::PackError::CompressionUnavailable
                        )
                    ) {
                        deferred_compression = true;
                        report.attestation_warnings.push(error.to_string());
                        continue;
                    }
                    if matches!(
                        error,
                        kit_attest::pack::PackError::FetchBudget
                            | kit_attest::pack::PackError::Io(_)
                    ) {
                        persist(&path, &record)?;
                        return Err(error.to_string().into());
                    }
                    report.attestations_rejected += 1;
                    report
                        .attestation_warnings
                        .push(format!("rejected attestation pack: {error}"));
                    pending_count -= record
                        .pending
                        .remove(&key)
                        .map_or(0, |subjects| subjects.len());
                    record.ids.insert(key);
                } else {
                    persist(&path, &record)?;
                    return Err(error);
                }
            }
        }
    }
    if !deferred_compression {
        record.head = head;
    }
    persist(&path, &record)?;
    if deferred_compression {
        return Err("compressed attestations deferred until pack-zstd is available".into());
    }
    Ok(())
}

fn walk(
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    mut cursor: Option<Hash>,
    stop: Option<Hash>,
) -> Result<(Vec<Hash>, bool), Failure> {
    let mut nodes = BTreeSet::new();
    let mut packs = Vec::new();
    let mut remaining = WALK_BYTES;
    while let Some(key) = cursor {
        if Some(key) == stop {
            return Ok((packs, false));
        }
        if observer.cancelled() {
            return Err("interrupted".into());
        }
        if nodes.len() == WALK_LIMIT || !nodes.insert(key) {
            return Err("attestation node walk limit or cycle".into());
        }
        if remaining == 0 {
            return Err("attestation node byte budget".into());
        }
        let requested = PackKey::from_hash(key);
        let mut sink = kit_core::protocol::MemorySink::new(NODE_BOUND.min(remaining));
        source.download_pack(&requested, ATTESTMAP_REF, &mut sink)?;
        let bytes = sink.into_bytes()?;
        remaining = remaining
            .checked_sub(bytes.len() as u64)
            .ok_or("attestation node byte budget")?;
        requested.verify_bytes(&bytes)?;
        let node = kit_core::transfer::decode_packlist(&bytes)?;
        if packs.len() + node.packs.len() > WALK_LIMIT {
            return Err("attestation pack walk limit".into());
        }
        packs.extend(node.packs.into_iter().rev());
        cursor = node.prev;
    }
    Ok((packs, true))
}

fn persist(path: &Path, record: &Record) -> std::io::Result<()> {
    let mut bounded = record.clone();
    let excess = bounded.ids.len().saturating_sub(WALK_LIMIT);
    let removed: Vec<_> = bounded
        .ids
        .iter()
        .filter(|id| !bounded.pending.contains_key(*id))
        .take(excess)
        .copied()
        .collect();
    for id in removed {
        bounded.ids.remove(&id);
    }
    let record = &bounded;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::applied_packs::write_atomic(path, &record.encode(RecordKind::Fetch))
}

struct Reader<'a> {
    pack: &'a kit_core::pack::VerifiedPack,
    offset: u64,
}
impl Read for Reader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = usize::try_from(self.pack.len() - self.offset)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        self.pack.read_at(self.offset, &mut buf[..len])?;
        self.offset += len as u64;
        Ok(len)
    }
}

#[allow(clippy::too_many_arguments)]
fn process_pack(
    store: &ObjectStore,
    layout: &RepoLayout,
    source: &dyn RemoteSource,
    observer: &dyn Observer<SyncEvent>,
    lock_wait: &LockWait,
    key: Hash,
    max: u64,
    budget: &mut kit_attest::pack::DecodeBudget,
    report: &mut FetchReport,
) -> Result<BTreeSet<Hash>, Failure> {
    let mut spool = kit_core::pack::PackSpool::create(&store.spool_dir(), max)?;
    let downloaded = source.download_pack(&PackKey::from_hash(key), ATTESTMAP_REF, &mut spool);
    if let Some(kind) = spool.failed() {
        return Err(std::io::Error::from(kind).into());
    }
    downloaded.map_err(|error| -> Failure {
        match error {
            error if error.is_not_found() => {
                kit_attest::pack::PackError::Invalid("listed pack is missing").into()
            }
            crate::SourceError::PayloadTooLarge(_) => {
                kit_attest::pack::PackError::Invalid("wire size limit").into()
            }
            other => other.into(),
        }
    })?;
    if let Some(kind) = spool.failed() {
        return Err(std::io::Error::from(kind).into());
    }
    let pack = spool
        .finish(&PackKey::from_hash(key))
        .map_err(|error| -> Failure {
            match error {
                kit_core::pack::PackError::Io(error) => error.into(),
                kit_core::pack::PackError::UnexpectedEof => {
                    std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()
                }
                other => kit_attest::pack::PackError::from(other).into(),
            }
        })?;
    let mut staged = tempfile::tempfile_in(store.spool_dir())?;
    let mut staging_error = None;
    kit_attest::pack::read(
        &mut Reader {
            pack: &pack,
            offset: 0,
        },
        pack.len(),
        max,
        key,
        budget,
        |subject, id, bytes| {
            if staging_error.is_none() {
                staging_error = (|| {
                    staged.write_all(&subject)?;
                    staged.write_all(&id)?;
                    staged.write_all(&(bytes.len() as u64).to_le_bytes())?;
                    staged.write_all(bytes)
                })()
                .err();
            }
        },
    )?;
    if let Some(error) = staging_error {
        return Err(error.into());
    }
    save_staged(&mut staged, store, layout, observer, lock_wait, report)
}

struct StagedEnvelope {
    subject: Hash,
    id: Hash,
    bytes: Vec<u8>,
}

fn read_staged(staged: &mut std::fs::File, total: u64) -> Result<Option<StagedEnvelope>, Failure> {
    if staged.stream_position()? == total {
        return Ok(None);
    }
    let mut subject = [0; 32];
    let mut id = [0; 32];
    let mut len = [0; 8];
    staged.read_exact(&mut subject)?;
    staged.read_exact(&mut id)?;
    staged.read_exact(&mut len)?;
    let len = usize::try_from(u64::from_le_bytes(len))?;
    if len > kit_attest::store::MAX_ENVELOPE_SIZE {
        return Err("staged envelope size limit".into());
    }
    let mut bytes = vec![0; len];
    staged.read_exact(&mut bytes)?;
    Ok(Some(StagedEnvelope { subject, id, bytes }))
}

fn save_staged(
    staged: &mut std::fs::File,
    store: &ObjectStore,
    layout: &RepoLayout,
    observer: &dyn Observer<SyncEvent>,
    lock_wait: &LockWait,
    report: &mut FetchReport,
) -> Result<BTreeSet<Hash>, Failure> {
    staged.seek(SeekFrom::Start(0))?;
    let _lock = wait_for_worktree_lock(layout, observer, lock_wait)?;
    let total = staged.metadata()?.len();
    let mut prepared = BTreeSet::new();
    let mut missing = BTreeSet::new();
    let mut overflow = false;
    while let Some(entry) = read_staged(staged, total)? {
        if observer.cancelled() {
            return Err("interrupted".into());
        }
        if !store.contains(&entry.subject) {
            if missing.len() < WALK_LIMIT {
                missing.insert(entry.subject);
            } else if !missing.contains(&entry.subject) {
                if !overflow {
                    report.attestations_rejected += 1;
                    overflow = true;
                }
                if !report
                    .attestation_warnings
                    .iter()
                    .any(|w| w == "attestation pending subject limit; excess subjects rejected")
                {
                    report
                        .attestation_warnings
                        .push("attestation pending subject limit; excess subjects rejected".into());
                }
                continue;
            }
            report.attestations_dropped += 1;
            continue;
        }
        // Existing envelopes retain their provenance and require no writes.
        if kit_attest::store::envelope_path(layout, &entry.subject, &entry.id).try_exists()? {
            continue;
        }
        if !prepared.insert(entry.id) {
            continue;
        }
        let marker = attestation_records::fetched_path(layout, &entry.id);
        let parent = marker.parent().ok_or("missing provenance directory")?;
        std::fs::create_dir_all(parent)?;
        let file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::OpenOptions::new().write(true).open(&marker)?
            }
            Err(error) => return Err(error.into()),
        };
        file.sync_all()?;
    }
    if prepared.is_empty() {
        return Ok(missing);
    }
    // Every marker and its ancestor directory is durable before any envelope
    // becomes visible. Directory syncs are shared by this pack's markers.
    crate::applied_packs::sync_parent_dir(&layout.attestations_dir().join(".fetched"))?;
    crate::applied_packs::sync_parent_dir(&layout.attestations_dir())?;
    crate::applied_packs::sync_parent_dir(layout.common_dir())?;
    staged.seek(SeekFrom::Start(0))?;
    while let Some(entry) = read_staged(staged, total)? {
        if observer.cancelled() {
            return Err("interrupted".into());
        }
        if prepared.remove(&entry.id) {
            kit_attest::store::save(layout, &entry.subject, &entry.bytes)?;
            report.attestations_stored += 1;
        }
    }
    Ok(missing)
}
