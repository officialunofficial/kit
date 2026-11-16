//! Bounded attestation reads, isolated from object application and its caches.
use crate::{
    FetchReport, Observer, RemoteSource, SyncEvent, SyncOptions,
    attestation_records::{self, NODE_BOUND, Record, RecordKind, WALK_LIMIT},
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
    kit_core::bounded_read::read_capped(path, 192 + 65 * WALK_LIMIT as u64)
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
    if matches!(snapshot, Snapshot::Unsupported) { return true; }
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
    if head == record.head && (head.is_some() || record.ids.is_empty()) {
        return Ok(());
    }
    // Enumerate before replacing the checkpoint: removed packs must not accumulate
    // across compactions, even when payload work is deferred by the budget.
    let mut nodes = BTreeSet::new();
    let mut packs = Vec::new();
    let mut cursor = head;
    while let Some(key) = cursor {
        if observer.cancelled() {
            return Err("interrupted".into());
        }
        if nodes.len() == WALK_LIMIT || !nodes.insert(key) {
            return Err("attestation node walk limit or cycle".into());
        }
        let requested = PackKey::from_hash(key);
        let mut sink = kit_core::protocol::MemorySink::new(NODE_BOUND);
        source.download_pack(&requested, ATTESTMAP_REF, &mut sink)?;
        let bytes = sink.into_bytes()?;
        if bytes.len() as u64 > NODE_BOUND {
            return Err("attestation node size limit".into());
        }
        requested.verify_bytes(&bytes)?;
        let node = kit_core::transfer::decode_packlist(&bytes)?;
        if packs.len() + node.packs.len() > WALK_LIMIT {
            return Err("attestation pack walk limit".into());
        }
        packs.extend(node.packs.into_iter().rev());
        cursor = node.prev;
    }
    let listed: BTreeSet<_> = packs.iter().copied().collect();
    record.ids.retain(|id| listed.contains(id));
    record.head = None;
    let mut budget = kit_attest::pack::DecodeBudget::new(options.attestation_decode_bytes);
    let max = source
        .upload_limits()
        .max_pack_bytes
        .unwrap_or(PACK_BODY_LIMIT)
        .min(PACK_BODY_LIMIT);
    for key in packs.into_iter().rev() {
        if record.ids.contains(&key) {
            continue;
        }
        if observer.cancelled() {
            persist(&path, &record)?;
            return Err("interrupted".into());
        }
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
            Ok(()) => {
                record.ids.insert(key);
            }
            Err(error) => {
                // Only a rejected payload is disposable. Network, storage and
                // budget failures must be retried with a fresh allowance.
                if let Some(error) = error.downcast_ref::<kit_attest::pack::PackError>() {
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
                    record.ids.insert(key);
                } else {
                    persist(&path, &record)?;
                    return Err(error);
                }
            }
        }
    }
    record.head = head;
    persist(&path, &record)?;
    Ok(())
}

fn persist(path: &Path, record: &Record) -> std::io::Result<()> {
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
) -> Result<(), Failure> {
    let mut spool = kit_core::pack::PackSpool::create(&store.spool_dir(), max)?;
    let downloaded = source.download_pack(&PackKey::from_hash(key), ATTESTMAP_REF, &mut spool);
    if let Some(kind) = spool.failed() {
        return Err(std::io::Error::from(kind).into());
    }
    downloaded.map_err(|error| -> Failure {
        match error {
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
                kit_core::pack::PackError::UnexpectedEof => std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into(),
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
    staged.seek(SeekFrom::Start(0))?;
    let _lock = wait_for_worktree_lock(layout, observer, lock_wait)?;
    let total = staged.metadata()?.len();
    while staged.stream_position()? < total {
        if observer.cancelled() {
            return Err("interrupted".into());
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
        if !store.contains(&subject) {
            report.attestations_dropped += 1;
            continue;
        }
        let marker = attestation_records::fetched_path(layout, &id);
        // An envelope already made here keeps its local authorship when it
        // returns through a remote. Metadata errors never confer authorship.
        if kit_attest::store::envelope_path(layout, &subject, &id).try_exists()?
            && !marker.try_exists()? { continue; }
        let parent = marker.parent().ok_or("missing provenance directory")?;
        std::fs::create_dir_all(parent)?;
        crate::applied_packs::write_atomic(&marker, b"")?;
        crate::applied_packs::sync_parent_dir(&layout.attestations_dir())?;
        crate::applied_packs::sync_parent_dir(layout.common_dir())?;
        kit_attest::store::save(layout, &subject, &bytes)?;
        report.attestations_stored += 1;
    }
    Ok(())
}
