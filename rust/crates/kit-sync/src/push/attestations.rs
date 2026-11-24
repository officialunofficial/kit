//! Optional publication of locally authored, subject-bound envelopes.
use super::{PushContext, PushError, PushOptions, PushReport};
use crate::{
    SourceError,
    attestation_records::{self, NODE_BOUND, Record, RecordKind, WALK_LIMIT},
};
use kit_core::{
    hash::{self, Hash},
    layout::RepoLayout,
    protocol::{MemorySink, PACK_BODY_LIMIT, PackBody, PackKey},
    refs::{ATTESTMAP_REF, RefWriteCondition},
    store::ObjectStore,
    transfer::{
        self,
        walk::{HeldCommits, PushWalk},
    },
};
use std::collections::{BTreeMap, BTreeSet};

type Failure = Box<dyn std::error::Error>;

pub(super) const PERMANENCE_WARNING: &str = "publishing attestations is permanent; removal requires resetting the log with force permission";

pub(super) fn run(
    layout: &RepoLayout,
    store: &ObjectStore,
    tx: &PushContext<'_>,
    options: &PushOptions<'_>,
    report: &mut PushReport,
) -> Result<(), PushError> {
    if !tx.supports_attestations() {
        report
            .attestation_warnings
            .push("remote does not support attestations; skipped".into());
        return Ok(());
    }
    let result = publish(layout, store, tx, options, report).and_then(|()| {
        let max = tx
            .upload_limits()
            .max_pack_bytes
            .unwrap_or(PACK_BODY_LIMIT)
            .min(PACK_BODY_LIMIT);
        compact_log(tx, options, max, &mut report.attestation_warnings, &[])
    });
    if let Err(error) = result {
        // An interrupt ends the push as one, not as a success with a warning.
        if tx.observer.cancelled() {
            return Err(crate::SyncError::Interrupted.into());
        }
        report
            .attestation_warnings
            .push(format!("attestation push stopped: {error}"));
    }
    Ok(())
}

fn persist(path: &std::path::Path, record: &Record) -> Result<(), Failure> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::applied_packs::write_atomic(path, &record.encode(RecordKind::Push))?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn publish(
    layout: &RepoLayout,
    store: &ObjectStore,
    tx: &PushContext<'_>,
    options: &PushOptions<'_>,
    report: &mut PushReport,
) -> Result<(), Failure> {
    let path = attestation_records::path(
        layout,
        tx.source,
        options.remote_name,
        &options.remote_url,
        true,
    );
    let mut record = kit_core::bounded_read::read_capped(
        &path,
        192 + 65 * attestation_records::PUSH_CACHE_IDS as u64,
    )
    .ok()
    .and_then(|bytes| Record::decode(&bytes, RecordKind::Push))
    .unwrap_or_default();
    let mut candidates = Vec::new();
    let entries = match std::fs::read_dir(layout.attestations_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let Some(subject) = entry.file_name().to_str().and_then(refs_hash) else {
            continue;
        };
        for path in kit_attest::store::list(layout, &subject)? {
            let Some(id) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(refs_hash)
            else {
                continue;
            };
            if record.ids.contains(&id) || fetched(layout, &id)? {
                continue;
            }
            candidates.push((subject, id, path));
        }
    }
    let before = candidates.len();
    candidates.retain(|(subject, _, _)| store.object_type(subject).is_ok());
    if candidates.len() < before {
        report.attestation_warnings.push(
            "skipped unreadable attestation subjects; restore their objects to publish them".into(),
        );
    }
    if candidates.is_empty() {
        return Ok(());
    }
    let tips: Vec<_> = tx
        .list_branches()?
        .into_iter()
        .chain(tx.list_refs("refs/tags/")?)
        .filter_map(|r| r.hash)
        .filter(|h| store.contains(h))
        .collect();
    let mut reachable = BTreeSet::new();
    // Commit and tag subjects need no tree/blob walk. Other subjects use the
    // full object walk only when at least one pending envelope names them.
    let needs_objects = candidates.iter().any(|(subject, _, _)| {
        !matches!(
            store.object_type(subject),
            Ok(kit_core::object::ObjectType::Commit
                | kit_core::object::ObjectType::Remix
                | kit_core::object::ObjectType::Tag)
        )
    });
    if needs_objects {
        match PushWalk::run_tips(
            store,
            &tips,
            &HeldCommits::default(),
            transfer::WalkLimits::default(),
            None,
        ) {
            Ok(walk) => reachable.extend(walk.objects()),
            Err(error) => report.attestation_warnings.push(format!(
                "cannot enumerate non-commit attestation subjects: {error}; skipped those subjects"
            )),
        }
    }
    if reachable.is_empty() {
        let mut stack = tips;
        while let Some(id) = stack.pop() {
            if !reachable.insert(id) {
                continue;
            }
            if reachable.len() > transfer::MAX_PUSH_WALK {
                return Err("attestation subject walk limit".into());
            }
            match store.read_object(&id) {
                Ok(kit_core::object::Object::Commit(value)) => stack.extend(value.parents),
                Ok(kit_core::object::Object::Remix(value)) => stack.extend(value.parents),
                Ok(kit_core::object::Object::Tag(value)) => stack.push(value.target),
                Ok(_) | Err(_) => {}
            }
        }
    }
    let mut pending = Vec::new();
    for (subject, expected, path) in candidates {
        if !reachable.contains(&subject) {
            continue;
        }
        let checked = (|| -> Result<(), Failure> {
            let bytes = kit_core::bounded_read::read_capped(
                &path,
                kit_attest::store::MAX_ENVELOPE_SIZE as u64,
            )?;
            let id = hash::hash(&bytes);
            if id != expected {
                return Err("attestation filename digest mismatch".into());
            }
            if fetched(layout, &id)? {
                return Err("envelope was recorded as fetched".into());
            }
            // Use exactly the pack encoder's stricter in-toto validation.
            kit_attest::pack::build(&[&bytes], PACK_BODY_LIMIT)?;
            let env = kit_attest::envelope::decode_expecting(
                &bytes,
                kit_attest::envelope::PAYLOAD_TYPE_IN_TOTO,
            )?;
            if kit_attest::verify::extract_primary_commit_hash(&env.payload)? != subject {
                return Err("attestation subject differs from its directory".into());
            }
            Ok(())
        })();
        match checked {
            Ok(()) => pending.push((expected, path)),
            Err(error) => report
                .attestation_warnings
                .push(format!("skipped invalid local attestation: {error}")),
        }
    }
    if pending.is_empty() {
        return Ok(());
    }
    let max = tx
        .upload_limits()
        .max_pack_bytes
        .unwrap_or(PACK_BODY_LIMIT)
        .min(PACK_BODY_LIMIT);
    let mut batch = Batch::new(max);
    let mut prepared = Vec::new();
    for (expected, path) in &pending {
        let bytes =
            kit_core::bounded_read::read_capped(path, kit_attest::store::MAX_ENVELOPE_SIZE as u64)?;
        if hash::hash(&bytes) != *expected || fetched(layout, expected)? {
            return Err("candidate changed during push".into());
        }
        batch.add(
            bytes,
            tx,
            &mut prepared,
            &mut report.attestation_warnings,
            "",
        )?;
    }
    batch.flush(tx, &mut prepared)?;
    let budget = tx
        .upload_limits()
        .data_packs_per_advance
        .unwrap_or(usize::MAX)
        .max(1);
    for group in prepared.chunks(budget) {
        let keys: Vec<_> = group.iter().map(|pack| pack.id).collect();
        let (_, existing) = chain(tx, tx.read_ref(ATTESTMAP_REF)?)?;
        if existing.len() + keys.len() > 4096
            && options
                .control
                .authority
                .is_some_and(|a| !a.can_compact_attestations())
        {
            return Err(
                "attestation log needs compaction, which requires the f permission; skipped".into(),
            );
        }
        if existing.len() + keys.len() > 4096 {
            compact_log(tx, options, max, &mut report.attestation_warnings, group)?;
        } else {
            for pack in group {
                pack.upload(tx)?;
            }
            append(tx, &keys, true)?;
        }
        if !record.warned {
            report.attestation_warnings.push(PERMANENCE_WARNING.into());
            tx.observer.event(&crate::SyncEvent::AttestationWarning {
                message: PERMANENCE_WARNING.into(),
            });
            record.warned = true;
        }
        for pack in group {
            report.attestations_pushed += pack.ids.len();
            record.ids.extend(&pack.ids);
        }
        persist(&path, &record)?;
    }
    Ok(())
}

// Append one ticket-sized group. A deep or large log can use one small linked
// node while compaction builds a replacement; each intermediate ref stays valid.
fn append(
    tx: &PushContext<'_>,
    added: &[Hash],
    rebaseline: bool,
) -> Result<(Hash, Vec<Hash>), Failure> {
    for _ in 0..super::packmap::PACKMAP_CAS_ATTEMPTS {
        let prior = tx.read_ref(ATTESTMAP_REF)?;
        let (depth, mut packs) = chain(tx, prior)?;
        let new: Vec<_> = added
            .iter()
            .copied()
            .filter(|id| !packs.contains(id))
            .collect();
        if new.is_empty() {
            return Ok((prior.ok_or("missing attestation head")?, packs));
        }
        if packs.len() + new.len() > WALK_LIMIT {
            return Err(
                "attestation append exceeds the reader walk limit; reset or compact the log first"
                    .into(),
            );
        }
        packs.extend_from_slice(&new);
        let baseline = rebaseline && depth >= 64 && packs.len() <= 4096;
        let bytes = transfer::encode_packlist(
            if baseline { None } else { prior },
            if baseline { &packs } else { &new },
        )?;
        match write_node(tx, prior, &bytes, &new) {
            Ok(head) => return Ok((head, packs)),
            Err(error)
                if error
                    .downcast_ref::<SourceError>()
                    .is_some_and(|e| matches!(e, SourceError::RefConflict)) => {}
            Err(error) => return Err(error),
        }
    }
    Err("attestation log remained busy after eight attempts".into())
}
fn write_node(
    tx: &PushContext<'_>,
    prior: Option<Hash>,
    bytes: &[u8],
    packs: &[Hash],
) -> Result<Hash, Failure> {
    if tx.observer.cancelled() {
        return Err("interrupted".into());
    }
    let id = hash::hash(bytes);
    let key = PackKey::new(id);
    tx.upload_blob(bytes, &key, ATTESTMAP_REF)?;
    let keys: Vec<_> = packs
        .iter()
        .copied()
        .map(PackKey::new)
        .chain(std::iter::once(key))
        .collect();
    tx.write_attestmap(
        prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
        &id,
        &keys,
    )?;
    Ok(id)
}
fn compact_log(
    tx: &PushContext<'_>,
    options: &PushOptions<'_>,
    max: u64,
    warnings: &mut Vec<String>,
    added: &[Prepared],
) -> Result<(), Failure> {
    for _ in 0..super::packmap::PACKMAP_CAS_ATTEMPTS {
        let prior = tx.read_ref(ATTESTMAP_REF)?;
        let (_, original) = chain(tx, prior)?;
        if original.len() + added.len() <= 4096 {
            if !added.is_empty() {
                for pack in added {
                    pack.upload(tx)?;
                }
                append(
                    tx,
                    &added.iter().map(|pack| pack.id).collect::<Vec<_>>(),
                    true,
                )?;
            }
            return Ok(());
        }
        if options
            .control
            .authority
            .is_some_and(|a| !a.can_compact_attestations())
        {
            return Err("attestation compaction requires f permission; skipped".into());
        }
        let prepared = compact_packs(tx, &original, added, max, warnings)?;
        if prepared.len() > 4096 {
            return Err("compacted attestation log exceeds 4096 packs".into());
        }
        if prepared.len()
            > tx.upload_limits()
                .data_packs_per_advance
                .unwrap_or(usize::MAX)
        {
            return Err(
                "attestation compaction exceeds the atomic upload ticket limit; skipped".into(),
            );
        }
        for pack in &prepared {
            pack.upload(tx)?;
        }
        let compacted: Vec<_> = prepared.iter().map(|pack| pack.id).collect();
        let bytes = transfer::encode_packlist(None, &compacted)?;
        match write_node(tx, prior, &bytes, &compacted) {
            Ok(_) => return Ok(()),
            Err(error)
                if error
                    .downcast_ref::<SourceError>()
                    .is_some_and(|e| matches!(e, SourceError::RefConflict)) => {}
            Err(error)
                if error
                    .downcast_ref::<SourceError>()
                    .is_some_and(|e| matches!(e, SourceError::AccessDenied) || matches!(e, SourceError::Remote(remote) if remote.code == "permission_denied")) =>
            {
                return Err("attestation compaction requires f permission; skipped".into());
            }
            Err(error) => return Err(error),
        }
    }
    Err("attestation compaction remained busy after eight attempts".into())
}

fn chain(tx: &PushContext<'_>, mut head: Option<Hash>) -> Result<(usize, Vec<Hash>), Failure> {
    let mut seen = BTreeSet::new();
    let mut packs = Vec::new();
    while let Some(id) = head {
        if tx.observer.cancelled() {
            return Err("interrupted".into());
        }
        if seen.len() == WALK_LIMIT || !seen.insert(id) {
            return Err("attestation node walk limit or cycle".into());
        }
        let key = PackKey::from_hash(id);
        let mut sink = MemorySink::new(NODE_BOUND);
        tx.download_pack(&key, ATTESTMAP_REF, &mut sink)?;
        let bytes = sink.into_bytes()?;
        key.verify_bytes(&bytes)?;
        let node = transfer::decode_packlist(&bytes)?;
        if packs.len() + node.packs.len() > WALK_LIMIT {
            return Err("attestation pack walk limit".into());
        }
        packs.extend(node.packs.into_iter().rev());
        head = node.prev;
    }
    packs.reverse();
    Ok((seen.len(), packs))
}

fn git_locator_issue(
    payload: &[u8],
) -> Result<Option<(&'static str, &'static str)>, serde_json::Error> {
    let statement: serde_json::Value = serde_json::from_slice(payload)?;
    let (kind, field) = match statement
        .get("predicateType")
        .and_then(serde_json::Value::as_str)
    {
        Some(kind) if kind.ends_with("/git-bridge/v1") => ("git-bridge", "/predicate/mirror"),
        Some(kind) if kind.ends_with("/git-import/v1") => ("git-import", "/predicate/remoteUrl"),
        _ => return Ok(None),
    };
    Ok(statement
        .pointer(field)
        .and_then(serde_json::Value::as_str)
        .and_then(locator_issue)
        .map(|reason| (kind, reason)))
}

fn locator_issue(locator: &str) -> Option<&'static str> {
    const LOCAL_PATH: &str = "contains a local path or ambiguous locator";
    if locator == "local" {
        return None;
    }
    let Some((scheme, rest)) = locator.split_once("://") else {
        return Some(LOCAL_PATH);
    };
    let mut scheme_bytes = scheme.bytes();
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if scheme.len() == 1
        || scheme.eq_ignore_ascii_case("file")
        || !scheme_bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme_bytes.all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
        || authority.is_empty()
        || path.starts_with(':')
        || locator.contains('\\')
    {
        return Some(LOCAL_PATH);
    }
    // An unexpected delimiter anywhere in a legacy locator can be part of a
    // malformed credential. Treat it as private even outside the authority.
    if locator.contains('?') {
        Some("contains a URL query")
    } else if locator.contains('#') {
        Some("contains a URL fragment")
    } else if locator.contains('@') || authority.contains('%') || !network_authority(authority) {
        Some("may contain URL userinfo")
    } else {
        None
    }
}

// Older imports could strip part of a credential as a query or fragment,
// leaving a non-port after the authority's colon.
fn network_authority(authority: &str) -> bool {
    let (host, port) = if let Some(address) = authority.strip_prefix('[') {
        let Some((host, port)) = address.split_once(']') else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        (host, port)
    } else {
        authority.split_at(authority.find(':').unwrap_or(authority.len()))
    };
    !host.is_empty()
        && (port.is_empty()
            || port.strip_prefix(':').is_some_and(|port| {
                !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
            }))
}

struct Batch {
    bytes: Vec<Vec<u8>>,
    size: u64,
    decoded: u64,
    max: u64,
}
impl Batch {
    fn new(max: u64) -> Self {
        Self {
            bytes: Vec::new(),
            size: 44,
            decoded: 0,
            max,
        }
    }
    fn add(
        &mut self,
        bytes: Vec<u8>,
        tx: &PushContext<'_>,
        keys: &mut Vec<Prepared>,
        warnings: &mut Vec<String>,
        warning_context: &str,
    ) -> Result<(), Failure> {
        // Check the exact bytes used to build new and compacted packs.
        let env = kit_attest::envelope::decode_expecting(
            &bytes,
            kit_attest::envelope::PAYLOAD_TYPE_IN_TOTO,
        )?;
        if let Some((kind, reason)) = git_locator_issue(&env.payload)? {
            let id = hash::to_hex(&hash::hash(&bytes));
            warnings.push(format!(
                "skipped {kind} attestation {id}{warning_context}: locator {reason}"
            ));
            return Ok(());
        }
        if self.size + bytes.len() as u64 + 15 > self.max
            || self.decoded + bytes.len() as u64 + 10 > kit_attest::pack::MAX_PACK_DECODED_BYTES
        {
            self.flush(tx, keys)?;
        }
        if 44 + bytes.len() as u64 + 15 > self.max {
            return Err("envelope exceeds remote pack cap".into());
        }
        self.size += bytes.len() as u64 + 15;
        self.decoded += bytes.len() as u64 + 10;
        self.bytes.push(bytes);
        Ok(())
    }
    fn flush(&mut self, tx: &PushContext<'_>, keys: &mut Vec<Prepared>) -> Result<(), Failure> {
        if self.bytes.is_empty() {
            return Ok(());
        }
        if tx.observer.cancelled() {
            return Err("interrupted".into());
        }
        let inputs: Vec<_> = self.bytes.iter().map(Vec::as_slice).collect();
        let bytes = kit_attest::pack::build(&inputs, self.max)?;
        let id = hash::hash(&bytes);
        let mut spool = kit_core::pack::PackSpool::create(&tx.spool_dir, self.max)?;
        spool.begin(Some(bytes.len() as u64))?;
        spool.write(&bytes)?;
        keys.push(Prepared {
            id,
            pack: spool.finish(&PackKey::new(id))?,
            ids: self.bytes.iter().map(|bytes| hash::hash(bytes)).collect(),
        });
        self.bytes.clear();
        self.size = 44;
        self.decoded = 0;
        Ok(())
    }
}

fn compact_packs(
    tx: &PushContext<'_>,
    packs: &[Hash],
    added: &[Prepared],
    max: u64,
    warnings: &mut Vec<String>,
) -> Result<Vec<Prepared>, Failure> {
    let mut seen = BTreeSet::new();
    let mut batch = Batch::new(max);
    let mut keys = Vec::new();
    let mut visited = BTreeSet::new();
    let local: BTreeMap<_, _> = added.iter().map(|pack| (pack.id, &pack.pack)).collect();
    for id in packs.iter().chain(local.keys()) {
        if !visited.insert(*id) {
            continue;
        }
        let remote_pack;
        let pack = if let Some(pack) = local.get(id) {
            *pack
        } else {
            let mut spool = kit_core::pack::PackSpool::create(&tx.spool_dir, PACK_BODY_LIMIT)?;
            match tx.download_pack(&PackKey::from_hash(*id), ATTESTMAP_REF, &mut spool) {
                Ok(()) => {}
                Err(error) if error.is_not_found() => {
                    warnings.push("discarded missing attestation pack during compaction".into());
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
            remote_pack = match spool.finish(&PackKey::from_hash(*id)) {
                Ok(pack) => pack,
                Err(kit_core::pack::PackError::Io(error)) => return Err(error.into()),
                Err(_) => {
                    warnings.push("discarded invalid attestation pack during compaction".into());
                    continue;
                }
            };
            &remote_pack
        };
        // Validate the entire pack before adding any of its envelopes.
        match kit_attest::pack::read(
            &mut Reader { pack, offset: 0 },
            pack.len(),
            PACK_BODY_LIMIT,
            *id,
            &mut kit_attest::pack::DecodeBudget::default(),
            |_, _, _| {},
        ) {
            Ok(()) => {}
            Err(kit_attest::pack::PackError::Io(error)) => return Err(error.into()),
            Err(
                error @ kit_attest::pack::PackError::Pack(
                    kit_core::pack::PackError::CompressionUnavailable,
                ),
            ) => return Err(error.into()),
            Err(_) => {
                warnings.push("discarded invalid attestation pack during compaction".into());
                continue;
            }
        }
        let mut error = None;
        kit_attest::pack::read(
            &mut Reader { pack, offset: 0 },
            pack.len(),
            PACK_BODY_LIMIT,
            *id,
            &mut kit_attest::pack::DecodeBudget::default(),
            |_, id, bytes| {
                if error.is_some() {
                    return;
                }
                if seen.len() == attestation_records::PUSH_CACHE_IDS {
                    error = Some("attestation compaction envelope limit".into());
                } else if seen.insert(id) {
                    error = batch
                        .add(
                            bytes.to_vec(),
                            tx,
                            &mut keys,
                            warnings,
                            " during compaction",
                        )
                        .err();
                }
            },
        )?;
        if let Some(error) = error {
            return Err(error);
        }
    }
    batch.flush(tx, &mut keys)?;
    Ok(keys)
}

struct Reader<'a> {
    pack: &'a kit_core::pack::VerifiedPack,
    offset: u64,
}
impl std::io::Read for Reader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = usize::try_from(self.pack.len() - self.offset)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        self.pack.read_at(self.offset, &mut buf[..len])?;
        self.offset += len as u64;
        Ok(len)
    }
}

fn refs_hash(name: &str) -> Option<Hash> {
    kit_core::refs::parse_lowercase_hash(name.as_bytes())
}
fn fetched(layout: &RepoLayout, id: &Hash) -> Result<bool, Failure> {
    match std::fs::symlink_metadata(attestation_records::fetched_path(layout, id)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

struct Prepared {
    id: Hash,
    pack: kit_core::pack::VerifiedPack,
    ids: Vec<Hash>,
}
impl Prepared {
    fn upload(&self, tx: &PushContext<'_>) -> Result<(), Failure> {
        let key = PackKey::new(self.id);
        // One existence check, as before. A pack that is there and whose
        // length the remote reports is skipped only at its own length, as for
        // a data pack; a remote that reports none (ssh, connect) keeps the
        // name-only skip and is asked nothing more.
        let whole = tx.pack_exists(&key, ATTESTMAP_REF)?
            && match tx.pack_len(&key, ATTESTMAP_REF) {
                Ok(Some(len)) => len == self.pack.len(),
                Ok(None) => true,
                Err(_) => false,
            };
        if !whole {
            tx.upload_pack(self, &key, ATTESTMAP_REF)?;
        }
        Ok(())
    }
}

impl PackBody for Prepared {
    fn len(&self) -> u64 {
        self.pack.len()
    }
    fn read_from(&self, offset: u64) -> std::io::Result<Box<dyn std::io::Read + Send + '_>> {
        if offset > self.pack.len() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        Ok(Box::new(Reader {
            pack: &self.pack,
            offset,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::RemoteSource;
    #[test]
    fn another_push_sweeping_spools_preserves_prepared_attestation_packs() {
        let temp = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(temp.path());
        let store = ObjectStore::init(&layout).unwrap();
        let transport = kit_transport_memory::MemoryTransport::new();
        let source = crate::TransportSource::new(&transport);
        let context = PushContext::new(&source, &crate::NoopObserver, &store);
        let bytes = include_bytes!("../../../../tests/golden/attest/envelope_basic.json");
        let mut batch = Batch::new(4096);
        let mut packs = Vec::new();
        batch
            .add(bytes.to_vec(), &context, &mut packs, &mut Vec::new(), "")
            .unwrap();
        batch.flush(&context, &mut packs).unwrap();
        kit_core::pack::sweep_spool_dir(&store.spool_dir());
        packs[0].upload(&context).unwrap();
        assert!(
            source
                .pack_exists(&PackKey::new(packs[0].id), ATTESTMAP_REF)
                .unwrap()
        );
    }
    /// A source over a memory remote that counts what a push asks of it and
    /// can report no pack length, as an ssh or connect remote does.
    struct Counting<'a> {
        inner: crate::TransportSource<'a>,
        uploads: std::cell::Cell<usize>,
        exists: std::cell::Cell<usize>,
        lengths: std::cell::Cell<usize>,
        knows_length: bool,
    }
    impl<'a> Counting<'a> {
        fn new(transport: &'a kit_transport_memory::MemoryTransport, knows_length: bool) -> Self {
            Self {
                inner: crate::TransportSource::new(transport),
                uploads: std::cell::Cell::new(0),
                exists: std::cell::Cell::new(0),
                lengths: std::cell::Cell::new(0),
                knows_length,
            }
        }
    }
    impl RemoteSource for Counting<'_> {
        fn list_branches(&self) -> Result<Vec<kit_core::refs::Ref>, SourceError> {
            self.inner.list_branches()
        }
        fn list_refs(&self, prefix: &str) -> Result<Vec<kit_core::refs::Ref>, SourceError> {
            self.inner.list_refs(prefix)
        }
        fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
            self.inner.read_ref(name)
        }
        fn download_blob(&self, key: &PackKey, hint: &str) -> Result<Vec<u8>, SourceError> {
            self.inner.download_blob(key, hint)
        }
        fn download_pack(
            &self,
            key: &PackKey,
            hint: &str,
            sink: &mut dyn kit_core::protocol::PackSink,
        ) -> Result<(), SourceError> {
            self.inner.download_pack(key, hint, sink)
        }
        fn pack_exists(&self, key: &PackKey, hint: &str) -> Result<bool, SourceError> {
            self.exists.set(self.exists.get() + 1);
            self.inner.pack_exists(key, hint)
        }
        fn pack_len(&self, key: &PackKey, hint: &str) -> Result<Option<u64>, SourceError> {
            self.lengths.set(self.lengths.get() + 1);
            if self.knows_length {
                self.inner.pack_len(key, hint)
            } else {
                Ok(None)
            }
        }
        fn upload_pack(
            &self,
            pack: &dyn PackBody,
            key: &PackKey,
            hint: &str,
        ) -> Result<(), SourceError> {
            self.uploads.set(self.uploads.get() + 1);
            self.inner.upload_pack(pack, key, hint)
        }
    }

    /// One prepared attestation pack, and the context that built it.
    fn prepared(store: &ObjectStore, source: &dyn RemoteSource) -> Prepared {
        let context = PushContext::new(source, &crate::NoopObserver, store);
        let bytes = include_bytes!("../../../../tests/golden/attest/envelope_basic.json");
        let mut batch = Batch::new(4096);
        let mut packs = Vec::new();
        batch
            .add(bytes.to_vec(), &context, &mut packs, &mut Vec::new(), "")
            .unwrap();
        batch.flush(&context, &mut packs).unwrap();
        packs.remove(0)
    }

    #[test]
    fn a_stored_attestation_pack_is_skipped_only_at_its_own_length_where_the_length_is_known() {
        use kit_core::protocol::Transport as _;
        let temp = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(temp.path());
        let store = ObjectStore::init(&layout).unwrap();
        let transport = kit_transport_memory::MemoryTransport::new();
        let source = Counting::new(&transport, true);
        let pack = prepared(&store, &source);
        let context = PushContext::new(&source, &crate::NoopObserver, &store);
        let key = PackKey::new(pack.id);
        let stored = || transport.pack_len(&key, None).unwrap();

        // Not stored: one existence check, no length check, uploaded.
        pack.upload(&context).unwrap();
        assert_eq!(source.uploads.get(), 1);
        assert_eq!((source.exists.get(), source.lengths.get()), (1, 0));
        assert_eq!(stored(), Some(pack.pack.len()));
        // Whole: skipped.
        pack.upload(&context).unwrap();
        assert_eq!(source.uploads.get(), 1);
        // Cut short by damage outside the push: uploaded again, and whole.
        transport
            .upload_pack(&kit_core::protocol::SliceBody(b"cut"), &key, None)
            .unwrap();
        pack.upload(&context).unwrap();
        assert_eq!(source.uploads.get(), 2);
        assert_eq!(stored(), Some(pack.pack.len()));
        // Longer than the local pack: uploaded again.
        let long = vec![0u8; usize::try_from(pack.pack.len()).unwrap() + 1];
        transport
            .upload_pack(&kit_core::protocol::SliceBody(&long), &key, None)
            .unwrap();
        pack.upload(&context).unwrap();
        assert_eq!(source.uploads.get(), 3);
        assert_eq!(stored(), Some(pack.pack.len()));
    }

    #[test]
    fn a_stored_attestation_pack_on_a_remote_with_no_length_keeps_the_name_only_skip() {
        let temp = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(temp.path());
        let store = ObjectStore::init(&layout).unwrap();
        let transport = kit_transport_memory::MemoryTransport::new();
        let source = Counting::new(&transport, false);
        let pack = prepared(&store, &source);
        let context = PushContext::new(&source, &crate::NoopObserver, &store);
        // Not stored: uploaded; stored: skipped, as before.
        pack.upload(&context).unwrap();
        pack.upload(&context).unwrap();
        assert_eq!(source.uploads.get(), 1);
        assert_eq!(source.exists.get(), 2);
    }

    #[test]
    fn append_never_publishes_a_chain_beyond_the_reader_walk_limit() {
        use kit_core::protocol::Transport as _;
        let temp = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(temp.path());
        let store = ObjectStore::init(&layout).unwrap();
        let transport = kit_transport_memory::MemoryTransport::new();
        let source = crate::TransportSource::new(&transport);
        let context = PushContext::new(&source, &crate::NoopObserver, &store);
        let mut prior = None;
        let mut left = WALK_LIMIT;
        while left > 0 {
            let count = left.min(4096);
            let node = transfer::encode_packlist(prior, &vec![[1; 32]; count]).unwrap();
            let id = hash::hash(&node);
            transport
                .upload_blob(&node, &PackKey::new(id), None)
                .unwrap();
            prior = Some(id);
            left -= count;
        }
        transport
            .update_ref(ATTESTMAP_REF, RefWriteCondition::Missing, &prior.unwrap())
            .unwrap();
        assert!(append(&context, &[[2; 32]], true).is_err());
        assert_eq!(transport.read_ref(ATTESTMAP_REF).unwrap(), prior);
    }
}
