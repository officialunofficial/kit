//! Optional publication of locally authored, subject-bound envelopes.
use super::{PushContext, PushOptions, PushReport};
use crate::{
    SourceError,
    attestation_records::{self, NODE_BOUND, Record, RecordKind, WALK_LIMIT},
};
use kit_core::{
    hash::{self, Hash},
    layout::RepoLayout,
    protocol::{MemorySink, PACK_BODY_LIMIT, PackKey, SliceBody},
    refs::{ATTESTMAP_REF, RefWriteCondition},
    store::ObjectStore,
    transfer::{
        self,
        walk::{HeldCommits, PushWalk},
    },
};
use std::collections::BTreeSet;

type Failure = Box<dyn std::error::Error>;

pub(super) fn run(
    layout: &RepoLayout,
    store: &ObjectStore,
    tx: &PushContext<'_>,
    options: &PushOptions<'_>,
    report: &mut PushReport,
) {
    if !tx.supports_attestations() {
        report
            .attestation_warnings
            .push("remote does not support attestations; skipped".into());
        return;
    }
    if let Err(error) = publish(layout, store, tx, options, report) {
        report
            .attestation_warnings
            .push(format!("attestation push stopped: {error}"));
    }
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
        let Some(subject) = entry.file_name().to_str().and_then(|name| refs_hash(name)) else { continue; };
        for path in kit_attest::store::list(layout, &subject)? {
            let Some(id) = path.file_stem().and_then(|s| s.to_str()).and_then(refs_hash) else { continue; };
            if record.ids.contains(&id) || fetched(layout, &id)? { continue; }
            candidates.push((subject, id, path));
        }
    }
    if candidates.is_empty() { return Ok(()); }
    let tips: Vec<_> = tx.list_branches()?.into_iter().chain(tx.list_refs("refs/tags/")?)
        .filter_map(|r| r.hash).filter(|h| store.contains(h)).collect();
    let mut reachable = BTreeSet::new();
    // Commit and tag subjects need no tree/blob walk. Other subjects use the
    // full object walk only when at least one pending envelope names them.
    let needs_objects = candidates.iter().any(|(subject, _, _)| !matches!(
        store.read_object(subject), Ok(kit_core::object::Object::Commit(_) | kit_core::object::Object::Remix(_) | kit_core::object::Object::Tag(_))));
    if needs_objects {
        reachable.extend(PushWalk::run_tips(store, &tips, &HeldCommits::default(), transfer::WalkLimits::default(), None)?.objects());
    } else {
        let mut stack = tips;
        while let Some(id) = stack.pop() {
            if !reachable.insert(id) { continue; }
            if reachable.len() > transfer::MAX_PUSH_WALK { return Err("attestation subject walk limit".into()); }
            match store.read_object(&id) {
                Ok(kit_core::object::Object::Commit(value)) => stack.extend(value.parents),
                Ok(kit_core::object::Object::Remix(value)) => stack.extend(value.parents),
                Ok(kit_core::object::Object::Tag(value)) => stack.push(value.target),
                Ok(_) | Err(_) => (),
            }
        }
    }
    let mut pending = Vec::new();
    for (subject, expected, path) in candidates {
        if !reachable.contains(&subject) { continue; }
        let checked = (|| -> Result<(Hash, bool), Failure> {
            let bytes = kit_core::bounded_read::read_capped(&path, kit_attest::store::MAX_ENVELOPE_SIZE as u64)?;
            let id = hash::hash(&bytes);
            if id != expected { return Err("attestation filename digest mismatch".into()); }
            if fetched(layout, &id)? { return Err("envelope was recorded as fetched".into()); }
            // Use exactly the pack encoder's stricter in-toto validation.
            kit_attest::pack::build(&[&bytes], PACK_BODY_LIMIT)?;
            let env = kit_attest::envelope::decode_expecting(&bytes, kit_attest::envelope::PAYLOAD_TYPE_IN_TOTO)?;
            if kit_attest::verify::extract_primary_commit_hash(&env.payload)? != subject {
                return Err("attestation subject differs from its directory".into());
            }
            let statement: serde_json::Value = serde_json::from_slice(&env.payload)?;
            let unsafe_mirror = statement.get("predicateType").and_then(serde_json::Value::as_str).is_some_and(|s| s.ends_with("/git-bridge/v1"))
                && statement.pointer("/predicate/mirror").and_then(serde_json::Value::as_str).is_some_and(|s| s.contains('@') || !s.contains("://"));
            Ok((id, unsafe_mirror))
        })();
        match checked {
            Ok((id, unsafe_mirror)) => {
                if unsafe_mirror { report.attestation_warnings.push("git-bridge envelope publishes a mirror containing user information or a local path".into()); }
                pending.push((id, path));
            }
            Err(error) => report.attestation_warnings.push(format!("skipped invalid local attestation: {error}")),
        }
    }
    if pending.is_empty() { return Ok(()); }
    let max = tx
        .upload_limits()
        .max_pack_bytes
        .unwrap_or(PACK_BODY_LIMIT)
        .min(PACK_BODY_LIMIT);
    let mut batch = Batch::new(max);
    let mut added = Vec::new();
    for (expected, path) in &pending {
        let bytes =
            kit_core::bounded_read::read_capped(path, kit_attest::store::MAX_ENVELOPE_SIZE as u64)?;
        if hash::hash(&bytes) != *expected {
            return Err("candidate changed during push".into());
        }
        // Recheck provenance after reading: a concurrent fetch must never promote bytes.
        if std::fs::symlink_metadata(attestation_records::fetched_path(
            layout,
            &hash::hash(&bytes),
        ))
        .is_ok()
        {
            return Err("candidate was recorded as fetched; retry push".into());
        }
        batch.add(bytes, tx, &mut added)?;
    }
    batch.flush(tx, &mut added)?;
    for _ in 0..super::packmap::PACKMAP_CAS_ATTEMPTS {
        if tx.observer.cancelled() {
            return Err("interrupted".into());
        }
        let prior = tx.read_ref(ATTESTMAP_REF)?;
        let (depth, mut packs) = chain(tx, prior)?;
        let new: Vec<_> = added
            .iter()
            .copied()
            .filter(|id| !packs.contains(id))
            .collect();
        if new.is_empty() {
            break;
        }
        packs.extend_from_slice(&new);
        let compact = packs.len() > 4096;
        if compact
            && options
                .control
                .authority
                .is_some_and(|a| !a.can_compact_attestations())
        {
            return Err(
                "attestation log needs compaction, which requires the f permission; skipped".into(),
            );
        }
        let (prev, listed) = if compact {
            (None, compact_packs(tx, &packs, max, &mut report.attestation_warnings)?)
        } else if depth >= 64 {
            (None, packs)
        } else {
            (prior, new)
        };
        if listed.len() > 4096 {
            return Err("compacted attestation log exceeds 4096 packs".into());
        }
        if !record.warned {
        report.attestation_warnings.push("publishing attestations is permanent; removal requires resetting the log with force permission".into());
        record.warned = true;
        persist(&path, &record)?;
    }
        let bytes = transfer::encode_packlist(prev, &listed)?;
        let key = PackKey::from_hash(hash::hash(&bytes));
        tx.upload_blob(&bytes, &key, ATTESTMAP_REF)?;
        let keys: Vec<_> = listed
            .into_iter()
            .map(PackKey::from_hash)
            .chain(std::iter::once(key))
            .collect();
        match tx.write_attestmap(
            prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
            &key.0,
            &keys,
        ) {
            Ok(()) => {
                report.attestations_pushed = pending.len();
                record.ids.extend(pending.iter().map(|(id, _)| *id));
                persist(&path, &record)?;
                return Ok(());
            }
            Err(SourceError::RefConflict) => (),
            Err(SourceError::AccessDenied) if compact => {
                return Err("attestation compaction requires f permission; skipped".into());
            }
            Err(error) => return Err(error.into()),
        }
    }
    // Also covers a lost write response followed by a concurrent append.
    let (_, packs) = chain(tx, tx.read_ref(ATTESTMAP_REF)?)?;
    if added.iter().all(|id| packs.contains(id)) {
        report.attestations_pushed = pending.len();
        record.ids.extend(pending.iter().map(|(id, _)| *id));
        persist(&path, &record)?;
        return Ok(());
    }
    Err("attestation log remained busy after eight attempts".into())
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
        keys: &mut Vec<Hash>,
    ) -> Result<(), Failure> {
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
    fn flush(&mut self, tx: &PushContext<'_>, keys: &mut Vec<Hash>) -> Result<(), Failure> {
        if self.bytes.is_empty() {
            return Ok(());
        }
        if tx.observer.cancelled() {
            return Err("interrupted".into());
        }
        let inputs: Vec<_> = self.bytes.iter().map(Vec::as_slice).collect();
        let bytes = kit_attest::pack::build(&inputs, self.max)?;
        let id = hash::hash(&bytes);
        let key = PackKey::from_hash(id);
        if !tx.pack_exists(&key, ATTESTMAP_REF)? {
            tx.upload_pack(&SliceBody(&bytes), &key, ATTESTMAP_REF)?;
        }
        keys.push(id);
        self.bytes.clear();
        self.size = 44;
        self.decoded = 0;
        Ok(())
    }
}

fn compact_packs(tx: &PushContext<'_>, packs: &[Hash], max: u64) -> Result<Vec<Hash>, Failure> {
    let mut seen = BTreeSet::new();
    let mut batch = Batch::new(max);
    let mut keys = Vec::new();
    for id in packs.iter().collect::<BTreeSet<_>>() {
        let mut spool = kit_core::pack::PackSpool::create(&tx.spool_dir, PACK_BODY_LIMIT)?;
        match tx.download_pack(&PackKey::from_hash(*id), ATTESTMAP_REF, &mut spool) {
            Ok(()) => (),
            Err(error) if error.is_not_found() => {
                warnings.push("discarded missing attestation pack during compaction".into());
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        let pack = match spool.finish(&PackKey::from_hash(*id)) {
            Ok(pack) => pack,
            Err(kit_core::pack::PackError::Io(error)) => return Err(error.into()),
            Err(_) => {
                warnings.push("discarded invalid attestation pack during compaction".into());
                continue;
            }
        };
        // Validate the entire pack before adding any of its envelopes.
        match kit_attest::pack::read(&mut Reader { pack: &pack, offset: 0 }, pack.len(), PACK_BODY_LIMIT, *id,
            &mut kit_attest::pack::DecodeBudget::default(), |_, _, _| {}) {
            Ok(()) => (),
            Err(kit_attest::pack::PackError::Io(error)) => return Err(error.into()),
            Err(_) => {
                warnings.push("discarded invalid attestation pack during compaction".into());
                continue;
            }
        }
        let mut error = None;
        kit_attest::pack::read(
            &mut Reader {
                pack: &pack,
                offset: 0,
            },
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
                    error = batch.add(bytes.to_vec(), tx, &mut keys).err();
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
