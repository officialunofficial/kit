//! The delta streams of one push, kept in one unnamed file.

use super::{DeltaBytes, DeltaCandidate, PlannedDelta};
use crate::hash::Hash;
use crate::store::{ObjectStore, StoreError};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

/// The delta streams one push encodes, in one unnamed file that lives until
/// the push ends, so a plan holds a stream's place rather than its bytes.
///
/// It remembers every `(target, base)` pair it has seen: the stream's place,
/// or that the delta was not worth sending. A push that plans several ranges
/// of a chain (split probing) encodes each pair once, however many plans
/// share it.
#[derive(Debug)]
pub struct DeltaSpool {
    file: Arc<File>,
    len: u64,
    seen: HashMap<(Hash, Hash), Option<(u64, u64)>>,
}

impl DeltaSpool {
    /// A spool in a new unnamed file in `dir`, which is created when it is
    /// missing.
    ///
    /// # Errors
    /// An I/O error creating the directory or the file.
    pub fn create(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            file: Arc::new(tempfile::tempfile_in(dir)?),
            len: 0,
            seen: HashMap::new(),
        })
    }

    /// A batch callback for [`super::plan_pack_with`]: one result per
    /// candidate, in order. Candidates this spool has not seen go to `encode`
    /// in one batch, and each stream it returns is written to the file. Every
    /// result refers to the file, so the streams are not held in memory once
    /// this returns.
    ///
    /// # Errors
    /// The error of `encode`, [`StoreError::DeltaBatchLengthMismatch`] when it
    /// returns a different count, or [`StoreError::Io`] writing the file.
    pub fn encode(
        &mut self,
        store: &ObjectStore,
        candidates: &[DeltaCandidate],
        encode: impl FnOnce(
            &ObjectStore,
            &[DeltaCandidate],
        ) -> Result<Vec<Option<PlannedDelta>>, StoreError>,
    ) -> Result<Vec<Option<PlannedDelta>>, StoreError> {
        let mut fresh = Vec::new();
        let mut listed = std::collections::HashSet::new();
        for candidate in candidates {
            let pair = (candidate.target, candidate.base);
            if !self.seen.contains_key(&pair) && listed.insert(pair) {
                fresh.push(*candidate);
            }
        }
        if !fresh.is_empty() {
            let results = encode(store, &fresh)?;
            if results.len() != fresh.len() {
                return Err(StoreError::DeltaBatchLengthMismatch {
                    expected: fresh.len(),
                    actual: results.len(),
                });
            }
            for (candidate, result) in fresh.iter().zip(results) {
                let place = match result {
                    Some(planned) => Some(self.append(&planned.stream.bytes()?)?),
                    None => None,
                };
                self.seen.insert((candidate.target, candidate.base), place);
            }
        }
        Ok(candidates
            .iter()
            .map(|candidate| {
                let place = self.seen.get(&(candidate.target, candidate.base))?;
                place.map(|(offset, len)| PlannedDelta {
                    target: candidate.target,
                    base: candidate.base,
                    stream: DeltaBytes::Spooled {
                        file: Arc::clone(&self.file),
                        offset,
                        len,
                    },
                })
            })
            .collect())
    }

    fn append(&mut self, stream: &[u8]) -> std::io::Result<(u64, u64)> {
        let offset = self.len;
        crate::pack::write_spooled(&self.file, offset, stream)?;
        self.len += stream.len() as u64;
        Ok((offset, stream.len() as u64))
    }
}
