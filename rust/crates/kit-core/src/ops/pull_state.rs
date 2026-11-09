//! The unfinished-pull record: target commit followed by the pre-pull tree.

use std::io;

use crate::hash::Hash;
use crate::layout::RepoLayout;
use crate::refs::{decode_ref_wire, encode_ref_wire};

/// Exact state needed to distinguish a partial restore from later staged work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PullState {
    /// Commit the pull is restoring.
    pub target: Hash,
    /// Tree proven to match the index before the pull moves refs.
    pub before_tree: Hash,
}

impl PullState {
    /// Two canonical 65-byte ref records: target, then pre-pull tree.
    #[must_use]
    pub fn encode(self) -> [u8; 130] {
        let mut bytes = [0; 130];
        bytes[..65].copy_from_slice(&encode_ref_wire(&self.target));
        bytes[65..].copy_from_slice(&encode_ref_wire(&self.before_tree));
        bytes
    }

    /// Decode exactly two canonical ref records. Reject every other shape.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 130 {
            return None;
        }
        let state = Self {
            target: decode_ref_wire(&bytes[..65])?,
            before_tree: decode_ref_wire(&bytes[65..])?,
        };
        (state.encode() == bytes).then_some(state)
    }

    /// Read the bounded worktree record, failing closed on malformed bytes.
    pub fn read(layout: &RepoLayout) -> io::Result<Option<Self>> {
        let bytes = match crate::bounded_read::read_capped(&layout.pull_head_file(), 130) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Self::decode(&bytes)
            .map(Some)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed PULL_HEAD"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_golden_and_all_other_shapes() {
        let bytes = include_bytes!("../../../../tests/golden/refs-index/pull_state.bin");
        let state = PullState {
            target: crate::hash::hash(b"refs-index-pull-target"),
            before_tree: crate::hash::hash(b"refs-index-pull-before-tree"),
        };
        assert_eq!(state.encode(), *bytes);
        assert_eq!(PullState::decode(bytes), Some(state));
        for len in 0..260 {
            if len != 130 {
                assert!(PullState::decode(&vec![b'a'; len]).is_none());
            }
        }
        for offset in 0..130 {
            let mut bad = *bytes;
            bad[offset] = b'G';
            assert!(PullState::decode(&bad).is_none());
        }
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        std::fs::create_dir(layout.worktree_state_dir()).unwrap();
        std::fs::write(layout.pull_head_file(), encode_ref_wire(&state.target)).unwrap();
        assert!(PullState::read(&layout).is_err());
    }
}
