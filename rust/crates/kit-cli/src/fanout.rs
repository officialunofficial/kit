//! Shared fan-out sizing helper, plus the two "sequential below a
//! threshold, parallel at or above it" dispatch shapes every
//! per-item fan-out in this crate uses. The implementation lives in
//! `kit-sync` (its fetch-side signature verification and restore use the
//! same shapes); this module re-exports it so call sites keep one path.

pub(crate) use kit_sync::fanout::{map_seq_or_par, threshold, try_map_seq_or_par};
