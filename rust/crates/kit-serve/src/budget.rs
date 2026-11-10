//! Per-connection resource caps (SPEC-TRANSPORT §4.4).
//!
//! One remote client drives a session. Bounding its total work stops a
//! misbehaving client from pinning the serving process.

use kit_rpc::kit::rpc::v1::ssh::{SshFrame, ssh_frame};

use crate::upload::UploadLimits;

/// The most top-level frames a session reads after `Hello`. The chunk frames
/// of an upload do not count here. [`UploadLimits::max_chunks`] caps them.
pub const MAX_FRAMES_PER_CONN: u32 = 10_000;

/// The reply when a session sends more than [`MAX_FRAMES_PER_CONN`] frames.
/// It names the limit, so a client that hits it can tell why: a fetch costs
/// one frame for the listing and at least two per branch, so one session
/// fetches at most 4,999 branches (SPEC-TRANSPORT §4.4).
pub const FRAME_BUDGET_EXCEEDED: &str =
    "per-connection frame budget exceeded: at most 10000 frames per session (SPEC-TRANSPORT 4.4)";

/// The most estimated request bytes per session (1 GiB). See
/// [`frame_byte_estimate`]. It also caps the declared size of an upload.
pub const MAX_BYTES_PER_CONN: u64 = 1024 * 1024 * 1024;

/// The upload caps of the ssh wire.
#[must_use]
pub const fn upload_limits() -> UploadLimits {
    UploadLimits {
        max_total_bytes: MAX_BYTES_PER_CONN,
        max_chunks: MAX_FRAMES_PER_CONN,
    }
}

/// The cost of a frame against [`MAX_BYTES_PER_CONN`], without a re-encode.
/// A chunk costs its data length. A header costs the `total_bytes` it
/// declares. Any other frame costs 64. An upload is charged its declared
/// size once, by its header. The chunks it reads are not charged again.
#[must_use]
pub fn frame_byte_estimate(f: &SshFrame) -> u64 {
    use ssh_frame::Body;
    match &f.body {
        Some(Body::PackChunk(c)) => c.data.as_ref().map_or(0, Vec::len) as u64,
        Some(Body::UploadPack(h)) => h.total_bytes.unwrap_or(0),
        Some(Body::DownloadPackHeader(h)) => h.total_bytes.unwrap_or(0),
        _ => 64,
    }
}

/// The running totals of one session.
#[derive(Debug, Default)]
pub(crate) struct Budget {
    frames: u32,
    bytes: u64,
}

impl Budget {
    /// Charge one top-level frame.
    ///
    /// # Errors
    /// The reply text of the cap that the frame exceeds.
    pub(crate) fn charge(&mut self, frame: &SshFrame) -> Result<(), &'static str> {
        self.frames = self.frames.saturating_add(1);
        if self.frames > MAX_FRAMES_PER_CONN {
            return Err(FRAME_BUDGET_EXCEEDED);
        }
        self.bytes = self.bytes.saturating_add(frame_byte_estimate(frame));
        if self.bytes > MAX_BYTES_PER_CONN {
            return Err("per-connection byte budget exceeded");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frame_budget_reply_names_the_limit() {
        assert!(FRAME_BUDGET_EXCEEDED.contains(&MAX_FRAMES_PER_CONN.to_string()));
    }
}
