#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]

mod budget;
mod io;
mod packs;
mod refs;
mod repo;
mod session;
mod upload;
mod verbs;

pub use budget::{MAX_BYTES_PER_CONN, MAX_FRAMES_PER_CONN, frame_byte_estimate, upload_limits};
pub use io::{ReadFrames, WriteFrames};
pub use packs::DOWNLOAD_CHUNK_MAX;
pub use refs::{MAX_REF_NAME_BYTES, REF_NAME_OUTSIDE_REFS, REF_NAME_TOO_LONG, is_served_ref_name};
pub use repo::{OpenError, RefUpdate, Repo, WritePolicy};
pub use session::{FrameIoError, FrameSink, FrameSource, SessionConfig, SessionEnd, serve_session};
pub use upload::UploadLimits;
pub use verbs::cas_conflict_body;
