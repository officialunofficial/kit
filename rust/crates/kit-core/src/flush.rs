//! The full flush of a file or directory: the call that makes its bytes or
//! its entries durable on the device.
//!
//! Every full flush of the repository code goes through [`file`], so a test
//! can count what a command flushes. With the `fault-injection` feature,
//! `fault::flushes` counts the flushes of a thread, and a process whose
//! environment sets `KIT_FLUSH_LOG` to a path appends one line to that file
//! for each full flush of any thread, so a test that runs the binary counts
//! the lines. Without the feature, [`file`] is `sync_all` and the environment
//! is not read. A per-file writeout that a later full flush covers
//! (`fsync(2)` on Apple, `fdatasync` on Linux) is not a full flush and is not
//! counted.

use std::fs::File;
use std::io;

/// Flush `file` and the device cache behind it.
///
/// # Errors
/// The flush failed.
#[doc(hidden)]
pub fn file(file: &File) -> io::Result<()> {
    #[cfg(feature = "fault-injection")]
    {
        crate::fault::count_flush();
        log();
    }
    file.sync_all()
}

#[cfg(feature = "fault-injection")]
fn log() {
    use std::io::Write as _;

    if let Some(path) = std::env::var_os("KIT_FLUSH_LOG")
        && let Ok(mut log) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
    {
        // One write, so processes that share the log do not interleave lines.
        let _ = log.write_all(b"full\n");
    }
}
