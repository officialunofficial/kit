//! The full flush of a file or directory: the call that makes its bytes or
//! its entries durable on the device.
//!
//! The full flushes of the objects, refs, index, fetch records, config and recovery log go through
//! [`file`], so a test can count what the commands of the edit loop flush. With the `fault-injection` feature,
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
        if let Some(path) = std::env::var_os("KIT_FLUSH_LOG") {
            append_line(std::path::Path::new(&path), &callers());
        }
    }
    file.sync_all()
}

/// The repository functions on the stack, innermost first, so a test that
/// counts a command's flushes can say which calls made them.
#[cfg(feature = "fault-injection")]
fn callers() -> String {
    std::backtrace::Backtrace::force_capture()
        .to_string()
        .lines()
        .filter_map(|line| line.split_once(": ").map(|(_, name)| name.trim()))
        .filter(|name| name.starts_with("kit") || name.starts_with("libkit"))
        .filter(|name| !name.starts_with("kit_core::flush"))
        .take(6)
        .collect::<Vec<_>>()
        .join(" < ")
}

/// Append the line of one flush, with its `callers`, to the log at `path`; a
/// log that cannot be written is skipped, since it only serves tests.
#[cfg(feature = "fault-injection")]
fn append_line(path: &std::path::Path, callers: &str) {
    use std::io::Write as _;

    if let Ok(mut log) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
    {
        // One write, so processes that share the log do not interleave lines.
        let _ = log.write_all(format!("full {callers}\n").as_bytes());
    }
}

#[cfg(all(test, feature = "fault-injection"))]
mod tests {
    use super::*;
    use crate::fault::flushes;

    #[test]
    fn each_call_is_one_counted_flush() {
        let dir = tempfile::tempdir().unwrap();
        let handle = File::create(dir.path().join("f")).unwrap();
        let before = flushes();
        file(&handle).unwrap();
        assert_eq!(flushes(), before + 1);
        file(&handle).unwrap();
        assert_eq!(flushes(), before + 2);
    }

    #[test]
    fn each_flush_appends_one_line_to_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("flushes");
        append_line(&log, "a < b");
        append_line(&log, &callers());
        let text = std::fs::read_to_string(&log).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.lines().all(|line| line.starts_with("full ")));
    }
}
