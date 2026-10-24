//! Capped reads of state files under `.kit`.
//!
//! A hostile repository controls the files in its `.kit` directory. A read
//! that sizes its buffer from the file, or that trusts an earlier `stat`,
//! lets that repository exhaust memory. These helpers read at most
//! `limit + 1` bytes from the open file. They fail if the file is longer
//! than `limit`, even when it grew after a `stat`.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Read all of `path`, failing when it holds more than `limit` bytes.
///
/// A missing file returns the `NotFound` error of the open call. Callers
/// that treat absence as a normal state match on that kind.
///
/// # Errors
/// The file cannot be opened or read, or it exceeds `limit` bytes. The
/// size error has kind [`io::ErrorKind::InvalidData`].
pub fn read_capped(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    read_capped_from(File::open(path)?, limit)
}

/// Read all of `reader`, failing when it yields more than `limit` bytes.
///
/// Use this when the caller already holds the open file, for example to
/// keep a lock while it reads.
///
/// # Errors
/// The reader fails, or it yields more than `limit` bytes. The size error
/// has kind [`io::ErrorKind::InvalidData`].
pub fn read_capped_from<R: Read>(reader: R, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "state file exceeds its size limit",
        ));
    }
    Ok(bytes)
}

/// Read all of `path` as UTF-8 text, failing when it holds more than
/// `limit` bytes.
///
/// # Errors
/// As [`read_capped`]. Text that is not valid UTF-8 has kind
/// [`io::ErrorKind::InvalidData`].
pub fn read_capped_string(path: &Path, limit: u64) -> io::Result<String> {
    String::from_utf8(read_capped(path, limit)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "state file is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_file_at_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        std::fs::write(&path, b"abcd").unwrap();
        assert_eq!(read_capped(&path, 4).unwrap(), b"abcd");
        assert_eq!(read_capped_string(&path, 4).unwrap(), "abcd");
    }

    #[test]
    fn rejects_a_file_over_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        std::fs::write(&path, b"abcde").unwrap();
        let err = read_capped(&path, 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_zero_limit_accepts_only_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        std::fs::write(&path, b"").unwrap();
        assert!(read_capped(&path, 0).unwrap().is_empty());
        std::fs::write(&path, b"x").unwrap();
        assert!(read_capped(&path, 0).is_err());
    }

    #[test]
    fn reads_from_an_open_reader_under_the_limit() {
        assert_eq!(read_capped_from(&b"abc"[..], 3).unwrap(), b"abc");
        assert!(read_capped_from(&b"abcd"[..], 3).is_err());
    }

    #[test]
    fn rejects_text_that_is_not_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        let err = read_capped_string(&path, 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_missing_file_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_capped(&dir.path().join("absent"), 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn stops_reading_an_unbounded_source() {
        // `/dev/zero` never ends. The read must stop at the limit.
        let err = read_capped(Path::new("/dev/zero"), 1024).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
