//! Packs held in unnamed files rather than in memory.
//!
//! A pack a writer builds goes into a spool ([`PackWriter::spool`]) and comes
//! out sealed, with its length and key ([`SpooledPack`]). A pack a transfer
//! downloads goes into a [`PackSpool`], which checks the length, the key and
//! the trailer as the bytes arrive, and only then yields a [`VerifiedPack`]
//! for [`super::PackReader::read_verified`].
//!
//! Every spool is an unnamed temporary file in the directory its caller
//! names: only its handle reaches it, so nothing can change it after it is
//! checked, and on Unix nothing is left on disk when the process ends.

use super::window::WindowSource;
use super::{
    ENTRY_COUNT_OFFSET, HEADER_LEN, PackError, PackWriter, TRAILER_LEN, VERSION_OFFSET, hash,
    initial_header, note_hashed,
};
use crate::hash::Hash;
use crate::protocol::{PackBody, PackKey, PackSink, TransportError, TransportResult};
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Bytes a spool buffers before it writes them to its file, and the size of
/// each read when a sealed spool is hashed.
pub const SPOOL_BUFFER: usize = 1 << 20;

/// A writer that spools its pack to an unnamed file.
pub type SpoolWriter = PackWriter<BufWriter<File>>;

/// A new unnamed file in `dir`, which is created when it is missing.
fn unnamed_file(dir: &Path) -> io::Result<File> {
    std::fs::create_dir_all(dir)?;
    tempfile::tempfile_in(dir)
}

/// Remove every spool file left in the spool directory `dir`: the files
/// named as `tempfile` names them, `.tmp` and a random suffix.
///
/// Spools are unnamed, so on Unix nothing a spool wrote is ever listed here.
/// On Windows a spool is deleted when its handle closes, which a power loss
/// skips, so fetch, push and gc call this when they start. Deleting a spool
/// another process still holds open fails, and that failure is ignored, as
/// is a missing directory. A `dir` that is a symlink is left alone, so the
/// sweep never deletes outside the repository.
pub fn sweep_spool_dir(dir: &Path) {
    if !std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let spool_name = entry.file_name().to_string_lossy().starts_with(".tmp");
        if spool_name && entry.file_type().is_ok_and(|kind| kind.is_file()) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Fill `buf` from `file` at `offset`. Each call names its own offset, so
/// threads may read one file at once.
pub(crate) fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut buf, mut offset) = (buf, offset);
        while !buf.is_empty() {
            match file.seek_read(buf, offset) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _cursor = seek_lock();
        let mut file = file;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(buf)
    }
}

/// Write all of `bytes` to `file` at `offset`. Each call names its own
/// offset, so threads may use one file at once.
pub(crate) fn write_all_at(file: &File, offset: u64, bytes: &[u8]) -> io::Result<()> {
    #[cfg(feature = "fault-injection")]
    crate::fault::check(crate::fault::Site::Spool)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(bytes, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut bytes, mut offset) = (bytes, offset);
        while !bytes.is_empty() {
            match file.seek_write(bytes, offset) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(n) => {
                    bytes = &bytes[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _cursor = seek_lock();
        let mut file = file;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)
    }
}

/// Where a file has no positional I/O, a seek and the read or write after it
/// move the one cursor of a shared handle, so they run under one lock.
#[cfg(not(any(unix, windows)))]
fn seek_lock() -> std::sync::MutexGuard<'static, ()> {
    static CURSOR: std::sync::Mutex<()> = std::sync::Mutex::new(());
    CURSOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl SpoolWriter {
    /// A writer whose pack goes to a new unnamed file in `dir`, through a
    /// [`SPOOL_BUFFER`]-byte buffer. `dir` is created when it is missing.
    ///
    /// # Errors
    /// [`PackError::Io`] when the directory or the file cannot be created.
    pub fn spool(dir: &Path) -> Result<Self, PackError> {
        let mut out = BufWriter::with_capacity(SPOOL_BUFFER, unnamed_file(dir)?);
        out.write_all(&initial_header())?;
        Ok(Self::over(out))
    }

    /// Seal the spooled pack: patch the header's version and entry count in
    /// place, then make one sequential read pass over the file through one
    /// BLAKE3 hasher. The hasher gives the trailer when it has read the body,
    /// and the pack key once the trailer is fed to it too, so the pack is
    /// hashed once. The trailer is then appended.
    ///
    /// # Errors
    /// [`PackError::TooManyObjects`] past the entry cap, and
    /// [`PackError::Io`] when the file cannot be written or read back.
    pub fn finish_spool(self) -> Result<SpooledPack, PackError> {
        let fields = self.patched_header()?;
        let body_len = self.len;
        let mut file = self
            .out
            .into_inner()
            .map_err(io::IntoInnerError::into_error)?;
        write_all_at(&file, VERSION_OFFSET as u64, &fields)?;
        debug_assert_eq!(VERSION_OFFSET + fields.len(), ENTRY_COUNT_OFFSET + 4);
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = hash::Hasher::new();
        let mut buf = vec![0u8; SPOOL_BUFFER];
        let mut left = body_len;
        while left > 0 {
            let n = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
            file.read_exact(&mut buf[..n])?;
            hasher.update(&buf[..n]);
            note_hashed(n);
            left -= n as u64;
        }
        let trailer = hasher.finalize();
        hasher.update(&trailer);
        note_hashed(TRAILER_LEN);
        write_all_at(&file, body_len, &trailer)?;
        Ok(SpooledPack {
            file,
            len: body_len + TRAILER_LEN as u64,
            key: hasher.finalize(),
        })
    }
}

/// A writer that keeps nothing: it counts the bytes a pack would take, for a
/// dry seal that only needs each pack's length.
pub type CountingWriter = PackWriter<io::Sink>;

impl CountingWriter {
    /// A writer that stores no byte and counts the pack's length.
    #[must_use]
    pub fn counting() -> Self {
        Self::over(io::sink())
    }

    /// The length the sealed pack would have, header and trailer included.
    ///
    /// # Errors
    /// [`PackError::TooManyObjects`] past the entry cap.
    pub fn finish_count(self) -> Result<u64, PackError> {
        self.patched_header()?;
        Ok(self.len + TRAILER_LEN as u64)
    }
}

/// A sealed pack in an unnamed file, with its length and key.
#[derive(Debug)]
pub struct SpooledPack {
    file: File,
    len: u64,
    key: Hash,
}

impl SpooledPack {
    /// The pack key: BLAKE3 of the whole pack, trailer included
    /// ([`super::pack_key`] of the same bytes).
    #[must_use]
    pub fn key(&self) -> Hash {
        self.key
    }

    /// Length of the pack in bytes, header and trailer included.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Never true: a sealed pack holds at least a header and a trailer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Fill `buf` with the pack's bytes from `offset`.
    ///
    /// # Errors
    /// An I/O error, or `UnexpectedEof` past the end of the pack.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(self.len, offset, buf.len())?;
        read_exact_at(&self.file, offset, buf)
    }
}

impl PackBody for SpooledPack {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_from(&self, offset: u64) -> io::Result<Box<dyn Read + Send + '_>> {
        if offset > self.len {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok(Box::new(SpoolReader {
            file: &self.file,
            at: offset,
            end: self.len,
        }))
    }
}

/// Reads a spooled pack from one offset to its end, by positional reads, so
/// readers of one pack never share a cursor.
struct SpoolReader<'a> {
    file: &'a File,
    at: u64,
    end: u64,
}

impl Read for SpoolReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = usize::try_from(self.end - self.at).map_or(buf.len(), |left| left.min(buf.len()));
        if n == 0 {
            return Ok(0);
        }
        read_exact_at(self.file, self.at, &mut buf[..n])?;
        self.at += n as u64;
        Ok(n)
    }
}

fn check_range(len: u64, offset: u64, n: usize) -> io::Result<()> {
    match offset.checked_add(n as u64) {
        Some(end) if end <= len => Ok(()),
        _ => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
    }
}

/// A downloaded pack on its way to disk. It refuses a declared length over
/// its limit before any byte, and any byte past the declared length or the
/// limit. It hashes the bytes as they arrive, and [`Self::finish`] yields a
/// [`VerifiedPack`] only when the length, the key and the trailer all check.
///
/// One BLAKE3 hasher serves both checks. It lags the input by the 32 bytes of
/// a trailer, kept aside, so when the stream ends it has read exactly the
/// body: it gives the trailer the body should end with, and then, fed the 32
/// kept bytes, the key of the whole pack.
#[derive(Debug)]
pub struct PackSpool {
    file: File,
    // Bytes not yet written to `file`, which holds the `flushed` bytes before
    // them.
    buf: Vec<u8>,
    flushed: u64,
    limit: u64,
    begun: bool,
    declared: Option<u64>,
    written: u64,
    hasher: hash::Hasher,
    tail: [u8; TRAILER_LEN],
    tail_len: usize,
    failed: Option<io::ErrorKind>,
}

impl PackSpool {
    /// A spool in a new unnamed file in `dir` (created when missing) that
    /// takes at most `limit` bytes.
    ///
    /// # Errors
    /// [`PackError::Io`] when the directory or the file cannot be created.
    pub fn create(dir: &Path, limit: u64) -> Result<Self, PackError> {
        Ok(Self {
            file: unnamed_file(dir)?,
            buf: Vec::with_capacity(SPOOL_BUFFER),
            flushed: 0,
            limit,
            begun: false,
            declared: None,
            written: 0,
            hasher: hash::Hasher::new(),
            tail: [0; TRAILER_LEN],
            tail_len: 0,
            failed: None,
        })
    }

    /// Start a body, or start over after a failed attempt: earlier bytes are
    /// discarded. `declared` is the length the sender announced, if any.
    ///
    /// # Errors
    /// [`PackError::PackfileTooLarge`] when `declared` is over the limit,
    /// before any byte is taken; [`PackError::Io`] when the file cannot be
    /// truncated or after an earlier I/O failure.
    pub fn begin(&mut self, declared: Option<u64>) -> Result<(), PackError> {
        self.check_failed()?;
        self.begun = false;
        if declared.is_some_and(|len| len > self.limit) {
            return Err(PackError::PackfileTooLarge);
        }
        self.buf.clear();
        if self.flushed > 0 {
            let truncated = self.file.set_len(0);
            self.record(truncated)?;
            self.flushed = 0;
        }
        self.begun = true;
        self.declared = declared;
        self.written = 0;
        self.hasher = hash::Hasher::new();
        self.tail_len = 0;
        Ok(())
    }

    /// Append `bytes` to the body.
    ///
    /// # Errors
    /// [`PackError::PackfileTooLarge`] for a byte past the declared length or
    /// the limit, which ends the body, [`PackError::UnexpectedEof`] before
    /// [`Self::begin`] or after a body ended that way, and
    /// [`PackError::Io`] when the file cannot be written or after an earlier
    /// I/O failure.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), PackError> {
        self.check_failed()?;
        if !self.begun {
            return Err(PackError::UnexpectedEof);
        }
        let Some(end) = self.written.checked_add(bytes.len() as u64).filter(|&end| {
            end <= self.limit && self.declared.is_none_or(|declared| end <= declared)
        }) else {
            // The body is over its length: it ends here, and only a new
            // `begin` takes bytes again.
            self.begun = false;
            return Err(PackError::PackfileTooLarge);
        };
        if self.buf.len() + bytes.len() > SPOOL_BUFFER {
            self.flush()?;
        }
        if bytes.len() >= SPOOL_BUFFER {
            let written = write_all_at(&self.file, self.flushed, bytes);
            self.record(written)?;
            self.flushed += bytes.len() as u64;
        } else {
            self.buf.extend_from_slice(bytes);
        }
        self.hash_lagging(bytes);
        self.written = end;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), PackError> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let written = write_all_at(&self.file, self.flushed, &self.buf);
        self.record(written)?;
        self.flushed += self.buf.len() as u64;
        self.buf.clear();
        Ok(())
    }

    /// The local I/O error that ended this spool, if any. It stays set:
    /// [`Self::begin`] does not clear it.
    #[must_use]
    pub fn failed(&self) -> Option<io::ErrorKind> {
        self.failed
    }

    /// Bytes taken of the current body, and how many of them reached the file.
    #[cfg(test)]
    pub(super) fn taken(&self) -> (u64, u64) {
        (self.written, self.flushed)
    }

    /// Check the body and hand it over as a [`VerifiedPack`]: its length is
    /// the declared one and at least a header and a trailer, it hashes to
    /// `key`, and its last 32 bytes are the BLAKE3 of the rest.
    ///
    /// # Errors
    /// [`PackError::UnexpectedEof`] when no body was begun or it is shorter
    /// than declared, [`PackError::PackfileTooShort`] under a header and a
    /// trailer, [`PackError::KeyMismatch`], [`PackError::PackfileCorrupted`]
    /// for a wrong trailer, and [`PackError::Io`].
    pub fn finish(mut self, key: &PackKey) -> Result<VerifiedPack, PackError> {
        self.check_failed()?;
        if !self.begun
            || self
                .declared
                .is_some_and(|declared| self.written != declared)
        {
            return Err(PackError::UnexpectedEof);
        }
        if self.written < (HEADER_LEN + TRAILER_LEN) as u64 {
            return Err(PackError::PackfileTooShort);
        }
        debug_assert_eq!(self.tail_len, TRAILER_LEN);
        let trailer = self.hasher.finalize();
        let mut hasher = self.hasher.clone();
        hasher.update(&self.tail);
        note_hashed(TRAILER_LEN);
        if hasher.finalize() != *key.as_bytes() {
            return Err(PackError::KeyMismatch);
        }
        if trailer != self.tail {
            return Err(PackError::PackfileCorrupted);
        }
        self.flush()?;
        Ok(VerifiedPack {
            file: self.file,
            len: self.written,
            #[cfg(test)]
            window_bytes: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            read_bytes: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Feed the hasher all but the last [`TRAILER_LEN`] bytes seen so far.
    fn hash_lagging(&mut self, bytes: &[u8]) {
        if bytes.len() >= TRAILER_LEN {
            let (body, tail) = bytes.split_at(bytes.len() - TRAILER_LEN);
            self.hasher.update(&self.tail[..self.tail_len]);
            self.hasher.update(body);
            note_hashed(self.tail_len + body.len());
            self.tail.copy_from_slice(tail);
            self.tail_len = TRAILER_LEN;
            return;
        }
        let total = self.tail_len + bytes.len();
        if total > TRAILER_LEN {
            let spill = total - TRAILER_LEN;
            self.hasher.update(&self.tail[..spill]);
            note_hashed(spill);
            self.tail.copy_within(spill..self.tail_len, 0);
            self.tail_len -= spill;
        }
        self.tail[self.tail_len..self.tail_len + bytes.len()].copy_from_slice(bytes);
        self.tail_len += bytes.len();
    }

    fn check_failed(&self) -> Result<(), PackError> {
        match self.failed {
            Some(kind) => Err(PackError::Io(io::Error::from(kind))),
            None => Ok(()),
        }
    }

    fn record<T>(&mut self, result: io::Result<T>) -> Result<T, PackError> {
        result.map_err(|error| {
            self.failed = Some(error.kind());
            self.begun = false;
            PackError::Io(error)
        })
    }
}

/// A transport writes into a spool through [`PackSink`]. An I/O failure is
/// recorded in [`PackSpool::failed`] and shows to the transport as
/// [`TransportError::ProtocolError`], which no transport retries.
impl PackSink for PackSpool {
    fn begin(&mut self, declared: Option<u64>) -> TransportResult<()> {
        let len = declared.unwrap_or(0);
        Self::begin(self, declared).map_err(|error| transport_error(&error, len))
    }

    fn write(&mut self, bytes: &[u8]) -> TransportResult<()> {
        let end = self.written.saturating_add(bytes.len() as u64);
        Self::write(self, bytes).map_err(|error| transport_error(&error, end))
    }

    fn failed(&self) -> Option<io::ErrorKind> {
        self.failed
    }
}

/// The transport's view of a spool error: a body too long, named by the
/// length it reached, or a local failure no transport retries.
fn transport_error(error: &PackError, len: u64) -> TransportError {
    match error {
        PackError::PackfileTooLarge => {
            TransportError::PayloadTooLarge(crate::protocol::saturating_usize(len))
        }
        _ => TransportError::ProtocolError,
    }
}

/// A pack whose length, key and trailer a [`PackSpool`] has checked, in an
/// unnamed file that only this handle reaches. [`PackSpool::finish`] is the
/// only way to make one, so a pack the reader takes from a file is always one
/// that passed those checks.
#[derive(Debug)]
pub struct VerifiedPack {
    file: File,
    len: u64,
    // Bytes read through `WindowSource`: the payload windows of a read.
    #[cfg(test)]
    pub(super) window_bytes: std::sync::atomic::AtomicU64,
    /// Every byte read from the file, by the header scan and the windows.
    #[cfg(test)]
    pub(super) read_bytes: std::sync::atomic::AtomicU64,
}

impl VerifiedPack {
    /// Length of the pack in bytes, header and trailer included.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Never true: a verified pack holds at least a header and a trailer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Fill `buf` with the pack's bytes from `offset`.
    ///
    /// # Errors
    /// An I/O error, or `UnexpectedEof` past the end of the pack.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(self.len, offset, buf.len())?;
        read_exact_at(&self.file, offset, buf)?;
        #[cfg(test)]
        self.read_bytes
            .fetch_add(buf.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

impl WindowSource for &VerifiedPack {
    fn read_window(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, PackError> {
        let n = usize::try_from(len).map_err(|_| PackError::PackfileTooLarge)?;
        check_range(self.len, offset, n).map_err(|_| PackError::UnexpectedEof)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(n)
            .map_err(|_| PackError::PackfileTooLarge)?;
        bytes.resize(n, 0);
        self.read_at(offset, &mut bytes).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                PackError::UnexpectedEof
            } else {
                PackError::Io(error)
            }
        })?;
        #[cfg(test)]
        self.window_bytes
            .fetch_add(len, std::sync::atomic::Ordering::Relaxed);
        Ok(bytes)
    }
}
