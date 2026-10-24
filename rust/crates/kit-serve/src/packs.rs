//! Pack files under `<root>/packs/<64-hex>`: the layout that
//! `FileTransport` writes.
//!
//! [`PackWriter`] streams an upload into a temp file in the pack directory
//! while it hashes the bytes. The pack becomes visible only when the hash
//! matches its name: fsync, rename, fsync of the directory. A failed,
//! aborted or dropped writer removes its temp file. It never touches an
//! existing pack.
//!
//! A process that crashes mid-upload leaves its temp file behind, named
//! `.<64-hex>.tmp.<pid>.<seq>`. [`sweep_stale_uploads`] removes the old ones.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use kit_core::hash::Hasher;
use kit_core::protocol::PackKey;
use kit_transport_file::{create_dir_all_durably, sync_dir, temp_path};

/// The directory under the root that holds the packs.
const PACK_DIR: &str = "packs";

/// The largest chunk of a download, in bytes.
pub const DOWNLOAD_CHUNK_MAX: usize = 800 * 1024;

/// Where the pack `key` lives.
pub(crate) fn pack_path(root: &Path, key: &PackKey) -> PathBuf {
    root.join(PACK_DIR).join(key.to_hex())
}

/// Why [`PackWriter::finish`] failed.
#[derive(Debug)]
pub(crate) enum FinishError {
    /// The bytes do not hash to the pack id.
    DigestMismatch,
    /// The file system failed.
    Io,
}

/// One upload in progress: a temp file and a running hash. Memory use is one
/// chunk, never the pack.
#[derive(Debug)]
pub(crate) struct PackWriter {
    /// The open temp file. `None` once closed for the rename.
    file: Option<File>,
    /// The temp file's path. `None` once renamed or removed.
    tmp: Option<PathBuf>,
    dest: PathBuf,
    key: PackKey,
    hasher: Hasher,
}

impl PackWriter {
    /// Open a temp file for the pack `key` under `root`.
    ///
    /// # Errors
    /// The pack directory or the temp file could not be created.
    pub(crate) fn begin(root: &Path, key: PackKey) -> io::Result<Self> {
        let dest = pack_path(root, &key);
        let dir = dest
            .parent()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "pack path has no directory"))?;
        create_dir_all_durably(dir)?;
        let tmp = temp_path(&dest)?;
        let file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        Ok(Self {
            file: Some(file),
            tmp: Some(tmp),
            dest,
            key,
            hasher: Hasher::new(),
        })
    }

    /// Append `data`.
    ///
    /// # Errors
    /// The write failed.
    pub(crate) fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let file = self.file.as_mut().ok_or_else(closed)?;
        file.write_all(data)?;
        self.hasher.update(data);
        Ok(())
    }

    /// Verify the hash and move the pack into place. An existing pack with
    /// the same name holds the same bytes, so the rename replaces it. That
    /// also repairs a pack that a crash left short.
    ///
    /// # Errors
    /// [`FinishError::DigestMismatch`] when the bytes do not match the pack
    /// id, [`FinishError::Io`] for a file system failure. In both cases
    /// dropping the writer removes the temp file.
    pub(crate) fn finish(mut self) -> Result<(), FinishError> {
        if self.hasher.finalize() != *self.key.as_bytes() {
            return Err(FinishError::DigestMismatch);
        }
        let file = self.file.take().ok_or(FinishError::Io)?;
        file.sync_all().map_err(|_| FinishError::Io)?;
        drop(file);
        let tmp = self.tmp.as_ref().ok_or(FinishError::Io)?;
        fs::rename(tmp, &self.dest).map_err(|_| FinishError::Io)?;
        self.tmp = None;
        if let Some(dir) = self.dest.parent() {
            sync_dir(dir).map_err(|_| FinishError::Io)?;
        }
        Ok(())
    }
}

impl Drop for PackWriter {
    fn drop(&mut self) {
        self.file = None;
        if let Some(tmp) = self.tmp.take() {
            let _ = fs::remove_file(tmp);
        }
    }
}

fn closed() -> io::Error {
    io::Error::other("pack upload already closed")
}

/// One chunk of a download.
#[derive(Debug)]
pub(crate) struct Chunk {
    pub(crate) offset: u64,
    pub(crate) data: Vec<u8>,
    pub(crate) last: bool,
}

/// A pack open for download: its length, then its chunks. An empty pack is
/// one empty `last` chunk.
#[derive(Debug)]
pub(crate) struct PackReader {
    file: File,
    len: u64,
    offset: u64,
    done: bool,
}

impl PackReader {
    /// Open the pack `key`; `None` if it does not exist.
    ///
    /// # Errors
    /// The file exists but could not be opened.
    pub(crate) fn open(root: &Path, key: &PackKey) -> io::Result<Option<Self>> {
        let file = match File::open(pack_path(root, key)) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Ok(None);
        }
        Ok(Some(Self {
            file,
            len: meta.len(),
            offset: 0,
            done: false,
        }))
    }

    /// The pack's length in bytes.
    pub(crate) const fn len(&self) -> u64 {
        self.len
    }

    /// The next chunk of at most [`DOWNLOAD_CHUNK_MAX`] bytes, or `None`
    /// after the `last` chunk.
    ///
    /// # Errors
    /// A read failed, or the file is shorter than it was at open.
    pub(crate) fn next_chunk(&mut self) -> io::Result<Option<Chunk>> {
        if self.done {
            return Ok(None);
        }
        let left = self.len - self.offset;
        let n = usize::try_from(left).map_or(DOWNLOAD_CHUNK_MAX, |l| l.min(DOWNLOAD_CHUNK_MAX));
        let mut data = vec![0; n];
        self.file.read_exact(&mut data)?;
        let chunk = Chunk {
            offset: self.offset,
            data,
            last: left == n as u64,
        };
        self.offset += n as u64;
        self.done = chunk.last;
        Ok(Some(chunk))
    }
}

/// Whether `name` is an upload's temp file name: `.<64 lowercase
/// hex>.tmp.<pid>.<seq>` with a decimal `u32` pid and `u64` sequence.
fn is_upload_temp_name(name: &str) -> bool {
    let decimal = |s: &str, max: usize| {
        !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_digit())
    };
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    let Some((hex, rest)) = rest.split_at_checked(64) else {
        return false;
    };
    let Some((pid, seq)) = rest.strip_prefix(".tmp.").and_then(|r| r.split_once('.')) else {
        return false;
    };
    hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && decimal(pid, 10)
        && decimal(seq, 20)
}

/// Remove the temp files that crashed uploads left in the pack directory.
/// It removes regular files named exactly like an upload temp file that
/// were last modified at least `min_age` ago. It touches nothing else: no
/// pack, no symlink, no other name, no file modified in the future. A file
/// that cannot be inspected or removed is skipped. A missing directory has
/// nothing to sweep. Returns how many files it removed.
///
/// A live upload keeps the modification time of its temp file fresh, so a
/// `min_age` well above any pause inside one upload is safe. The caller must
/// also rule out a live upload that can pause for longer.
///
/// # Errors
/// The directory could not be listed.
pub(crate) fn sweep_stale_uploads(root: &Path, min_age: Duration) -> io::Result<usize> {
    let now = SystemTime::now();
    let entries = match fs::read_dir(root.join(PACK_DIR)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0;
    for entry in entries {
        let Ok(entry) = entry else { continue };
        if !entry.file_name().to_str().is_some_and(is_upload_temp_name) {
            continue;
        }
        // `DirEntry::metadata` does not follow a symlink.
        let Ok(meta) = entry.metadata() else { continue };
        let stale = meta.is_file()
            && meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age >= min_age);
        if stale && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::hash::hash;

    fn key_of(bytes: &[u8]) -> PackKey {
        PackKey::new(hash(bytes))
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_verified_upload_becomes_a_pack() {
        let td = tempfile::tempdir().unwrap();
        let bytes = b"pack bytes".to_vec();
        let key = key_of(&bytes);
        let mut w = PackWriter::begin(td.path(), key).unwrap();
        w.write(&bytes[..4]).unwrap();
        w.write(&bytes[4..]).unwrap();
        w.finish().unwrap();
        assert_eq!(fs::read(pack_path(td.path(), &key)).unwrap(), bytes);
        assert_eq!(files(&td.path().join("packs")), [key.to_hex()]);
    }

    #[test]
    fn a_wrong_hash_leaves_nothing() {
        let td = tempfile::tempdir().unwrap();
        let key = key_of(b"right");
        let mut w = PackWriter::begin(td.path(), key).unwrap();
        w.write(b"wrong").unwrap();
        assert!(matches!(w.finish(), Err(FinishError::DigestMismatch)));
        assert!(files(&td.path().join("packs")).is_empty());
    }

    #[test]
    fn a_dropped_writer_leaves_nothing() {
        let td = tempfile::tempdir().unwrap();
        let mut w = PackWriter::begin(td.path(), key_of(b"x")).unwrap();
        w.write(b"x").unwrap();
        drop(w);
        assert!(files(&td.path().join("packs")).is_empty());
    }

    #[test]
    fn a_rejected_upload_keeps_the_existing_pack() {
        let td = tempfile::tempdir().unwrap();
        let bytes = b"kept".to_vec();
        let key = key_of(&bytes);
        let mut w = PackWriter::begin(td.path(), key).unwrap();
        w.write(&bytes).unwrap();
        w.finish().unwrap();
        let mut w = PackWriter::begin(td.path(), key).unwrap();
        w.write(b"bad").unwrap();
        assert!(w.finish().is_err());
        assert_eq!(fs::read(pack_path(td.path(), &key)).unwrap(), bytes);
    }

    fn stored(root: &Path, bytes: &[u8]) -> PackKey {
        let key = key_of(bytes);
        let mut w = PackWriter::begin(root, key).unwrap();
        w.write(bytes).unwrap();
        w.finish().unwrap();
        key
    }

    #[test]
    fn a_download_is_contiguous_chunks_with_one_last() {
        let td = tempfile::tempdir().unwrap();
        let big: Vec<u8> = (0..2 * DOWNLOAD_CHUNK_MAX + 123)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let key = stored(td.path(), &big);
        let mut r = PackReader::open(td.path(), &key).unwrap().unwrap();
        assert_eq!(r.len(), big.len() as u64);
        let mut got = Vec::new();
        let mut lasts = 0;
        while let Some(c) = r.next_chunk().unwrap() {
            assert_eq!(c.offset, got.len() as u64);
            assert!(c.data.len() <= DOWNLOAD_CHUNK_MAX);
            got.extend_from_slice(&c.data);
            lasts += usize::from(c.last);
        }
        assert_eq!(got, big);
        assert_eq!(lasts, 1);
        assert!(r.next_chunk().unwrap().is_none());
    }

    #[test]
    fn a_chunk_boundary_pack_has_no_empty_tail() {
        let td = tempfile::tempdir().unwrap();
        let key = stored(td.path(), &vec![5; DOWNLOAD_CHUNK_MAX]);
        let mut r = PackReader::open(td.path(), &key).unwrap().unwrap();
        let c = r.next_chunk().unwrap().unwrap();
        assert!(c.last);
        assert_eq!(c.data.len(), DOWNLOAD_CHUNK_MAX);
        assert!(r.next_chunk().unwrap().is_none());
    }

    #[test]
    fn the_empty_pack_is_one_empty_last_chunk() {
        let td = tempfile::tempdir().unwrap();
        let key = stored(td.path(), b"");
        let mut r = PackReader::open(td.path(), &key).unwrap().unwrap();
        assert_eq!(r.len(), 0);
        let c = r.next_chunk().unwrap().unwrap();
        assert!(c.last && c.data.is_empty() && c.offset == 0);
        assert!(r.next_chunk().unwrap().is_none());
    }

    #[test]
    fn a_missing_pack_or_a_directory_is_absent() {
        let td = tempfile::tempdir().unwrap();
        let key = key_of(b"nope");
        assert!(PackReader::open(td.path(), &key).unwrap().is_none());
        fs::create_dir_all(pack_path(td.path(), &key)).unwrap();
        assert!(PackReader::open(td.path(), &key).unwrap().is_none());
    }

    #[test]
    fn a_pack_that_shrinks_fails_the_read() {
        let td = tempfile::tempdir().unwrap();
        let key = stored(td.path(), &[1; 100]);
        let mut r = PackReader::open(td.path(), &key).unwrap().unwrap();
        fs::write(pack_path(td.path(), &key), [1; 10]).unwrap();
        assert!(r.next_chunk().is_err());
    }

    #[test]
    fn temp_names_are_exact() {
        let hex = "a".repeat(64);
        assert!(is_upload_temp_name(&format!(".{hex}.tmp.1.2")));
        assert!(!is_upload_temp_name(&format!("{hex}.tmp.1.2")));
        assert!(!is_upload_temp_name(&format!(".{hex}.tmp.1")));
        assert!(!is_upload_temp_name(&format!(".{hex}.tmp.x.2")));
        assert!(!is_upload_temp_name(&format!(
            ".{}.tmp.1.2",
            "A".repeat(64)
        )));
        assert!(!is_upload_temp_name(&format!(".{hex}.tmp.12345678901.2")));
        assert!(!is_upload_temp_name(&hex));
    }

    #[test]
    fn the_sweep_removes_only_old_upload_temp_files() {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path().join("packs");
        fs::create_dir_all(&dir).unwrap();
        let hex = "b".repeat(64);
        let temp = dir.join(format!(".{hex}.tmp.1.2"));
        let pack = dir.join(&hex);
        let other = dir.join(".other.tmp.1.2");
        for p in [&temp, &pack, &other] {
            fs::write(p, b"x").unwrap();
        }
        // Too young: nothing goes.
        assert_eq!(
            sweep_stale_uploads(td.path(), Duration::from_hours(1)).unwrap(),
            0
        );
        assert!(temp.exists());
        // Old enough: only the upload temp file goes.
        assert_eq!(sweep_stale_uploads(td.path(), Duration::ZERO).unwrap(), 1);
        assert!(!temp.exists() && pack.exists() && other.exists());
    }

    #[test]
    fn the_sweep_of_a_missing_directory_is_empty() {
        let td = tempfile::tempdir().unwrap();
        assert_eq!(sweep_stale_uploads(td.path(), Duration::ZERO).unwrap(), 0);
    }
}
