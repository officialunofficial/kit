//! Export the tree of a revision as a tar archive, for `kit archive`.
//!
//! [`write`] reads only the tree of the revision, never the worktree, and
//! writes a POSIX ustar archive whose bytes depend only on the tree:
//!
//! - Entries follow the order of the tree, each directory before what it
//!   holds. Directories end with `/`.
//! - Every entry has uid and gid 0, user and group `root`, and the
//!   commit's time as its mtime, or 0 for a tree. Files have mode 0644 or
//!   0755, directories 0755, and symlinks 0777 with their target as the
//!   link name.
//! - A commit adds a pax global header first, whose `comment` record holds
//!   the full commit id, as git writes it.
//! - A path that does not fit the ustar name and prefix fields, or a link
//!   target over 100 bytes, takes a pax extended header.
//! - The archive ends with two zero blocks and fills whole records of
//!   10,240 bytes.
//!
//! A file's content streams from the store one chunk at a time.

use std::io::{self, Write};

use kit_core::hash::{self, Hash};
use kit_core::object::{EntryMode, Object, Tree};
use kit_core::store::{MAX_TREE_DEPTH, ObjectStore};
use kit_core::worktree::LoadedBlob;

use crate::{Repo, revspec};

/// The size of a tar block.
const BLOCK: usize = 512;

/// The size of a tar record, which the archive fills to the end.
const RECORD: u64 = 10_240;

/// Errors from writing an archive.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The revision does not resolve.
    #[error("{spec}: {source}")]
    BadRevision {
        /// The text the caller gave.
        spec: String,
        /// Why it did not resolve.
        source: revspec::Error,
    },
    /// The revision names neither a commit nor a tree.
    #[error("{0}: not a commit or a tree")]
    NotATree(String),
    /// The prefix is absolute or holds a `..` component.
    #[error("--prefix {0}: must be relative and hold no '..'")]
    BadPrefix(String),
    /// A path matches nothing in the tree.
    #[error("path '{0}' did not match any file in the tree")]
    NoMatch(String),
    /// An entry name of the tree could escape the archive's root.
    #[error("tree entry name {0:?} is not a plain name")]
    BadName(String),
    /// The tree is nested deeper than a tree may be.
    #[error("tree deeper than {MAX_TREE_DEPTH} levels")]
    TooDeep,
    /// An object could not be read.
    #[error("read {}: {message}", hash::to_hex(.hash))]
    Read {
        /// The object.
        hash: Hash,
        /// Why it failed.
        message: String,
    },
    /// The output could not be written.
    #[error("write: {0}")]
    Io(#[from] io::Error),
}

/// What to archive.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The revision: a commit, a tag of one, or a tree.
    pub revision: &'a str,
    /// Text put before every path, such as `name-1.0/`.
    pub prefix: &'a str,
    /// Keep only these files and directories, in the form of the index.
    /// Empty keeps the whole tree.
    pub paths: &'a [String],
}

/// What an archive holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// The number of entries, directories included and headers not.
    pub entries: usize,
}

/// Write the archive of `request` to `out`.
///
/// # Errors
/// [`Error::BadRevision`], [`Error::NotATree`], [`Error::BadPrefix`] and
/// [`Error::NoMatch`] before anything is written. [`Error::BadName`],
/// [`Error::TooDeep`] and [`Error::Read`] for a tree that cannot be
/// archived, and [`Error::Io`] when `out` fails; then part of the archive
/// may have been written.
pub fn write(repo: &Repo, request: &Request<'_>, out: &mut dyn Write) -> Result<Summary, Error> {
    let store = repo.store();
    check_prefix(request.prefix)?;
    let hash = revspec::resolve_revision(store, repo.layout(), request.revision)
        .map(|h| revspec::peel_tags(store, h))
        .map_err(|source| Error::BadRevision {
            spec: request.revision.to_owned(),
            source,
        })?;
    let (tree, mtime, commit) = match read(store, &hash)? {
        Object::Commit(c) => (c.tree_hash, c.timestamp, Some(hash)),
        Object::Tree(_) => (hash, 0, None),
        _ => return Err(Error::NotATree(request.revision.to_owned())),
    };
    for path in request.paths {
        if !path.is_empty() && !exists(store, tree, path)? {
            return Err(Error::NoMatch(path.clone()));
        }
    }
    let mut tar = TarWriter {
        out,
        mtime,
        entries: 0,
        written: 0,
    };
    if let Some(id) = commit {
        let record = pax_record("comment", hash::to_hex(&id).as_bytes());
        tar.entry(b"pax_global_header", b'g', 0o644, &record)?;
        tar.entries -= 1;
    }
    let prefix = request.prefix.as_bytes();
    if prefix.ends_with(b"/") {
        tar.header(prefix, b'5', 0o755, 0, b"")?;
    }
    let walk = Walk {
        store,
        paths: request.paths,
    };
    walk.tree(&mut tar, tree, prefix, "", 0)?;
    tar.finish()?;
    Ok(Summary {
        entries: tar.entries,
    })
}

/// Refuse a prefix that is absolute or climbs out with `..`.
fn check_prefix(prefix: &str) -> Result<(), Error> {
    let bad = prefix.starts_with('/')
        || prefix.contains('\0')
        || prefix.split('/').any(|part| part == "..");
    if bad {
        Err(Error::BadPrefix(prefix.to_owned()))
    } else {
        Ok(())
    }
}

fn read(store: &ObjectStore, hash: &Hash) -> Result<Object, Error> {
    store.read_object(hash).map_err(|e| Error::Read {
        hash: *hash,
        message: e.to_string(),
    })
}

fn read_tree(store: &ObjectStore, hash: &Hash) -> Result<Tree, Error> {
    match read(store, hash)? {
        Object::Tree(t) => Ok(t),
        _ => Err(Error::Read {
            hash: *hash,
            message: "not a tree".to_owned(),
        }),
    }
}

/// Whether `path` names an entry of `tree`.
fn exists(store: &ObjectStore, tree: Hash, path: &str) -> Result<bool, Error> {
    let mut current = tree;
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        let t = read_tree(store, &current)?;
        let Some(entry) = t.entries.iter().find(|e| e.name == part.as_bytes()) else {
            return Ok(false);
        };
        if i + 1 == parts.len() {
            return Ok(true);
        }
        if entry.mode != EntryMode::Tree {
            return Ok(false);
        }
        current = entry.object_hash;
    }
    Ok(false)
}

/// The walk over the tree, limited to the paths of the request.
struct Walk<'a> {
    store: &'a ObjectStore,
    paths: &'a [String],
}

impl Walk<'_> {
    /// Whether the entry at `path` is kept: it is a requested path, under
    /// one, or, for a directory, above one.
    fn keeps(&self, path: &str, dir: bool) -> bool {
        self.paths.is_empty()
            || self.paths.iter().any(|p| {
                p.is_empty()
                    || p == path
                    || path
                        .strip_prefix(p.as_str())
                        .is_some_and(|r| r.starts_with('/'))
                    || (dir && p.strip_prefix(path).is_some_and(|r| r.starts_with('/')))
            })
    }

    fn tree(
        &self,
        tar: &mut TarWriter<'_>,
        tree: Hash,
        prefix: &[u8],
        path: &str,
        depth: usize,
    ) -> Result<(), Error> {
        if depth >= MAX_TREE_DEPTH {
            return Err(Error::TooDeep);
        }
        for entry in read_tree(self.store, &tree)?.entries {
            let name = String::from_utf8_lossy(&entry.name).into_owned();
            let plain = !entry.name.is_empty()
                && entry.name != b"."
                && entry.name != b".."
                && !entry.name.contains(&b'/')
                && !entry.name.contains(&0);
            if !plain {
                return Err(Error::BadName(name));
            }
            let rel = if path.is_empty() {
                name
            } else {
                format!("{path}/{name}")
            };
            let dir = entry.mode == EntryMode::Tree;
            if !self.keeps(&rel, dir) {
                continue;
            }
            let mut full = prefix.to_vec();
            full.extend_from_slice(rel.as_bytes());
            match entry.mode {
                EntryMode::Tree => {
                    full.push(b'/');
                    tar.header(&full, b'5', 0o755, 0, b"")?;
                    self.tree(tar, entry.object_hash, prefix, &rel, depth + 1)?;
                }
                EntryMode::Symlink => {
                    let blob = self.load(&entry.object_hash)?;
                    let mut target = Vec::new();
                    blob.write_content(self.store, &mut target)
                        .map_err(|e| Error::Read {
                            hash: entry.object_hash,
                            message: e.to_string(),
                        })?;
                    tar.header(&full, b'2', 0o777, 0, &target)?;
                }
                EntryMode::Blob | EntryMode::Executable => {
                    let mode = if entry.mode == EntryMode::Executable {
                        0o755
                    } else {
                        0o644
                    };
                    let blob = self.load(&entry.object_hash)?;
                    tar.header(&full, b'0', mode, blob.len(), b"")?;
                    let mut counted = Counter {
                        out: &mut *tar.out,
                        n: 0,
                    };
                    blob.write_content(self.store, &mut counted)
                        .map_err(|e| Error::Read {
                            hash: entry.object_hash,
                            message: e.to_string(),
                        })?;
                    let n = counted.n;
                    if n != blob.len() {
                        return Err(Error::Read {
                            hash: entry.object_hash,
                            message: format!("expected {} bytes, read {n}", blob.len()),
                        });
                    }
                    tar.written += n;
                    tar.pad()?;
                }
            }
        }
        Ok(())
    }

    fn load(&self, hash: &Hash) -> Result<LoadedBlob, Error> {
        LoadedBlob::load(self.store, hash).map_err(|e| Error::Read {
            hash: *hash,
            message: e.to_string(),
        })
    }
}

/// A writer that counts the bytes it passes on.
struct Counter<'a> {
    out: &'a mut dyn Write,
    n: u64,
}

impl Write for Counter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.n += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// The tar stream: headers, content and padding.
struct TarWriter<'a> {
    out: &'a mut dyn Write,
    mtime: u64,
    entries: usize,
    written: u64,
}

impl TarWriter<'_> {
    fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.out.write_all(bytes)?;
        self.written += bytes.len() as u64;
        Ok(())
    }

    /// Zero bytes up to the next block.
    fn pad(&mut self) -> io::Result<()> {
        let rest = usize::try_from(self.written % BLOCK as u64).unwrap_or(0);
        if rest != 0 {
            self.put(&[0u8; BLOCK][..BLOCK - rest])?;
        }
        Ok(())
    }

    /// An entry with its whole content.
    fn entry(&mut self, path: &[u8], kind: u8, mode: u32, data: &[u8]) -> io::Result<()> {
        self.header(path, kind, mode, data.len() as u64, b"")?;
        self.put(data)?;
        self.pad()
    }

    /// The header of an entry, after a pax header when a field does not fit.
    fn header(
        &mut self,
        path: &[u8],
        kind: u8,
        mode: u32,
        size: u64,
        link: &[u8],
    ) -> io::Result<()> {
        let mut pax = Vec::new();
        let (name, prefix) = split_path(path).unwrap_or_else(|| {
            pax.extend(pax_record("path", path));
            (&path[..path.len().min(100)], &[][..])
        });
        let link = if link.len() > 100 {
            pax.extend(pax_record("linkpath", link));
            &link[..100]
        } else {
            link
        };
        if !pax.is_empty() {
            let block = ustar(
                b"././@PaxHeader",
                b'x',
                0o644,
                pax.len() as u64,
                self.mtime,
                b"",
                b"",
            );
            self.put(&block)?;
            self.put(&pax)?;
            self.pad()?;
        }
        let block = ustar(name, kind, mode, size, self.mtime, link, prefix);
        self.put(&block)?;
        self.entries += 1;
        Ok(())
    }

    /// Two zero blocks, then zeros to the end of the record.
    fn finish(&mut self) -> io::Result<()> {
        self.put(&[0u8; 2 * BLOCK])?;
        let rest = self.written % RECORD;
        if rest != 0 {
            let fill = vec![0u8; usize::try_from(RECORD - rest).unwrap_or(0)];
            self.put(&fill)?;
        }
        self.out.flush()
    }
}

/// Split `path` into the ustar name (at most 100 bytes) and prefix (at
/// most 155 bytes), cutting at a `/`. `None` when it does not fit.
fn split_path(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.len() <= 100 {
        return Some((path, &[]));
    }
    // A directory's trailing `/` stays with its name.
    let body = path.strip_suffix(b"/").unwrap_or(path);
    let limit = body.len().min(156);
    let cut = body[..limit].iter().rposition(|&b| b == b'/')?;
    let (prefix, name) = (&path[..cut], &path[cut + 1..]);
    (cut > 0 && name.len() <= 100).then_some((name, prefix))
}

/// One pax record, `<length> <key>=<value>\n`, where the length counts the
/// whole record.
fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let body = key.len() + value.len() + 3;
    let mut len = body + 1;
    while len != body + len.to_string().len() {
        len = body + len.to_string().len();
    }
    let mut out = format!("{len} {key}=").into_bytes();
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

/// Write `value` in octal, zero padded to `field.len() - 1` digits, then a
/// NUL.
fn octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let text = format!("{value:0width$o}");
    let text = text.as_bytes();
    // A value too wide keeps its low digits; callers keep values in range.
    let text = &text[text.len().saturating_sub(width)..];
    field[..width].copy_from_slice(text);
    field[width] = 0;
}

/// One ustar header block.
fn ustar(
    name: &[u8],
    kind: u8,
    mode: u32,
    size: u64,
    mtime: u64,
    link: &[u8],
    prefix: &[u8],
) -> [u8; BLOCK] {
    let mut b = [0u8; BLOCK];
    b[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
    octal(&mut b[100..108], u64::from(mode));
    octal(&mut b[108..116], 0);
    octal(&mut b[116..124], 0);
    octal(&mut b[124..136], size);
    octal(&mut b[136..148], mtime);
    b[148..156].copy_from_slice(b"        ");
    b[156] = kind;
    b[157..157 + link.len().min(100)].copy_from_slice(&link[..link.len().min(100)]);
    b[257..263].copy_from_slice(b"ustar\0");
    b[263..265].copy_from_slice(b"00");
    b[265..269].copy_from_slice(b"root");
    b[297..301].copy_from_slice(b"root");
    octal(&mut b[329..337], 0);
    octal(&mut b[337..345], 0);
    b[345..345 + prefix.len().min(155)].copy_from_slice(&prefix[..prefix.len().min(155)]);
    let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
    let text = format!("{sum:06o}\0 ");
    b[148..156].copy_from_slice(text.as_bytes());
    b
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pax_records_count_their_own_length() {
        let id = "a".repeat(64);
        let r = pax_record("comment", id.as_bytes());
        assert_eq!(r.len(), 76);
        assert!(r.starts_with(b"76 comment="));
        for n in [0usize, 1, 5, 89, 90, 91, 995, 996, 997] {
            let r = pax_record("path", &vec![b'x'; n]);
            let len: usize = std::str::from_utf8(&r[..r.iter().position(|&b| b == b' ').unwrap()])
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(len, r.len(), "{n}");
        }
    }

    #[test]
    fn long_paths_split_at_a_slash_or_not_at_all() {
        let short = b"a/b";
        assert_eq!(split_path(short), Some((&short[..], &b""[..])));
        let long = format!("{}/{}", "d".repeat(120), "f".repeat(50));
        let (name, prefix) = split_path(long.as_bytes()).unwrap();
        assert_eq!((name.len(), prefix.len()), (50, 120));
        assert_eq!(split_path("x".repeat(101).as_bytes()), None);
        let dir = format!("{}/{}/", "d".repeat(120), "e".repeat(50));
        let (name, _) = split_path(dir.as_bytes()).unwrap();
        assert!(name.ends_with(b"/"));
    }

    #[test]
    fn prefixes_must_stay_inside() {
        assert!(check_prefix("pkg-1.0/").is_ok());
        assert!(check_prefix("pkg-").is_ok());
        assert!(check_prefix("../x/").is_err());
        assert!(check_prefix("a/../../x/").is_err());
        assert!(check_prefix("/abs/").is_err());
    }

    #[test]
    fn headers_have_a_valid_checksum() {
        let b = ustar(b"f", b'0', 0o644, 3, 7, b"", b"");
        let stored = u32::from_str_radix(std::str::from_utf8(&b[148..154]).unwrap(), 8).unwrap();
        let mut copy = b;
        copy[148..156].copy_from_slice(b"        ");
        assert_eq!(stored, copy.iter().map(|&x| u32::from(x)).sum::<u32>());
    }
}
