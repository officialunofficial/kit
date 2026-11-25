//! Recovery log — durable record of commits superseded by
//! history-rewriting operations (`commit --amend`, `reset`, `rebase`),
//! so they (a) remain GC roots within a retention window and (b) can be
//! surfaced and restored. This is the recovery half of
//! the gc model (the reachability root set lives in
//! [`super::gc`]).
//!
//! Why this exists: the per-branch history journal stores only opaque
//! MMB digests, so a superseded tip is otherwise unrecoverable the moment
//! it leaves the ref set — and `kit gc` would reclaim it. Each
//! rewrite appends the old tip here; gc treats every logged hash as a
//! root (clock-free), and [`expire`] drops entries older than the
//! retention policy so they stop pinning objects.
//!
//! On-disk: `.kit/recovery-log`, append-only, one tab-delimited record
//! per line — `<unix_ts>\t<op>\t<64-hex superseded>\t<branch>`. The
//! branch is last because ref names cannot contain tabs or spaces; `op`
//! is a short internal token. Parsing is **strict** (fail closed) so a
//! corrupt log makes gc abort rather than under-count roots. The one
//! exception is a last line without its newline: a write that a crash or a
//! full disk cut short. [`record`] syncs the line before the caller moves
//! the ref, so a cut entry protects nothing that moved. Readers ignore it
//! and [`record`] cuts it off before it appends.
//!
//! NOTE: the *producers* (recording at the amend/reset/rebase rewrite
//! sites) live elsewhere — this module is the format, store, retention
//! policy, and gc-root integration.
//!
//! ## Concurrency
//!
//! [`record`] takes the leaf `recovery-log.lock`, so two linked trees that
//! append at once cannot cut each other's line off with the torn-tail repair.
//! [`expire`] is **not** internally synchronized.
//! [`expire`] reads-filters-rewrites the log, so an [`record`] append
//! that interleaves between its read and its atomic replace would be
//! clobbered — and the superseded commit would silently drop out of
//! [`roots`], un-pinning it for gc. Callers MUST therefore hold the repo
//! lock, which every mutating command and `kit gc` already do (they
//! serialize via `worktree.lock`); gc's "expire then collect roots"
//! sequence must run under that same lock. This module assumes that
//! invariant rather than taking a second, nested lock.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};

use crate::bounded_read;
use crate::durable::Parents;
use crate::hash::{self, Hash};
use crate::layout::RepoLayout;
use crate::repo_lock;

/// File name under `.kit/` for the append-only recovery log.
pub const RECOVERY_LOG: &str = "recovery-log";

/// Default retention: keep entries from the last 90 days, and always the
/// most recent 50 regardless of age, so a recent mistake is recoverable
/// even on a long-idle repo.
pub const DEFAULT_GRACE_SECS: u64 = 90 * 24 * 60 * 60;
/// Default floor on retained entries regardless of age.
pub const DEFAULT_KEEP_LAST: usize = 50;

/// Longest recovery log that kit reads (64 MiB). A log of this size holds
/// about 600,000 entries. A longer log is an error, not a reason to
/// allocate without bound.
const LOG_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Errors from the recovery log.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("malformed object id in recovery log: {0}")]
    BadHash(#[from] hash::FromHexError),
    #[error("malformed recovery-log line: {0}")]
    Malformed(String),
    #[error("recovery-log field {0} may not contain a tab or newline")]
    InvalidField(&'static str),
}

type Result<T> = std::result::Result<T, RecoveryError>;

/// One superseded-commit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEntry {
    /// Unix seconds when the rewrite happened.
    pub timestamp: u64,
    /// Short operation token, e.g. `amend`, `reset`, `rebase`.
    pub op: String,
    /// The commit that was superseded (and would otherwise dangle).
    pub superseded: Hash,
    /// Branch the rewrite moved (empty for a detached HEAD).
    pub branch: String,
}

/// Retention policy for [`expire`]. An entry is kept if it is newer than
/// `grace_secs` **or** among the most recent `keep_last`.
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy {
    pub grace_secs: u64,
    pub keep_last: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            grace_secs: DEFAULT_GRACE_SECS,
            keep_last: DEFAULT_KEEP_LAST,
        }
    }
}

/// Append `entry` to the recovery log, creating it if absent. The
/// zero-hash is rejected (nothing to recover).
///
/// **Durable**: the appended line is `fsync`'d (and the parent directory
/// `fsync`'d) before returning, so a crash cannot leave a ref rewrite
/// durable while its recovery entry is lost — that would reopen the
/// unrecoverable-superseded-commit gap this log exists to close.
///
/// **Not internally synchronized**: callers MUST hold the repo lock (as
/// every mutating command and `kit gc` do). See the module-level
/// concurrency note — a concurrent [`expire`] could otherwise clobber a
/// racing append.
///
/// # Errors
/// [`RecoveryError::InvalidField`] if `op`/`branch` contain a tab or
/// newline; [`RecoveryError::Io`] on filesystem failure.
pub fn record(layout: &RepoLayout, entry: &RecoveryEntry) -> Result<()> {
    if entry.op.contains(['\t', '\n']) {
        return Err(RecoveryError::InvalidField("op"));
    }
    if entry.branch.contains(['\t', '\n']) {
        return Err(RecoveryError::InvalidField("branch"));
    }
    if entry.superseded == hash::ZERO {
        return Ok(());
    }
    fs::create_dir_all(layout.common_dir())?;
    let _lock = repo_lock::acquire_default(layout.common_dir(), repo_lock::RECOVERY_LOG_LOCK)
        .map_err(|e| RecoveryError::Io(io::Error::other(e)))?;
    let line = format!(
        "{}\t{}\t{}\t{}\n",
        entry.timestamp,
        entry.op,
        hash::to_hex(&entry.superseded),
        entry.branch,
    );
    let path = layout.recovery_log_file();
    let mut f = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(&path)?;
    cut_unterminated_tail(&mut f)?;
    f.write_all(line.as_bytes())?;
    // fsync the data, then the directory entry (cheap — records happen
    // only on history rewrites, and durability is the whole point).
    crate::durable::flush_file(&f, &path)?;
    crate::durable::flush_dir(layout.common_dir())?;
    Ok(())
}

/// Cut a last line that has no newline off `file`: the torn end of an earlier
/// append. Appending to it would glue the new line to the torn bytes. The
/// caller holds the recovery-log lock, so no append lands between the scan and
/// the cut.
fn cut_unterminated_tail(file: &mut File) -> io::Result<()> {
    let mut end = file.seek(SeekFrom::End(0))?;
    let keep = loop {
        if end == 0 {
            break 0;
        }
        let start = end.saturating_sub(4096);
        let mut chunk = vec![0; usize::try_from(end - start).unwrap_or(4096)];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut chunk)?;
        if let Some(at) = chunk.iter().rposition(|byte| *byte == b'\n') {
            break start + at as u64 + 1;
        }
        end = start;
    };
    // `keep` is the end of the file when it already ends in a newline.
    file.set_len(keep)?;
    Ok(())
}

/// Read every recovery-log entry, oldest first. Absent log ⇒ empty. A last
/// line without its newline is a cut append and is ignored.
///
/// # Errors
/// Strict: any other unparseable line or bad hash errors (fail closed for
/// gc).
pub fn read_all(layout: &RepoLayout) -> Result<Vec<RecoveryEntry>> {
    let raw = match bounded_read::read_capped(&layout.recovery_log_file(), LOG_MAX_BYTES) {
        Ok(raw) => raw,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let complete = raw
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(&raw[..0], |at| &raw[..=at]);
    let text = std::str::from_utf8(complete).map_err(|_| {
        RecoveryError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "state file is not UTF-8",
        ))
    })?;
    text.lines()
        .filter(|l| !l.is_empty())
        .map(parse_line)
        .collect()
}

/// The set of superseded-commit hashes currently in the log — gc roots,
/// clock-free. Call [`expire`] first to drop entries past the retention
/// policy before treating these as live.
///
/// # Errors
/// Propagates [`RecoveryError`] from a strict [`read_all`].
pub fn roots(layout: &RepoLayout) -> Result<BTreeSet<Hash>> {
    Ok(read_all(layout)?
        .into_iter()
        .map(|e| e.superseded)
        .filter(|h| *h != hash::ZERO)
        .collect())
}

/// Whether the entry at position `i` of a `total`-length log is retained
/// under `policy`: kept if fresher than `grace_secs` OR among the last
/// `keep_last`. Shared by [`expire`] and [`would_expire`] so the preview
/// can't drift from the real prune.
fn is_retained(
    i: usize,
    e: &RecoveryEntry,
    total: usize,
    now: u64,
    policy: &RetentionPolicy,
) -> bool {
    let fresh = now.saturating_sub(e.timestamp) <= policy.grace_secs;
    let keep_floor = total.saturating_sub(policy.keep_last);
    fresh || i >= keep_floor
}

/// Count how many entries [`expire`] would prune, **without** mutating the
/// log. For `gc --dry-run` previews.
///
/// # Errors
/// [`RecoveryError`] from a strict [`read_all`].
pub fn would_expire(layout: &RepoLayout, now: u64, policy: &RetentionPolicy) -> Result<usize> {
    let all = read_all(layout)?;
    let total = all.len();
    Ok(all
        .iter()
        .enumerate()
        .filter(|(i, e)| !is_retained(*i, e, total, now, policy))
        .count())
}

/// Drop entries that are both older than `policy.grace_secs` (relative to
/// `now`, unix seconds) and not among the most recent `policy.keep_last`.
/// Rewrites the log atomically (durably, via `write_pointer`). Returns
/// the number of entries pruned.
///
/// Must be called under the repo lock — see the module concurrency note;
/// a concurrent [`record`] append would otherwise be lost in the rewrite.
///
/// # Errors
/// [`RecoveryError`] on a strict read or filesystem failure.
pub fn expire(layout: &RepoLayout, now: u64, policy: &RetentionPolicy) -> Result<usize> {
    let all = read_all(layout)?;
    let total = all.len();
    if total == 0 {
        return Ok(0);
    }
    let kept: Vec<RecoveryEntry> = all
        .into_iter()
        .enumerate()
        .filter(|(i, e)| is_retained(*i, e, total, now, policy))
        .map(|(_, e)| e)
        .collect();
    let pruned = total - kept.len();
    if pruned == 0 {
        return Ok(0);
    }
    let mut buf = String::new();
    for e in &kept {
        let _ = writeln!(
            buf,
            "{}\t{}\t{}\t{}",
            e.timestamp,
            e.op,
            hash::to_hex(&e.superseded),
            e.branch
        );
    }
    crate::durable::write_pointer(&layout.recovery_log_file(), buf.as_bytes(), Parents::Create)?;
    Ok(pruned)
}

fn parse_line(line: &str) -> Result<RecoveryEntry> {
    let mut it = line.splitn(4, '\t');
    let ts = it.next().ok_or_else(|| malformed(line))?;
    let op = it.next().ok_or_else(|| malformed(line))?;
    let hex = it.next().ok_or_else(|| malformed(line))?;
    let branch = it.next().ok_or_else(|| malformed(line))?;
    // A tab in the branch is two entries glued together.
    if branch.contains('\t') {
        return Err(malformed(line));
    }
    let timestamp = ts.parse::<u64>().map_err(|_| malformed(line))?;
    let superseded = hash::from_hex(hex)?;
    Ok(RecoveryEntry {
        timestamp,
        op: op.to_owned(),
        superseded,
        branch: branch.to_owned(),
    })
}

fn malformed(line: &str) -> RecoveryError {
    RecoveryError::Malformed(line.to_owned())
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn md() -> (TempDir, RepoLayout) {
        let d = TempDir::new().unwrap();
        let md = RepoLayout::single(d.path());
        fs::create_dir_all(md.common_dir()).unwrap();
        (d, md)
    }

    fn h(byte: u8) -> Hash {
        [byte; 32]
    }

    fn entry(ts: u64, byte: u8) -> RecoveryEntry {
        RecoveryEntry {
            timestamp: ts,
            op: "amend".into(),
            superseded: h(byte),
            branch: "main".into(),
        }
    }

    #[test]
    fn record_then_read_roundtrips_in_order() {
        let (_d, md) = md();
        record(&md, &entry(100, 1)).unwrap();
        record(&md, &entry(200, 2)).unwrap();
        let all = read_all(&md).unwrap();
        assert_eq!(all, vec![entry(100, 1), entry(200, 2)]);
        assert_eq!(roots(&md).unwrap(), BTreeSet::from([h(1), h(2)]));
    }

    #[test]
    fn absent_log_is_empty_not_error() {
        let (_d, md) = md();
        assert!(read_all(&md).unwrap().is_empty());
        assert!(roots(&md).unwrap().is_empty());
    }

    #[test]
    fn record_rejects_tab_in_fields_and_skips_zero_hash() {
        let (_d, md) = md();
        let mut e = entry(1, 1);
        e.branch = "a\tb".into();
        assert!(matches!(
            record(&md, &e),
            Err(RecoveryError::InvalidField("branch"))
        ));
        // Zero hash is a no-op (nothing to recover), not an error.
        record(&md, &entry(1, 0)).unwrap();
        assert!(roots(&md).unwrap().is_empty());
    }

    #[test]
    fn read_fails_closed_on_corrupt_line() {
        let (_d, md) = md();
        fs::write(md.recovery_log_file(), "not-a-valid-line\n").unwrap();
        assert!(read_all(&md).is_err(), "corrupt log must fail closed");
    }

    #[test]
    fn expire_drops_old_entries_outside_keep_last() {
        let (_d, md) = md();
        // 3 entries; now=1000, grace=200 → fresh means ts>=800, so
        // ts=850/900 are fresh and ts=10 is old. keep_last=1 would also
        // retain the newest, but the old ts=10 entry is neither fresh nor
        // in the last-1, so it is pruned.
        record(&md, &entry(10, 1)).unwrap();
        record(&md, &entry(850, 2)).unwrap();
        record(&md, &entry(900, 3)).unwrap();
        let pruned = expire(
            &md,
            1000,
            &RetentionPolicy {
                grace_secs: 200,
                keep_last: 1,
            },
        )
        .unwrap();
        assert_eq!(pruned, 1, "the ts=10 entry is old and not in last-1");
        assert_eq!(roots(&md).unwrap(), BTreeSet::from([h(2), h(3)]));
    }

    #[test]
    fn would_expire_counts_without_mutating() {
        let (_d, md) = md();
        record(&md, &entry(10, 1)).unwrap();
        record(&md, &entry(850, 2)).unwrap();
        record(&md, &entry(900, 3)).unwrap();
        let policy = RetentionPolicy {
            grace_secs: 200,
            keep_last: 1,
        };
        let before = read_all(&md).unwrap();
        let n = would_expire(&md, 1000, &policy).unwrap();
        assert_eq!(n, 1, "ts=10 is the only expirable entry");
        // The log itself is untouched by the preview.
        assert_eq!(
            read_all(&md).unwrap(),
            before,
            "would_expire must not mutate"
        );
    }

    #[test]
    fn expire_keep_last_retains_old_recent_entries() {
        let (_d, md) = md();
        record(&md, &entry(1, 1)).unwrap();
        record(&md, &entry(2, 2)).unwrap();
        // Everything is "old" vs now, but keep_last=5 retains all.
        let pruned = expire(
            &md,
            1_000_000,
            &RetentionPolicy {
                grace_secs: 0,
                keep_last: 5,
            },
        )
        .unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(roots(&md).unwrap(), BTreeSet::from([h(1), h(2)]));
    }

    #[test]
    fn a_record_after_a_torn_tail_is_not_glued_to_it() {
        let (_d, md) = md();
        record(&md, &entry(100, 1)).unwrap();
        let mut f = OpenOptions::new()
            .append(true)
            .open(md.recovery_log_file())
            .unwrap();
        f.write_all(b"1700000000\tamend\t").unwrap();
        drop(f);
        record(&md, &entry(200, 2)).unwrap();
        let roots = roots(&md).expect("a torn tail must not make the log unreadable");
        assert!(
            roots.contains(&h(2)),
            "a record appended after a torn tail must be a root"
        );
    }

    #[test]
    fn an_entry_cut_before_its_newline_does_not_swallow_the_next_record() {
        let (_d, md) = md();
        let line = format!("100\tamend\t{}\tmain", hash::to_hex(&h(1)));
        fs::write(md.recovery_log_file(), line).unwrap();
        record(&md, &entry(200, 2)).unwrap();
        let roots = roots(&md).unwrap();
        assert!(
            roots.contains(&h(2)),
            "the record after an entry missing its newline must be a root"
        );
    }

    #[test]
    fn a_log_with_an_unterminated_last_line_still_reads() {
        let (_d, md) = md();
        record(&md, &entry(100, 1)).unwrap();
        let mut f = OpenOptions::new()
            .append(true)
            .open(md.recovery_log_file())
            .unwrap();
        f.write_all(&[0; 40]).unwrap();
        drop(f);
        assert_eq!(roots(&md).unwrap(), BTreeSet::from([h(1)]));
        assert_eq!(
            would_expire(&md, 10_000, &RetentionPolicy::default()).unwrap(),
            0
        );
    }

    #[test]
    fn a_record_after_a_torn_tail_keeps_the_complete_lines() {
        let (_d, md) = md();
        record(&md, &entry(100, 1)).unwrap();
        let mut f = OpenOptions::new()
            .append(true)
            .open(md.recovery_log_file())
            .unwrap();
        f.write_all(&[0; 5000]).unwrap();
        drop(f);
        record(&md, &entry(200, 2)).unwrap();
        assert_eq!(roots(&md).unwrap(), BTreeSet::from([h(1), h(2)]));
        let raw = fs::read_to_string(md.recovery_log_file()).unwrap();
        assert!(raw.ends_with('\n') && !raw.contains('\0'));
    }

    #[test]
    fn a_log_that_is_only_a_torn_line_is_emptied_by_the_next_record() {
        let (_d, md) = md();
        fs::write(md.recovery_log_file(), b"1700000000\tam").unwrap();
        assert!(roots(&md).unwrap().is_empty());
        record(&md, &entry(200, 2)).unwrap();
        assert_eq!(roots(&md).unwrap(), BTreeSet::from([h(2)]));
    }

    #[test]
    fn records_from_parallel_writers_are_all_kept() {
        let (_d, md) = md();
        std::thread::scope(|scope| {
            for writer in 0..8_u8 {
                let md = &md;
                scope.spawn(move || {
                    for n in 0..20_u8 {
                        let id = writer * 20 + n + 1;
                        record(md, &entry(u64::from(id), id)).unwrap();
                    }
                });
            }
        });
        assert_eq!(roots(&md).unwrap().len(), 160);
    }

    #[test]
    fn two_entries_glued_into_one_line_fail_closed() {
        let (_d, md) = md();
        let a = hash::to_hex(&h(1));
        let b = hash::to_hex(&h(2));
        let glued = format!("100\tamend\t{a}\tmain200\tamend\t{b}\tmain\n");
        fs::write(md.recovery_log_file(), glued).unwrap();
        assert!(read_all(&md).is_err());
    }
}
