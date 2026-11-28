//! `kit grep` — print the lines of tracked files that match a pattern, from
//! the worktree, the index (`--cached`) or revisions. The matcher and the
//! line scanner live in [`libkit::grep`].

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use clap::Parser;
use kit_core::hash::Hash;
use kit_core::index::EntryStatus;
use kit_core::object::{EntryMode, Object};
use kit_core::store::ObjectStore;
use kit_core::worktree;
use libkit::grep::{Matcher, Options, Scanner};

use crate::clap_args;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "kit grep",
    about = "Print lines of tracked files that match a pattern."
)]
#[allow(clippy::struct_excessive_bools)] // one flag each, as git has them
struct GrepOpts {
    /// Ignore case.
    #[arg(short = 'i', long = "ignore-case")]
    ignore_case: bool,
    /// Match whole words only.
    #[arg(short = 'w', long = "word-regexp")]
    word: bool,
    /// Select the lines that do not match.
    #[arg(short = 'v', long = "invert-match")]
    invert: bool,
    /// Print line numbers.
    #[arg(short = 'n', long = "line-number")]
    line_number: bool,
    /// Print only the names of files with a selected line.
    #[arg(short = 'l', long = "files-with-matches", conflicts_with = "count")]
    files: bool,
    /// Print the number of selected lines in each file.
    #[arg(short = 'c', long = "count")]
    count: bool,
    /// Print nothing; the exit status says whether a line was selected.
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
    /// Take the patterns literally.
    #[arg(short = 'F', long = "fixed-strings", conflicts_with_all = ["extended", "basic"])]
    fixed: bool,
    /// Read the patterns as regular expressions (the default).
    #[arg(short = 'E', long = "extended-regexp", conflicts_with = "basic")]
    extended: bool,
    /// Read the patterns as `-E` does.
    #[arg(short = 'G', long = "basic-regexp")]
    basic: bool,
    /// A pattern; repeatable. A line matching any of them is selected.
    #[arg(short = 'e', value_name = "pattern", allow_hyphen_values = true)]
    patterns: Vec<String>,
    /// Search the staged content instead of the worktree.
    #[arg(long)]
    cached: bool,
    /// The pattern, unless `-e` gives one, then revisions and paths.
    args: Vec<String>,
}

/// What `kit grep` prints for each file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Lines { numbers: bool },
    Files,
    Count,
    Quiet,
}

/// One file to search, and where its bytes come from.
enum Source {
    Worktree,
    Object(Hash),
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    // Arguments after `--` are paths. clap would drop the separator.
    let (args, explicit) = match args.iter().position(|a| a == "--") {
        Some(at) => (&args[..at], &args[at + 1..]),
        None => (args, &[][..]),
    };
    let mut opts = match clap_args::parse::<GrepOpts>("kit grep", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    if opts.patterns.is_empty() {
        if opts.args.is_empty() {
            return super::usage_error(
                "usage: kit grep [<options>] [-e] <pattern> [--cached | <rev>...] [[--] <path>...]",
            );
        }
        let pattern = opts.args.remove(0);
        opts.patterns.push(pattern);
    }
    let options = Options {
        ignore_case: opts.ignore_case,
        word: opts.word,
        invert: opts.invert,
        fixed: opts.fixed,
    };
    let matcher = match Matcher::new(&opts.patterns, options) {
        Ok(m) => m,
        Err(e) => return super::usage_error(&format!("invalid pattern: {e}")),
    };
    let mode = if opts.quiet {
        Mode::Quiet
    } else if opts.files {
        Mode::Files
    } else if opts.count {
        Mode::Count
    } else {
        Mode::Lines {
            numbers: opts.line_number,
        }
    };

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };
    let (revs, paths) = match split_args(&repo, &cwd, &opts.args, explicit) {
        Ok(split) => split,
        Err(code) => return code,
    };
    if opts.cached && !revs.is_empty() {
        return super::usage_error("--cached does not combine with a revision");
    }

    let mut out = BufWriter::new(io::stdout().lock());
    let mut search = Search {
        store: repo.store(),
        root: repo.layout().worktree_root(),
        matcher: &matcher,
        mode,
        out: &mut out,
        any: false,
    };
    let result = if revs.is_empty() {
        search_index(&repo, &mut search, &paths, opts.cached)
    } else {
        revs.iter()
            .try_for_each(|rev| search_revision(&repo, &mut search, rev, &paths))
    };
    let any = search.any;
    if let Err(code) = result {
        return code;
    }
    match out.flush() {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => {
            return super::error(&format!("write: {e}"), exit::IOERR);
        }
        _ => {}
    }
    if any { exit::OK } else { exit::GENERAL_ERROR }
}

/// Split the positional arguments into revisions and paths, as git does: an
/// argument that resolves is a revision until the first one that does not,
/// which starts the paths. `explicit` holds the arguments after `--`.
fn split_args(
    repo: &libkit::Repo,
    cwd: &Path,
    positional: &[String],
    explicit: &[String],
) -> Result<(Vec<String>, Vec<String>), u8> {
    let mut revs = Vec::new();
    let mut raw: Vec<&String> = Vec::new();
    for arg in positional {
        let in_worktree = cwd.join(arg).symlink_metadata().is_ok();
        let is_rev = raw.is_empty()
            && libkit::revspec::resolve_revision(repo.store(), repo.layout(), arg).is_ok();
        if is_rev && in_worktree && explicit.is_empty() {
            return Err(super::usage_error(&format!(
                "ambiguous argument '{arg}': both revision and filename; \
                 use '--' to separate paths from revisions"
            )));
        }
        if is_rev {
            revs.push(arg.clone());
        } else if in_worktree {
            raw.push(arg);
        } else {
            return Err(super::usage_error(&format!(
                "ambiguous argument '{arg}': unknown revision or path not in the worktree; \
                 use '--' to separate paths from revisions"
            )));
        }
    }
    raw.extend(explicit);
    let root = repo.layout().worktree_root();
    let mut paths = Vec::with_capacity(raw.len());
    for arg in raw {
        if arg.starts_with(':') || arg.contains(['*', '?', '[']) {
            return Err(super::usage_error(&format!(
                "'{arg}': globs and pathspec magic are not supported"
            )));
        }
        let abs = cwd.join(arg);
        let at_root = matches!(
            (abs.canonicalize(), root.canonicalize()),
            (Ok(a), Ok(b)) if a == b
        );
        if at_root {
            paths.push(String::new());
            continue;
        }
        match super::index_path_for_arg(root, &abs) {
            Ok(path) => paths.push(path),
            Err(e) => return Err(super::usage_error(&e)),
        }
    }
    Ok((revs, paths))
}

/// Whether `path` is one of `paths` or below one. No paths selects every
/// path, and so does the empty path, which names the root.
fn selected(paths: &[String], path: &str) -> bool {
    paths.is_empty()
        || paths.iter().any(|p| {
            let p = p.trim_end_matches('/');
            p.is_empty()
                || path == p
                || path
                    .strip_prefix(p)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

struct Search<'a> {
    store: &'a ObjectStore,
    root: &'a Path,
    matcher: &'a Matcher,
    mode: Mode,
    out: &'a mut dyn Write,
    any: bool,
}

impl Search<'_> {
    /// Search one file, shown as `name`, at `path` in the tree.
    fn file(&mut self, name: &str, path: &str, source: &Source) -> Result<(), u8> {
        let numbers = matches!(self.mode, Mode::Lines { numbers: true });
        let print = matches!(self.mode, Mode::Lines { .. });
        let out = &mut *self.out;
        let mut on_line = |n: u64, line: &[u8]| {
            if !print {
                return;
            }
            let _ = if numbers {
                write!(out, "{name}:{n}:")
            } else {
                write!(out, "{name}:")
            };
            let _ = out.write_all(line);
            let _ = out.write_all(b"\n");
        };
        let mut scanner = Scanner::new(self.matcher, &mut on_line);
        match source {
            Source::Worktree => {
                let Ok(mut file) = File::open(self.root.join(path)) else {
                    // A tracked file missing from the worktree has nothing to
                    // search, as in git.
                    return Ok(());
                };
                if let Err(e) = io::copy(&mut file, &mut scanner) {
                    return Err(super::error(&format!("read {name}: {e}"), exit::IOERR));
                }
            }
            Source::Object(hash) => {
                if let Err(e) = worktree::write_blob(self.store, hash, &mut scanner) {
                    return Err(super::error(&format!("read {name}: {e}"), exit::DATAERR));
                }
            }
        }
        let found = scanner.finish();
        if found.selected == 0 {
            return Ok(());
        }
        self.any = true;
        let _ = match self.mode {
            Mode::Lines { .. } if found.binary => writeln!(self.out, "Binary file {name} matches"),
            Mode::Files => writeln!(self.out, "{name}"),
            Mode::Count => writeln!(self.out, "{name}:{}", found.selected),
            Mode::Lines { .. } | Mode::Quiet => Ok(()),
        };
        Ok(())
    }
}

/// Search the tracked files: their content in the worktree, or the staged
/// content with `cached`. Symlinks are not searched.
fn search_index(
    repo: &libkit::Repo,
    search: &mut Search<'_>,
    paths: &[String],
    cached: bool,
) -> Result<(), u8> {
    let idx = super::read_or_seed_index_from_head(repo.layout(), repo.store())
        .map_err(|e| super::error(&e, exit::DATAERR))?;
    for entry in &idx.entries {
        if !matches!(entry.status, EntryStatus::Blob | EntryStatus::Executable)
            || !selected(paths, &entry.path)
        {
            continue;
        }
        let source = if cached {
            Source::Object(entry.object_hash)
        } else {
            Source::Worktree
        };
        let name = super::display_path(&entry.path);
        search.file(&name, &entry.path, &source)?;
    }
    Ok(())
}

/// Search the tree of `rev`, with `rev:` before each path. Only the store is
/// read.
fn search_revision(
    repo: &libkit::Repo,
    search: &mut Search<'_>,
    rev: &str,
    paths: &[String],
) -> Result<(), u8> {
    let store = repo.store();
    let hash = libkit::revspec::resolve_revision(store, repo.layout(), rev)
        .map_err(|e| super::usage_error(&format!("{rev}: {e}")))?;
    let tree = match store.read_object(&hash) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(Object::Tree(_)) => hash,
        Ok(_) => return Err(super::usage_error(&format!("{rev}: not a commit or tree"))),
        Err(e) => return Err(super::error(&format!("{rev}: {e}"), exit::DATAERR)),
    };
    let entries = kit_core::ops::diff_trees(store, None, Some(tree))
        .map_err(|e| super::error(&format!("{rev}: {e}"), exit::DATAERR))?;
    for e in entries.entries {
        let (Some(blob), Some(mode)) = (e.new_hash, e.new_mode) else {
            continue;
        };
        if !matches!(mode, EntryMode::Blob | EntryMode::Executable) || !selected(paths, &e.path) {
            continue;
        }
        let name = format!("{rev}:{}", super::display_path(&e.path));
        search.file(&name, &e.path, &Source::Object(blob))?;
    }
    Ok(())
}
