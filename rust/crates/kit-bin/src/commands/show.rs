//! `kit show [<object>...]` — display objects (default `HEAD`).
//!
//! Mirrors `git show`:
//! - **commit** / **remix**: a header (`commit <hash>` / `Author` / `Date` /
//!   indented message, matching `kit log`) followed by the unified diff
//!   against its first parent. The diff body is produced by the same code as
//!   `kit diff`, so `show <commit>` is byte-identical to
//!   `diff <parent> <commit>` (modulo the abbreviated `index` ids).
//! - **tag**: the tag header, then the peeled target object.
//! - **tree**: an `ls-tree`-style listing.
//! - **blob**: the raw contents.
//!
//! Like `kit log`, the commit/tag headers carry kit's signed `Identity`
//! and 64-hex BLAKE3 ids, so the header lines diverge from git's
//! `Author: Name <email>` / 40-hex form — the same documented divergence as
//! `log`. The diff body, tree listing, and blob output match git.

use std::io::Write;

use clap::Parser;
use kit_core::hash::Hash;
use kit_core::object::{Identity, Object, Tag};
use kit_core::worktree;

use crate::clap_args;
use crate::exit;
use crate::format;
use libkit::{Repo, revspec};

/// Bound on tag-of-tag recursion, mirroring `diff`/`log`'s peel depth.
const MAX_TAG_DEPTH: usize = 16;

#[derive(Debug, Parser)]
#[command(
    name = "kit show",
    about = "Display objects (default HEAD): commits with their diff, tags, trees, blobs."
)]
struct ShowOpts {
    /// Show a diffstat instead of the full patch for commit/remix objects
    /// (like `git show --stat`): per-file changed-line counts, a `+`/`-`
    /// graph, and a summary line. Non-commit objects are shown as usual.
    #[arg(long)]
    stat: bool,
    /// Objects to show — revisions, refs, or hashes (e.g. `HEAD`, `main`,
    /// `HEAD~2`, `<hash>`, `<tag>`). Defaults to `HEAD`.
    objects: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<ShowOpts>("kit show", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };

    let specs: Vec<String> = if opts.objects.is_empty() {
        vec!["HEAD".to_string()]
    } else {
        opts.objects.clone()
    };

    let mut stdout = std::io::stdout().lock();
    for spec in &specs {
        let h = match revspec::resolve_revision(repo.store(), repo.layout(), spec) {
            Ok(h) => h,
            Err(e) => return emit_err(&e.to_string(), exit::GENERAL_ERROR),
        };
        if let Err((msg, code)) = show_object(&mut stdout, &repo, &h, 0, opts.stat) {
            return emit_err(&msg, code);
        }
    }
    exit::OK
}

/// Display one object. `tag_depth` bounds tag-of-tag recursion.
fn show_object(
    out: &mut impl Write,
    repo: &Repo,
    h: &Hash,
    tag_depth: usize,
    stat: bool,
) -> Result<(), (String, u8)> {
    let obj = repo
        .store()
        .read_object(h)
        .map_err(|e| (format!("read object: {e}"), exit::GENERAL_ERROR))?;
    match obj {
        Object::Commit(c) => show_commit_like(
            out,
            repo,
            h,
            "commit",
            &c.author,
            c.timestamp,
            &c.message,
            c.parents.first().copied(),
            c.tree_hash,
            stat,
        ),
        Object::Remix(r) => show_commit_like(
            out,
            repo,
            h,
            "remix",
            &r.author,
            r.timestamp,
            &r.message,
            r.parents.first().copied(),
            r.tree_hash,
            stat,
        ),
        Object::Tag(t) => show_tag(out, repo, &t, tag_depth, stat),
        Object::Tree(t) => {
            for e in &t.entries {
                let (mode, ty) = super::cat_file::git_mode_and_type(e.mode);
                let _ = writeln!(
                    out,
                    "{mode} {ty} {}\t{}",
                    format::hex_hash(&e.object_hash),
                    String::from_utf8_lossy(&e.name)
                );
            }
            Ok(())
        }
        Object::Blob(b) => {
            let _ = out.write_all(&b.data);
            Ok(())
        }
        Object::ChunkedBlob(_) => {
            let data = worktree::read_blob(repo.store(), h)
                .map_err(|e| (format!("reassemble: {e}"), exit::GENERAL_ERROR))?;
            let _ = out.write_all(&data);
            Ok(())
        }
        // `Delta` is a pack-only encoding and never the result of a plain
        // `read_object`, but handle it explicitly rather than via a wildcard.
        Object::Delta(_) => Err(("cannot show a delta object".to_string(), exit::DATAERR)),
    }
}

/// Render a commit or remix: a `kit log`-style header followed by the
/// unified diff against the first parent (an empty tree for a root commit).
#[allow(clippy::too_many_arguments)]
fn show_commit_like(
    out: &mut impl Write,
    repo: &Repo,
    hash: &Hash,
    label: &str,
    author: &Identity,
    timestamp: u64,
    message: &[u8],
    parent: Option<Hash>,
    tree: Hash,
    stat: bool,
) -> Result<(), (String, u8)> {
    let _ = writeln!(out, "{label} {}", format::hex_hash(hash));
    let _ = writeln!(
        out,
        "Author: {}",
        format::safe_text(&libkit::identity::short(author))
    );
    let _ = writeln!(out, "Date:   {}", format::human_date_utc(timestamp));
    let _ = writeln!(out);
    write_indented_message(out, message);
    let _ = writeln!(out);

    // Diff the first parent's tree against this tree (None ⇒ empty, so a
    // root commit shows every file as added), reusing `diff`'s renderer.
    let parent_tree = match parent {
        Some(p) => Some(
            libkit::revspec::tree_of(repo.store(), &p)
                .map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?,
        ),
        None => None,
    };
    let diff = libkit::diff::between_trees(repo, parent_tree, Some(tree))
        .map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?;
    // `--stat` renders the diffstat instead of the full patch (like
    // `git show --stat`), reusing `diff`'s byte-exact stat renderer.
    if stat {
        let rows = diff
            .stats()
            .map_err(|e| (e.to_string(), exit::GENERAL_ERROR))?;
        return super::diff::render_stat(out, &rows).map_err(|e| (e, exit::GENERAL_ERROR));
    }
    for e in diff.entries() {
        super::diff::emit_entry_patch(out, e, || {
            diff.patch_body(
                e,
                kit_core::ops::DEFAULT_CONTEXT_LINES,
                kit_core::ops::WhitespaceMode::Exact,
            )
        })
        .map_err(|e| (e, exit::GENERAL_ERROR))?;
    }
    Ok(())
}

/// Render an annotated/signed tag header, then the peeled target object.
fn show_tag(
    out: &mut impl Write,
    repo: &Repo,
    t: &Tag,
    tag_depth: usize,
    stat: bool,
) -> Result<(), (String, u8)> {
    let _ = writeln!(
        out,
        "tag {}",
        format::safe_text(&String::from_utf8_lossy(&t.name))
    );
    let _ = writeln!(
        out,
        "Tagger: {}",
        format::safe_text(&libkit::identity::short(&t.tagger))
    );
    let _ = writeln!(out, "Date:   {}", format::human_date_utc(t.timestamp));
    let _ = writeln!(out);
    // git prints the tag message un-indented, then a blank line, then the
    // target object.
    let msg = String::from_utf8_lossy(&t.message);
    for line in msg.lines() {
        let _ = writeln!(out, "{}", format::safe_text(line));
    }
    let _ = writeln!(out);

    if tag_depth + 1 >= MAX_TAG_DEPTH {
        return Err(("tag chain too deep".to_string(), exit::DATAERR));
    }
    show_object(out, repo, &t.target, tag_depth + 1, stat)
}

/// Write a commit message indented four spaces per line (blank lines stay
/// blank), matching `kit log`'s default format.
fn write_indented_message(out: &mut impl Write, message: &[u8]) {
    let text = String::from_utf8_lossy(message);
    for line in text.lines() {
        if line.is_empty() {
            let _ = writeln!(out);
        } else {
            let _ = writeln!(out, "    {}", format::safe_text(line));
        }
    }
}

use super::error as emit_err;
