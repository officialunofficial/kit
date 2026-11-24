//! `kit ls-tree [-r] [-z] <tree-ish> [<path>...]` — list the entries of a
//! tree, like `git ls-tree`.
//!
//! Each entry prints as `<mode> <type> <hash>\t<name>` where `<mode>` is
//! the git octal mode (`100644`/`100755`/`120000`/`040000`) and `<hash>`
//! is a 64-hex BLAKE3 id. `-r` recurses (showing leaf blobs with full
//! paths and omitting tree lines, like git); `-z` NUL-terminates records
//! and emits raw paths (otherwise special-byte paths are C-style quoted).

use std::io::Write;

use clap::Parser;
use kit_core::hash::Hash;
use kit_core::object::{EntryMode, Object};
use kit_core::store::{MAX_TREE_DEPTH, ObjectStore};

use crate::clap_args;
use crate::exit;
use crate::format;
use libkit::revspec;

#[derive(Debug, Parser)]
#[command(name = "kit ls-tree", about = "List the contents of a tree object.")]
struct LsTreeOpts {
    /// Recurse into sub-trees (show leaf blobs with full paths).
    #[arg(short = 'r')]
    recursive: bool,
    /// NUL-terminate records and emit raw (unquoted) paths.
    #[arg(short = 'z')]
    z: bool,
    /// Tree-ish (commit, tag, tree, ref, or hash) followed by optional
    /// pathspecs limiting the listing.
    args: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<LsTreeOpts>("kit ls-tree", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let Some((spec, pathspecs)) = opts.args.split_first() else {
        return super::usage_error("usage: kit ls-tree [-r] [-z] <tree-ish> [<path>...]");
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a kit repo: {e}"), exit::GENERAL_ERROR),
    };

    let tree_hash = match resolve_tree(&store, &layout, spec) {
        Ok(h) => h,
        Err(msg) => return emit_err(&msg, exit::GENERAL_ERROR),
    };

    // Each pathspec is (normalized-path, had-trailing-slash). A trailing
    // slash (`sub/`) means "list the directory's contents".
    let specs: Vec<(String, bool)> = pathspecs.iter().map(|p| normalize(p)).collect();
    let mut stdout = std::io::stdout().lock();
    let listing = Listing {
        store: &store,
        recursive: opts.recursive,
        z: opts.z,
        pathspecs: &specs,
    };
    if let Err(msg) = listing.list(&tree_hash, "", 0, &mut stdout) {
        return emit_err(&msg, exit::GENERAL_ERROR);
    }
    exit::OK
}

/// What a listing reads and how it prints: the store, `-r`, `-z` and the
/// normalized pathspecs.
struct Listing<'a> {
    store: &'a ObjectStore,
    recursive: bool,
    z: bool,
    pathspecs: &'a [(String, bool)],
}

impl Listing<'_> {
    /// Recursively emit a tree's entries, honoring pathspecs like git.
    ///
    /// Without pathspecs: list immediate entries (a sub-tree prints as
    /// `040000 tree`), recursing only under `-r`. With pathspecs we descend
    /// into a sub-tree whenever a pathspec lies **within** it (e.g.
    /// `sub/inner.txt` descends through `sub`), when `-r` recurses a selected
    /// tree, or when a `sub/` pathspec asks to list its contents; a sub-tree
    /// named exactly by a pathspec (no trailing slash, no `-r`) prints as a
    /// tree line. An entry is printed when it equals or lies under a pathspec.
    ///
    /// `depth` is the nesting of `tree_hash` below the listed tree. Past
    /// [`MAX_TREE_DEPTH`], the limit checkout uses, the listing refuses, so a
    /// hostile chain of trees cannot overflow the stack.
    fn list(
        &self,
        tree_hash: &Hash,
        prefix: &str,
        depth: usize,
        out: &mut impl Write,
    ) -> Result<(), String> {
        if depth > MAX_TREE_DEPTH {
            return Err(format!("tree nesting exceeds {MAX_TREE_DEPTH} levels"));
        }
        let Object::Tree(tree) = self
            .store
            .read_object(tree_hash)
            .map_err(|e| format!("read tree: {e}"))?
        else {
            return Err(format!("{} is not a tree", format::hex_hash(tree_hash)));
        };
        for e in &tree.entries {
            let Ok(name) = std::str::from_utf8(&e.name) else {
                return Err("tree entry name is not valid UTF-8".to_string());
            };
            let path = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}/{name}")
            };
            let is_tree = e.mode == EntryMode::Tree;

            if self.pathspecs.is_empty() {
                if is_tree && self.recursive {
                    self.list(&e.object_hash, &path, depth + 1, out)?;
                } else {
                    emit_entry(e, &path, self.z, out);
                }
                continue;
            }

            // `path` equals or lies under a pathspec.
            let matched = self
                .pathspecs
                .iter()
                .any(|(s, _)| super::index_path_matches_or_descends(&path, s));
            // A pathspec lies strictly under `path` (a dir on the way to a
            // deeper target) — descend to reach it.
            let ancestor = self
                .pathspecs
                .iter()
                .any(|(s, _)| super::index_path_descends_from(s, &path));
            // `path` is named with a trailing slash → list its contents.
            let list_contents = self.pathspecs.iter().any(|(s, slash)| *slash && &path == s);

            if is_tree {
                if ancestor || list_contents || (matched && self.recursive) {
                    self.list(&e.object_hash, &path, depth + 1, out)?;
                } else if matched {
                    emit_entry(e, &path, self.z, out);
                }
            } else if matched {
                emit_entry(e, &path, self.z, out);
            }
        }
        Ok(())
    }
}

/// Emit one `<mode> <type> <hash>\t<name>` record (NUL-terminated raw under
/// `-z`, else newline-terminated with the name C-style quoted if needed).
fn emit_entry(e: &kit_core::object::TreeEntry, path: &str, z: bool, out: &mut impl Write) {
    let (mode, ty) = git_mode_and_type(e.mode);
    let hash = format::hex_hash(&e.object_hash);
    if z {
        let _ = write!(out, "{mode} {ty} {hash}\t{path}\0");
    } else {
        let shown = super::c_quote_path(path);
        let shown = shown.as_deref().unwrap_or(path);
        let _ = writeln!(out, "{mode} {ty} {hash}\t{shown}");
    }
}

/// Map an [`EntryMode`] to git's octal mode + object type token.
fn git_mode_and_type(mode: EntryMode) -> (&'static str, &'static str) {
    match mode {
        EntryMode::Blob => ("100644", "blob"),
        EntryMode::Executable => ("100755", "blob"),
        EntryMode::Symlink => ("120000", "blob"),
        EntryMode::Tree => ("040000", "tree"),
    }
}

/// Resolve a tree-ish spec to a tree hash: commit/remix → its tree, tag →
/// its target's tree, a tree → itself.
fn resolve_tree(
    store: &ObjectStore,
    layout: &kit_core::layout::RepoLayout,
    spec: &str,
) -> Result<Hash, String> {
    let h = revspec::resolve_revision(store, layout, spec)
        .map_err(|e| format!("bad revision '{spec}': {e}"))?;
    revspec::tree_of(store, &h).map_err(|e| e.to_string())
}

/// Normalize a pathspec to `(repo-relative path, had-trailing-slash)`.
fn normalize(spec: &str) -> (String, bool) {
    let s = spec.replace('\\', "/");
    let s = s.strip_prefix("./").unwrap_or(&s);
    let dir_slash = s.ends_with('/');
    let s = s.strip_suffix('/').unwrap_or(s);
    (s.to_string(), dir_slash)
}

use super::error as emit_err;
