//! `kit show-ref [--heads] [--tags] [<pattern>...]` — list refs as
//! `<hash> <refname>`, like `git show-ref`. Output is sorted by full ref name;
//! the hash is a 64-hex BLAKE3 id (vs git's 40-hex SHA-1). A pattern keeps a
//! ref when it equals the full ref name or equals its trailing path
//! components, so `main` keeps `refs/heads/main` and not `refs/heads/domain`.

use std::io::Write;

use clap::Parser;
use kit_core::refs;

use crate::clap_args;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "kit show-ref", about = "List refs and their object ids.")]
struct ShowRefOpts {
    /// Limit to `refs/heads/*` (branches).
    #[arg(long)]
    heads: bool,
    /// Limit to `refs/tags/*`.
    #[arg(long)]
    tags: bool,
    /// Keep the refs that a pattern names: the full ref name, or its trailing
    /// path components (`main` for `refs/heads/main`).
    patterns: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<ShowRefOpts>("kit show-ref", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    if opts.patterns.iter().any(String::is_empty) {
        return super::usage_error("a pattern must not be empty");
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };

    // Neither flag → show both heads and tags; either flag selects only
    // that namespace (both flags → the union, matching git).
    let want_heads = opts.heads || !opts.tags;
    let want_tags = opts.tags || !opts.heads;

    let mut lines: Vec<(String, String)> = Vec::new(); // (full refname, hash hex)
    if want_heads {
        match super::list_refs_parallel(&layout) {
            Ok(rs) => collect(&mut lines, &rs, "refs/heads/"),
            Err(e) => return emit_err(&format!("list refs: {e}"), exit::GENERAL_ERROR),
        }
    }
    if want_tags {
        match super::list_tags_parallel(&layout) {
            Ok(rs) => collect(&mut lines, &rs, "refs/tags/"),
            Err(e) => return emit_err(&format!("list tags: {e}"), exit::GENERAL_ERROR),
        }
    }
    // Remote-tracking refs are listed in the unfiltered view (like
    // git show-ref); --heads/--tags keep their narrow meaning.
    if !opts.heads && !opts.tags {
        match refs::list_remote_names(&layout) {
            Ok(remotes) => {
                for remote in remotes {
                    match super::list_remote_refs_parallel(&layout, &remote) {
                        Ok(rs) => {
                            collect(&mut lines, &rs, &format!("refs/remotes/{remote}/"));
                        }
                        Err(e) => {
                            return emit_err(
                                &format!("list remote refs: {e}"),
                                exit::GENERAL_ERROR,
                            );
                        }
                    }
                }
            }
            Err(e) => return emit_err(&format!("list remotes: {e}"), exit::GENERAL_ERROR),
        }
    }
    lines.retain(|(name, _)| matches_any(name, &opts.patterns));
    lines.sort_by(|a, b| a.0.cmp(&b.0));

    let mut stdout = std::io::stdout().lock();
    for (name, hash) in &lines {
        let _ = writeln!(stdout, "{hash} {name}");
    }
    // Like git, exit non-zero (no diagnostic) when nothing matched, so a
    // script can test for the existence of any head/tag.
    if lines.is_empty() {
        exit::GENERAL_ERROR
    } else {
        exit::OK
    }
}

/// Whether `name` passes the patterns: no pattern keeps every ref, and a
/// pattern keeps the ref it equals or the ref whose trailing path components
/// it equals.
fn matches_any(name: &str, patterns: &[String]) -> bool {
    patterns.is_empty()
        || patterns.iter().any(|p| {
            name == p
                || name
                    .strip_suffix(p.as_str())
                    .is_some_and(|head| head.ends_with('/'))
        })
}

/// Push `(<prefix><name>, hex hash)` for every ref with a readable hash.
fn collect(out: &mut Vec<(String, String)>, rs: &[refs::Ref], prefix: &str) {
    for r in rs {
        if let Some(h) = &r.hash {
            out.push((format!("{prefix}{}", r.name), format::hex_hash(h)));
        }
    }
}

use super::error as emit_err;
