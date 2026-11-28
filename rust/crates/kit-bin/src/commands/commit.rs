//! `kit commit` — make a signed commit from the staging index.
//!
//! The library makes the commit: see [`libkit::commit`]. This module reads
//! the arguments, composes the message (`-m`, `-F`, the editor), loads the
//! key, and prints the summary or the JSON result.
//!
//! The module also keeps two helpers for the commands that sign objects:
//! `load_commit_signer` and `resolve_author`.

use std::io::{BufWriter, Write};

use clap::{Parser, ValueEnum};
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity, Object, Tag};
use kit_core::ops::conflict_state::ConflictRecord;
use libkit::signer::{self, Signer};

use crate::clap_args;
use crate::config::Config;
use crate::editor::{COMMIT_EDITMSG_TEMPLATE, check_usable, spawn_editor};
use crate::exit;
use crate::format::{self, JsonObject};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CommitFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "kit commit",
    about = "Create a signed commit from the staging index."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct CommitOptions {
    /// Commit message. If omitted, `$EDITOR` is launched.
    #[arg(short, long)]
    message: Option<String>,
    /// Read the commit message from `<file>` (like `git commit -F`). Use
    /// `-` to read from stdin. Mutually exclusive with `-m`.
    #[arg(
        short = 'F',
        long = "file",
        value_name = "FILE",
        conflicts_with = "message"
    )]
    file: Option<String>,
    /// Override the author Identity for this commit.
    #[arg(long = "author", value_name = "SPEC")]
    author_spec: Option<String>,
    /// Stage every tracked-and-modified file before committing
    /// (mirrors `git commit -a`).
    #[arg(short = 'a', long)]
    all: bool,
    /// Accept a commit whose tree equals its parent's, and a first commit with
    /// nothing staged. kit commits an unchanged tree without the flag too, so
    /// the flag only matters for the first commit.
    #[arg(long = "allow-empty")]
    allow_empty: bool,
    /// Replace the current commit (HEAD) instead of adding a new one.
    ///
    /// The new commit re-uses HEAD's parent(s) as its own parent(s)
    /// (so it supersedes HEAD rather than building on it), takes its
    /// tree from the staging index, and is re-signed. The branch is
    /// moved to the new commit; the superseded commit becomes
    /// unreachable. If `-m` is omitted, the previous commit's message
    /// is reused (no `$EDITOR` is launched).
    ///
    /// NOTE: the superseded commit is not deleted — it stays on disk as
    /// an unreachable object until `kit gc` reclaims it.
    #[arg(long)]
    amend: bool,
    /// Make a commit whose subject is `fixup! ` and the subject of `<rev>`,
    /// for `kit rebase --autosquash` to fold into `<rev>`. No editor opens;
    /// `-m` or `-F` text goes in the body.
    #[arg(long, value_name = "REV", conflicts_with_all = ["amend", "squash"])]
    fixup: Option<String>,
    /// Make a commit whose subject is `squash! ` and the subject of `<rev>`.
    /// The body comes from `-m` or `-F`, else from `$EDITOR`.
    #[arg(long, value_name = "REV", conflicts_with = "amend")]
    squash: Option<String>,
    /// Suppress the commit summary line (git `-q`).
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,
    /// Emit a machine-readable JSON result object to stdout on success:
    /// `{"ok":true,"hash":"<64-hex>","branch":"<name>|null",
    /// "parents":["<64-hex>",...],"tree":"<64-hex>","subject":"...",
    /// "is_merge":<bool>,"is_root":<bool>}`.
    #[arg(long, value_enum, default_value = "default")]
    format: CommitFormat,
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    // Split fused `-am<msg>` / `-am <msg>` shortcuts into the
    // equivalent `-a -m <msg>` so clap sees only canonical forms.
    let normalised = expand_dash_am(args);
    let opts = match clap_args::parse::<CommitOptions>("kit commit", &normalised) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, CommitFormat::Json);

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match super::open_store_configured(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a kit repo: {e}"), exit::GENERAL_ERROR),
    };
    let cfg = match crate::config::read_or_default(&layout) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    // The library reads the merge state and the commit to amend. The message
    // may take long to compose, so the lock comes later, in `create`.
    let pending = match libkit::commit::begin(&layout, &store, opts.amend) {
        Ok(p) => p,
        Err(e) => return super::fail(e),
    };

    // `--fixup` and `--squash` put their subject before the `-m` or `-F`
    // text. `--squash` without either opens the editor on the subject.
    let fold = match fold_subject(&layout, &store, &opts) {
        Ok(fold) => fold,
        Err(code) => return code,
    };
    let msg = if let Some((subject, opens_editor)) = fold {
        let body = match (&opts.message, &opts.file) {
            (Some(m), _) => Some(m.clone()),
            (None, Some(path)) => match read_message_file(path) {
                Ok(m) => Some(m),
                Err(e) => return emit_err(&format!("read message file: {e}"), exit::NOINPUT),
            },
            (None, None) => None,
        };
        match body {
            Some(body) if !body.trim().is_empty() => format!("{subject}\n\n{}", body.trim()),
            None if opens_editor => {
                if let Err(e) = check_usable() {
                    return emit_err(&format!("commit: {e}, or pass -m <msg>"), exit::USAGE);
                }
                match spawn_editor(&format!("{subject}\n{COMMIT_EDITMSG_TEMPLATE}")) {
                    Ok(m) if !m.is_empty() => m,
                    Ok(_) => return emit_err("empty commit message — aborting", exit::USAGE),
                    Err(e) => return emit_err(&format!("editor: {e}"), exit::GENERAL_ERROR),
                }
            }
            Some(_) | None => subject,
        }
    } else {
        // Message precedence: `-m` → `-F <file>` → amend-reuse → merge message
        // (`MERGE_MSG`) → `$EDITOR`. `-F` and the defaults never launch the editor,
        // so they stay usable in non-interactive contexts.
        match opts.message {
            Some(m) => m,
            None => match &opts.file {
                Some(path) => match read_message_file(path) {
                    Ok(m) if !m.trim().is_empty() => m,
                    Ok(_) => return emit_err("empty commit message — aborting", exit::USAGE),
                    Err(e) => return emit_err(&format!("read message file: {e}"), exit::NOINPUT),
                },
                None => {
                    if let Some(m) = pending.default_message() {
                        m
                    } else {
                        if let Err(e) = check_usable() {
                            return emit_err(
                                &format!("commit: {e}, or pass -m <msg>"),
                                exit::USAGE,
                            );
                        }
                        match spawn_editor(COMMIT_EDITMSG_TEMPLATE) {
                            Ok(m) if !m.is_empty() => m,
                            Ok(_) => {
                                return emit_err("empty commit message — aborting", exit::USAGE);
                            }
                            Err(e) => {
                                return emit_err(&format!("editor: {e}"), exit::GENERAL_ERROR);
                            }
                        }
                    }
                }
            },
        }
    };

    let mut signer = match load_commit_signer(&layout, &cfg) {
        Ok(signer) => signer,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    let signer_public = match signer.public_key() {
        Ok(public) => public,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    // Precedence: --author flag → config.user_identity → pubkey-derived.
    let author = match resolve_author(
        opts.author_spec.as_deref(),
        &cfg.user_identity,
        &signer_public,
    ) {
        Ok(id) => id,
        Err(e) => return emit_err(&format!("author: {e}"), exit::CONFIG_ERROR),
    };

    // A merge in progress needs every conflict resolved and staged, exactly
    // like `kit merge --continue`.
    let gate = |records: &[ConflictRecord]| -> Result<(), String> {
        if let Some(path) =
            libkit::conflict::first_unresolved_marker(&cwd, records).map_err(|e| e.to_string())?
        {
            return Err(format!(
                "committing is not possible because '{path}' still has unresolved \
                 conflict markers; resolve it and `kit add` it"
            ));
        }
        libkit::conflict::ensure_staged(&layout, &store, records).map_err(|e| e.to_string())?;
        libkit::rerere::record(
            &layout,
            &store,
            super::conflict::rerere(&layout),
            records,
            &super::conflict::Notes,
        );
        Ok(())
    };
    let request = libkit::commit::Request {
        message: &msg,
        author,
        signer_public,
        all: opts.all,
        allow_empty: opts.allow_empty,
    };
    let created = match libkit::commit::create(
        &layout,
        &store,
        &pending,
        &request,
        &mut signer.0,
        &gate,
        &crate::progress::ServedWarning,
    ) {
        Ok(c) => c,
        Err(e) => return super::fail(e),
    };

    let subject = msg.lines().next().unwrap_or("");
    // git-shaped post-commit summary: `[<branch> <hash>] <subject>` plus
    // a diffstat and create/delete-mode trailers. Merge commits show no
    // diffstat, like git.
    let head_ref = match &created.branch {
        Some(b) => super::summary::HeadRef::Branch(b),
        None => super::summary::HeadRef::Detached,
    };
    if !opts.quiet {
        let mut stderr = BufWriter::with_capacity(8 * 1024, std::io::stderr().lock());
        super::summary::print_commit_summary(
            &mut stderr,
            &store,
            &head_ref,
            &created.commit,
            subject,
            created.is_root(),
            created.base_tree,
            Some(created.tree),
        );
        let _ = stderr.flush();
    }
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_hash("hash", &created.commit)
            .field_opt_str("branch", created.branch.as_deref())
            .field_raw(
                "parents",
                &format::json_string_array(
                    &created
                        .parents
                        .iter()
                        .map(format::hex_hash)
                        .collect::<Vec<_>>(),
                ),
            )
            .field_hash("tree", &created.tree)
            .field_str("subject", subject)
            .field_bool("is_merge", created.is_merge())
            .field_bool("is_root", created.is_root());
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    // The commit is published and its locks are released. A repository that
    // never fetches builds up packs, so the due step runs here, after the
    // output, and cannot change the result.
    super::maintenance::after_write(&layout, &store, &cfg, opts.quiet);
    exit::OK
}

/// The subject that `--fixup` or `--squash` asks for, with whether the
/// editor opens when no `-m` or `-F` gives a body, or `None` without either
/// flag.
fn fold_subject(
    layout: &RepoLayout,
    store: &kit_core::store::ObjectStore,
    opts: &CommitOptions,
) -> Result<Option<(String, bool)>, u8> {
    let (prefix, spec, opens_editor) = match (&opts.fixup, &opts.squash) {
        (Some(spec), _) => ("fixup!", spec, false),
        (None, Some(spec)) => ("squash!", spec, true),
        (None, None) => return Ok(None),
    };
    let target = libkit::revspec::resolve_revision(store, layout, spec)
        .map(|h| libkit::revspec::peel_tags(store, h))
        .map_err(|e| emit_err(&format!("bad commit '{spec}': {e}"), exit::DATAERR))?;
    let message = match store.read_object(&target) {
        Ok(Object::Commit(c)) => c.message,
        Ok(_) => {
            return Err(emit_err(
                &format!("'{spec}' is not a commit"),
                exit::DATAERR,
            ));
        }
        Err(e) => {
            return Err(emit_err(
                &format!("read '{spec}': {e}"),
                exit::GENERAL_ERROR,
            ));
        }
    };
    let subject = String::from_utf8_lossy(&message)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    Ok(Some((format!("{prefix} {subject}"), opens_editor)))
}

/// Pre-process `args` to canonicalize the combined `-am<msg>` /
/// `-am <msg>` shortcut into `-a -m <msg>`. Everything else passes
/// through unchanged. Clap then sees only canonical forms.
fn expand_dash_am(args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(args.len() + 2);
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-am" => {
                out.push("-a".to_owned());
                out.push("-m".to_owned());
                if let Some(next) = iter.next() {
                    out.push(next.clone());
                }
            }
            s if s.starts_with("-am") && s.len() > 3 => {
                out.push("-a".to_owned());
                out.push("-m".to_owned());
                out.push(s[3..].to_owned());
            }
            _ => out.push(a.clone()),
        }
    }
    out
}

/// A key that signs objects, with the failure shape that the commands share:
/// a message and an exit code.
pub(super) struct CommitSigner(pub(super) Signer);

impl CommitSigner {
    pub(super) fn public_key(&self) -> Result<[u8; 32], (String, u8)> {
        self.0.public_key().map_err(|e| signer_failure(&e))
    }

    /// Sign a [`Tag`] under the distinct tag domain.
    pub(super) fn sign_tag(&mut self, tag: &Tag) -> Result<[u8; 64], (String, u8)> {
        self.0.sign_tag(tag).map_err(|e| signer_failure(&e))
    }

    pub(super) fn sign_commit(&mut self, commit: &Commit) -> Result<[u8; 64], (String, u8)> {
        self.0.sign_commit(commit).map_err(|e| signer_failure(&e))
    }
}

fn signer_failure(error: &signer::Error) -> (String, u8) {
    (error.to_string(), crate::exit_map::signer_exit_code(error))
}

/// Load the signing key that the config names. A missing key is an error:
/// the user makes the key once with `kit keygen`.
pub(super) fn load_commit_signer(
    layout: &RepoLayout,
    cfg: &Config,
) -> Result<CommitSigner, (String, u8)> {
    signer::load(layout, &crate::environment::current(), cfg)
        .map(CommitSigner)
        .map_err(|e| signer_failure(&e))
}

/// Resolve the author of a commit or a tag.
///
/// The sibling commands (`cherry-pick`, `merge`, `tag`) share the precedence
/// of `commit`: the `--author` flag, then `user.identity`, then the signer
/// key. They pass `None` for a flag that they do not accept.
pub(super) fn resolve_author(
    author_flag: Option<&str>,
    cfg_user_identity: &str,
    signer_public: &[u8; 32],
) -> Result<Identity, String> {
    libkit::identity::resolve_author(author_flag, cfg_user_identity, signer_public)
        .map_err(|e| e.to_string())
}

/// Read a `-F`/`--file` commit message. `-` reads stdin; otherwise the
/// named file. Trailing whitespace is trimmed (git's default `-F` cleanup
/// drops trailing blank lines).
fn read_message_file(path: &str) -> std::io::Result<String> {
    use std::io::Read as _;
    let raw = if path == "-" {
        let mut s = String::new();
        std::io::stdin().lock().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(path)?
    };
    Ok(raw.trim_end().to_string())
}

use super::error as emit_err;

#[cfg(test)]
mod expand_dash_am_tests {
    use super::expand_dash_am;

    fn to_strs(args: &[String]) -> Vec<&str> {
        args.iter().map(String::as_str).collect()
    }

    #[test]
    fn fused_dash_am_with_inline_message() {
        let out = expand_dash_am(&["-amhello".to_owned()]);
        assert_eq!(to_strs(&out), &["-a", "-m", "hello"]);
    }

    #[test]
    fn spaced_dash_am_with_following_message() {
        let out = expand_dash_am(&["-am".to_owned(), "hello".to_owned()]);
        assert_eq!(to_strs(&out), &["-a", "-m", "hello"]);
    }

    #[test]
    fn unrelated_args_pass_through() {
        let out = expand_dash_am(&[
            "-m".to_owned(),
            "msg".to_owned(),
            "--author".to_owned(),
            "id".to_owned(),
        ]);
        assert_eq!(to_strs(&out), &["-m", "msg", "--author", "id"]);
    }
}
