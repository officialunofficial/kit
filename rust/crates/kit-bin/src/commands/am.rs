//! `kit am` — apply a mailbox of patch mails as commits (SPEC-PATCH §5,
//! §6). The mails are read by [`kit_core::ops::mailbox`], each patch is
//! applied by [`libkit::apply`] and committed by [`libkit::commit`].
//!
//! A paused `am` keeps its state in `<worktree-state>/am/`: the commit
//! `HEAD` named at the start, the number of the next mail, the number of
//! mails, and the mails.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use clap::Parser;
use kit_core::durable::{Parents, write_pointer};
use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::object::{Identity, Object};
use kit_core::ops::conflict_state;
use kit_core::ops::mailbox::{self, Mail};
use kit_core::ops::patch::{self, MAX_PATCH_BYTES};
use kit_core::refs;
use kit_core::store::{EphemeralSink, ObjectStore};
use libkit::apply::Target;

use crate::clap_args;
use crate::exit;

/// The most mails one `am` takes, so each has a four-digit name.
const MAX_MAILS: usize = 9999;

#[derive(Debug, Parser)]
#[command(name = "kit am", about = "Apply a mailbox of patches as commits.")]
struct AmOpts {
    /// Commit the staged result of the stopped mail and go on.
    #[arg(long = "continue", conflicts_with_all = ["skip", "abort", "mbox"])]
    resume: bool,
    /// Drop the stopped mail and go on.
    #[arg(long, conflicts_with_all = ["abort", "mbox"])]
    skip: bool,
    /// Go back to where `am` started.
    #[arg(long, conflicts_with = "mbox")]
    abort: bool,
    /// Mailbox files; `-` reads standard input.
    #[arg(value_name = "mbox", required_unless_present_any = ["resume", "skip", "abort"])]
    mbox: Vec<String>,
}

/// The state of a paused `am`.
struct State {
    orig_head: Hash,
    next: usize,
    last: usize,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_args::parse::<AmOpts>("kit am", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return super::error(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let repo = match super::open_repo(&cwd) {
        Ok(repo) => repo,
        Err(code) => return code,
    };
    let (layout, store) = (repo.layout(), repo.store());
    if opts.mbox.is_empty() {
        let state = match read_state(layout) {
            Ok(Some(s)) => s,
            Ok(None) => return super::error("no am is in progress", exit::GENERAL_ERROR),
            Err(e) => return super::error(&format!("am state: {e}"), exit::DATAERR),
        };
        return if opts.abort {
            abort(layout, &state)
        } else if opts.skip {
            go_on(layout, store, &state, state.next + 1)
        } else {
            resume(layout, store, &state)
        };
    }
    start(layout, store, &opts.mbox)
}

/// Read and check every mail, record the state, then apply them.
fn start(layout: &RepoLayout, store: &ObjectStore, names: &[String]) -> u8 {
    if let Some(op) = conflict_state::in_progress_op_name(layout) {
        return super::error(
            &format!("cannot start am: a {op} is in progress"),
            exit::GENERAL_ERROR,
        );
    }
    let mut mails: Vec<Vec<u8>> = Vec::new();
    for name in names {
        let text = match super::apply::read_patch(name) {
            Ok(t) => t,
            Err(code) => return code,
        };
        for (i, raw) in mailbox::split(&text).into_iter().enumerate() {
            if let Err(e) = mailbox::parse(raw) {
                return super::error(&format!("{name}: mail {}: {e}", i + 1), exit::DATAERR);
            }
            mails.push(raw.to_vec());
        }
    }
    if mails.is_empty() {
        return super::error("the mailbox holds no mail", exit::DATAERR);
    }
    if mails.len() > MAX_MAILS {
        return super::error(
            &format!("the mailbox holds over {MAX_MAILS} mails"),
            exit::DATAERR,
        );
    }
    let orig_head = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        Ok(None) => return super::error("am needs a commit to apply onto", exit::GENERAL_ERROR),
        Err(e) => return super::error(&format!("read HEAD: {e}"), exit::DATAERR),
    };
    if let Err(e) = write_state(layout, orig_head, &mails) {
        let _ = fs::remove_dir_all(layout.am_dir());
        return super::error(&format!("write am state: {e}"), exit::CANTCREAT);
    }
    let state = State {
        orig_head,
        next: 1,
        last: mails.len(),
    };
    go_on(layout, store, &state, 1)
}

/// Apply mails `from..=last`, committing each. Stop at one that does not
/// apply, with `next` naming it.
fn go_on(layout: &RepoLayout, store: &ObjectStore, state: &State, from: usize) -> u8 {
    for n in from..=state.last {
        if let Err(e) = set_next(layout, n) {
            return super::error(&format!("write am state: {e}"), exit::CANTCREAT);
        }
        let mail = match read_mail(layout, n) {
            Ok(m) => m,
            Err(code) => return code,
        };
        let subject = mail.message.lines().next().unwrap_or("").to_owned();
        let _ = writeln!(std::io::stdout().lock(), "Applying: {subject}");
        let files = match patch::parse(&mail.patch) {
            Ok(f) => f,
            Err(e) => return super::error(&format!("mail {n}: {e}"), exit::DATAERR),
        };
        if let Err(e) = libkit::apply::apply(
            layout,
            store,
            &files,
            Target::Both,
            false,
            &crate::progress::ServedWarning,
        ) {
            if !e.is_conflict() {
                return super::error(&format!("mail {n}: {e}"), exit::IOERR);
            }
            return super::error(
                &format!(
                    "mail {n} ({subject}) does not apply: {e}\n\
                     hint: apply it by hand, stage it, and run `kit am --continue`; \
                     or run `kit am --skip` or `kit am --abort`"
                ),
                exit::GENERAL_ERROR,
            );
        }
        if let Err(code) = commit(layout, store, &mail) {
            return code;
        }
    }
    if let Err(e) = fs::remove_dir_all(layout.am_dir()) {
        return super::error(&format!("remove am state: {e}"), exit::CANTCREAT);
    }
    exit::OK
}

/// `--continue`: commit the staged result of the stopped mail, then go on.
fn resume(layout: &RepoLayout, store: &ObjectStore, state: &State) -> u8 {
    match index_matches_head(layout, store) {
        Ok(true) => {
            return super::error(
                "nothing is staged for the stopped mail; stage the change, or run \
                 `kit am --skip`",
                exit::GENERAL_ERROR,
            );
        }
        Ok(false) => {}
        Err(e) => return super::error(&e, exit::DATAERR),
    }
    let mail = match read_mail(layout, state.next) {
        Ok(m) => m,
        Err(code) => return code,
    };
    if let Err(code) = commit(layout, store, &mail) {
        return code;
    }
    go_on(layout, store, state, state.next + 1)
}

/// `--abort`: move the branch, the index and the worktree back to
/// `orig-head`, then drop the state. `reset --hard` refuses, before any
/// change, a tracked file with a change that is not committed and an
/// untracked file the restore would overwrite.
fn abort(layout: &RepoLayout, state: &State) -> u8 {
    let args = [
        "--hard".to_owned(),
        "-q".to_owned(),
        hash::to_hex(&state.orig_head),
    ];
    let code = super::reset::run(&args);
    if code != exit::OK {
        return code;
    }
    if let Err(e) = fs::remove_dir_all(layout.am_dir()) {
        return super::error(&format!("remove am state: {e}"), exit::CANTCREAT);
    }
    exit::OK
}

/// Commit the index with the message and author of `mail`, signed by the
/// applier.
fn commit(layout: &RepoLayout, store: &ObjectStore, mail: &Mail) -> Result<(), u8> {
    let cfg = crate::config::read_or_default(layout)
        .map_err(|e| super::error(&format!("config: {e}"), exit::CONFIG_ERROR))?;
    let mut signer = super::commit::load_commit_signer(layout, &cfg)
        .map_err(|(msg, code)| super::error(&msg, code))?;
    let signer_public = signer
        .public_key()
        .map_err(|(msg, code)| super::error(&msg, code))?;
    let pending = libkit::commit::begin(layout, store, false).map_err(super::fail)?;
    let request = libkit::commit::Request {
        message: &mail.message,
        author: Identity::opaque(mail.author.as_bytes().to_vec()),
        signer_public,
        all: false,
        allow_empty: false,
    };
    libkit::commit::create(
        layout,
        store,
        &pending,
        &request,
        &mut signer.0,
        &|_| Ok(()),
        &crate::progress::ServedWarning,
    )
    .map_err(super::fail)?;
    Ok(())
}

/// Whether the staged tree is the tree of `HEAD`.
fn index_matches_head(layout: &RepoLayout, store: &ObjectStore) -> Result<bool, String> {
    let head = refs::resolve_head(layout)
        .map_err(|e| format!("read HEAD: {e}"))?
        .ok_or("HEAD names no commit")?;
    let Ok(Object::Commit(c)) = store.read_object(&head) else {
        return Err("HEAD is not a commit".to_owned());
    };
    let idx = super::read_or_seed_index_from_head(layout, store)?;
    let snapshot = EphemeralSink::new(store);
    let staged = kit_core::worktree::build_tree_from_index_against(
        store,
        &snapshot,
        &idx,
        false,
        Some(c.tree_hash),
    )
    .map_err(|e| format!("read index: {e}"))?;
    Ok(staged == c.tree_hash)
}

fn write_state(layout: &RepoLayout, orig_head: Hash, mails: &[Vec<u8>]) -> std::io::Result<()> {
    let dir = layout.am_dir();
    // `create_dir` fails when another `am` made the directory first.
    fs::create_dir(&dir)?;
    for (i, mail) in mails.iter().enumerate() {
        write_pointer(&dir.join(format!("{:04}", i + 1)), mail, Parents::Existing)?;
    }
    write_pointer(
        &dir.join("orig-head"),
        format!("{}\n", hash::to_hex(&orig_head)).as_bytes(),
        Parents::Existing,
    )?;
    write_pointer(
        &dir.join("last"),
        format!("{}\n", mails.len()).as_bytes(),
        Parents::Existing,
    )?;
    set_next(layout, 1)
}

fn set_next(layout: &RepoLayout, n: usize) -> std::io::Result<()> {
    write_pointer(
        &layout.am_dir().join("next"),
        format!("{n}\n").as_bytes(),
        Parents::Existing,
    )
}

/// The state of a paused `am`, or `None` when none is paused.
fn read_state(layout: &RepoLayout) -> Result<Option<State>, String> {
    let dir = layout.am_dir();
    if !dir.exists() {
        return Ok(None);
    }
    let field = |name: &str| -> Result<String, String> {
        let text = read_small(&dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
        text.strip_suffix('\n')
            .filter(|t| !t.is_empty() && !t.contains('\n'))
            .map(str::to_owned)
            .ok_or_else(|| format!("{name}: malformed"))
    };
    let number = |name: &str| -> Result<usize, String> {
        let t = field(name)?;
        if t.len() > 4 || !t.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{name}: malformed"));
        }
        t.parse().map_err(|_| format!("{name}: malformed"))
    };
    let orig = field("orig-head")?;
    if orig.len() != 64 {
        return Err("orig-head: malformed".to_owned());
    }
    let orig_head = hash::from_hex(&orig).map_err(|_| "orig-head: malformed".to_owned())?;
    let last = number("last")?;
    let next = number("next")?;
    if last == 0 || last > MAX_MAILS || next == 0 || next > last + 1 {
        return Err("next or last is out of range".to_owned());
    }
    Ok(Some(State {
        orig_head,
        next,
        last,
    }))
}

fn read_small(path: &Path) -> std::io::Result<String> {
    let mut text = String::new();
    fs::File::open(path)?.take(128).read_to_string(&mut text)?;
    Ok(text)
}

/// Mail `n` of the paused `am`, read.
fn read_mail(layout: &RepoLayout, n: usize) -> Result<Mail, u8> {
    let path = layout.am_dir().join(format!("{n:04}"));
    let limit = u64::try_from(MAX_PATCH_BYTES).unwrap_or(u64::MAX);
    let mut raw = Vec::new();
    fs::File::open(&path)
        .and_then(|f| f.take(limit).read_to_end(&mut raw))
        .map_err(|e| super::error(&format!("{}: {e}", path.display()), exit::NOINPUT))?;
    mailbox::parse(&raw).map_err(|e| super::error(&format!("mail {n}: {e}"), exit::DATAERR))
}
