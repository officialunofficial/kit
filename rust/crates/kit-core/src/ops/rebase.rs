//! Rebase state machine.
//!
//! Persists rebase state under `.kit/rebase-apply/` as six files and one
//! optional file:
//!
//! - `head-name`  : symbolic name of the branch being rebased
//! - `orig-head`  : 64-hex BLAKE3 of the tip before rebase started
//! - `onto`       : 64-hex BLAKE3 of the rebase target
//! - `todo`       : newline-separated list of remaining commits
//! - `actions`    : the steps that remain, one per line. `pick`, `reword`,
//!   `squash`, `fixup` and `edit` each take the next commit of `todo`;
//!   `exec <command>` takes none. A plan with only the first four keywords
//!   is written as them alone, one line per `todo` line. Any other plan
//!   starts with the line `kit-rebase-actions 2`, which a reader that knows
//!   only the four keywords refuses as malformed state
//! - `done`       : newline-separated list of replayed commits
//! - `strategy-option` : `ours` or `theirs`, the side every replayed
//!   commit's conflicts resolve to; absent when conflicts stop the rebase
//!
//! Trailing newlines are tolerated on read and always written.
//!
//! [`collect_commits_to_replay`] walks the first-parent chain from
//! the rebase head until it hits `onto` or any ancestor of `onto`.
//! It returns commits in oldest-first order. It reads every commit it
//! walks and every ancestor of `onto`, and fails when one cannot be read:
//! a walk that ended there would replay part of the branch, or commits
//! the base already holds.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use crate::hash::{self, HEX_LEN, Hash};
use crate::layout::RepoLayout;
use crate::ops::merge::Favor;
use crate::store::ObjectStore;

/// Directory under `.kit/` that holds the persisted rebase state.
pub const REBASE_DIR: &str = "rebase-apply";

const HEAD_NAME_FILE: &str = "head-name";
const ORIG_HEAD_FILE: &str = "orig-head";
const ONTO_FILE: &str = "onto";
const TODO_FILE: &str = "todo";
const DONE_FILE: &str = "done";
const ACTIONS_FILE: &str = "actions";
/// The first line of an `actions` file that holds an `edit` or `exec` step.
const ACTIONS_V2_HEADER: &str = "kit-rebase-actions 2";
const STRATEGY_OPTION_FILE: &str = "strategy-option";
const MAX_STRATEGY_OPTION_BYTES: u64 = 64;

const MAX_HEAD_NAME_BYTES: u64 = 4096;
const MAX_HASH_FILE_BYTES: u64 = 128;
const MAX_HASH_LIST_BYTES: u64 = 1024 * 1024;

/// Maximum commits [`collect_commits_to_replay`] replays. A longer branch
/// fails with [`REPLAY_LIMIT`].
///
/// The todo, done and actions files hold one line per commit and are read
/// back under [`MAX_HASH_LIST_BYTES`], so a longer replay could not be
/// resumed or aborted. This limit keeps them inside it.
const MAX_REPLAY_DEPTH: usize = 10_000;

/// The limit a rebase reports when the branch has more than
/// [`MAX_REPLAY_DEPTH`] commits to replay.
const REPLAY_LIMIT: &str = "10,000-commit replay of a rebase";

/// The limit a rebase reports when the ancestors of its base exceed
/// [`crate::ops::merge::MAX_STRICT_WALK_COMMITS`].
const ONTO_ANCESTOR_LIMIT: &str = "1,000,000-commit ancestor walk of the rebase base";

/// Errors raised by this module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RebaseError {
    /// `read_state` was called but `.kit/rebase-apply/` does not exist.
    #[error("no rebase in progress")]
    NoRebaseInProgress,
    /// On-disk state is malformed (bad hex, missing file, etc.).
    #[error("rebase state on disk is malformed")]
    InvalidRebaseState,
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Object decode failure during the walk.
    #[error(transparent)]
    Object(#[from] crate::object::KitError),
    /// Object-store failure during the walk.
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    /// A commit to replay or of the history of the base cannot be read or
    /// is not a commit, or a walk reached its cap. The error names the
    /// commit or the limit.
    #[error(transparent)]
    History(#[from] crate::ops::graph::AncestorError),
}

/// Result alias.
pub type RebaseResult<T> = Result<T, RebaseError>;

/// What to do with a commit when it is replayed during an interactive
/// rebase. Non-interactive rebase uses [`RebaseAction::Pick`] for every
/// commit. (`drop` is represented by omitting the commit from the todo.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebaseAction {
    /// Replay the commit unchanged (default).
    Pick,
    /// Replay the commit, then open the editor to rewrite its message.
    Reword,
    /// Fold the commit into the previous one, combining their messages
    /// (the editor opens on the combined message).
    Squash,
    /// Fold the commit into the previous one, discarding this commit's
    /// message (the previous message is kept).
    Fixup,
    /// Replay the commit, then stop so the user can amend it or add
    /// commits.
    Edit,
    /// Run a shell command. It takes no commit; its command is the next
    /// entry of [`RebaseState::exec`].
    Exec,
}

impl RebaseAction {
    /// The todo-file keyword for this action.
    #[must_use]
    pub fn keyword(self) -> &'static str {
        match self {
            RebaseAction::Pick => "pick",
            RebaseAction::Reword => "reword",
            RebaseAction::Squash => "squash",
            RebaseAction::Fixup => "fixup",
            RebaseAction::Edit => "edit",
            RebaseAction::Exec => "exec",
        }
    }

    /// `true` for every action but [`RebaseAction::Exec`]: the action
    /// replays the next commit of the todo list.
    #[must_use]
    pub fn takes_commit(self) -> bool {
        self != RebaseAction::Exec
    }

    /// `true` for actions that fold into the previous commit rather than
    /// creating a new one on top of it.
    #[must_use]
    pub fn folds_into_previous(self) -> bool {
        matches!(self, RebaseAction::Squash | RebaseAction::Fixup)
    }

    /// Parse an action that takes a commit from its persisted keyword.
    /// `exec` carries a command and is not a bare keyword.
    #[must_use]
    pub fn from_keyword(s: &str) -> Option<Self> {
        match s {
            "pick" => Some(RebaseAction::Pick),
            "reword" => Some(RebaseAction::Reword),
            "squash" => Some(RebaseAction::Squash),
            "fixup" => Some(RebaseAction::Fixup),
            "edit" => Some(RebaseAction::Edit),
            _ => None,
        }
    }
}

/// Whether `command` can be an `exec` step: not empty, with no leading or
/// trailing whitespace, and no line break or NUL, so it fits on one line of
/// the todo list and of the state.
#[must_use]
pub fn is_valid_exec_command(command: &str) -> bool {
    !command.is_empty() && command.trim() == command && !command.contains(['\n', '\r', '\0'])
}

/// The fewest hex digits that name a target by id in [`autosquash`].
pub const AUTOSQUASH_MIN_ID_DIGITS: usize = 4;

/// The part of `subject` after its leading `fixup! ` and `squash! `
/// prefixes, with the action that the first prefix asks for, or `None` when
/// the subject has neither prefix.
fn fold_request(subject: &str) -> Option<(RebaseAction, &str)> {
    let action = if subject.starts_with("fixup! ") {
        RebaseAction::Fixup
    } else if subject.starts_with("squash! ") {
        RebaseAction::Squash
    } else {
        return None;
    };
    let mut rest = subject;
    loop {
        rest = rest.trim_start();
        match rest
            .strip_prefix("fixup! ")
            .or_else(|| rest.strip_prefix("squash! "))
        {
            Some(inner) => rest = inner,
            None => return Some((action, rest)),
        }
    }
}

/// Arrange the commits of a rebase, oldest first, as `--autosquash` does.
/// Each commit whose subject starts with `fixup! ` or `squash! ` moves to
/// just after the commit it names, after the commits already moved there,
/// with the [`RebaseAction::Fixup`] or [`RebaseAction::Squash`] action. Every
/// other commit is a [`RebaseAction::Pick`] and keeps its order.
///
/// The leading prefixes are stripped, so `fixup! fixup! x` names `x`. The
/// target is an earlier commit that is not moved itself: the first whose
/// subject equals the rest, else, when the rest is one word of
/// [`AUTOSQUASH_MIN_ID_DIGITS`] or more hex digits, the one commit of
/// `commits` whose id starts with it, else the first whose subject starts
/// with the rest. A commit with no target stays a pick where it is.
#[must_use]
pub fn autosquash<S: AsRef<str>>(commits: &[(Hash, S)]) -> Vec<(Hash, RebaseAction)> {
    // `chains[i]` holds the commits moved after commit `i`, in order.
    let mut chains: Vec<Vec<usize>> = vec![Vec::new(); commits.len()];
    let mut moved = vec![false; commits.len()];
    for (i, (_, subject)) in commits.iter().enumerate() {
        let Some((_, key)) = fold_request(subject.as_ref()) else {
            continue;
        };
        let earlier = |j: &usize| *j < i && !moved[*j];
        let by_subject = (0..i)
            .filter(earlier)
            .find(|&j| commits[j].1.as_ref() == key);
        let by_id = || {
            let is_id =
                key.len() >= AUTOSQUASH_MIN_ID_DIGITS && key.bytes().all(|b| b.is_ascii_hexdigit());
            if !is_id {
                return None;
            }
            let prefix = key.to_ascii_lowercase();
            let mut named = commits
                .iter()
                .enumerate()
                .filter(|(_, (h, _))| hash::to_hex(h).starts_with(&prefix))
                .map(|(j, _)| j);
            match (named.next(), named.next()) {
                (Some(j), None) if earlier(&j) => Some(j),
                _ => None,
            }
        };
        let by_prefix = || {
            (0..i)
                .filter(earlier)
                .find(|&j| commits[j].1.as_ref().starts_with(key))
        };
        if let Some(target) = by_subject.or_else(by_id).or_else(by_prefix) {
            chains[target].push(i);
            moved[i] = true;
        }
    }
    let mut out = Vec::with_capacity(commits.len());
    for (i, (h, _)) in commits.iter().enumerate() {
        if moved[i] {
            continue;
        }
        out.push((*h, RebaseAction::Pick));
        for &j in &chains[i] {
            let action = fold_request(commits[j].1.as_ref()).map_or(RebaseAction::Pick, |r| r.0);
            out.push((commits[j].0, action));
        }
    }
    out
}

/// Persisted rebase state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebaseState {
    /// Name of the branch being rebased (e.g. `main`, `feature/x`).
    pub head_name: String,
    /// Tip of `head_name` before rebase started.
    pub orig_head: Hash,
    /// The commit being rebased onto.
    pub onto: Hash,
    /// Remaining commits to replay (oldest-first).
    pub todo: Vec<Hash>,
    /// The steps that remain, in order. Each action but
    /// [`RebaseAction::Exec`] takes the next commit of `todo`, so `todo` has
    /// one commit for each of them. A rebase without `-i` or `--exec` has
    /// only [`RebaseAction::Pick`].
    pub actions: Vec<RebaseAction>,
    /// The command of each [`RebaseAction::Exec`] in `actions`, in order.
    pub exec: Vec<String>,
    /// Commits already replayed.
    pub done: Vec<Hash>,
    /// The side the conflicts of every replayed commit resolve to.
    pub favor: Favor,
}

impl RebaseState {
    /// The next step (defaults to `Pick` if the actions list is somehow
    /// short).
    #[must_use]
    pub fn front_action(&self) -> RebaseAction {
        self.actions.first().copied().unwrap_or(RebaseAction::Pick)
    }

    /// The command of the next step when it is an `exec`.
    #[must_use]
    pub fn front_exec(&self) -> Option<&str> {
        if self.actions.first() == Some(&RebaseAction::Exec) {
            self.exec.first().map(String::as_str)
        } else {
            None
        }
    }

    /// Drop the next step with its commit or its command, so the lists stay
    /// aligned as steps are consumed.
    pub fn consume_front(&mut self) {
        let takes_commit = self.front_action().takes_commit();
        if !self.actions.is_empty() {
            self.actions.remove(0);
        }
        if takes_commit {
            if !self.todo.is_empty() {
                self.todo.remove(0);
            }
        } else if !self.exec.is_empty() {
            self.exec.remove(0);
        }
    }
}

/// Returns `true` when `<kit_dir>/rebase-apply/` exists.
#[must_use]
pub fn is_rebase_in_progress(layout: &RepoLayout) -> bool {
    layout.rebase_dir().is_dir()
}

/// Read rebase state from `<kit_dir>/rebase-apply/`.
///
/// # Errors
/// - [`RebaseError::NoRebaseInProgress`] if the directory does not exist.
/// - [`RebaseError::InvalidRebaseState`] if any file is malformed.
pub fn read_state(layout: &RepoLayout) -> RebaseResult<RebaseState> {
    let dir = layout.rebase_dir();
    if !dir.is_dir() {
        return Err(RebaseError::NoRebaseInProgress);
    }

    let head_name = read_text_capped(&dir.join(HEAD_NAME_FILE), MAX_HEAD_NAME_BYTES)
        .map_err(|_| RebaseError::InvalidRebaseState)?;
    let head_name = trim_trailing(&head_name).to_string();
    if head_name.is_empty() {
        return Err(RebaseError::InvalidRebaseState);
    }

    let orig_head = read_hex_hash(&dir.join(ORIG_HEAD_FILE))?;
    let onto = read_hex_hash(&dir.join(ONTO_FILE))?;

    let todo = read_hash_list(&dir.join(TODO_FILE))?;
    let done = read_hash_list(&dir.join(DONE_FILE))?;
    // The actions file is parallel to todo. A missing file or a length
    // mismatch is corrupt state.
    let (actions, exec) = read_actions(&dir.join(ACTIONS_FILE), todo.len())?;
    let favor = read_favor(&dir.join(STRATEGY_OPTION_FILE))?;

    Ok(RebaseState {
        head_name,
        orig_head,
        onto,
        todo,
        actions,
        exec,
        done,
        favor,
    })
}

/// Persist `state` to `<kit_dir>/rebase-apply/`.
///
/// Every file that changed is staged in a synced temporary file first. Only
/// when all are staged does the function rename them into place and sync the
/// directory once. A failure while staging leaves the previous state whole.
/// Each file is replaced whole, but the renames are not atomic as a group: a
/// crash between them can leave `todo` and `actions` out of step, and
/// [`read_state`] then reports malformed state. A file whose content did not
/// change is not rewritten.
///
/// # Errors
/// - [`RebaseError::Io`] for filesystem failures.
pub fn write_state(layout: &RepoLayout, state: &RebaseState) -> RebaseResult<()> {
    let dir = layout.rebase_dir();
    fs::create_dir_all(&dir)?;

    let files = [
        (HEAD_NAME_FILE, with_newline(state.head_name.as_bytes())),
        (
            ORIG_HEAD_FILE,
            with_newline(hash::to_hex(&state.orig_head).as_bytes()),
        ),
        (
            ONTO_FILE,
            with_newline(hash::to_hex(&state.onto).as_bytes()),
        ),
        (TODO_FILE, hash_list_bytes(&state.todo)),
        (ACTIONS_FILE, actions_bytes(&state.actions, &state.exec)),
        (DONE_FILE, hash_list_bytes(&state.done)),
    ];
    let option = state
        .favor
        .option()
        .map(|o| (STRATEGY_OPTION_FILE, with_newline(o.as_bytes())));
    if option.is_none() {
        match fs::remove_file(dir.join(STRATEGY_OPTION_FILE)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(RebaseError::Io(e)),
        }
    }
    let files: Vec<_> = files.into_iter().chain(option).collect();
    let mut staged = Vec::with_capacity(files.len());
    for (name, bytes) in &files {
        if holds(&dir.join(name), bytes) {
            continue;
        }
        let mut tmp = NamedTempFile::with_prefix_in(".rebase-state-", &dir)?;
        tmp.as_file_mut().write_all(bytes)?;
        tmp.as_file_mut().sync_all()?;
        staged.push((name, tmp));
    }
    for (name, tmp) in staged {
        tmp.persist(dir.join(name)).map_err(|e| e.error)?;
    }
    crate::durable::flush_dir(&dir)?;
    Ok(())
}

/// Remove `<kit_dir>/rebase-apply/`. Idempotent.
///
/// # Errors
/// - [`RebaseError::Io`] for filesystem failures other than "not found".
pub fn cleanup_rebase(layout: &RepoLayout) -> RebaseResult<()> {
    let dir = layout.rebase_dir();
    match fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(RebaseError::Io(e)),
    }
}

/// Walk first-parent chain from `head_hash` back, stopping when we reach
/// `onto_hash` or any ancestor of it. Returns commits in oldest-first
/// order (ready for replay). More than `MAX_REPLAY_DEPTH` commits to replay
/// is an error, and so is a base with more ancestors than one walk visits:
/// a partial ancestor set would replay commits the base already holds. So
/// is a commit that cannot be read, on either side.
///
/// # Errors
/// [`RebaseError::History`] when the base has too many ancestors, when the
/// branch is too long to replay, or when a commit to replay or an ancestor
/// of the base cannot be read or is another kind of object. The error names
/// the limit or the commit.
pub fn collect_commits_to_replay(
    store: &ObjectStore,
    head_hash: Hash,
    onto_hash: Hash,
) -> RebaseResult<Vec<Hash>> {
    collect_commits_with_caps(
        store,
        head_hash,
        onto_hash,
        MAX_REPLAY_DEPTH,
        crate::ops::merge::MAX_STRICT_WALK_COMMITS,
    )
}

/// [`collect_commits_to_replay`] with caller-supplied caps.
fn collect_commits_with_caps(
    store: &ObjectStore,
    head_hash: Hash,
    onto_hash: Hash,
    max_replay: usize,
    max_ancestors: usize,
) -> RebaseResult<Vec<Hash>> {
    if head_hash == onto_hash {
        return Ok(Vec::new());
    }

    let mut onto_ancestors: HashSet<Hash> = HashSet::new();
    crate::ops::graph::collect_history_with_cap(
        store,
        onto_hash,
        &mut onto_ancestors,
        max_ancestors,
        ONTO_ANCESTOR_LIMIT,
    )?;

    let mut commits: Vec<Hash> = Vec::new();
    let mut current = head_hash;
    loop {
        if current == onto_hash || onto_ancestors.contains(&current) {
            break;
        }
        if commits.len() >= max_replay {
            return Err(RebaseError::History(
                crate::ops::graph::AncestorError::Limit(
                    crate::store::StoreError::OperationLimitExceeded(REPLAY_LIMIT),
                ),
            ));
        }
        // Every commit of the range must be read: ending the walk at one
        // that cannot be read would drop it and every commit below it.
        let commit = crate::ops::graph::read_history_commit(store, current)?;
        commits.push(current);
        // A root commit ends the range: the branch shares no history with
        // the base.
        let Some(&parent) = commit.parents.first() else {
            break;
        };
        current = parent;
    }

    commits.reverse();
    Ok(commits)
}

// -- Internal helpers --------------------------------------------------------

fn read_hex_hash(path: &Path) -> RebaseResult<Hash> {
    let raw =
        read_text_capped(path, MAX_HASH_FILE_BYTES).map_err(|_| RebaseError::InvalidRebaseState)?;
    let trimmed = trim_trailing(&raw);
    hash::from_hex(trimmed).map_err(|_| RebaseError::InvalidRebaseState)
}

fn read_hash_list(path: &Path) -> RebaseResult<Vec<Hash>> {
    let raw = match read_text_capped(path, MAX_HASH_LIST_BYTES) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(RebaseError::Io(e)),
    };
    let trimmed = trim_trailing(&raw);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for line in trimmed.split('\n') {
        let line = line.trim_end_matches(['\r', ' ']);
        if line.is_empty() {
            continue;
        }
        if line.len() != HEX_LEN {
            return Err(RebaseError::InvalidRebaseState);
        }
        let h = hash::from_hex(line).map_err(|_| RebaseError::InvalidRebaseState)?;
        out.push(h);
    }
    Ok(out)
}

/// Read the parallel-to-todo action list. The list must have exactly
/// `todo_len` entries, so the two lists can never desync.
/// Read the `actions` file: the steps and the commands of the `exec` steps.
/// A file without the version line holds only the four keywords of the
/// first format. The steps that take a commit must number `todo_len`.
fn read_actions(path: &Path, todo_len: usize) -> RebaseResult<(Vec<RebaseAction>, Vec<String>)> {
    let raw = match read_text_capped(path, MAX_HASH_LIST_BYTES) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(RebaseError::InvalidRebaseState);
        }
        Err(e) => return Err(RebaseError::Io(e)),
    };
    parse_actions(&raw, todo_len).ok_or(RebaseError::InvalidRebaseState)
}

/// The parser of [`read_actions`]. `None` for malformed text.
fn parse_actions(raw: &str, todo_len: usize) -> Option<(Vec<RebaseAction>, Vec<String>)> {
    let text = trim_trailing(raw);
    let mut actions = Vec::with_capacity(todo_len);
    let mut exec = Vec::new();
    if let Some(body) = text
        .strip_prefix(ACTIONS_V2_HEADER)
        .and_then(|rest| rest.strip_prefix('\n').or(rest.is_empty().then_some("")))
    {
        for line in body.split('\n').filter(|l| !l.is_empty()) {
            if let Some(command) = line.strip_prefix("exec ") {
                if !is_valid_exec_command(command) {
                    return None;
                }
                actions.push(RebaseAction::Exec);
                exec.push(command.to_owned());
            } else {
                actions.push(RebaseAction::from_keyword(line)?);
            }
        }
    } else {
        for line in text.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match RebaseAction::from_keyword(line)? {
                RebaseAction::Edit | RebaseAction::Exec => return None,
                action => actions.push(action),
            }
        }
    }
    let commits = actions.iter().filter(|a| a.takes_commit()).count();
    (commits == todo_len).then_some((actions, exec))
}

/// The `actions` file for `actions` and the commands of their `exec` steps.
/// A plan of the four first keywords keeps the first format.
fn actions_bytes(actions: &[RebaseAction], exec: &[String]) -> Vec<u8> {
    let first_format = actions
        .iter()
        .all(|a| !matches!(a, RebaseAction::Edit | RebaseAction::Exec));
    if actions.is_empty() {
        return b"\n".to_vec();
    }
    let mut buf = String::with_capacity(actions.len() * 8);
    if !first_format {
        buf.push_str(ACTIONS_V2_HEADER);
        buf.push('\n');
    }
    let mut commands = exec.iter();
    for a in actions {
        buf.push_str(a.keyword());
        if *a == RebaseAction::Exec {
            buf.push(' ');
            buf.push_str(commands.next().map_or("", String::as_str));
        }
        buf.push('\n');
    }
    buf.into_bytes()
}

fn hash_list_bytes(hashes: &[Hash]) -> Vec<u8> {
    if hashes.is_empty() {
        return b"\n".to_vec();
    }
    let mut buf = String::with_capacity(hashes.len() * (HEX_LEN + 1));
    for h in hashes {
        buf.push_str(&hash::to_hex(h));
        buf.push('\n');
    }
    buf.into_bytes()
}

fn with_newline(content: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(content.len() + 1);
    buf.extend_from_slice(content);
    if buf.last().copied() != Some(b'\n') {
        buf.push(b'\n');
    }
    buf
}

/// Whether the file at `path` already holds exactly `bytes`. A file of
/// another length is not read.
fn holds(path: &Path, bytes: &[u8]) -> bool {
    let same_len = fs::metadata(path).is_ok_and(|m| m.len() == bytes.len() as u64);
    same_len && fs::read(path).is_ok_and(|on_disk| on_disk == bytes)
}

/// Read the optional strategy-option file. A missing file is
/// [`Favor::None`]; any value but `ours` or `theirs` is corrupt state.
fn read_favor(path: &Path) -> RebaseResult<Favor> {
    match read_text_capped(path, MAX_STRATEGY_OPTION_BYTES) {
        Ok(text) => Favor::from_option(trim_trailing(&text)).ok_or(RebaseError::InvalidRebaseState),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Favor::None),
        Err(_) => Err(RebaseError::InvalidRebaseState),
    }
}

fn read_text_capped(path: &Path, cap: u64) -> io::Result<String> {
    crate::bounded_read::read_capped_string(path, cap)
}

fn trim_trailing(s: &str) -> &str {
    s.trim_end_matches(['\n', '\r', ' '])
}

/// Convenience: full path to the rebase-apply directory under `kit_dir`.
#[must_use]
pub fn rebase_dir_path(layout: &RepoLayout) -> PathBuf {
    layout.rebase_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Commit, Identity, Object, Tree, TreeEntry};
    use crate::ops::graph::{names_commit, names_limit};
    use crate::serialize;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
        (dir, store)
    }

    fn put_blob(store: &ObjectStore, data: &[u8]) -> Hash {
        let bytes = serialize::serialize(&Object::Blob(crate::object::Blob {
            data: data.to_vec(),
        }))
        .unwrap();
        store.write(&bytes).unwrap()
    }

    fn put_tree(store: &ObjectStore, name: &str, blob_h: Hash) -> Hash {
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: crate::object::EntryMode::Blob,
                object_hash: blob_h,
            }],
        });
        let bytes = serialize::serialize(&tree).unwrap();
        store.write(&bytes).unwrap()
    }

    fn put_commit(store: &ObjectStore, tree_h: Hash, parents: Vec<Hash>, ts: u64) -> Hash {
        let commit = Object::Commit(Commit::new_unannotated(
            tree_h,
            parents,
            Identity::ed25519([0u8; 32]),
            [0u8; 32],
            b"msg".to_vec(),
            ts,
            [0u8; 64],
        ));
        let bytes = serialize::serialize(&commit).unwrap();
        store.write(&bytes).unwrap()
    }

    #[test]
    fn the_rebase_base_walk_reaches_a_million_commits() {
        assert_eq!(MAX_REPLAY_DEPTH, 10_000);
        assert!(MAX_REPLAY_DEPTH as u64 * 65 <= MAX_HASH_LIST_BYTES);
        assert_eq!(crate::ops::merge::MAX_STRICT_WALK_COMMITS, 1_000_000);
        assert!(ONTO_ANCESTOR_LIMIT.starts_with("1,000,000-commit"));
    }

    #[test]
    fn a_rebase_over_its_caps_fails_and_never_replays_a_part() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        // base - o1 - o2 (onto), and base - h1 - h2 - h3 (head).
        let base = put_commit(&store, tree, vec![], 1);
        let o1 = put_commit(&store, tree, vec![base], 2);
        let o2 = put_commit(&store, tree, vec![o1], 3);
        let h1 = put_commit(&store, tree, vec![base], 4);
        let h2 = put_commit(&store, tree, vec![h1], 5);
        let h3 = put_commit(&store, tree, vec![h2], 6);
        let all = collect_commits_with_caps(&store, h3, o2, 3, 3).unwrap();
        assert_eq!(all, [h1, h2, h3]);
        let long = collect_commits_with_caps(&store, h3, o2, 2, 3).unwrap_err();
        assert!(
            matches!(&long, RebaseError::History(e) if names_limit(e, REPLAY_LIMIT)),
            "{long:?}"
        );
        assert!(long.to_string().contains(REPLAY_LIMIT), "{long}");
        let deep = collect_commits_with_caps(&store, h3, o2, 3, 2).unwrap_err();
        assert!(
            matches!(&deep, RebaseError::History(e) if names_limit(e, ONTO_ANCESTOR_LIMIT)),
            "{deep:?}"
        );
        assert!(deep.to_string().contains(ONTO_ANCESTOR_LIMIT), "{deep}");
    }

    /// Assert that `err` names `culprit`.
    fn assert_names(err: &RebaseError, culprit: &Hash) {
        assert!(
            matches!(err, RebaseError::History(e) if names_commit(e, culprit)),
            "{err:?}"
        );
        assert!(err.to_string().contains(&hash::to_hex(culprit)), "{err}");
    }

    #[test]
    fn an_unreadable_commit_fails_the_walk_and_never_returns_a_part() {
        let (dir, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        // base - o1 (onto), and base - h1 - h2 - h3 (head).
        let base = put_commit(&store, tree, vec![], 1);
        let o1 = put_commit(&store, tree, vec![base], 2);
        let h1 = put_commit(&store, tree, vec![base], 3);
        let h2 = put_commit(&store, tree, vec![h1], 4);
        let h3 = put_commit(&store, tree, vec![h2], 5);
        assert_eq!(
            collect_commits_to_replay(&store, h3, o1).unwrap(),
            [h1, h2, h3]
        );

        // A missing commit in the middle of the branch.
        let missing = hash::hash(b"a commit that is not in the store");
        let above_missing = put_commit(&store, tree, vec![missing], 6);
        let err = collect_commits_to_replay(&store, above_missing, o1).unwrap_err();
        assert_names(&err, &missing);

        // A parent that is not a commit.
        let above_tree = put_commit(&store, tree, vec![tree], 7);
        let err = collect_commits_to_replay(&store, above_tree, o1).unwrap_err();
        assert_names(&err, &tree);

        // A missing commit in the history of the base: its ancestor set would
        // lack `base`, and the walk would replay `base` again.
        let onto_above_missing = put_commit(&store, tree, vec![missing], 8);
        let err = collect_commits_to_replay(&store, h1, onto_above_missing).unwrap_err();
        assert_names(&err, &missing);

        // A parent in the history of the base that is not a commit.
        let onto_above_tree = put_commit(&store, tree, vec![tree], 9);
        let err = collect_commits_to_replay(&store, h1, onto_above_tree).unwrap_err();
        assert_names(&err, &tree);

        // An object whose bytes match its id but do not decode, on either
        // side.
        let junk = store.write(b"bytes that do not decode").unwrap();
        let above_junk = put_commit(&store, tree, vec![junk], 10);
        let err = collect_commits_to_replay(&store, above_junk, o1).unwrap_err();
        assert_names(&err, &junk);
        let err = collect_commits_to_replay(&store, h1, above_junk).unwrap_err();
        assert_names(&err, &junk);

        // A corrupt commit in the middle of the branch: flip one byte of h2.
        let hex = hash::to_hex(&h2);
        let path = RepoLayout::single(dir.path())
            .objects_dir()
            .join(&hex[..2])
            .join(&hex[2..]);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        let err = collect_commits_to_replay(&store, h3, o1).unwrap_err();
        assert_names(&err, &h2);
    }

    #[test]
    fn state_roundtrip_writes_recoverable_files() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();

        let state = RebaseState {
            favor: Favor::None,
            exec: Vec::new(),
            head_name: "feature-branch".to_string(),
            orig_head: hash::hash(b"orig-head"),
            onto: hash::hash(b"onto"),
            todo: vec![hash::hash(b"t1"), hash::hash(b"t2")],
            actions: vec![RebaseAction::Pick, RebaseAction::Reword],
            done: vec![hash::hash(b"d1")],
        };
        write_state(&kit, &state).unwrap();

        // Files should exist on disk — this models the "mid-rebase crash
        // leaves recoverable state" invariant.
        let dir = kit.rebase_dir();
        assert!(dir.join("head-name").is_file());
        assert!(dir.join("orig-head").is_file());
        assert!(dir.join("onto").is_file());
        assert!(dir.join("todo").is_file());
        assert!(dir.join("actions").is_file());
        assert!(dir.join("done").is_file());

        let read = read_state(&kit).unwrap();
        assert_eq!(read, state);
    }

    #[test]
    fn missing_or_misaligned_actions_file_is_invalid_state() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        let state = RebaseState {
            favor: Favor::None,
            exec: Vec::new(),
            head_name: "main".to_string(),
            orig_head: hash::hash(b"head"),
            onto: hash::hash(b"onto"),
            todo: vec![hash::hash(b"t1"), hash::hash(b"t2")],
            actions: vec![RebaseAction::Pick, RebaseAction::Pick],
            done: Vec::new(),
        };
        write_state(&kit, &state).unwrap();
        let actions = kit.rebase_dir().join("actions");
        fs::write(&actions, b"pick\n").unwrap();
        assert!(matches!(
            read_state(&kit),
            Err(RebaseError::InvalidRebaseState)
        ));
        fs::remove_file(&actions).unwrap();
        assert!(matches!(
            read_state(&kit),
            Err(RebaseError::InvalidRebaseState)
        ));
    }

    fn sample_state(todo: &[&[u8]]) -> RebaseState {
        RebaseState {
            favor: Favor::None,
            exec: Vec::new(),
            head_name: "main".to_string(),
            orig_head: hash::hash(b"head"),
            onto: hash::hash(b"onto"),
            todo: todo.iter().map(|t| hash::hash(t)).collect(),
            actions: vec![RebaseAction::Pick; todo.len()],
            done: Vec::new(),
        }
    }

    #[test]
    fn the_first_actions_format_reads_as_before() {
        use RebaseAction::{Fixup, Pick, Reword, Squash};
        for (text, want, written) in [
            ("\n", vec![], "\n"),
            ("pick\n", vec![Pick], "pick\n"),
            (
                "pick\nreword\nsquash\nfixup\n",
                vec![Pick, Reword, Squash, Fixup],
                "pick\nreword\nsquash\nfixup\n",
            ),
            ("pick\n\n  reword \n", vec![Pick, Reword], "pick\nreword\n"),
        ] {
            let (actions, exec) = parse_actions(text, want.len()).unwrap();
            assert_eq!(actions, want, "{text:?}");
            assert!(exec.is_empty());
            assert_eq!(
                actions_bytes(&actions, &exec),
                written.as_bytes(),
                "{text:?}"
            );
        }
    }

    #[test]
    fn the_versioned_actions_format_round_trips() {
        use RebaseAction::{Edit, Exec, Pick};
        let text = "kit-rebase-actions 2\npick\nexec make test\nedit\nexec true\n";
        let (actions, exec) = parse_actions(text, 2).unwrap();
        assert_eq!(actions, [Pick, Exec, Edit, Exec]);
        assert_eq!(exec, ["make test", "true"]);
        assert_eq!(actions_bytes(&actions, &exec), text.as_bytes());
        let header_only = "kit-rebase-actions 2\n";
        assert_eq!(parse_actions(header_only, 0), Some((vec![], vec![])));
    }

    #[test]
    fn malformed_actions_are_refused() {
        for (text, todo_len) in [
            ("edit\n", 1),
            ("exec true\n", 0),
            ("pick\n", 2),
            ("kit-rebase-actions 3\npick\n", 1),
            ("kit-rebase-actions 2\nexec\n", 0),
            ("kit-rebase-actions 2\nexec  true\n", 0),
            ("kit-rebase-actions 2\nexec true\0\n", 0),
            ("kit-rebase-actions 2\nedit\n", 0),
            ("kit-rebase-actions 2\ndrop\n", 1),
            ("kit-rebase-actions 2pick\n", 1),
        ] {
            assert_eq!(parse_actions(text, todo_len), None, "{text:?}");
        }
    }

    #[test]
    fn consuming_steps_keeps_the_commits_and_commands_aligned() {
        let mut state = sample_state(&[b"a", b"b"]);
        state.actions = vec![
            RebaseAction::Pick,
            RebaseAction::Exec,
            RebaseAction::Edit,
            RebaseAction::Exec,
        ];
        state.exec = vec!["one".to_owned(), "two".to_owned()];
        state.consume_front();
        assert_eq!(state.front_exec(), Some("one"));
        assert_eq!(state.todo, [hash::hash(b"b")]);
        state.consume_front();
        assert_eq!(state.front_action(), RebaseAction::Edit);
        assert_eq!(state.front_exec(), None);
        state.consume_front();
        assert!(state.todo.is_empty());
        assert_eq!(state.front_exec(), Some("two"));
        state.consume_front();
        assert!(state.actions.is_empty() && state.exec.is_empty());
    }

    #[test]
    fn the_strategy_option_round_trips_and_is_removed_when_cleared() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        let mut state = sample_state(&[b"t1"]);
        let option = kit.rebase_dir().join(STRATEGY_OPTION_FILE);
        write_state(&kit, &state).unwrap();
        assert!(!option.exists());
        assert_eq!(read_state(&kit).unwrap().favor, Favor::None);
        for favor in [Favor::Ours, Favor::Theirs] {
            state.favor = favor;
            write_state(&kit, &state).unwrap();
            assert_eq!(read_state(&kit).unwrap(), state);
        }
        state.favor = Favor::None;
        write_state(&kit, &state).unwrap();
        assert!(!option.exists());
        assert_eq!(read_state(&kit).unwrap(), state);
    }

    #[test]
    fn an_unknown_strategy_option_is_invalid_state() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        write_state(&kit, &sample_state(&[b"t1"])).unwrap();
        let option = kit.rebase_dir().join(STRATEGY_OPTION_FILE);
        for content in [&b""[..], b"patience\n", b"Ours\n", &[b'o'; 100][..]] {
            fs::write(&option, content).unwrap();
            assert!(matches!(
                read_state(&kit),
                Err(RebaseError::InvalidRebaseState)
            ));
        }
    }

    #[test]
    fn an_empty_head_name_is_invalid_state() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        write_state(&kit, &sample_state(&[b"t1"])).unwrap();
        let head_name = kit.rebase_dir().join("head-name");

        for content in [&b""[..], b"\n"] {
            fs::write(&head_name, content).unwrap();
            assert!(matches!(
                read_state(&kit),
                Err(RebaseError::InvalidRebaseState)
            ));
        }
    }

    #[test]
    fn a_save_leaves_only_the_state_files() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        write_state(&kit, &sample_state(&[b"t1", b"t2"])).unwrap();
        write_state(&kit, &sample_state(&[b"t2"])).unwrap();

        let mut names: Vec<String> = fs::read_dir(kit.rebase_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["actions", "done", "head-name", "onto", "orig-head", "todo"]
        );
    }

    #[test]
    fn a_save_repairs_a_damaged_state_file() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        let state = sample_state(&[b"t1"]);
        write_state(&kit, &state).unwrap();
        let dir = kit.rebase_dir();
        // One file loses its content. Another keeps its length but not its bytes.
        fs::write(dir.join("head-name"), b"").unwrap();
        let mut todo = fs::read(dir.join("todo")).unwrap();
        todo[0] = b'z';
        fs::write(dir.join("todo"), todo).unwrap();

        write_state(&kit, &state).unwrap();

        assert_eq!(read_state(&kit).unwrap(), state);
    }

    #[cfg(unix)]
    #[test]
    fn a_save_rewrites_only_the_files_that_changed() {
        use std::os::unix::fs::MetadataExt;

        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        let dir = kit.rebase_dir();
        write_state(&kit, &sample_state(&[b"t1", b"t2"])).unwrap();
        let ino = |name: &str| fs::metadata(dir.join(name)).unwrap().ino();
        let (head_name, todo) = (ino("head-name"), ino("todo"));

        write_state(&kit, &sample_state(&[b"t2"])).unwrap();

        assert_eq!(ino("head-name"), head_name);
        assert_ne!(ino("todo"), todo);
    }

    #[cfg(unix)]
    #[test]
    fn a_save_that_cannot_stage_keeps_the_previous_state() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        let first = sample_state(&[b"t1", b"t2"]);
        write_state(&kit, &first).unwrap();
        let dir = kit.rebase_dir();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        // A privileged user can create files in a read-only directory.
        let privileged = fs::File::create(dir.join("probe")).is_ok();

        let result = write_state(&kit, &sample_state(&[b"t2"]));

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        if privileged {
            return;
        }
        assert!(matches!(result, Err(RebaseError::Io(_))));
        assert_eq!(read_state(&kit).unwrap(), first);
    }

    #[test]
    fn action_keyword_roundtrip_and_folds() {
        for a in [
            RebaseAction::Pick,
            RebaseAction::Reword,
            RebaseAction::Squash,
            RebaseAction::Fixup,
        ] {
            assert_eq!(RebaseAction::from_keyword(a.keyword()), Some(a));
        }
        assert!(RebaseAction::Squash.folds_into_previous());
        assert!(RebaseAction::Fixup.folds_into_previous());
        assert!(!RebaseAction::Pick.folds_into_previous());
        assert!(!RebaseAction::Reword.folds_into_previous());
        assert_eq!(RebaseAction::from_keyword("nope"), None);
    }

    #[test]
    fn consume_front_keeps_todo_and_actions_aligned() {
        let mut state = RebaseState {
            favor: Favor::None,
            exec: Vec::new(),
            head_name: "main".to_string(),
            orig_head: hash::hash(b"head"),
            onto: hash::hash(b"onto"),
            todo: vec![hash::hash(b"t1"), hash::hash(b"t2")],
            actions: vec![RebaseAction::Reword, RebaseAction::Pick],
            done: Vec::new(),
        };
        assert_eq!(state.front_action(), RebaseAction::Reword);
        state.consume_front();
        assert_eq!(state.todo, vec![hash::hash(b"t2")]);
        assert_eq!(state.actions, vec![RebaseAction::Pick]);
        assert_eq!(state.front_action(), RebaseAction::Pick);
    }

    #[test]
    fn state_roundtrip_with_empty_todo_and_done() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();

        let state = RebaseState {
            favor: Favor::None,
            exec: Vec::new(),
            head_name: "main".to_string(),
            orig_head: hash::hash(b"head"),
            onto: hash::hash(b"onto"),
            todo: Vec::new(),
            actions: Vec::new(),
            done: Vec::new(),
        };
        write_state(&kit, &state).unwrap();
        let read = read_state(&kit).unwrap();
        assert_eq!(read, state);
    }

    #[test]
    fn is_rebase_in_progress_detection() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        assert!(!is_rebase_in_progress(&kit));
        fs::create_dir_all(kit.rebase_dir()).unwrap();
        assert!(is_rebase_in_progress(&kit));
    }

    #[test]
    fn cleanup_removes_state_dir() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        fs::create_dir_all(kit.rebase_dir()).unwrap();
        fs::write(kit.rebase_dir().join("head-name"), b"main\n").unwrap();
        assert!(is_rebase_in_progress(&kit));
        cleanup_rebase(&kit).unwrap();
        assert!(!is_rebase_in_progress(&kit));
    }

    #[test]
    fn cleanup_on_missing_dir_is_noop() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        cleanup_rebase(&kit).unwrap();
    }

    #[test]
    fn read_state_when_no_rebase_returns_error() {
        let tmp = TempDir::new().unwrap();
        let kit = RepoLayout::single(tmp.path());
        fs::create_dir_all(kit.worktree_state_dir()).unwrap();
        let err = read_state(&kit).unwrap_err();
        assert!(matches!(err, RebaseError::NoRebaseInProgress));
    }

    #[test]
    fn collect_commits_on_linear_chain() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        let c1 = put_commit(&store, tree, vec![], 1);
        let c2 = put_commit(&store, tree, vec![c1], 2);
        let c3 = put_commit(&store, tree, vec![c2], 3);
        let c4 = put_commit(&store, tree, vec![c3], 4);

        let res = collect_commits_to_replay(&store, c4, c2).unwrap();
        assert_eq!(res, vec![c3, c4]);
    }

    #[test]
    fn collect_commits_same_commit_returns_empty() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        let c1 = put_commit(&store, tree, vec![], 1);
        let res = collect_commits_to_replay(&store, c1, c1).unwrap();
        assert!(res.is_empty());
    }

    #[test]
    fn collect_commits_y_shape_stops_at_ancestor_of_onto() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        let c1 = put_commit(&store, tree, vec![], 1);
        let c2 = put_commit(&store, tree, vec![c1], 2);
        let c3 = put_commit(&store, tree, vec![c2], 3);
        let c4 = put_commit(&store, tree, vec![c1], 4);
        let c5 = put_commit(&store, tree, vec![c4], 5);

        // Replay feature (c5) onto main (c3): should yield [c4, c5].
        let res = collect_commits_to_replay(&store, c5, c3).unwrap();
        assert_eq!(res, vec![c4, c5]);
    }

    fn h(n: u8) -> Hash {
        [n; 32]
    }

    fn arranged(commits: &[(Hash, &str)]) -> Vec<(u8, RebaseAction)> {
        autosquash(commits)
            .into_iter()
            .map(|(h, a)| (h[0], a))
            .collect()
    }

    #[test]
    fn autosquash_moves_a_fixup_after_its_target() {
        use RebaseAction::{Fixup, Pick, Squash};
        let commits = [
            (h(1), "A"),
            (h(2), "B"),
            (h(3), "fixup! A"),
            (h(4), "squash! B"),
        ];
        assert_eq!(
            arranged(&commits),
            [(1, Pick), (3, Fixup), (2, Pick), (4, Squash)]
        );
    }

    #[test]
    fn autosquash_strips_nested_prefixes_and_keeps_chain_order() {
        use RebaseAction::{Fixup, Pick, Squash};
        let commits = [
            (h(1), "A"),
            (h(2), "fixup! A"),
            (h(3), "B"),
            (h(4), "squash! fixup! A"),
            (h(5), "fixup! fixup! A"),
        ];
        assert_eq!(
            arranged(&commits),
            [(1, Pick), (2, Fixup), (4, Squash), (5, Fixup), (3, Pick)]
        );
    }

    #[test]
    fn autosquash_matches_subject_then_id_then_subject_prefix() {
        use RebaseAction::{Fixup, Pick};
        let id = hash::to_hex(&h(0xab));
        let by_id = format!("fixup! {}", &id[..6]);
        let commits = [
            (h(0xab), "Add the parser for dates"),
            (h(2), "Add the parser"),
            (h(3), "fixup! Add the parser"),
            (h(4), by_id.as_str()),
            (h(5), "fixup! Add the"),
        ];
        // The exact subject wins over the earlier prefix match, the id
        // names the first commit, and a prefix takes the first match.
        assert_eq!(
            arranged(&commits),
            [(0xab, Pick), (4, Fixup), (5, Fixup), (2, Pick), (3, Fixup)]
        );
    }

    #[test]
    fn autosquash_leaves_unmatched_and_short_or_later_ids_in_place() {
        use RebaseAction::Pick;
        let later = hash::to_hex(&h(0xcd));
        let to_later = format!("fixup! {}", &later[..8]);
        let commits = [
            (h(1), "fixup! not in the range"),
            (h(2), "fixup! 0606"),
            (h(3), "fixup! 01"),
            (h(4), to_later.as_str()),
            (h(0xcd), "C"),
            (h(5), "fixup!A"),
        ];
        // `0606` names no commit, `01` is too short to be an id, and
        // commit 4 names a later commit by id.
        assert_eq!(
            arranged(&commits),
            [
                (1, Pick),
                (2, Pick),
                (3, Pick),
                (4, Pick),
                (0xcd, Pick),
                (5, Pick)
            ]
        );
    }

    /// A subject drawn from a few targets, so fixups often find one.
    fn subject_strategy() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;
        let base = prop::sample::select(vec!["A", "B", "C", "A B", "Z"]);
        let prefix = prop::sample::select(vec!["", "", "fixup! ", "squash! ", "fixup! fixup! "]);
        (prefix, base).prop_map(|(p, b)| format!("{p}{b}"))
    }

    proptest::proptest! {
        #[test]
        fn autosquash_invariants(
            subjects in proptest::collection::vec(subject_strategy(), 0..12),
        ) {
            let commits: Vec<(Hash, String)> = subjects
                .iter()
                .enumerate()
                .map(|(i, s)| (h(u8::try_from(i).unwrap()), s.clone()))
                .collect();
            let out = autosquash(&commits);

            // A permutation of the input.
            let mut ids: Vec<u8> = out.iter().map(|(h, _)| h[0]).collect();
            ids.sort_unstable();
            let all: Vec<u8> = (0..commits.len()).map(|i| u8::try_from(i).unwrap()).collect();
            proptest::prop_assert_eq!(ids, all);

            // A plain subject is a pick, and the picks keep their order.
            let picks: Vec<u8> = out
                .iter()
                .filter(|(_, a)| *a == RebaseAction::Pick)
                .map(|(h, _)| h[0])
                .collect();
            proptest::prop_assert!(picks.windows(2).all(|w| w[0] < w[1]));
            for (h, a) in &out {
                let subject = &commits[usize::from(h[0])].1;
                if fold_request(subject).is_none() {
                    proptest::prop_assert_eq!(*a, RebaseAction::Pick);
                }
            }

            // The count of commits after folding is the input count minus
            // the matched fixups and squashes.
            let folded = out.iter().filter(|(_, a)| a.folds_into_previous()).count();
            proptest::prop_assert_eq!(picks.len(), commits.len() - folded);
            proptest::prop_assert!(out.first().is_none_or(|(_, a)| *a == RebaseAction::Pick));

            // Each folded commit comes after its target, and after only
            // folds since that target.
            for (k, (h, a)) in out.iter().enumerate() {
                if !a.folds_into_previous() {
                    continue;
                }
                let (_, key) = fold_request(&commits[usize::from(h[0])].1).unwrap();
                let head = out[..k]
                    .iter()
                    .rev()
                    .find(|(_, a)| !a.folds_into_previous())
                    .unwrap();
                let target = &commits[usize::from(head.0[0])].1;
                proptest::prop_assert!(head.0[0] < h[0]);
                proptest::prop_assert!(target.starts_with(key), "{} -> {}", key, target);
            }

            // Arranging an arranged list changes nothing.
            let again: Vec<(Hash, String)> = out
                .iter()
                .map(|(h, _)| (*h, commits[usize::from(h[0])].1.clone()))
                .collect();
            let twice: Vec<Hash> = autosquash(&again).into_iter().map(|(h, _)| h).collect();
            let once: Vec<Hash> = out.iter().map(|(h, _)| *h).collect();
            proptest::prop_assert_eq!(twice, once);
        }
    }
}
