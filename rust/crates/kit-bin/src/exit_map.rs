//! The map from library errors to the exit codes in `docs/CLI.md`.
//!
//! This table is the one place that decides which code a library error
//! gets. A command turns a [`libkit::Error`] into a code with [`exit_code`]
//! and into the text for stderr with [`message`].

use kit_core::store::StoreError;
use libkit::{blame, branch, diff, head, linked, mv, repo, revspec};

use crate::exit;

/// The exit code for `error`.
///
/// An error variant that this table does not list yet fails closed with
/// [`exit::GENERAL_ERROR`].
#[must_use]
pub fn exit_code(error: &libkit::Error) -> u8 {
    match error {
        libkit::Error::Repo(inner) => repo_exit_code(inner),
        libkit::Error::Revspec(inner) => revspec_exit_code(inner),
        // Another `kit` holds the lock, or a stale lock file is present.
        libkit::Error::Lock(_) => exit::TEMPFAIL,
        libkit::Error::Head(inner) => head_exit_code(inner),
        // A damaged registry, an unreadable sibling HEAD, a wrong revision
        // or a bad object in the history is malformed input.
        libkit::Error::Worktrees(_) | libkit::Error::Log(_) => exit::DATAERR,
        libkit::Error::Diff(inner) => diff_exit_code(inner),
        libkit::Error::Blame(inner) => blame_exit_code(inner),
        libkit::Error::Branch(inner) => branch_exit_code(inner),
        libkit::Error::Linked(inner) => linked_exit_code(inner),
        libkit::Error::Mv(inner) => mv_exit_code(inner),
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn revspec_exit_code(error: &revspec::Error) -> u8 {
    match error {
        revspec::Error::Unknown(_)
        | revspec::Error::Ambiguous(_)
        | revspec::Error::BadSuffix { .. }
        | revspec::Error::NotACommit(_)
        | revspec::Error::NotTreeish(_)
        | revspec::Error::ReadHead(_)
        | revspec::Error::ScanObjects(_)
        | revspec::Error::ReadObject(_) => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn diff_exit_code(error: &diff::Error) -> u8 {
    match error {
        // The arguments contradict each other.
        diff::Error::MergeBaseNeedsRevision | diff::Error::StagedWithRevision => exit::USAGE,
        // The caller named a revision that does not exist, or two revisions
        // without a common ancestor.
        diff::Error::BadRevision { .. }
        | diff::Error::UnknownRevision(_)
        | diff::Error::NoMergeBaseBetween { .. }
        | diff::Error::NoMergeBase => exit::DATAERR,
        diff::Error::Tree(_)
        | diff::Error::MergeBase(_)
        | diff::Error::ResolveHead(_)
        | diff::Error::HeadWithoutCommit
        | diff::Error::ReadHead(_)
        | diff::Error::Index(_)
        | diff::Error::BuildIndexTree(_)
        | diff::Error::BuildTree(_)
        | diff::Error::Diff(_)
        | diff::Error::RenameDetection(_)
        | diff::Error::ReadObject(_) => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn blame_exit_code(error: &blame::Error) -> u8 {
    match error {
        // The arguments contradict each other, or the range is wrong.
        blame::Error::ReverseWithDetection
        | blame::Error::PreciseWithoutIgnore
        | blame::Error::ReverseMissingFile(_)
        | blame::Error::ReverseNeedsRange
        | blame::Error::ReverseNotARange(_)
        | blame::Error::ReverseNotASingleRange(_)
        | blame::Error::ReverseNeedsStart
        | blame::Error::ReverseEmptyRange(_)
        | blame::Error::Lines(_) => exit::USAGE,
        // The caller named a commit that does not exist, or a list of
        // commits that is malformed or too long.
        blame::Error::IgnoreRevNotFound(_)
        | blame::Error::InvalidObjectName(_)
        | blame::Error::IgnoreFileTooLong { .. } => exit::DATAERR,
        // An input is missing: a list file, a revision or a file in the tree.
        blame::Error::IgnoreFileUnreadable(_)
        | blame::Error::Revision(_)
        | blame::Error::Blame(_) => exit::NOINPUT,
        blame::Error::HeadWithoutCommit | blame::Error::ResolveHead(_) => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn branch_exit_code(error: &branch::Error) -> u8 {
    match error {
        // Another `kit` holds the registry lock.
        branch::Error::Lock(_) => exit::TEMPFAIL,
        // The branch cannot be written.
        branch::Error::AlreadyExists(_) | branch::Error::Write { .. } => exit::CANTCREAT,
        // A sibling tree holds the branch, or the registry is damaged, or a
        // revision of a filter is wrong.
        branch::Error::CheckedOut { .. }
        | branch::Error::Worktrees(_)
        | branch::Error::BadRevision { .. }
        | branch::Error::NotACommit(_)
        | branch::Error::ReadRevision { .. } => exit::DATAERR,
        branch::Error::NoHeadCommit
        | branch::Error::NotFound(_)
        | branch::Error::Read { .. }
        | branch::Error::Delete { .. }
        | branch::Error::DetachedHead
        | branch::Error::MovedWhileRenaming(_)
        | branch::Error::RollbackFailed { .. }
        | branch::Error::UpdateHead { .. }
        | branch::Error::ListRefs(_)
        | branch::Error::OpenStore(_)
        | branch::Error::Ancestry(_) => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn linked_exit_code(error: &linked::Error) -> u8 {
    match error {
        // Another `kit` holds a lock.
        linked::Error::Lock(_) => exit::TEMPFAIL,
        // The object store is missing.
        linked::Error::OpenStore(_) => exit::UNAVAILABLE,
        // The caller named a path that the operation refuses.
        linked::Error::InsideWorktree { .. }
        | linked::Error::NoBranchName(_)
        | linked::Error::NoWorktreeId(_)
        | linked::Error::RemoveMain
        | linked::Error::RemoveCurrent
        | linked::Error::NotLinked(_) => exit::USAGE,
        // A name or a path is in use, or a file cannot be created.
        linked::Error::TargetNotEmpty(_)
        | linked::Error::TargetNotDirectory(_)
        | linked::Error::BranchExists(_)
        | linked::Error::CreateStateDir(_)
        | linked::Error::WriteState { .. }
        | linked::Error::WriteHead(_)
        | linked::Error::CreateBranch { .. }
        | linked::Error::CreateTree { .. }
        | linked::Error::WritePointer(_) => exit::CANTCREAT,
        // The state of the repository is wrong for the request: no commit,
        // a branch in use, local work, or a damaged registry.
        linked::Error::NoCommits
        | linked::Error::ResolveHead(_)
        | linked::Error::CheckedOutElsewhere { .. }
        | linked::Error::CheckedOutHere(_)
        | linked::Error::NotACommit(_)
        | linked::Error::OperationInProgress(_)
        | linked::Error::Dirty(_)
        | linked::Error::DirtyCheck(_)
        | linked::Error::Worktrees(_) => exit::DATAERR,
        linked::Error::InspectTarget { .. }
        | linked::Error::UnknownCommitish { .. }
        | linked::Error::ReadCommit(_)
        | linked::Error::Restore(_)
        | linked::Error::RemoveTree { .. }
        | linked::Error::RemoveStateDir { .. }
        | linked::Error::Prune { .. } => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn mv_exit_code(error: &mv::Error) -> u8 {
    match error {
        // Another `kit` holds the lock.
        mv::Error::Lock(_) => exit::TEMPFAIL,
        // The caller named a path, a destination or a batch that the
        // operation refuses.
        mv::Error::Path(_)
        | mv::Error::DestinationNotDirectory(_)
        | mv::Error::SameSourceAndDestination(_)
        | mv::Error::MoveIntoItself(_)
        | mv::Error::DuplicateSource(_)
        | mv::Error::OverlappingSources { .. }
        | mv::Error::SameDestination(_)
        | mv::Error::NestedDestinations { .. }
        | mv::Error::SameDirectoryDestination(_) => exit::USAGE,
        // A directory cannot be created.
        mv::Error::CreateDirectory { .. } => exit::CANTCREAT,
        mv::Error::NotARepository(_)
        | mv::Error::ReadIndex(_)
        | mv::Error::RepoRoot(_)
        | mv::Error::NotTracked(_)
        | mv::Error::BadSource { .. }
        | mv::Error::DestinationEscapes(_)
        | mv::Error::DestinationSymlink(_)
        | mv::Error::DestinationIsDirectory(_)
        | mv::Error::DestinationExists(_)
        | mv::Error::DirectoryDestinationExists(_)
        | mv::Error::DestinationHasDescendants(_)
        | mv::Error::DestinationUnderFile(_)
        | mv::Error::DestinationConflict(_)
        | mv::Error::Rename { .. }
        | mv::Error::WriteIndex(_) => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

fn head_exit_code(error: &head::Error) -> u8 {
    match error {
        // The state to move from is damaged.
        head::Error::ReadHead(_) => exit::DATAERR,
        // The state cannot be written.
        head::Error::WriteRef { .. } | head::Error::WriteHead(_) => exit::CANTCREAT,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn repo_exit_code(error: &repo::Error) -> u8 {
    match error {
        // The caller named a path that the library refuses.
        repo::Error::PathTraversal(_) => exit::USAGE,
        // The working directory is unusable, so there is no input to read.
        repo::Error::NotAbsolute(_) => exit::NOINPUT,
        repo::Error::NotARepository(_) | repo::Error::Store(_) => exit::GENERAL_ERROR,
        // A broken linked-worktree pointer is malformed input.
        repo::Error::Discover(_) => exit::DATAERR,
        _ => exit::GENERAL_ERROR,
    }
}

/// The text that follows `error: ` on stderr for `error`.
#[must_use]
pub fn message(error: &libkit::Error) -> String {
    match error {
        libkit::Error::Repo(repo::Error::Discover(inner)) => {
            format!("worktree discovery: {inner}")
        }
        libkit::Error::Repo(repo::Error::NotARepository(_)) => {
            format!("not a kit repo: {}", StoreError::NotAKitRepository)
        }
        libkit::Error::Repo(repo::Error::Store(inner)) => format!("not a kit repo: {inner}"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kit_core::layout::DiscoverError;
    use kit_core::refs::RefError;
    use kit_core::repo_lock::LockError;
    use libkit::{lock, log, worktrees};

    use super::*;

    fn path() -> PathBuf {
        PathBuf::from("/work")
    }

    /// Every library error variant with the code that `docs/CLI.md` assigns.
    #[allow(clippy::too_many_lines)] // a flat table with one row for each variant
    fn table() -> Vec<(libkit::Error, u8)> {
        vec![
            (repo::Error::PathTraversal(path()).into(), exit::USAGE),
            (repo::Error::NotAbsolute(path()).into(), exit::NOINPUT),
            (
                repo::Error::NotARepository(path()).into(),
                exit::GENERAL_ERROR,
            ),
            (
                repo::Error::Discover(DiscoverError::PointerMalformed(path())).into(),
                exit::DATAERR,
            ),
            (
                repo::Error::Store(StoreError::AlreadyInitialized).into(),
                exit::GENERAL_ERROR,
            ),
            (
                revspec::Error::Unknown("x".to_owned()).into(),
                exit::GENERAL_ERROR,
            ),
            (
                revspec::Error::NotTreeish("x".to_owned()).into(),
                exit::GENERAL_ERROR,
            ),
            (
                lock::Error::Worktree(LockError::Busy("worktree.lock".to_owned())).into(),
                exit::TEMPFAIL,
            ),
            (
                lock::Error::Registry(LockError::Busy("worktrees.lock".to_owned())).into(),
                exit::TEMPFAIL,
            ),
            (
                head::Error::ReadHead(RefError::NoHead).into(),
                exit::DATAERR,
            ),
            (
                head::Error::WriteRef {
                    branch: "main".to_owned(),
                    source: RefError::NoHead,
                }
                .into(),
                exit::CANTCREAT,
            ),
            (
                head::Error::WriteHead(RefError::NoHead).into(),
                exit::CANTCREAT,
            ),
            (
                worktrees::Error::Registry(DiscoverError::PointerMalformed(path())).into(),
                exit::DATAERR,
            ),
            (log::Error::NotACommit([1; 32]).into(), exit::DATAERR),
            (blame::Error::ReverseWithDetection.into(), exit::USAGE),
            (blame::Error::ReverseNeedsStart.into(), exit::USAGE),
            (
                blame::Error::Lines(blame::line_range::Error::EmptyRange).into(),
                exit::USAGE,
            ),
            (
                blame::Error::IgnoreRevNotFound("x".to_owned()).into(),
                exit::DATAERR,
            ),
            (
                blame::Error::InvalidObjectName("x".to_owned()).into(),
                exit::DATAERR,
            ),
            (
                blame::Error::IgnoreFileUnreadable("x".to_owned()).into(),
                exit::NOINPUT,
            ),
            (
                blame::Error::Revision(revspec::Error::Unknown("x".to_owned())).into(),
                exit::NOINPUT,
            ),
            (blame::Error::HeadWithoutCommit.into(), exit::GENERAL_ERROR),
            (
                branch::Error::AlreadyExists("x".to_owned()).into(),
                exit::CANTCREAT,
            ),
            (
                branch::Error::CheckedOut {
                    branch: "x".to_owned(),
                    at: path(),
                }
                .into(),
                exit::DATAERR,
            ),
            (
                branch::Error::NotACommit("x".to_owned()).into(),
                exit::DATAERR,
            ),
            (
                branch::Error::Lock(lock::Error::Registry(LockError::Busy("l".to_owned()))).into(),
                exit::TEMPFAIL,
            ),
            (branch::Error::NoHeadCommit.into(), exit::GENERAL_ERROR),
            (
                branch::Error::NotFound("x".to_owned()).into(),
                exit::GENERAL_ERROR,
            ),
            (linked::Error::RemoveMain.into(), exit::USAGE),
            (linked::Error::NoCommits.into(), exit::DATAERR),
            (
                linked::Error::TargetNotEmpty(path()).into(),
                exit::CANTCREAT,
            ),
            (
                linked::Error::Prune {
                    id: "x".to_owned(),
                    source: std::io::Error::other("x"),
                    pruned: Vec::new(),
                }
                .into(),
                exit::GENERAL_ERROR,
            ),
            (
                mv::Error::DuplicateSource("x".to_owned()).into(),
                exit::USAGE,
            ),
            (
                mv::Error::DestinationExists("x".to_owned()).into(),
                exit::GENERAL_ERROR,
            ),
            (
                mv::Error::CreateDirectory {
                    path: path(),
                    source: std::io::Error::other("x"),
                }
                .into(),
                exit::CANTCREAT,
            ),
            (diff::Error::StagedWithRevision.into(), exit::USAGE),
            (diff::Error::MergeBaseNeedsRevision.into(), exit::USAGE),
            (
                diff::Error::UnknownRevision("x".to_owned()).into(),
                exit::DATAERR,
            ),
            (diff::Error::NoMergeBase.into(), exit::DATAERR),
            (
                diff::Error::Index("read index: x".to_owned()).into(),
                exit::GENERAL_ERROR,
            ),
            (
                log::Error::BadRevision {
                    spec: "x".to_owned(),
                    source: revspec::Error::Unknown("x".to_owned()),
                }
                .into(),
                exit::DATAERR,
            ),
        ]
    }

    #[test]
    fn each_variant_has_its_documented_code() {
        for (error, code) in table() {
            assert_eq!(exit_code(&error), code, "{error:?}");
        }
    }

    #[test]
    fn every_code_is_a_documented_code() {
        let documented = [
            exit::OK,
            exit::GENERAL_ERROR,
            exit::USAGE,
            exit::DATAERR,
            exit::NOINPUT,
            exit::UNAVAILABLE,
            exit::SOFTWARE,
            exit::CANTCREAT,
            exit::TEMPFAIL,
            exit::PROTOCOL_ERROR,
            exit::NOPERM,
            exit::CONFIG_ERROR,
        ];
        for (error, _) in table() {
            assert!(documented.contains(&exit_code(&error)), "{error:?}");
        }
    }

    #[test]
    fn messages_keep_the_established_wording() {
        let discover: libkit::Error =
            repo::Error::Discover(DiscoverError::PointerMalformed(path())).into();
        assert!(message(&discover).starts_with("worktree discovery: "));
        let missing: libkit::Error = repo::Error::NotARepository(path()).into();
        assert_eq!(
            message(&missing),
            "not a kit repo: path is not a kit repository (missing .kit/objects)"
        );
        let store: libkit::Error = repo::Error::Store(StoreError::AlreadyInitialized).into();
        assert_eq!(
            message(&store),
            "not a kit repo: .kit already exists in this directory"
        );
        let busy: libkit::Error = lock::Error::Worktree(LockError::Busy("l".to_owned())).into();
        assert_eq!(message(&busy), "repo lock: lock 'l' busy after timeout");
        let head: libkit::Error = head::Error::WriteHead(RefError::NoHead).into();
        assert!(message(&head).starts_with("update HEAD: "));
        let traversal: libkit::Error = repo::Error::PathTraversal(path()).into();
        assert!(message(&traversal).contains(".."));
    }
}
