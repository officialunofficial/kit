//! The map from library errors to the exit codes in `docs/CLI.md`.
//!
//! This table is the one place that decides which code a library error
//! gets. A command turns a [`libkit::Error`] into a code with [`exit_code`]
//! and into the text for stderr with [`message`].

use kit_core::ops::DiffError;
use kit_core::store::StoreError;
use kit_core::worktree::WorktreeError;
use libkit::signing::ErrorKind;
use libkit::{
    add, attest_signer, attestation, blame, branch, commit, diff, head, keys, linked, merge, mv,
    push, rebase, remote, repo, revspec, signer, status,
};

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
        libkit::Error::Status(inner) => status_exit_code(inner),
        libkit::Error::Add(inner) => add_exit_code(inner),
        libkit::Error::Signer(inner) => signer_exit_code(inner),
        libkit::Error::AttestSigner(inner) => attest_signer_exit_code(inner),
        libkit::Error::Attestation(inner) => attestation_exit_code(inner),
        libkit::Error::Keys(inner) => keys_exit_code(inner),
        libkit::Error::Commit(inner) => commit_exit_code(inner),
        libkit::Error::Merge(inner) => merge_exit_code(inner),
        libkit::Error::Rebase(inner) => rebase_exit_code(inner),
        libkit::Error::Remote(inner) => remote_exit_code(inner),
        libkit::Error::Push(inner) => push_exit_code(inner),
        #[cfg(feature = "git-bridge")]
        libkit::Error::Git(inner) => git_exit_code(inner),
        _ => exit::GENERAL_ERROR,
    }
}

/// The code for a failure of the key.
fn signing_exit_code(error: &libkit::signing::Error) -> u8 {
    match error.kind() {
        ErrorKind::Config => exit::CONFIG_ERROR,
        ErrorKind::MissingInput => exit::NOINPUT,
        ErrorKind::Denied => exit::NOPERM,
        ErrorKind::Unavailable => exit::UNAVAILABLE,
        ErrorKind::Data => exit::DATAERR,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn merge_exit_code(error: &merge::Error) -> u8 {
    match error {
        // The key has its own code.
        merge::Error::Signing(inner) => signing_exit_code(inner),
        // `HEAD` has its own table when it goes back.
        merge::Error::RestoreHead(inner) => head_exit_code(inner),
        // An object of the wrong kind, a commit that cannot be encoded, or a
        // history that cannot be read.
        merge::Error::NotACommit | merge::Error::Serialize(_) | merge::Error::History(_) => {
            exit::DATAERR
        }
        // The state of the merge, the commit or `HEAD` cannot be written.
        merge::Error::AdvanceHead(_)
        | merge::Error::WriteState(_)
        | merge::Error::StoreCommit(_) => exit::CANTCREAT,
        merge::Error::InProgress(_)
        | merge::Error::NoHeadCommit
        | merge::Error::ResolveHead(_)
        | merge::Error::Target(_)
        | merge::Error::MergeBase(_)
        | merge::Error::ReadCommit(_)
        | merge::Error::Merge(_)
        | merge::Error::Worktree(_)
        | merge::Error::NoMergeInProgress
        | merge::Error::ReadState(_)
        | merge::Error::ReadConflicts(_)
        | merge::Error::UnresolvedMarkers(_)
        | merge::Error::BuildTree(_)
        | merge::Error::ClearState(_)
        | merge::Error::Conflict(_) => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn rebase_exit_code(error: &rebase::Error) -> u8 {
    match error {
        // The key has its own code.
        rebase::Error::Signing(inner) => signing_exit_code(inner),
        // The todo list contradicts the rules of the command.
        rebase::Error::Todo(_) => exit::USAGE,
        // An object of the wrong kind, a commit that cannot be encoded, or
        // a `HEAD` that the rebase lost.
        rebase::Error::NotACommit
        | rebase::Error::NoPrecedingCommit
        | rebase::Error::Serialize(_)
        | rebase::Error::HeadMissingAtFinish
        | rebase::Error::ReadFinalHead(_) => exit::DATAERR,
        // State, commits, refs or the recovery log cannot be written.
        rebase::Error::WriteState(_)
        | rebase::Error::DetachHead(_)
        | rebase::Error::UpdateHead(_)
        | rebase::Error::PersistState(_)
        | rebase::Error::WriteConflicts(_)
        | rebase::Error::Store(_)
        | rebase::Error::Recovery(_)
        | rebase::Error::WriteRef(_)
        | rebase::Error::ReattachHead(_)
        | rebase::Error::RestoreRef(_)
        | rebase::Error::RestoreHead(_) => exit::CANTCREAT,
        rebase::Error::InProgress(_)
        | rebase::Error::NoRebaseInProgress
        | rebase::Error::NoSuchCommit { .. }
        | rebase::Error::NoHeadCommit
        | rebase::Error::ResolveHead(_)
        | rebase::Error::ReadHead(_)
        | rebase::Error::DetachedHead
        | rebase::Error::CollectCommits(_)
        | rebase::Error::Editor(_)
        | rebase::Error::ReadCommit(_)
        | rebase::Error::Worktree(_)
        | rebase::Error::ReadState(_)
        | rebase::Error::ReadConflicts(_)
        | rebase::Error::NothingToSkip
        | rebase::Error::UnresolvedMarkers(_)
        | rebase::Error::InconsistentState
        | rebase::Error::BuildTree(_)
        | rebase::Error::ClearConflicts(_)
        | rebase::Error::CherryPick(_)
        | rebase::Error::Conflict(_) => exit::GENERAL_ERROR,
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
        // The caller named a revision that does not exist, two revisions
        // without a common ancestor, or a history that cannot be read.
        diff::Error::BadRevision { .. }
        | diff::Error::History(_)
        | diff::Error::UnknownRevision(_)
        | diff::Error::NoMergeBaseBetween { .. }
        | diff::Error::NoMergeBase => exit::DATAERR,
        // A file or a stored blob is above the size that kit holds in memory.
        diff::Error::ReadObject(WorktreeError::ContentTooLarge { .. })
        | diff::Error::BuildTree(WorktreeError::FileTooLarge { .. }) => exit::NOINPUT,
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
        | branch::Error::ReadRevision { .. }
        | branch::Error::History(_) => exit::DATAERR,
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

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn status_exit_code(error: &status::Error) -> u8 {
    match error {
        // The caller gave a threshold that is not a number.
        status::Error::InvalidRenameThreshold(_) => exit::USAGE,
        // A worktree file or a stored blob is above the size that kit holds
        // in memory.
        status::Error::Compare(DiffError::Worktree(
            WorktreeError::FileTooLarge { .. } | WorktreeError::ContentTooLarge { .. },
        )) => exit::NOINPUT,
        status::Error::NotARepository(_)
        | status::Error::HeadTree(_)
        | status::Error::ReadIndex(_)
        | status::Error::Compare(_)
        | status::Error::Renames(_)
        | status::Error::ReadHeadTree(_)
        | status::Error::SeedIndex(_) => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn add_exit_code(error: &add::Error) -> u8 {
    match error {
        // Another `kit` holds the lock.
        add::Error::Lock(_) => exit::TEMPFAIL,
        // The caller combined modes that exclude each other, named an ignored
        // path, or asked for hunks of a file that is not a regular file.
        add::Error::PatchWithBulk
        | add::Error::DryRunWithMode
        | add::Error::PatchNeedsPaths
        | add::Error::AllWithUpdate
        | add::Error::BulkTakesNoPaths
        | add::Error::NoPaths
        | add::Error::Ignored(_)
        | add::Error::PatchRegularOnly(_) => exit::USAGE,
        // The input is malformed: a path that leaves the repository or goes
        // through a symlink, a symlink target that is not allowed, or a blob
        // that cannot be compared.
        add::Error::InvalidPath(_)
        | add::Error::ResolveParent { .. }
        | add::Error::RepoRoot(_)
        | add::Error::Outside(_)
        | add::Error::ThroughSymlink(_)
        | add::Error::SymlinkTargetNotUtf8
        | add::Error::InvalidSymlinkTarget(_)
        | add::Error::Serialize(_)
        | add::Error::CompareStaged { .. } => exit::DATAERR,
        // The input cannot be read.
        add::Error::Metadata { .. }
        | add::Error::ReadLink { .. }
        | add::Error::NotRegular(_)
        | add::Error::ReadDir { .. }
        | add::Error::ReadFile { .. }
        | add::Error::ReadInput(_) => exit::NOINPUT,
        // The store or the index cannot be written.
        add::Error::Store(_) | add::Error::StoreFile(_) | add::Error::WriteIndex(_) => {
            exit::CANTCREAT
        }
        add::Error::Hash { source, .. } => match source {
            WorktreeError::Io(_)
            | WorktreeError::FileTooLarge { .. }
            | WorktreeError::ContentTooLarge { .. } => exit::NOINPUT,
            WorktreeError::Object(_) | WorktreeError::Store(_) => exit::CANTCREAT,
            WorktreeError::InvalidSymlinkTarget(_) | WorktreeError::InvalidUtf8 => exit::DATAERR,
            // A contract violation between kit-core and its caller, which no
            // input can trigger.
            WorktreeError::ChunkBatchLengthMismatch { .. } => exit::SOFTWARE,
        },
        // A staged blob is above the size that kit holds in memory.
        add::Error::ReadStagedBlob(WorktreeError::ContentTooLarge { .. }) => exit::NOINPUT,
        add::Error::NotARepository(_)
        | add::Error::ReadIndex(_)
        | add::Error::IgnoreFile(_)
        | add::Error::Refresh(_)
        | add::Error::ReadStagedBlob(_) => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

/// The code of a key that cannot load or sign.
pub(crate) fn signer_exit_code(error: &signer::Error) -> u8 {
    match error {
        // The config names a key that the library refuses.
        signer::Error::KeyPath(_) | signer::Error::UnknownSigner(_) | signer::Error::KeyRef(_) => {
            exit::CONFIG_ERROR
        }
        // The user has not made the key.
        signer::Error::NoKeyFile(_) | signer::Error::MissingKey { .. } => exit::NOINPUT,
        // The key file is there, but this user cannot read it.
        signer::Error::LoadKey(_) => exit::NOPERM,
        // The keystore backend is not usable on this machine.
        signer::Error::Backend(_) => exit::UNAVAILABLE,
        // The key or its answer is malformed.
        signer::Error::CannotOpen(_)
        | signer::Error::OpenKey(_)
        | signer::Error::PublicKey(_)
        | signer::Error::PublicKeyLength(_)
        | signer::Error::CommitHash(_)
        | signer::Error::TagHash(_)
        | signer::Error::KeystoreSign(_)
        | signer::Error::SignatureLength(_) => exit::DATAERR,
        // A file key cannot sign, or a future variant fails closed.
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn commit_exit_code(error: &commit::Error) -> u8 {
    match error {
        // The caller asked for a state that the repository does not have.
        commit::Error::AmendDuringMerge
        | commit::Error::NothingToAmend
        | commit::Error::NothingStaged
        | commit::Error::MergeDiscarded => exit::USAGE,
        // Another writer changed the state, so the caller can run again.
        commit::Error::Lock(_)
        | commit::Error::MergeChanged
        | commit::Error::HeadMoved
        | commit::Error::BranchMoved { .. } => exit::TEMPFAIL,
        // The state to commit from is damaged.
        commit::Error::ReadHead(_)
        | commit::Error::AmendNotACommit(_)
        | commit::Error::ReadAmendTarget { .. }
        | commit::Error::Serialize(_) => exit::DATAERR,
        // The commit, its log or the index cannot be written.
        commit::Error::Store(_) | commit::Error::Recovery(_) | commit::Error::SyncIndex(_) => {
            exit::CANTCREAT
        }
        commit::Error::Signer(inner) => signer_exit_code(inner),
        commit::Error::Head(inner) => head_exit_code(inner),
        commit::Error::ReadMergeState(_)
        | commit::Error::StageTracked(_)
        | commit::Error::ReadConflicts(_)
        | commit::Error::Unresolved(_)
        | commit::Error::ReadIndex(_)
        | commit::Error::BuildTree(_)
        | commit::Error::ClearMergeState(_) => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

/// The exit code for a failure to build a signer of an attestation.
///
/// A signer that is not a known word is a usage error. A key that does not
/// exist is a missing input. Any other failure is a bad setting.
#[must_use]
pub fn attest_signer_exit_code(error: &attest_signer::Error) -> u8 {
    match error {
        attest_signer::Error::UnknownAlgorithm(_) | attest_signer::Error::UnknownSignerKind(_) => {
            exit::USAGE
        }
        attest_signer::Error::MissingKeyFile { .. }
        | attest_signer::Error::MissingKeystoreKey { .. } => exit::NOINPUT,
        _ => exit::CONFIG_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn attestation_exit_code(error: &attestation::Error) -> u8 {
    match error {
        attestation::Error::Signer(inner) => attest_signer_exit_code(inner),
        // A signer spec that does not parse.
        attestation::Error::SpecPart(_)
        | attestation::Error::SpecAlgorithm(_)
        | attestation::Error::SpecSigner(_)
        | attestation::Error::SpecKey(_)
        | attestation::Error::SpecMissingAlgorithm
        | attestation::Error::SpecMissingSigner => exit::USAGE,
        // An input is missing: the predicate file or the list of envelopes.
        attestation::Error::PredicateRead { .. } | attestation::Error::List(_) => exit::NOINPUT,
        // The predicate is wrong, or the statement or envelope is malformed.
        attestation::Error::PredicateTooLarge(_)
        | attestation::Error::PredicateNotObject
        | attestation::Error::Statement(_)
        | attestation::Error::Encode(_) => exit::DATAERR,
        // The envelope cannot be written.
        attestation::Error::Pruned(_) | attestation::Error::Store(_) => exit::CANTCREAT,
        // Another `kit` holds the worktree lock.
        attestation::Error::Lock(_) => exit::TEMPFAIL,
        attestation::Error::NoHeadCommit
        | attestation::Error::ReadHead(_)
        | attestation::Error::OpenStore(_)
        | attestation::Error::ReadCommit { .. }
        | attestation::Error::Sign { .. }
        | attestation::Error::KeyId { .. } => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn keys_exit_code(error: &keys::Error) -> u8 {
    match error {
        // A backend name or a key reference in the settings is wrong.
        keys::Error::Backend(_) | keys::Error::ConfigKeyRef(_) => exit::CONFIG_ERROR,
        // The backend is not built in or not usable here.
        keys::Error::OpenBackend(_) => exit::UNAVAILABLE,
        // The keystore refused, or the secret input is malformed.
        keys::Error::Keystore(_)
        | keys::Error::SecretHexLength
        | keys::Error::SecretHexDigit
        | keys::Error::ReadKeyFile(_) => exit::DATAERR,
        _ => exit::GENERAL_ERROR,
    }
}

/// The code for a git bridge error.
#[cfg(feature = "git-bridge")]
fn git_exit_code(error: &libkit::git::Error) -> u8 {
    use libkit::git::{Class, Error};

    match error {
        Error::Step { class, .. } => match class {
            Class::Usage => exit::USAGE,
            Class::Data => exit::DATAERR,
            Class::NoInput => exit::NOINPUT,
            Class::Unavailable => exit::UNAVAILABLE,
            Class::CannotCreate => exit::CANTCREAT,
            Class::Config => exit::CONFIG_ERROR,
            Class::TempFail => exit::TEMPFAIL,
            _ => exit::GENERAL_ERROR,
        },
        // The arguments contradict each other, or the recorded bindings.
        Error::EmptyUrl
        | Error::InvalidUrl(_)
        | Error::NotARepository
        | Error::ImportSource { .. }
        | Error::PassthroughNeedsImport { .. }
        | Error::PassthroughNormalized { .. }
        | Error::DirectionBound { .. }
        | Error::StateBound { .. }
        | Error::DuplicateImport { .. }
        | Error::BadRefName(_)
        | Error::NothingToExport
        | Error::TagExists { .. } => exit::USAGE,
        // A named ref or range is wrong, or the history is damaged.
        Error::Discover(_)
        | Error::RefNotFound(_)
        | Error::NotFastForward { .. }
        | Error::RangeNotACommit(_)
        | Error::BinaryChange { .. }
        | Error::CommitCycle => exit::DATAERR,
        Error::GitUnavailable(_) => exit::UNAVAILABLE,
        // Another process holds a lock.
        Error::StateBusy { .. } | Error::WorktreeBusy(_) => exit::TEMPFAIL,
        Error::DestinationExists(_) => exit::CANTCREAT,
        Error::OtherImporter { .. } | Error::NoImportState(_) => exit::CONFIG_ERROR,
        // The command that built the signer knows the code.
        Error::Signer(inner) => inner
            .downcast_ref::<crate::commands::git::SignerSetup>()
            .map_or(exit::GENERAL_ERROR, |setup| setup.code),
        // The rest, including the errors of later versions, is general.
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn remote_exit_code(error: &remote::Error) -> u8 {
    match error {
        // The address or the name is malformed, or the rename names the
        // reserved remote.
        remote::Error::UrlControlCharacters(_)
        | remote::Error::UnsupportedScheme(_)
        | remote::Error::NameControlCharacters(_)
        | remote::Error::InvalidName(_)
        | remote::Error::RenameDefault => exit::PROTOCOL_ERROR,
        // The config cannot take the remote.
        remote::Error::AlreadyExists(_) | remote::Error::Write(_) => exit::CANTCREAT,
        remote::Error::NoDefault | remote::Error::NotFound(_) => exit::GENERAL_ERROR,
        _ => exit::GENERAL_ERROR,
    }
}

#[allow(clippy::match_same_arms)] // the table lists each variant, even when its code equals the fallback
fn push_exit_code(error: &push::Error) -> u8 {
    match error {
        // The two force switches contradict each other.
        push::Error::ConflictingForce | push::Error::Refspec(_) => exit::USAGE,
        push::Error::NoSuchBranch(_) => exit::DATAERR,
        // The branch, the upstream or the remote is missing from the config.
        push::Error::DetachedHead
        | push::Error::ReadHead(_)
        | push::Error::NoUpstream(_)
        | push::Error::UnknownRemote(_)
        | push::Error::NoRemote => exit::CONFIG_ERROR,
        // The upstream cannot be written.
        push::Error::RecordUpstream(_) => exit::CANTCREAT,
        push::Error::Ancestry(_) => exit::GENERAL_ERROR,
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
    use libkit::attest::Algorithm;
    use libkit::rebase::TodoError;
    use libkit::signing::{self, ErrorKind};
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
            (
                status::Error::InvalidRenameThreshold("x".to_owned()).into(),
                exit::USAGE,
            ),
            (
                status::Error::HeadTree("x".to_owned()).into(),
                exit::GENERAL_ERROR,
            ),
            (
                status::Error::Compare(DiffError::Worktree(WorktreeError::FileTooLarge {
                    path: path(),
                    limit: 1,
                }))
                .into(),
                exit::NOINPUT,
            ),
            (
                status::Error::Compare(DiffError::Worktree(WorktreeError::ContentTooLarge {
                    size: 1,
                }))
                .into(),
                exit::NOINPUT,
            ),
            (
                diff::Error::ReadObject(WorktreeError::ContentTooLarge { size: 1 }).into(),
                exit::NOINPUT,
            ),
            (
                diff::Error::BuildTree(WorktreeError::FileTooLarge {
                    path: path(),
                    limit: 1,
                })
                .into(),
                exit::NOINPUT,
            ),
            (
                diff::Error::BuildTree(WorktreeError::InvalidUtf8).into(),
                exit::GENERAL_ERROR,
            ),
            (
                add::Error::ReadStagedBlob(WorktreeError::ContentTooLarge { size: 1 }).into(),
                exit::NOINPUT,
            ),
            (
                add::Error::ReadFile {
                    path: path(),
                    source: WorktreeError::FileTooLarge {
                        path: path(),
                        limit: 1,
                    },
                }
                .into(),
                exit::NOINPUT,
            ),
            (add::Error::NoPaths.into(), exit::USAGE),
            (add::Error::SymlinkTargetNotUtf8.into(), exit::DATAERR),
            (add::Error::NotRegular(path()).into(), exit::NOINPUT),
            (
                add::Error::Refresh("x".to_owned()).into(),
                exit::GENERAL_ERROR,
            ),
            (
                add::Error::Hash {
                    path: path(),
                    source: WorktreeError::InvalidUtf8,
                }
                .into(),
                exit::DATAERR,
            ),
            (
                remote::Error::UnsupportedScheme("x".to_owned()).into(),
                exit::PROTOCOL_ERROR,
            ),
            (remote::Error::RenameDefault.into(), exit::PROTOCOL_ERROR),
            (
                remote::Error::AlreadyExists("x".to_owned()).into(),
                exit::CANTCREAT,
            ),
            (remote::Error::NoDefault.into(), exit::GENERAL_ERROR),
            (
                remote::Error::NotFound("x".to_owned()).into(),
                exit::GENERAL_ERROR,
            ),
            (push::Error::ConflictingForce.into(), exit::USAGE),
            (push::Error::DetachedHead.into(), exit::CONFIG_ERROR),
            (
                push::Error::NoUpstream("x".to_owned()).into(),
                exit::CONFIG_ERROR,
            ),
            (
                push::Error::UnknownRemote("x".to_owned()).into(),
                exit::CONFIG_ERROR,
            ),
            (push::Error::NoRemote.into(), exit::CONFIG_ERROR),
            (push::Error::Refspec("x".to_owned()).into(), exit::USAGE),
            (
                push::Error::NoSuchBranch("x".to_owned()).into(),
                exit::DATAERR,
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
            (merge::Error::NotACommit.into(), exit::DATAERR),
            (
                merge::Error::AdvanceHead(head::Error::WriteHead(RefError::NoHead)).into(),
                exit::CANTCREAT,
            ),
            (
                merge::Error::RestoreHead(head::Error::ReadHead(RefError::NoHead)).into(),
                exit::DATAERR,
            ),
            (merge::Error::NoMergeInProgress.into(), exit::GENERAL_ERROR),
            (
                merge::Error::Signing(signing::Error::new(ErrorKind::Denied, "x")).into(),
                exit::NOPERM,
            ),
            (
                rebase::Error::Signing(signing::Error::new(ErrorKind::Config, "x")).into(),
                exit::CONFIG_ERROR,
            ),
            (
                rebase::Error::Todo(TodoError::EditUnsupported).into(),
                exit::USAGE,
            ),
            (rebase::Error::HeadMissingAtFinish.into(), exit::DATAERR),
            (
                rebase::Error::WriteRef(RefError::NoHead).into(),
                exit::CANTCREAT,
            ),
            (
                rebase::Error::NoRebaseInProgress.into(),
                exit::GENERAL_ERROR,
            ),
            (
                signer::Error::UnknownSigner("x".to_owned()).into(),
                exit::CONFIG_ERROR,
            ),
            (signer::Error::NoKeyFile(path()).into(), exit::NOINPUT),
            (signer::Error::PublicKeyLength(3).into(), exit::DATAERR),
            (signer::Error::SignatureLength(3).into(), exit::DATAERR),
            (commit::Error::AmendDuringMerge.into(), exit::USAGE),
            (commit::Error::NothingToAmend.into(), exit::USAGE),
            (commit::Error::NothingStaged.into(), exit::USAGE),
            (commit::Error::MergeChanged.into(), exit::TEMPFAIL),
            (commit::Error::HeadMoved.into(), exit::TEMPFAIL),
            (
                commit::Error::BranchMoved {
                    branch: "main".to_owned(),
                    commit: [1; 32],
                }
                .into(),
                exit::TEMPFAIL,
            ),
            (
                commit::Error::Unresolved("x".to_owned()).into(),
                exit::GENERAL_ERROR,
            ),
            (
                commit::Error::SyncIndex("x".to_owned()).into(),
                exit::CANTCREAT,
            ),
            (
                commit::Error::Signer(signer::Error::PublicKeyLength(3)).into(),
                exit::DATAERR,
            ),
            (
                log::Error::BadRevision {
                    spec: "x".to_owned(),
                    source: revspec::Error::Unknown("x".to_owned()),
                }
                .into(),
                exit::DATAERR,
            ),
            (
                attest_signer::Error::UnknownAlgorithm("x".to_owned()).into(),
                exit::USAGE,
            ),
            (
                attest_signer::Error::UnknownSignerKind("x".to_owned()).into(),
                exit::USAGE,
            ),
            (
                attest_signer::Error::MissingKeyFile {
                    algorithm: Algorithm::Ed25519,
                    path: "k".to_owned(),
                }
                .into(),
                exit::NOINPUT,
            ),
            (
                attest_signer::Error::MissingKeystoreKey {
                    algorithm: Algorithm::P256,
                    backend: "software".to_owned(),
                    reason: "x".to_owned(),
                }
                .into(),
                exit::NOINPUT,
            ),
            (
                attest_signer::Error::InvalidKeyFile {
                    path: "k".to_owned(),
                    reason: "x".to_owned(),
                }
                .into(),
                exit::CONFIG_ERROR,
            ),
            (
                attest_signer::Error::ExternalSignerPath("x".to_owned()).into(),
                exit::CONFIG_ERROR,
            ),
            (
                attestation::Error::Signer(attest_signer::Error::UnknownAlgorithm("x".to_owned()))
                    .into(),
                exit::USAGE,
            ),
            (
                attestation::Error::Signer(attest_signer::Error::Keystore("x".to_owned())).into(),
                exit::CONFIG_ERROR,
            ),
            (
                attestation::Error::SpecPart("x".to_owned()).into(),
                exit::USAGE,
            ),
            (attestation::Error::SpecMissingSigner.into(), exit::USAGE),
            (
                attestation::Error::PredicateTooLarge("p".to_owned()).into(),
                exit::DATAERR,
            ),
            (attestation::Error::PredicateNotObject.into(), exit::DATAERR),
            (
                attestation::Error::PredicateRead {
                    path: "p".to_owned(),
                    source: std::io::Error::other("x"),
                }
                .into(),
                exit::NOINPUT,
            ),
            (attestation::Error::Pruned([1; 32]).into(), exit::CANTCREAT),
            (
                attestation::Error::Lock(lock::Error::Worktree(LockError::Busy("l".to_owned())))
                    .into(),
                exit::TEMPFAIL,
            ),
            (attestation::Error::NoHeadCommit.into(), exit::GENERAL_ERROR),
            (
                attestation::Error::List(kit_attest::Error::Io("x".to_owned())).into(),
                exit::NOINPUT,
            ),
            (
                keys::Error::Backend(kit_keystore::Error::Encoding("x".into())).into(),
                exit::CONFIG_ERROR,
            ),
            (
                keys::Error::ConfigKeyRef(kit_keystore::Error::Encoding("x".into())).into(),
                exit::CONFIG_ERROR,
            ),
            (
                keys::Error::OpenBackend(kit_keystore::Error::BackendUnavailable("x".into()))
                    .into(),
                exit::UNAVAILABLE,
            ),
            (
                keys::Error::Keystore(kit_keystore::Error::UnsupportedOperation("list")).into(),
                exit::DATAERR,
            ),
            (keys::Error::SecretHexLength.into(), exit::DATAERR),
            (keys::Error::SecretHexDigit.into(), exit::DATAERR),
        ]
    }

    #[cfg(feature = "git-bridge")]
    #[test]
    fn git_errors_have_their_documented_codes() {
        use libkit::git::{Class, Error, Skipped};

        let step = |class| Error::Step {
            class,
            context: "x".to_owned(),
            message: "y".to_owned(),
        };
        let table: Vec<(Error, u8)> = vec![
            (step(Class::Usage), exit::USAGE),
            (step(Class::Data), exit::DATAERR),
            (step(Class::NoInput), exit::NOINPUT),
            (step(Class::Unavailable), exit::UNAVAILABLE),
            (step(Class::CannotCreate), exit::CANTCREAT),
            (step(Class::Config), exit::CONFIG_ERROR),
            (step(Class::TempFail), exit::TEMPFAIL),
            (step(Class::General), exit::GENERAL_ERROR),
            (Error::EmptyUrl, exit::USAGE),
            (Error::NothingToExport, exit::USAGE),
            (Error::RefNotFound("x".to_owned()), exit::DATAERR),
            (Error::CommitCycle, exit::DATAERR),
            (Error::GitUnavailable("x".to_owned()), exit::UNAVAILABLE),
            (Error::DestinationExists("x".to_owned()), exit::CANTCREAT),
            (Error::NoImportState("x".to_owned()), exit::CONFIG_ERROR),
            (
                Error::StateBusy {
                    name: "x".to_owned(),
                    source: kit_core::repo_lock::LockError::Busy("l".to_owned()),
                },
                exit::TEMPFAIL,
            ),
            (
                Error::AllRefsSkipped {
                    skipped: vec![Skipped {
                        ref_name: "x".to_owned(),
                        reason: "y".to_owned(),
                    }],
                },
                exit::GENERAL_ERROR,
            ),
            (
                Error::Signer(Box::new(crate::commands::git::SignerSetup::new(
                    "x".to_owned(),
                    exit::NOINPUT,
                ))),
                exit::NOINPUT,
            ),
            (Error::Signer("x".into()), exit::GENERAL_ERROR),
        ];
        for (error, code) in table {
            let error = libkit::Error::from(error);
            assert_eq!(exit_code(&error), code, "{error:?}");
        }
    }

    #[cfg(feature = "git-bridge")]
    #[test]
    fn git_messages_keep_the_established_wording() {
        let error: libkit::Error = libkit::git::Error::AllRefsSkipped {
            skipped: Vec::new(),
        }
        .into();
        assert_eq!(
            message(&error),
            "every requested ref was skipped (0 refusals)"
        );
        let error: libkit::Error = libkit::git::Error::Step {
            class: libkit::git::Class::General,
            context: "update-ref refs/heads/main".to_owned(),
            message: "boom".to_owned(),
        }
        .into();
        assert_eq!(message(&error), "update-ref refs/heads/main: boom");
        let error: libkit::Error = libkit::git::Error::Step {
            class: libkit::git::Class::General,
            context: String::new(),
            message: "boom".to_owned(),
        }
        .into();
        assert_eq!(message(&error), "boom");
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
        let backend: libkit::Error =
            keys::Error::Backend(kit_keystore::Error::Encoding("x".into())).into();
        assert!(message(&backend).starts_with("key backend: "));
        let hex: libkit::Error = keys::Error::SecretHexLength.into();
        assert_eq!(message(&hex), "--hex must be exactly 64 hex characters");
        let spec: libkit::Error = attestation::Error::SpecMissingAlgorithm.into();
        assert_eq!(message(&spec), "--additional-signer: missing algorithm=...");
    }
}
