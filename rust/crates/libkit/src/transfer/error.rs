//! The error of a transfer: the failures of a push, a pull and a fetch, and
//! the transport failures that they carry.
//!
//! Each variant keeps the text and the cause of the failure that it comes
//! from. A program matches on the variant to choose its exit code and its
//! advice.

use kit_core::object::KitError;
use kit_core::ops::restore;
use kit_core::pack::PackError;
use kit_core::protocol::TransportError;
use kit_core::refs;
use kit_core::store::StoreError;
use kit_core::transfer::PackListError;
use kit_sync::push::RetryReason;
use kit_transport_connect::PENDING_INTERRUPTED_MESSAGE;
#[cfg(feature = "transport-ssh")]
use kit_transport_ssh::SshInitError;

/// An error from a transfer. A command maps each variant to an exit code.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The URL names a scheme that a sync remote cannot use.
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
    /// The URL has no valid form.
    #[error("malformed URL: {0}")]
    MalformedUrl(String),
    /// The remote holds no repository of this name.
    #[error(
        "repository `{identity}` not found at {origin}; check the remote URL path against the server's configured name (an empty path selects `default` on a single-repository deployment)"
    )]
    RepositoryNotFound {
        identity: String,
        origin: String,
        source: kit_sync::SourceError,
    },
    /// A checkpoint of the transfer saw a cancel request and stopped partway.
    /// A retry is safe. The transfer is half-finished, but the remote is
    /// unmodified for any ref that it had not reached yet.
    #[error("interrupted")]
    Interrupted,
    /// An upload stopped partway. The text says how to resume it.
    #[error("{0}")]
    UploadInterrupted(String),
    /// The transport failed.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// The remote source failed in a way that has no transport equivalent.
    #[error("transport: {0}")]
    Source(#[source] kit_sync::SourceError),
    /// A ref could not be read or written.
    #[error("refs: {0}")]
    Refs(#[from] refs::RefError),
    /// The repository lock could not be taken.
    #[error("repo lock: {0}")]
    RepoLock(#[from] kit_core::repo_lock::LockError),
    /// No repository was found.
    #[error("worktree discovery: {0}")]
    Discover(#[from] kit_core::layout::DiscoverError),
    /// A file operation failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The object store failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// A pack could not be built or read.
    #[error("pack: {0}")]
    Pack(#[from] PackError),
    /// A pack list could not be built or read.
    #[error("packlist: {0}")]
    PackList(#[from] PackListError),
    /// The `ssh` child could not start or greet.
    #[cfg(feature = "transport-ssh")]
    #[cfg_attr(docsrs, doc(cfg(feature = "transport-ssh")))]
    #[error("ssh init: {0}")]
    SshInit(#[from] SshInitError),
    /// A pull needs `HEAD` to point at a branch.
    #[error("pull requires HEAD to point at a branch")]
    DetachedHead,
    /// The remote has no branch of this name.
    #[error("remote branch '{0}' not found")]
    RemoteBranchMissing(String),
    /// A pull would not fast-forward the branch.
    #[error("pull would not fast-forward branch '{branch}'; merge or rebase first")]
    NonFastForwardPull { branch: String },
    /// The restore after a pull refused to overwrite local changes.
    #[error("restore safety: {0}")]
    RestoreSafety(String),
    /// A tip is not a commit.
    #[error("object is not a commit")]
    NotCommit,
    /// The restore after a pull failed.
    #[error("restore: {0}")]
    Restore(#[from] restore::RestoreError),
    /// The credential-trust gate refused to build a credential-bearing
    /// transport for an endpoint that the repository chose and the user has
    /// not trusted. The text says how to trust the endpoint.
    #[error("{0}")]
    UntrustedRemote(String),
    /// A CAS ref write was rejected because the remote moved under us
    /// (non-fast-forward). Callers map this to an actionable
    /// fetch-then-retry / `--force-with-lease` hint.
    #[error(
        "updates were rejected for branch '{branch}' (non-fast-forward); fetch and merge first, or re-run with --force-with-lease / --force"
    )]
    NonFastForwardPush { branch: String },
    /// The branch's packmap pointer could not be durably advanced under
    /// sustained concurrent pushes. The branch ref was NOT moved, so the
    /// remote stays consistent; the push is safe to retry.
    #[error(
        "could not establish the pack map for branch '{branch}' under concurrent pushes; retry"
    )]
    PackmapContended { branch: String },
    /// A packmap chain was malformed — it exceeded the depth cap, contained
    /// a cycle, or a node could not be downloaded/decoded. Indicates a
    /// corrupt or hostile remote.
    #[error("pack map chain for branch '{branch}' is malformed (too deep, cyclic, or unreadable)")]
    PackChainInvalid {
        branch: String,
        source: Option<kit_sync::SourceError>,
    },
    /// The remote advertised a branch ref but no packmap
    /// (`refs/kit/packmap/<branch>`) for it. kit speaks a single,
    /// packmap-only transfer dialect: the push path ALWAYS advertises a
    /// packmap before moving the branch ref, so a branch with a tip but no
    /// packmap is a corrupt/incomplete remote, not a format we degrade to.
    /// We refuse to fetch rather than silently materialise a partial ref.
    #[error("remote advertised branch '{0}' but no pack map to reconstruct it")]
    PackmapMissing(String),
    /// The packmap advertised a pack the remote does not hold. The branch's
    /// closure cannot be reconstructed, so the fetch is aborted rather than
    /// publishing a ref to an incomplete history.
    #[error("remote advertised pack {pack} for branch '{branch}' but does not hold it")]
    AdvertisedPackMissing {
        branch: String,
        pack: String,
        source: kit_sync::SourceError,
    },
    /// After unpacking the branch's whole packmap chain, an object
    /// reachable from the fetched tip is still absent from the local store —
    /// the chain did not deliver the full closure. This is a pure integrity
    /// assertion (no recovery download is attempted): the remote's packmap
    /// is incomplete, so fetch aborts before publishing the ref.
    #[error("remote is missing object {0} needed to reconstruct the ref")]
    RemoteMissingObject(String),
    /// The fetched tip's object closure exceeds the
    /// [`kit_core::ops::graph::MAX_REACHABLE`] verification cap, so
    /// completeness could not be confirmed. On the applied-pack skip path
    /// this closure walk is the sole guarantee the local store is
    /// whole; a truncated walk could silently pass over missing objects, so
    /// we fail closed rather than publish a ref we can't fully verify. This is
    /// NOT a self-heal trigger.
    #[error(
        "fetched history is too large to verify (closure exceeds the {0}-object cap); refusing to publish an unverified ref"
    )]
    ClosureTooLarge(usize),
    /// The fetched history has a chunk that does not fit the manifest that
    /// names it: not a blob, or a blob of another length than its span. The
    /// check reads everything the fetched tip reaches in the local store, so
    /// the mismatch may come from what this fetch received, such as a manifest
    /// whose span is wrong, or from damage to the local store. Nothing was
    /// published. NOT a self-heal trigger.
    #[error("fetched history has a chunk that does not fit its manifest: {0}")]
    RemoteObject(KitError),
    /// A commit/remix/tag newly introduced by this fetch failed Ed25519
    /// signature verification via [`kit_core::sign::verify_commit`] /
    /// `verify_remix` / `verify_tag` — the exact check `kit verify <rev>`
    /// runs manually. A hostile remote (THREAT-MODEL §3.1) can
    /// otherwise push an unsigned or forged history that `clone`/`pull`/
    /// `fetch` would silently materialise. Deliberately distinct from
    /// [`RemoteMissingObject`](Self::RemoteMissingObject) so it does NOT
    /// feed the applied-pack self-heal retry: an invalid signature
    /// is not evidence of local staleness, and clearing the applied-packs
    /// record would not make a hostile remote's history valid. Fails
    /// closed by default; opt out with `--no-verify-signatures` or the
    /// user-scoped `pull.require_signed = false` config (never settable
    /// from repo-scoped config — see [`crate::config::REPO_FORBIDDEN_KEYS`]).
    #[error("object {hash} failed signature verification: {reason}")]
    UnsignedOrInvalidObject { hash: String, reason: String },
    /// A remote name passed to the applied-packs record is not a legal
    /// ref name (per [`kit_core::refs::validate_ref_name`]). A remote name
    /// *is* a ref name, so this should never occur for a config-registered
    /// remote; it is defence-in-depth against a malformed name being used as
    /// a raw path component under `.kit/applied-packs/`.
    #[error("invalid remote name for applied-packs record: '{0}'")]
    InvalidRemoteName(String),
    /// One advance would need more data packs than the server permits per
    /// advance. `commit` names the single commit or merge that cannot be split
    /// further when the refusal came from the pre-flight dry seal, before
    /// anything was published; without it the seal-time backstop fired.
    #[error(
        "push needs {packs} data packs but this server permits {limit} per advance{}{}; ask the operator to raise the tickets per advance (or max_pack_bytes)",
        .commit.as_ref().map_or_else(String::new, |c| format!(" ({c} cannot be split further)")),
        if *.holds_remote_head {
            " (it is the first commit that contains the remote head: rebase onto the remote head, or merge it in a smaller or earlier commit)"
        } else {
            ""
        }
    )]
    PushTooLarge {
        packs: usize,
        limit: usize,
        commit: Option<String>,
        /// The unsplittable commit is the first that contains the remote head,
        /// so the split could not cut before it.
        holds_remote_head: bool,
    },
    /// A retry of one advance (a rejected ticket, a lost delta base) re-planned
    /// the push and the new plan no longer fits one advance. Found by a dry
    /// seal, so nothing was uploaded for the retry.
    #[error(
        "{reason}, and the retry needs {packs} data packs but this server permits {limit} per advance; nothing was uploaded for the retry"
    )]
    RetryTooLarge {
        reason: RetryReason,
        packs: usize,
        limit: usize,
    },
    /// A split push would exceed a bound (steps or chain length). Nothing was
    /// published.
    #[error("{0}")]
    PushSplitLimit(String),
    /// The stored grants do not authorize every advance of a split push.
    /// Nothing was published.
    #[error("{0}")]
    PushNotAuthorized(String),
    /// Force push refused before upload because discovery was unavailable.
    #[error(
        "force push requires successful atomic-advance capability discovery; reconnect and retry"
    )]
    ForceCapabilityUnknown,
    /// A split push failed after publishing some advances. `head` is the last
    /// advance this push published, a first-parent ancestor of the local tip
    /// (another pusher may have moved the branch since); re-running the push
    /// resumes from the remote branch unless a concurrent push caused the
    /// failure.
    #[error(
        "{cause}; {published} of {total} advances were published and the last published advance was {head} on branch '{branch}'{}",
        resume_hint(.cause)
    )]
    SplitInterrupted {
        branch: String,
        head: String,
        published: usize,
        total: usize,
        cause: Box<Error>,
    },
    /// The upload ticket stayed rejected after the retry.
    #[error("upload ticket was rejected after the push was retried")]
    TicketRejected,
    /// The delta base stayed unavailable after the restart.
    #[error("delta base is unavailable after a restart")]
    DeltaBaseUnavailable,
    /// The pack list still names a pack that this repository lacks after the retry.
    #[error("packlist still names a pack absent from this repository after retry")]
    PacklistNotInRepository,
}

/// The closing advice of a split push's failure: resume, unless the failure
/// was a concurrent push (the branch then moved, and a re-run would only
/// compare against whatever the other pusher left).
fn resume_hint(cause: &Error) -> &'static str {
    if matches!(cause, Error::NonFastForwardPush { .. }) {
        "; the branch was moved by another push, so fetch and merge before pushing again"
    } else {
        "; re-run the push to resume"
    }
}

/// The advances a split push published before it failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPrefix {
    pub branch: String,
    pub published: usize,
    pub total: usize,
    pub head: String,
    /// Whether re-running the push is the advice (not after a concurrent push).
    pub resumable: bool,
}

impl PublishedPrefix {
    /// The note printed with any failure that left a prefix published.
    #[must_use]
    pub fn note(&self) -> String {
        format!(
            "{} of {} advances were published; the last published advance on branch '{}' was {}{}",
            self.published,
            self.total,
            self.branch,
            self.head,
            if self.resumable {
                "; re-run the push to resume"
            } else {
                "; the branch was moved by another push, so fetch and merge before pushing again"
            }
        )
    }
}

impl Error {
    /// The error a split push failed with, without its published-prefix
    /// wrapper, and that prefix (`None` when no advance of this branch was published).
    #[must_use]
    pub fn into_published_prefix(self) -> (Self, Option<PublishedPrefix>) {
        match self {
            Self::SplitInterrupted {
                branch,
                head,
                published,
                total,
                cause,
            } => {
                let resumable = !matches!(*cause, Self::NonFastForwardPush { .. });
                (
                    *cause,
                    Some(PublishedPrefix {
                        branch,
                        published,
                        total,
                        head,
                        resumable,
                    }),
                )
            }
            other => (other, None),
        }
    }
}

impl From<kit_sync::SourceError> for Error {
    fn from(error: kit_sync::SourceError) -> Self {
        use kit_sync::SourceError as S;
        let transport = match error {
            S::PackNotFound => TransportError::PackNotFound,
            S::AccessDenied => TransportError::AccessDenied,
            S::AdmissionConfiguration(value) => TransportError::AdmissionConfiguration(value),
            S::TlsConfiguration(value) => TransportError::TlsConfiguration(value),
            S::AdmissionHelperFailed(value) => TransportError::AdmissionHelperFailed(value),
            S::RemoteError(value) if value.starts_with("upload interrupted; ") => {
                return Self::UploadInterrupted(value);
            }
            S::RemoteError(value) if value == PENDING_INTERRUPTED_MESSAGE => {
                return Self::Interrupted;
            }
            S::RemoteError(value) => TransportError::RemoteError(value),
            S::RefConflict => TransportError::RefConflict,
            S::InvalidRef(value) => TransportError::InvalidRef(value),
            S::ConnectionFailed => TransportError::ConnectionFailed,
            S::ServerError { status } => TransportError::ServerError { status },
            S::InvalidResponse => TransportError::InvalidResponse,
            S::ProtocolError => TransportError::ProtocolError,
            S::PayloadTooLarge(value) => TransportError::PayloadTooLarge(value),
            S::InsecureScheme => TransportError::InsecureScheme,
            S::AdmissionRequired { challenges } => TransportError::AdmissionRequired(challenges),
            other => return Self::Source(other),
        };
        Self::Transport(transport)
    }
}

impl From<kit_sync::SyncError> for Error {
    fn from(error: kit_sync::SyncError) -> Self {
        use kit_sync::SyncError as S;
        match error {
            S::Interrupted => Self::Interrupted,
            S::UploadInterrupted(message) => Self::UploadInterrupted(message),
            S::RepositoryNotFound {
                identity,
                origin,
                source,
            } => Self::RepositoryNotFound {
                identity,
                origin,
                source,
            },
            S::Source(e) => e.into(),
            S::Refs(e) => Self::Refs(e),
            S::RepoLock(e) => Self::RepoLock(e),
            S::Discover(e) => Self::Discover(e),
            S::Io(e) => Self::Io(e),
            S::Store(e) => Self::Store(e),
            S::Pack(e) => Self::Pack(e),
            S::PackList(e) => Self::PackList(e),
            S::DetachedHead => Self::DetachedHead,
            S::RemoteBranchMissing(b) => Self::RemoteBranchMissing(b),
            S::NonFastForwardPull { branch } => Self::NonFastForwardPull { branch },
            S::RestoreSafety(m) => Self::RestoreSafety(m),
            S::NotCommit => Self::NotCommit,
            S::Restore(e) => Self::Restore(e),
            S::PackChainInvalid { branch, source } => Self::PackChainInvalid { branch, source },
            S::PackmapMissing(b) => Self::PackmapMissing(b),
            S::AdvertisedPackMissing {
                branch,
                pack,
                source,
            } => Self::AdvertisedPackMissing {
                branch,
                pack,
                source,
            },
            S::RemoteMissingObject(h) => Self::RemoteMissingObject(h),
            S::ClosureTooLarge(n) => Self::ClosureTooLarge(n),
            S::RemoteObject(e) => Self::RemoteObject(e),
            S::UnsignedOrInvalidObject { hash, reason } => {
                Self::UnsignedOrInvalidObject { hash, reason }
            }
            S::InvalidRemoteName(n) => Self::InvalidRemoteName(n),
        }
    }
}

impl From<kit_sync::PushError> for Error {
    fn from(error: kit_sync::PushError) -> Self {
        use kit_sync::PushError as P;
        match error {
            P::Sync(kit_sync::SyncError::Source(kit_sync::SourceError::PendingVerification {
                retry_after,
            })) => Self::Transport(TransportError::PendingVerification { retry_after }),
            P::Sync(kit_sync::SyncError::Source(kit_sync::SourceError::MembershipNotVisible)) => {
                Self::Transport(TransportError::MembershipNotVisible)
            }
            P::Sync(kit_sync::SyncError::Source(kit_sync::SourceError::RetryAfter { ms })) => {
                Self::Transport(TransportError::RetryAfter { ms })
            }
            P::Sync(error) => error.into(),
            P::NonFastForwardPush { branch } => Self::NonFastForwardPush { branch },
            P::PackmapContended { branch } => Self::PackmapContended { branch },
            P::PushTooLarge {
                packs,
                limit,
                commit,
                holds_remote_head,
            } => Self::PushTooLarge {
                packs,
                limit,
                commit,
                holds_remote_head,
            },
            P::RetryTooLarge {
                reason,
                packs,
                limit,
            } => Self::RetryTooLarge {
                reason,
                packs,
                limit,
            },
            P::PushSplitLimit(message) => Self::PushSplitLimit(message),
            P::PushNotAuthorized(message) => Self::PushNotAuthorized(message),
            P::ForceCapabilityUnknown => Self::ForceCapabilityUnknown,
            P::SplitInterrupted {
                branch,
                head,
                published,
                total,
                cause,
            } => Self::SplitInterrupted {
                branch,
                head,
                published,
                total,
                cause: Box::new((*cause).into()),
            },
            P::TicketRejected => Self::TicketRejected,
            P::DeltaBaseUnavailable => Self::DeltaBaseUnavailable,
            P::PacklistNotInRepository => Self::PacklistNotInRepository,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_mapping_preserves_transport_scheduling_outcomes() {
        use kit_core::protocol::TransportError;
        for transport in [
            TransportError::PendingVerification {
                retry_after: std::time::Duration::from_secs(2),
            },
            TransportError::MembershipNotVisible,
            TransportError::RetryAfter { ms: 3 },
        ] {
            let expected = format!("transport: {transport}");
            let source = kit_sync::SourceError::from(transport);
            let error = Error::from(kit_sync::PushError::Sync(kit_sync::SyncError::Source(
                source,
            )));
            assert_eq!(error.to_string().as_bytes(), expected.as_bytes());
            assert!(matches!(error, Error::Transport(_)));
        }
    }

    #[test]
    fn sync_context_mapping_preserves_remote_evidence_and_output_bytes() {
        use Error;
        use kit_sync::{RemoteDetail, RemoteFailure, SourceError, SyncError};

        fn remote() -> SourceError {
            SourceError::Remote(Box::new(RemoteFailure {
                code: "not_found".into(),
                message: "not visible".into(),
                details: vec![RemoteDetail {
                    type_url: "type.example/detail".into(),
                    value: Some("eA==".into()),
                }],
                status: 404,
                headers: vec![("x-evidence".into(), b"retained".to_vec())],
            }))
        }

        for (error, expected) in [
            (
                SyncError::Source(remote()),
                "transport: pack not found on remote",
            ),
            (
                SyncError::RepositoryNotFound {
                    identity: "repo".into(),
                    origin: "https://remote.example".into(),
                    source: remote(),
                },
                "repository `repo` not found at https://remote.example; check the remote URL path against the server's configured name (an empty path selects `default` on a single-repository deployment)",
            ),
            (
                SyncError::PackChainInvalid {
                    branch: "main".into(),
                    source: Some(remote()),
                },
                "pack map chain for branch 'main' is malformed (too deep, cyclic, or unreadable)",
            ),
            (
                SyncError::AdvertisedPackMissing {
                    branch: "main".into(),
                    pack: "abc".into(),
                    source: remote(),
                },
                "remote advertised pack abc for branch 'main' but does not hold it",
            ),
        ] {
            let error = Error::from(error);
            assert_eq!(error.to_string().as_bytes(), expected.as_bytes());
            let source = std::error::Error::source(&error)
                .expect("mapping must retain the source cause")
                .downcast_ref::<SourceError>()
                .expect("the source cause must stay typed");
            let SourceError::Remote(remote) = source else {
                panic!("mapping lost remote evidence")
            };
            assert_eq!(remote.code, "not_found");
            assert_eq!(remote.message, "not visible");
            assert_eq!(remote.status, 404);
            assert_eq!(remote.details[0].type_url, "type.example/detail");
            assert_eq!(remote.details[0].value.as_deref(), Some("eA=="));
            assert_eq!(
                remote.headers,
                vec![("x-evidence".into(), b"retained".to_vec())]
            );
        }
    }

    #[test]
    fn sync_source_mapping_preserves_transport_output_bytes() {
        use Error;
        use kit_core::protocol::{AdmissionRequired, TransportError};
        for error in [
            TransportError::PackNotFound,
            TransportError::AccessDenied,
            TransportError::AdmissionRequired(Box::new(AdmissionRequired::new(
                Vec::new(),
                "admit".into(),
                Vec::new(),
                Vec::new(),
            ))),
            TransportError::AdmissionConfiguration("bad".into()),
            TransportError::TlsConfiguration("bad".into()),
            TransportError::AdmissionHelperFailed("bad".into()),
            TransportError::RemoteError("bad".into()),
            TransportError::RefConflict,
            TransportError::InvalidRef("bad".into()),
            TransportError::ConnectionFailed,
            TransportError::ServerError { status: 429 },
            TransportError::ServerError { status: 503 },
            TransportError::InvalidResponse,
            TransportError::ProtocolError,
            TransportError::PayloadTooLarge(42),
            TransportError::InsecureScheme,
        ] {
            let expected = format!("transport: {error}");
            let error = Error::from(kit_sync::SyncError::from(kit_sync::SourceError::from(
                error,
            )));
            assert_eq!(error.to_string().as_bytes(), expected.as_bytes());
            assert!(matches!(error, Error::Transport(_)));
        }
    }
}
