//! Create and verify the attestations of a commit.
//!
//! [`create`] signs an in-toto statement about a commit and saves the DSSE
//! envelope in the attestation store. One envelope can carry more than one
//! signature. [`verify_commit`] checks every envelope that is attached to a
//! commit against a trust registry.
//!
//! The library holds the worktree lock of [`create`] only while it writes
//! the envelope. A concurrent `gc` treats the subject of an attestation as a
//! root, so the lock keeps `gc` from pruning the commit between the check
//! and the write.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use kit_attest::verify::{VerifyResult, extract_primary_commit_hash, verify};
use kit_attest::{
    Algorithm, Envelope, PAYLOAD_TYPE_IN_TOTO, Registry, Sig, Signer, envelope, statement, store,
};
use kit_core::hash::{self, Hash};
use kit_core::layout::RepoLayout;
use kit_core::observer::Observer;
use kit_core::refs::{self, RefError};
use kit_core::store::{ObjectStore, StoreError};

use crate::config::{self, Config};
use crate::{Environment, attest_signer, lock};

/// The predicate type of an attestation that names none.
///
/// The URI follows `docs/specs/SPEC-ATTESTATIONS.md` §6.4,
/// `https://kit.storage/spec/predicate/<name>/v<n>`. It points at a location
/// that the project controls.
pub const DEFAULT_PREDICATE_TYPE: &str = "https://kit.storage/spec/predicate/empty/v1";

/// Longest predicate file that [`create`] reads (1 MiB).
///
/// A predicate is a small JSON object. The cap keeps a runaway or hostile
/// file out of memory before the JSON parse runs.
pub const MAX_PREDICATE_BYTES: u64 = 1024 * 1024;

/// Errors from creating or verifying attestations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// `HEAD` has no commit to attest or verify.
    #[error("HEAD has no commit yet")]
    NoHeadCommit,
    /// `HEAD` could not be read.
    #[error("read HEAD: {0}")]
    ReadHead(RefError),
    /// The object store cannot be opened.
    #[error("not a kit repo: {0}")]
    OpenStore(StoreError),
    /// The commit object cannot be read.
    #[error("read {}: {source}", hash::to_hex(.hash))]
    ReadCommit {
        /// The commit.
        hash: Hash,
        /// Why the read failed.
        source: StoreError,
    },
    /// A signer cannot be built, or its text is wrong.
    #[error(transparent)]
    Signer(#[from] attest_signer::Error),
    /// A part of a signer spec is not `key=value`.
    #[error("--additional-signer spec part '{0}' is not key=value")]
    SpecPart(String),
    /// A signer spec names an algorithm that does not exist.
    #[error(
        "--additional-signer: unknown algorithm '{0}' — expected one of: ed25519, secp256k1, p256"
    )]
    SpecAlgorithm(String),
    /// A signer spec names a signer kind that it cannot use.
    #[error("--additional-signer: unknown signer '{0}' — expected one of: repo-key, external")]
    SpecSigner(String),
    /// A signer spec has a key that does not exist.
    #[error("--additional-signer: unknown spec key '{0}'")]
    SpecKey(String),
    /// A signer spec has no algorithm.
    #[error("--additional-signer: missing algorithm=...")]
    SpecMissingAlgorithm,
    /// A signer spec has no signer kind.
    #[error("--additional-signer: missing signer=...")]
    SpecMissingSigner,
    /// The predicate file cannot be read.
    #[error("predicate file '{path}': {source}")]
    PredicateRead {
        /// The path of the file.
        path: String,
        /// Why the read failed.
        source: std::io::Error,
    },
    /// The predicate file is larger than [`MAX_PREDICATE_BYTES`].
    #[error("predicate file '{0}' exceeds {MAX_PREDICATE_BYTES}-byte cap")]
    PredicateTooLarge(String),
    /// The predicate is not a JSON object in the canonical form.
    #[error("--predicate-file must contain a JCS-canonical JSON object")]
    PredicateNotObject,
    /// The statement cannot be built.
    #[error("statement: {0}")]
    Statement(kit_attest::Error),
    /// A signer failed to sign. `index` counts from 1, the primary first.
    #[error("sign (signer #{index}): {source}")]
    Sign {
        /// The place of the signer in the list.
        index: usize,
        /// Why signing failed.
        source: kit_attest::Error,
    },
    /// A signer failed to name its key. `index` counts from 1.
    #[error("keyid (signer #{index}): {source}")]
    KeyId {
        /// The place of the signer in the list.
        index: usize,
        /// Why the key could not be named.
        source: kit_attest::Error,
    },
    /// The envelope cannot be encoded.
    #[error("encode envelope: {0}")]
    Encode(kit_attest::Error),
    /// The worktree lock could not be taken.
    #[error(transparent)]
    Lock(#[from] lock::Error),
    /// The commit was pruned between the check and the write.
    #[error("attested commit {} no longer exists (pruned concurrently?); aborting", hash::to_hex(.0))]
    Pruned(Hash),
    /// The envelope cannot be saved.
    #[error("store: {0}")]
    Store(kit_attest::Error),
    /// The envelopes of the commit cannot be listed.
    #[error("list attestations: {0}")]
    List(kit_attest::Error),
}

/// Which kind of signer an additional signer uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpecKind {
    RepoKey,
    External,
}

/// An additional signer of a multi-signature envelope.
///
/// The text form is a comma-separated `key=value` list:
///
/// ```text
/// algorithm=<algo>,signer=<kind>[,path=<file-or-binary>][,args=<a>|<b>|<c>]
/// ```
///
/// - `algorithm` is `ed25519`, `secp256k1` or `p256`. It is required.
/// - `signer` is `repo-key` or `external`. It is required.
/// - `path` replaces the key path of `repo-key`, or the signer program of
///   `external`. Without it, the `[attest]` config applies, as for the
///   primary signer.
/// - `args` replaces the `attest.external_signer_args` of `external`. The
///   items are separated by `|`, because `,` separates the keys. An empty
///   value means no arguments. It is not the same as omitting `args`.
#[derive(Debug, PartialEq, Eq)]
pub struct SignerSpec {
    algorithm: Algorithm,
    kind: SpecKind,
    path: Option<String>,
    args: Option<Vec<String>>,
}

impl FromStr for SignerSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let mut algorithm = None;
        let mut kind = None;
        let mut path = None;
        let mut args = None;
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some((key, value)) = part.split_once('=') else {
                return Err(Error::SpecPart(part.to_owned()));
            };
            let value = value.trim();
            match key.trim() {
                "algorithm" => {
                    algorithm = Some(
                        attest_signer::parse_algorithm(value)
                            .map_err(|_| Error::SpecAlgorithm(value.to_owned()))?,
                    );
                }
                "signer" => {
                    kind = Some(match value {
                        "repo-key" => SpecKind::RepoKey,
                        "external" => SpecKind::External,
                        other => return Err(Error::SpecSigner(other.to_owned())),
                    });
                }
                "path" => path = Some(value.to_owned()),
                "args" => args = Some(config::parse_pipe_list(value)),
                other => return Err(Error::SpecKey(other.to_owned())),
            }
        }
        Ok(Self {
            algorithm: algorithm.ok_or(Error::SpecMissingAlgorithm)?,
            kind: kind.ok_or(Error::SpecMissingSigner)?,
            path,
            args,
        })
    }
}

impl SignerSpec {
    fn build(
        &self,
        layout: &RepoLayout,
        environment: &Environment,
        base: &Config,
    ) -> Result<Box<dyn Signer>, attest_signer::Error> {
        let mut config = base.clone();
        let kind = match self.kind {
            SpecKind::RepoKey => {
                if let Some(path) = self.path.as_deref() {
                    // The path can come from a CI-controlled string, so `..`
                    // traversal is refused here as it is in the user config.
                    config::validate_key_path(path).map_err(|e| {
                        attest_signer::Error::InvalidKeyFile {
                            path: path.to_owned(),
                            reason: e.to_string(),
                        }
                    })?;
                    match self.algorithm {
                        Algorithm::Ed25519 => path.clone_into(&mut config.signing_key),
                        Algorithm::Secp256k1 => {
                            path.clone_into(&mut config.attest.secp256k1_key_path);
                        }
                        Algorithm::P256 => path.clone_into(&mut config.attest.p256_key_path),
                    }
                }
                attest_signer::Kind::RepoKey
            }
            SpecKind::External => {
                if let Some(path) = self.path.as_deref() {
                    path.clone_into(&mut config.attest.external_signer_path);
                }
                if let Some(args) = self.args.as_ref() {
                    config.attest.external_signer_args.clone_from(args);
                }
                attest_signer::Kind::External
            }
        };
        attest_signer::build(layout, environment, self.algorithm, kind, &config)
    }
}

/// What [`create`] attests and how it signs.
#[derive(Debug, Default)]
pub struct Request {
    /// The commit to attest. `HEAD` when `None`.
    pub commit: Option<Hash>,
    /// The algorithm of the primary signer. `attest.default_algorithm` when
    /// `None`.
    pub algorithm: Option<Algorithm>,
    /// The kind of the primary signer. `attest.signer` when `None`.
    pub signer: Option<attest_signer::Kind>,
    /// The predicate type. [`DEFAULT_PREDICATE_TYPE`] when `None`.
    pub predicate_type: Option<String>,
    /// A file that holds the JSON predicate. `{}` when `None`.
    pub predicate_file: Option<PathBuf>,
    /// The signers after the primary one, in signing order.
    pub additional: Vec<SignerSpec>,
}

/// A saved attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created {
    /// The id of the envelope.
    pub id: Hash,
    /// Where the envelope is stored.
    pub path: PathBuf,
    /// How many signatures the envelope holds.
    pub signatures: usize,
}

/// The commit to work on: `commit` when given, else the commit of `HEAD`.
///
/// # Errors
/// - [`Error::NoHeadCommit`] when `HEAD` has no commit.
/// - [`Error::ReadHead`] when `HEAD` cannot be read.
pub fn resolve_commit(layout: &RepoLayout, commit: Option<Hash>) -> Result<Hash, Error> {
    if let Some(commit) = commit {
        return Ok(commit);
    }
    match refs::resolve_head(layout) {
        Ok(Some(commit)) => Ok(commit),
        Ok(None) => Err(Error::NoHeadCommit),
        Err(e) => Err(Error::ReadHead(e)),
    }
}

/// Sign a statement about a commit and save the envelope.
///
/// Every signer signs in order, the primary first. A failure of any signer
/// aborts the run before anything is written. The call takes the worktree
/// lock after signing, because an external signer can run for a long time,
/// and holds it for the write only.
///
/// `config` is the merged config. A caller that wants other external signer
/// arguments changes `config.attest.external_signer_args` first.
///
/// # Errors
/// - [`Error::NoHeadCommit`] and [`Error::ReadHead`] when `request.commit`
///   is `None` and `HEAD` is no help.
/// - [`Error::OpenStore`] and [`Error::ReadCommit`] when the commit cannot
///   be read.
/// - [`Error::Signer`] when a signer cannot be built.
/// - The predicate errors when the predicate file is wrong.
/// - [`Error::Sign`] and [`Error::KeyId`] when a signer fails.
/// - [`Error::Lock`], [`Error::Pruned`] and [`Error::Store`] for the write.
pub fn create(
    layout: &RepoLayout,
    environment: &Environment,
    config: &Config,
    request: &Request,
    observer: &dyn Observer<lock::Event>,
) -> Result<Created, Error> {
    let commit = resolve_commit(layout, request.commit)?;

    // The subject digests cover the stored bytes of the commit, so the
    // bytes are read here. The check under the lock below still catches a
    // `gc` that prunes the commit before the write.
    let commit_bytes = {
        let objects = ObjectStore::open(layout).map_err(Error::OpenStore)?;
        objects.read(&commit).map_err(|source| Error::ReadCommit {
            hash: commit,
            source,
        })?
    };

    let algorithm = match request.algorithm {
        Some(algorithm) => algorithm,
        None => attest_signer::parse_algorithm(config.attest.default_algorithm_or_fallback())?,
    };
    let kind = match request.signer {
        Some(kind) => kind,
        None => config.attest.signer_or_fallback().parse()?,
    };
    let mut signers: Vec<Box<dyn Signer>> = Vec::with_capacity(1 + request.additional.len());
    signers.push(attest_signer::build(
        layout,
        environment,
        algorithm,
        kind,
        config,
    )?);
    for spec in &request.additional {
        signers.push(spec.build(layout, environment, config)?);
    }

    let predicate = match request.predicate_file.as_deref() {
        Some(path) => read_predicate(path)?,
        None => b"{}".to_vec(),
    };
    let predicate_type = request
        .predicate_type
        .as_deref()
        .unwrap_or(DEFAULT_PREDICATE_TYPE);
    let statement = statement::for_commit(&commit, &commit_bytes, predicate_type, &predicate)
        .map_err(|e| match e {
            kit_attest::Error::PredicateMustBeJsonObject
            | kit_attest::Error::PredicateNotJsonObject
            | kit_attest::Error::PredicateNotUtf8 => Error::PredicateNotObject,
            other => Error::Statement(other),
        })?
        .into_bytes();

    let pae = kit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, &statement);
    let mut signatures = Vec::with_capacity(signers.len());
    for (index, signer) in signers.iter_mut().enumerate() {
        let index = index + 1;
        let sig = signer
            .sign(&pae)
            .map_err(|source| Error::Sign { index, source })?;
        let keyid = signer
            .keyid()
            .map_err(|source| Error::KeyId { index, source })?;
        signatures.push(Sig { keyid, sig });
    }
    let signature_count = signatures.len();
    let encoded = Envelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
        payload: statement,
        signatures,
    }
    .encode()
    .map_err(Error::Encode)?;

    let _lock = lock::acquire_worktree(layout, observer)?;
    let objects = ObjectStore::open(layout).map_err(Error::OpenStore)?;
    if !objects.contains(&commit) {
        return Err(Error::Pruned(commit));
    }
    let (id, path) = store::save(layout, &commit, encoded.as_bytes()).map_err(Error::Store)?;
    Ok(Created {
        id,
        path,
        signatures: signature_count,
    })
}

/// Read a predicate file of at most [`MAX_PREDICATE_BYTES`].
///
/// The size is checked before the read, and the read stops at the cap, so a
/// file that grows between the two steps cannot fill the memory.
fn read_predicate(path: &Path) -> Result<Vec<u8>, Error> {
    let shown = || path.display().to_string();
    let read_error = |source| Error::PredicateRead {
        path: shown(),
        source,
    };
    let meta = std::fs::metadata(path).map_err(read_error)?;
    if meta.len() > MAX_PREDICATE_BYTES {
        return Err(Error::PredicateTooLarge(shown()));
    }
    let file = std::fs::File::open(path).map_err(read_error)?;
    let mut data = Vec::new();
    file.take(MAX_PREDICATE_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(read_error)?;
    if data.len() as u64 > MAX_PREDICATE_BYTES {
        return Err(Error::PredicateTooLarge(shown()));
    }
    Ok(data)
}

/// Why an envelope did not pass the structural checks of [`verify_commit`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Failure {
    /// The envelope file cannot be read, or it exceeds its size limit.
    #[error("read error: {0}")]
    Read(std::io::Error),
    /// The envelope does not decode or does not verify structurally.
    #[error("malformed envelope: {0}")]
    Malformed(kit_attest::Error),
    /// The statement names no usable subject.
    #[error("subject error: {0}")]
    Subject(kit_attest::Error),
    /// The statement is about another commit.
    #[error(
        "subject mismatch: statement names {}, requested {}",
        hash::to_hex(.statement),
        hash::to_hex(.requested)
    )]
    SubjectMismatch {
        /// The commit that the statement names.
        statement: Hash,
        /// The commit that was asked for.
        requested: Hash,
    },
}

/// The outcome for one stored envelope.
#[derive(Debug)]
pub struct Checked {
    /// Where the envelope is stored.
    pub path: PathBuf,
    /// The id of the envelope. `None` when the file could not be read.
    pub id: Option<Hash>,
    /// The signature verdicts, or the reason that there are none.
    pub outcome: Result<VerifyResult, Failure>,
}

impl Checked {
    /// Does the envelope name the commit and carry a valid trusted
    /// signature?
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.outcome
            .as_ref()
            .is_ok_and(|result| result.any_verified)
    }
}

/// Verify every envelope that is attached to `commit` against `registry`.
///
/// An envelope passes when it decodes, when its first subject is `commit`
/// and when at least one signature verifies against a root of the registry.
/// A bad envelope does not stop the run. It shows up in the result. The
/// result is empty when the commit has no envelope.
///
/// # Errors
/// [`Error::List`] when the store of the commit cannot be listed.
pub fn verify_commit(
    layout: &RepoLayout,
    commit: &Hash,
    registry: &Registry,
) -> Result<Vec<Checked>, Error> {
    let paths = store::list(layout, commit).map_err(Error::List)?;
    Ok(paths
        .into_iter()
        .map(|path| check(path, commit, registry))
        .collect())
}

fn check(path: PathBuf, commit: &Hash, registry: &Registry) -> Checked {
    let limit = u64::try_from(store::MAX_ENVELOPE_SIZE).unwrap_or(u64::MAX);
    let bytes = match kit_core::bounded_read::read_capped(&path, limit) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Checked {
                path,
                id: None,
                outcome: Err(Failure::Read(e)),
            };
        }
    };
    let id = envelope::attestation_id(&bytes);
    let outcome = check_bytes(&bytes, commit, registry);
    Checked {
        path,
        id: Some(id),
        outcome,
    }
}

fn check_bytes(bytes: &[u8], commit: &Hash, registry: &Registry) -> Result<VerifyResult, Failure> {
    let envelope = envelope::decode(bytes).map_err(Failure::Malformed)?;
    let subject = extract_primary_commit_hash(&envelope.payload).map_err(Failure::Subject)?;
    if subject != *commit {
        return Err(Failure::SubjectMismatch {
            statement: subject,
            requested: *commit,
        });
    }
    verify(&envelope, registry).map_err(Failure::Malformed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

    use super::*;

    fn spec(text: &str) -> Result<SignerSpec, Error> {
        text.parse()
    }

    #[test]
    fn a_spec_with_a_path_parses() {
        let parsed = spec("algorithm=secp256k1,signer=repo-key,path=k.key").unwrap();
        assert_eq!(parsed.algorithm, Algorithm::Secp256k1);
        assert_eq!(parsed.kind, SpecKind::RepoKey);
        assert_eq!(parsed.path.as_deref(), Some("k.key"));
        assert!(parsed.args.is_none());
    }

    #[test]
    fn a_spec_splits_its_arguments_at_the_pipe() {
        let parsed =
            spec("algorithm=p256,signer=external,path=/usr/bin/signer,args=sign|--tag|demo")
                .unwrap();
        assert_eq!(parsed.kind, SpecKind::External);
        assert_eq!(
            parsed.args.as_deref(),
            Some(["sign".to_owned(), "--tag".to_owned(), "demo".to_owned()].as_slice())
        );
    }

    #[test]
    fn empty_arguments_differ_from_no_arguments() {
        let empty = spec("algorithm=ed25519,signer=external,args=").unwrap();
        assert_eq!(empty.args.as_deref(), Some([].as_slice()));
        let absent = spec("algorithm=ed25519,signer=external").unwrap();
        assert!(absent.args.is_none());
        assert!(absent.path.is_none());
    }

    #[test]
    fn a_spec_ignores_blanks_around_parts() {
        let parsed = spec(" algorithm = p256 , signer = external ,").unwrap();
        assert_eq!(parsed.algorithm, Algorithm::P256);
        assert_eq!(parsed.kind, SpecKind::External);
    }

    #[test]
    fn a_spec_needs_an_algorithm_and_a_signer() {
        assert!(matches!(
            spec("signer=repo-key").unwrap_err(),
            Error::SpecMissingAlgorithm
        ));
        assert!(matches!(
            spec("algorithm=ed25519").unwrap_err(),
            Error::SpecMissingSigner
        ));
        assert!(matches!(spec("").unwrap_err(), Error::SpecMissingAlgorithm));
    }

    #[test]
    fn a_spec_refuses_what_it_does_not_know() {
        let err = spec("algorithm=rsa,signer=repo-key").unwrap_err();
        assert!(matches!(err, Error::SpecAlgorithm(ref v) if v == "rsa"));
        let err = spec("algorithm=ed25519,signer=keystore").unwrap_err();
        assert!(matches!(err, Error::SpecSigner(ref v) if v == "keystore"));
        let err = spec("algorithm=ed25519,signer=repo-key,color=red").unwrap_err();
        assert!(matches!(err, Error::SpecKey(ref v) if v == "color"));
        let err = spec("algorithm").unwrap_err();
        assert!(matches!(err, Error::SpecPart(ref v) if v == "algorithm"));
    }

    #[test]
    fn a_spec_error_keeps_the_text_of_the_flag() {
        assert_eq!(
            spec("algorithm=rsa,signer=repo-key")
                .unwrap_err()
                .to_string(),
            "--additional-signer: unknown algorithm 'rsa' — expected one of: ed25519, secp256k1, p256"
        );
        assert_eq!(
            spec("algorithm=ed25519,signer=sigstore")
                .unwrap_err()
                .to_string(),
            "--additional-signer: unknown signer 'sigstore' — expected one of: repo-key, external"
        );
    }

    #[test]
    fn a_missing_head_commit_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        let err = resolve_commit(&layout, None).unwrap_err();
        assert!(matches!(err, Error::NoHeadCommit), "{err:?}");
        assert_eq!(resolve_commit(&layout, Some([7; 32])).unwrap(), [7; 32]);
    }
}
