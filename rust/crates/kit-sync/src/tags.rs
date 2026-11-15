//! The tag phase of a fetch (SPEC-TRANSPORT §1.4).
//!
//! After the branches are published, a fetch lists the remote's tags and
//! publishes each one it does not hold. A tag publishes only whole and
//! proved: [`TagProver::prove`] checks that every object of its closure is in
//! the store, down to history local refs already reach, and, when signatures
//! are required, that every commit, remix and tag in its history passes its
//! signature check, down to history a signed fetch verified. That check is the
//! range walk the branch path runs ([`HistoryWalk`]), over the same verified
//! set, so tags and branches share one trust anchor.
//!
//! A tag whose closure is local publishes with no further request. Otherwise
//! its tag map (`refs/kit/tagmap/<t>`) names a pack chain, whose first nodes
//! usually belong to a branch chain this fetch already applied. The walk
//! stops at such a node, so a tag chain costs its own node and packs.
//!
//! A failure that belongs to one tag refuses that tag and the phase goes on;
//! a refused tag never fails the branches. Interruption, transport and local
//! I/O errors fail the fetch, as on the branch path.

use std::collections::{BTreeSet, HashMap, HashSet};

use kit_core::hash::{Hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::object::{KitError, Object, ObjectType};
use kit_core::ops::{Known, Presence};
use kit_core::refs::{self, TAG_REF_PREFIX, TAGMAP_REF_PREFIX};
use kit_core::store::{ObjectStore, StoreError};

use crate::applied_packs::AppliedPacks;
use crate::apply::{ChainApplied, apply_pack_chain};
use crate::error::SyncError;
use crate::fetch::FetchReport;
use crate::lock::{LockWait, wait_for_worktree_lock};
use crate::observer::{Observer, SyncEvent};
use crate::packmap::{MAX_PACK_CHAIN_DEPTH, flatten_oldest_first, walk_pack_chain_until};
use crate::source::RemoteSource;
use crate::verify::{
    FailedHistory, HistoryWalk, MissingHistory, VerifiedHistory, remember_missing,
};

/// The most self-heals the tag phase of one fetch runs. A self-heal clears
/// the applied-pack record and walks a tag's whole chain again, so a remote
/// whose tags each lack an object cannot make a fetch download the branch
/// history once per tag.
pub const TAG_SELF_HEALS_PER_FETCH: usize = 1;

/// The most annotated tags a tag may nest, as revision syntax peels them.
const MAX_TAG_DEPTH: usize = 16;

/// Why a fetch refused a remote tag. The tag is not published, the fetch
/// goes on, and the next fetch tries it again.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TagRejectReason {
    /// A local tag of that name holds another value. A fetch never moves a
    /// tag; delete the local one to take the remote's.
    #[error("would clobber existing tag")]
    WouldClobber,
    /// A local tag's name is a directory of this one, or this one's name is
    /// a directory of it, as `v1` and `v1/rc` are. One of them must go first.
    /// `other` names the local tag, or is `None` when the file system
    /// reported the clash, as a case-insensitive one does for `V1/rc`.
    #[error("{}", name_conflict_message(.other.as_deref()))]
    NameConflict { other: Option<String> },
    /// The tag's objects are not local and the remote has no tag map that
    /// rebuilds them.
    #[error("the remote has no tag map for it")]
    NoTransferChain,
    /// The annotated tag object carries another name than its ref, which
    /// would let a remote publish one signed tag under another tag's name.
    #[error("the tag object is named `{object_name}`")]
    NameMismatch { object_name: String },
    /// A commit, remix or tag in its history failed its signature check.
    #[error("object {hash} failed signature verification: {reason}")]
    Signature { hash: String, reason: String },
    /// The tag nests more annotated tags than a revision peels.
    #[error("it nests more than {MAX_TAG_DEPTH} tags")]
    TooDeep,
    /// Its history is too large to check.
    #[error("its history exceeds the {0}-object check")]
    ClosureTooLarge(usize),
    /// An object of its closure is still missing after its chain was applied
    /// and retried.
    #[error("the remote is missing object {0}")]
    Missing(String),
    /// Its tag map chain is too deep, cyclic, or names a node the remote
    /// cannot serve.
    #[error(
        "its tag map chain is malformed (too deep, cyclic, or unreadable); delete and re-create the tag"
    )]
    ChainInvalid,
    /// A pack of its chain is missing on the remote, fails its key, or does
    /// not decode, or an object of it breaks its manifest.
    #[error("{0}")]
    Transfer(String),
}

fn name_conflict_message(other: Option<&str>) -> String {
    match other {
        Some(other) => format!("conflicts with existing tag `{other}`"),
        None => "conflicts with the name of an existing tag".to_owned(),
    }
}

/// Whether a tag read or write failed because a tag's name is a directory of
/// another's, as a case-insensitive file system reports `V1/rc` beside `v1`.
fn is_name_clash(error: &refs::RefError) -> bool {
    matches!(
        error,
        refs::RefError::Io(e) if matches!(
            e.kind(),
            std::io::ErrorKind::NotADirectory | std::io::ErrorKind::IsADirectory
        )
    )
}

/// A remote tag a fetch refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TagRejection {
    /// The tag's name, without `refs/tags/`.
    pub name: String,
    pub reason: TagRejectReason,
}

/// A remote tag a fetch skipped without a refusal: its name is not one this
/// client can push or fetch (`check_pushable_tag`). The user cannot fix a
/// remote name, so it does not fail the fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TagWarning {
    pub name: String,
    pub reason: String,
}

/// What [`TagProver::prove`] found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Proof {
    /// The tag may publish.
    Proved,
    /// An object is missing: the tag needs its chain.
    Missing(String),
    /// The tag is refused.
    Refused(TagRejectReason),
}

/// The proof state of one fetch's tag phase, shared by every tag.
///
/// - The trusted set `R`: the commits, remixes and tags that local refs
///   reach, read once, the first time a tag needs it. Their closure is in the
///   store. When signatures are required, `R` is kept in two parts. The part
///   below a tip the verified set holds is anchored: the history of a
///   verified object was verified in full, so the signature walk stops there
///   as at the verified set. A tip that no signed fetch verified, such as one
///   a fetch with the opt-out published, is in the other part, so a tag above
///   it is still checked down to verified history.
/// - The proved set `P`: the objects whose closure a successful `prove`
///   checked. A failed `prove` adds nothing.
/// - The failed set `F`: the signature failures of earlier walks, with their
///   walk paths, so many tags over one bad history cost one walk.
/// - The missing set `M`: the objects whose closure lacked a missing object,
///   with the walk paths of the signature walk and the closure check, so many
///   tags over one incomplete history cost one walk too. An entry holds only
///   while its object is missing: [`TagProver::refresh_missing`] drops it
///   once a pack brings the object.
///
/// Each set holds at most `cap` ids. Past that, `R` stops growing, and `P`,
/// `F` and `M` are cleared. That only makes later walks longer. A walk also
/// keeps, while it runs, the objects it visited and the object that first
/// named each one.
pub(crate) struct TagProver {
    require_signed: bool,
    cap: usize,
    trusted: Option<Trusted>,
    proved: HashSet<Hash>,
    failed: FailedHistory,
    missing: MissingHistory,
    /// The missing objects that `missing` maps to.
    missing_objects: HashSet<Hash>,
    /// Objects the closure checks visited, and signed objects the history
    /// walks read, over every call.
    pub(crate) objects_checked: usize,
    pub(crate) signed_read: usize,
}

/// The set `R`, in two disjoint parts.
#[derive(Default)]
struct Trusted {
    /// Reached from a tip the verified set holds, when signatures are
    /// required.
    anchored: HashSet<Hash>,
    /// Reached from the other tips.
    rest: HashSet<Hash>,
}

impl Trusted {
    fn contains(&self, h: &Hash) -> bool {
        self.anchored.contains(h) || self.rest.contains(h)
    }
}

impl TagProver {
    pub(crate) fn new(require_signed: bool) -> Self {
        Self::with_cap(require_signed, kit_core::ops::graph::MAX_REACHABLE)
    }

    /// [`TagProver::new`] with another bound, so a test reaches it.
    pub(crate) fn with_cap(require_signed: bool, cap: usize) -> Self {
        Self {
            require_signed,
            cap,
            trusted: None,
            proved: HashSet::new(),
            failed: FailedHistory::default(),
            missing: MissingHistory::new(),
            missing_objects: HashSet::new(),
            objects_checked: 0,
            signed_read: 0,
        }
    }

    /// Drop the entries of `M` whose object the store now holds. Called after
    /// each chain apply.
    pub(crate) fn refresh_missing(&mut self, store: &ObjectStore) {
        let found: HashSet<Hash> = self
            .missing_objects
            .iter()
            .filter(|object| store.contains(object))
            .copied()
            .collect();
        if found.is_empty() {
            return;
        }
        self.missing.retain(|_, object| !found.contains(object));
        self.missing_objects
            .retain(|object| !found.contains(object));
    }

    /// Whether tag `name` may publish at `value`: T5 on the outermost tag
    /// object, the peel bound, the signature range walk, and the closure
    /// check, in that order. A refusal that depends on the object alone is
    /// remembered for the fetch; T5, the peel bound and the size bound depend
    /// on where the walk starts and are not.
    pub(crate) fn prove(
        &mut self,
        store: &ObjectStore,
        layout: &RepoLayout,
        observer: &dyn Observer<SyncEvent>,
        verified: &mut VerifiedHistory,
        name: &str,
        value: Hash,
    ) -> Result<Proof, SyncError> {
        if let Some(proof) = self.peel(store, name, value)? {
            return Ok(proof);
        }
        if self.trusted.is_none() {
            self.trusted = Some(self.trusted_set(store, layout, observer, verified)?);
        }
        let Self {
            require_signed,
            cap,
            trusted,
            proved,
            failed,
            missing,
            missing_objects,
            objects_checked,
            signed_read,
        } = self;
        let trusted = trusted.as_ref().unwrap_or_else(|| unreachable!());
        if *require_signed {
            let mut walk = HistoryWalk {
                verified,
                anchored: Some(&trusted.anchored),
                failed: Some(failed),
                missing: Some(missing),
                cap: *cap,
                read: 0,
            };
            let result = walk.run(store, observer, &value);
            *signed_read += walk.read;
            match result {
                Ok(()) => {}
                Err(SyncError::UnsignedOrInvalidObject { hash, reason }) => {
                    return Ok(Proof::Refused(TagRejectReason::Signature { hash, reason }));
                }
                Err(SyncError::ClosureTooLarge(cap)) => {
                    return Ok(Proof::Refused(TagRejectReason::ClosureTooLarge(cap)));
                }
                Err(SyncError::Store(StoreError::ObjectNotFound(hex))) => {
                    missing_objects.extend(refs::parse_lowercase_hash(hex.as_bytes()));
                    return Ok(Proof::Missing(hex));
                }
                Err(e) => return Err(e),
            }
        }
        let known = |h: &Hash| {
            if trusted.contains(h) || proved.contains(h) {
                Known::Present
            } else if missing.contains_key(h) {
                Known::Missing
            } else {
                Known::Unknown
            }
        };
        let stop = || observer.cancelled();
        let presence =
            match kit_core::ops::check_closure_present_above(store, &value, &known, *cap, &stop) {
                Ok(presence) => presence,
                Err(StoreError::Decode(
                    e @ (KitError::ChunkLengthMismatch { .. } | KitError::ChunkNotBlob { .. }),
                )) => {
                    return Ok(Proof::Refused(TagRejectReason::Transfer(
                        SyncError::RemoteObject(e).to_string(),
                    )));
                }
                Err(e) => return Err(e.into()),
            };
        match presence {
            Presence::Complete(checked) => {
                *objects_checked += checked.len();
                if proved.len() + checked.len() > *cap {
                    proved.clear();
                }
                proved.extend(checked);
                Ok(Proof::Proved)
            }
            Presence::TooLarge(checked) => {
                *objects_checked += checked;
                Ok(Proof::Refused(TagRejectReason::ClosureTooLarge(*cap)))
            }
            Presence::Missing {
                object,
                path,
                checked,
            } => {
                *objects_checked += checked;
                // An object `M` holds stands for the object it lacks.
                let lacked = missing.get(&object).copied().unwrap_or(object);
                let via: HashMap<Hash, Hash> = path.windows(2).map(|w| (w[0], w[1])).collect();
                remember_missing(missing, &via, object, lacked, *cap);
                missing_objects.insert(lacked);
                Ok(Proof::Missing(to_hex(&lacked)))
            }
            Presence::Stopped(checked) => {
                *objects_checked += checked;
                Err(SyncError::Interrupted)
            }
        }
    }

    /// Peel `value` through its annotated tags: T5 on the outermost one, at
    /// most [`MAX_TAG_DEPTH`] of them, and no object the failed or missing
    /// set holds. `None` when the tag passes.
    fn peel(
        &self,
        store: &ObjectStore,
        name: &str,
        value: Hash,
    ) -> Result<Option<Proof>, SyncError> {
        let mut at = value;
        let mut depth = 0;
        loop {
            if let Some((hash, reason)) = self.failed.get(&at) {
                return Ok(Some(Proof::Refused(TagRejectReason::Signature {
                    hash: hash.clone(),
                    reason: reason.clone(),
                })));
            }
            if let Some(object) = self.missing.get(&at) {
                return Ok(Some(Proof::Missing(to_hex(object))));
            }
            match store.object_type(&at) {
                Ok(ObjectType::Tag) => {}
                Ok(_) => return Ok(None),
                Err(StoreError::ObjectNotFound(hex)) => return Ok(Some(Proof::Missing(hex))),
                Err(e) => return Err(e.into()),
            }
            if depth == MAX_TAG_DEPTH {
                return Ok(Some(Proof::Refused(TagRejectReason::TooDeep)));
            }
            let Object::Tag(tag) = store.read_object(&at)? else {
                return Err(SyncError::Store(StoreError::ObjectNotFound(to_hex(&at))));
            };
            if depth == 0 && tag.name != name.as_bytes() {
                return Ok(Some(Proof::Refused(TagRejectReason::NameMismatch {
                    object_name: String::from_utf8_lossy(&tag.name).into_owned(),
                })));
            }
            depth += 1;
            at = tag.target;
        }
    }

    /// The set `R`, walked from the tips of every local branch, tracking ref
    /// and tag. When signatures are required, the walk from the tips that
    /// `verified` holds runs first and fills the anchored part.
    fn trusted_set(
        &self,
        store: &ObjectStore,
        layout: &RepoLayout,
        observer: &dyn Observer<SyncEvent>,
        verified: &VerifiedHistory,
    ) -> Result<Trusted, SyncError> {
        let mut tips = Vec::new();
        for r in refs::list_refs(layout)?
            .into_iter()
            .chain(refs::list_tags(layout)?)
        {
            tips.extend(r.hash);
        }
        for remote in refs::list_remote_names(layout)? {
            for r in refs::list_remote_refs(layout, &remote)? {
                tips.extend(r.hash);
            }
        }
        let (anchored, rest): (Vec<Hash>, Vec<Hash>) = if self.require_signed {
            tips.into_iter().partition(|tip| verified.contains(tip))
        } else {
            (Vec::new(), tips)
        };
        let mut trusted = Trusted::default();
        let cancelled = || observer.cancelled();
        reach(
            store,
            &anchored,
            &mut trusted.anchored,
            &HashSet::new(),
            self.cap,
            &cancelled,
        )?;
        let room = self.cap.saturating_sub(trusted.anchored.len());
        reach(
            store,
            &rest,
            &mut trusted.rest,
            &trusted.anchored,
            room,
            &cancelled,
        )?;
        Ok(trusted)
    }
}

/// Add to `into` the commits, remixes and tags reachable from `tips`
/// through parents and tag targets. An object `into` or `skip` holds is not
/// walked again, a missing one is skipped, and the walk stops once `into`
/// holds `cap` ids. `cancelled` is polled every few thousand objects.
fn reach(
    store: &ObjectStore,
    tips: &[Hash],
    into: &mut HashSet<Hash>,
    skip: &HashSet<Hash>,
    cap: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), SyncError> {
    let mut pending = tips.to_vec();
    let mut visited = 0usize;
    while let Some(h) = pending.pop() {
        if into.len() >= cap {
            return Ok(());
        }
        visited += 1;
        if visited.is_multiple_of(4096) && cancelled() {
            return Err(SyncError::Interrupted);
        }
        if into.contains(&h) || skip.contains(&h) {
            continue;
        }
        let object = match store.object_type(&h) {
            Ok(ObjectType::Commit | ObjectType::Remix | ObjectType::Tag) => store.read_object(&h),
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => continue,
            Err(e) => return Err(e.into()),
        };
        let object = match object {
            Ok(object) => object,
            Err(StoreError::ObjectNotFound(_)) => continue,
            Err(e) => return Err(e.into()),
        };
        match &object {
            Object::Commit(c) => pending.extend(&c.parents),
            Object::Remix(r) => pending.extend(&r.parents),
            Object::Tag(t) => pending.push(t.target),
            Object::Blob(_) | Object::Tree(_) | Object::ChunkedBlob(_) | Object::Delta(_) => {}
        }
        into.insert(h);
    }
    Ok(())
}

/// The node ids a tag chain walk stops at: nodes of chains this fetch applied
/// and checked, whose chain is therefore already applied. At most
/// [`MAX_PACK_CHAIN_DEPTH`] ids; past that nothing is added, and walks only
/// skip less.
#[derive(Default)]
pub(crate) struct StopSet(HashSet<Hash>);

impl StopSet {
    pub(crate) fn extend(&mut self, keys: impl IntoIterator<Item = Hash>) {
        for key in keys {
            if self.0.len() >= MAX_PACK_CHAIN_DEPTH {
                return;
            }
            self.0.insert(key);
        }
    }

    fn contains(&self, key: &Hash) -> bool {
        self.0.contains(key)
    }
}

/// What the tag phase needs from the fetch that runs it.
pub(crate) struct TagPhase<'a> {
    pub(crate) store: &'a ObjectStore,
    pub(crate) layout: &'a RepoLayout,
    pub(crate) source: &'a dyn RemoteSource,
    pub(crate) observer: &'a dyn Observer<SyncEvent>,
    pub(crate) remote: &'a str,
    pub(crate) require_signed: bool,
    pub(crate) lock_wait: &'a LockWait,
    pub(crate) applied: &'a mut AppliedPacks,
    pub(crate) verified: &'a mut VerifiedHistory,
    pub(crate) stop: StopSet,
    pub(crate) report: &'a mut FetchReport,
    /// `report.packs_downloaded` when `M` was last refreshed.
    pub(crate) packs_since_refresh: usize,
}

/// What became of one listed tag.
enum Outcome {
    Publish(Hash),
    /// A stale listing: the tag is gone.
    Skip,
    Refused(TagRejectReason),
}

/// What the tag phase remembers between tags.
#[derive(Default)]
struct Attempts {
    /// The tag maps, listed once, the first time a tag needs its chain.
    tagmaps: Option<HashMap<String, Hash>>,
    /// The self-heals run so far.
    heals: usize,
    /// Each pack whose download or apply this fetch refused, with the tag
    /// it was refused for and the refusal, so a pack that many tag chains
    /// share costs one download.
    failed_packs: HashMap<Hash, FailedPack>,
}

/// A pack refused for one tag: the tag and the refusal.
type FailedPack = (String, TagRejectReason);

/// The refusal of a tag whose chain holds `pack`, refused before for the
/// tag `first`. A transfer message names the first tag's ref, so it is
/// given as that tag's.
fn shared_refusal(pack: &Hash, (first, reason): &FailedPack) -> TagRejectReason {
    match reason {
        TagRejectReason::Transfer(message) => TagRejectReason::Transfer(format!(
            "pack {} failed for tag `{first}`: {message}",
            to_hex(pack)
        )),
        reason => reason.clone(),
    }
}

/// A failure of the tag or tag map listing, which stops the phase.
struct ListingFailed(String);

/// How a tag's chain attempt failed.
enum ChainFailure {
    /// A missing object or delta base, named by its hex id: retried once.
    Retry(String),
    Refused(TagRejectReason),
    Fatal(SyncError),
}

impl From<SyncError> for ChainFailure {
    fn from(error: SyncError) -> Self {
        match error {
            SyncError::RemoteMissingObject(hex)
            | SyncError::Pack(kit_core::pack::PackError::DeltaBaseMissing(hex)) => Self::Retry(hex),
            SyncError::PackChainInvalid { .. } | SyncError::PackList(_) => {
                Self::Refused(TagRejectReason::ChainInvalid)
            }
            SyncError::UnsignedOrInvalidObject { hash, reason } => {
                Self::Refused(TagRejectReason::Signature { hash, reason })
            }
            SyncError::ClosureTooLarge(cap) => Self::Refused(TagRejectReason::ClosureTooLarge(cap)),
            // The local store failed while the pack was written: that is no
            // fault of this tag, and the next tag would meet it too.
            e @ SyncError::Pack(kit_core::pack::PackError::Store(
                StoreError::Io(_) | StoreError::HashMismatch { .. },
            )) => Self::Fatal(e),
            e @ (SyncError::AdvertisedPackMissing { .. }
            | SyncError::Pack(_)
            | SyncError::RemoteObject(_)
            | SyncError::Source(
                crate::SourceError::InvalidResponse | crate::SourceError::PayloadTooLarge(_),
            )) => Self::Refused(TagRejectReason::Transfer(e.to_string())),
            e => Self::Fatal(e),
        }
    }
}

impl TagPhase<'_> {
    /// List the remote's tags and publish each one that proves, refusing the
    /// rest one by one.
    pub(crate) fn run(mut self) -> Result<(), SyncError> {
        let listed = match self.source.list_refs(TAG_REF_PREFIX) {
            Ok(listed) => listed,
            // A listing cut short by an interrupt is the interrupt.
            Err(_) if self.observer.cancelled() => return Err(SyncError::Interrupted),
            Err(e) => {
                self.listing_failed(&ListingFailed(e.to_string()));
                return Ok(());
            }
        };
        let mut prover = TagProver::new(self.require_signed);
        let mut attempts = Attempts::default();
        let mut publish: Vec<(String, Hash)> = Vec::new();
        // Local tag names and the names this phase will publish: a name that
        // is a directory of another cannot be written beside it.
        let mut names: BTreeSet<String> = refs::list_tags(self.layout)?
            .into_iter()
            .map(|r| r.name)
            .collect();
        let mut fatal = None;
        for listed in listed {
            if self.observer.cancelled() {
                fatal = Some(SyncError::Interrupted);
                break;
            }
            let Some(value) = listed.hash else { continue };
            let name = listed.name;
            if let Err(e) = refs::check_pushable_tag(&name) {
                self.report.tag_warnings.push(TagWarning {
                    name,
                    reason: e.to_string(),
                });
                continue;
            }
            if let Some(other) = name_conflict(&names, &name) {
                self.refuse(name, TagRejectReason::NameConflict { other: Some(other) });
                continue;
            }
            let local = match refs::read_tag(self.layout, &name) {
                Ok(local) => local,
                Err(e) if is_name_clash(&e) => {
                    self.refuse(name, TagRejectReason::NameConflict { other: None });
                    continue;
                }
                Err(e) => {
                    fatal = Some(e.into());
                    break;
                }
            };
            match local {
                Some(local) if local == value => continue,
                Some(_) => {
                    self.refuse(name, TagRejectReason::WouldClobber);
                    continue;
                }
                None => {}
            }
            match self.fetch_tag(&mut prover, &mut attempts, &name, value) {
                Ok(Outcome::Publish(value)) => {
                    names.insert(name.clone());
                    publish.push((name, value));
                }
                Ok(Outcome::Skip) => {}
                Ok(Outcome::Refused(reason)) => self.refuse(name, reason),
                Err(Ok(_)) if self.observer.cancelled() => {
                    fatal = Some(SyncError::Interrupted);
                    break;
                }
                Err(Ok(failed)) => {
                    self.listing_failed(&failed);
                    break;
                }
                Err(Err(e)) => {
                    fatal = Some(e);
                    break;
                }
            }
        }
        // The tags proved before a failure publish, as the branches before a
        // failed branch do. An interrupt publishes nothing more.
        if let Some(e) = fatal {
            if !matches!(e, SyncError::Interrupted) {
                // The first failure is the one to report; a failed publish
                // here only leaves those tags for the next fetch.
                let _ = self.publish(publish);
            }
            return Err(e);
        }
        self.publish(publish)
    }

    /// Bring one tag's objects and prove it.
    fn fetch_tag(
        &mut self,
        prover: &mut TagProver,
        attempts: &mut Attempts,
        name: &str,
        value: Hash,
    ) -> Result<Outcome, Result<ListingFailed, SyncError>> {
        match self.prove(prover, name, value).map_err(Err)? {
            Proof::Proved => return Ok(Outcome::Publish(value)),
            Proof::Refused(reason) => return Ok(Outcome::Refused(reason)),
            Proof::Missing(_) => {}
        }
        // The tag needs its chain. The tag maps are listed once, after the
        // tags, so on an ordered listing a tag map covers its tag's value.
        let tagmaps = &mut attempts.tagmaps;
        if tagmaps.is_none() {
            let listed = self
                .source
                .list_refs(TAGMAP_REF_PREFIX)
                .map_err(|e| Ok(ListingFailed(e.to_string())))?;
            *tagmaps = Some(
                listed
                    .into_iter()
                    .filter_map(|r| Some((r.name, r.hash?)))
                    .collect(),
            );
        }
        let tag_ref = format!("{TAG_REF_PREFIX}{name}");
        let map_ref = format!("{TAGMAP_REF_PREFIX}{name}");
        let listed_map = tagmaps.as_ref().and_then(|maps| maps.get(name).copied());
        let map = if let Some(map) = listed_map {
            map
        } else {
            if self
                .source
                .read_ref(&tag_ref)
                .map_err(|e| Err(e.into()))?
                .is_none()
            {
                return Ok(Outcome::Skip);
            }
            match self.source.read_ref(&map_ref).map_err(|e| Err(e.into()))? {
                Some(map) => map,
                None => return Ok(Outcome::Refused(TagRejectReason::NoTransferChain)),
            }
        };
        let applied = self.apply_chain(&tag_ref, map, true, &mut attempts.failed_packs);
        self.refresh_after_apply(prover);
        let skipped = match applied {
            Ok((skipped, keys)) => match self.prove(prover, name, value).map_err(Err)? {
                Proof::Proved => {
                    self.stop.extend(keys);
                    return Ok(Outcome::Publish(value));
                }
                Proof::Refused(reason) => return Ok(Outcome::Refused(reason)),
                Proof::Missing(_) => skipped,
            },
            Err((skipped, ChainFailure::Retry(_))) => skipped,
            Err((_, ChainFailure::Refused(reason))) => return Ok(Outcome::Refused(reason)),
            Err((_, ChainFailure::Fatal(e))) => return Err(Err(e)),
        };
        // One retry over a strong re-read of both refs, as a branch does. It
        // also covers a tag deleted and made again between the two listings.
        let Some(value) = self.source.read_ref(&tag_ref).map_err(|e| Err(e.into()))? else {
            return Ok(Outcome::Skip);
        };
        let Some(map) = self.source.read_ref(&map_ref).map_err(|e| Err(e.into()))? else {
            return Ok(Outcome::Refused(TagRejectReason::NoTransferChain));
        };
        // A first try that skipped packs, or stopped at a node of a chain
        // already applied, may have trusted a stale record: the retry then
        // clears it and walks the whole chain, at most once per fetch.
        let heal = skipped && attempts.heals < TAG_SELF_HEALS_PER_FETCH;
        if heal {
            attempts.heals += 1;
            self.observer.event(&SyncEvent::AppliedPacksStale {
                remote: self.remote.to_owned(),
                branch: tag_ref.clone(),
                cause: "a tag's closure is incomplete".to_owned(),
            });
            self.applied.clear();
            crate::fetch::persist_record(self.applied, self.observer, self.remote);
        }
        let applied = self.apply_chain(&tag_ref, map, !heal, &mut attempts.failed_packs);
        self.refresh_after_apply(prover);
        match applied {
            Ok((_, keys)) => match self.prove(prover, name, value).map_err(Err)? {
                Proof::Proved => {
                    self.stop.extend(keys);
                    Ok(Outcome::Publish(value))
                }
                Proof::Refused(reason) => Ok(Outcome::Refused(reason)),
                Proof::Missing(hex) => Ok(Outcome::Refused(TagRejectReason::Missing(hex))),
            },
            Err((_, ChainFailure::Retry(hex))) => {
                Ok(Outcome::Refused(TagRejectReason::Missing(hex)))
            }
            Err((_, ChainFailure::Refused(reason))) => Ok(Outcome::Refused(reason)),
            Err((_, ChainFailure::Fatal(e))) => Err(Err(e)),
        }
    }

    fn prove(
        &mut self,
        prover: &mut TagProver,
        name: &str,
        value: Hash,
    ) -> Result<Proof, SyncError> {
        prover.prove(
            self.store,
            self.layout,
            self.observer,
            self.verified,
            name,
            value,
        )
    }

    /// Drop what `M` holds for objects the last apply brought, if it brought
    /// any.
    fn refresh_after_apply(&mut self, prover: &mut TagProver) {
        if self.packs_since_refresh != self.report.packs_downloaded {
            self.packs_since_refresh = self.report.packs_downloaded;
            prover.refresh_missing(self.store);
        }
    }

    /// Walk the chain of `tag_ref` from `map`, stopping at the stop set when
    /// `use_stop`, and apply its packs. A chain that holds a pack this fetch
    /// already refused is refused with no download, and a pack refused here
    /// joins `failed_packs`. Returns whether anything was skipped (a recorded
    /// pack or a node of the stop set) and the nodes it walked.
    #[allow(clippy::type_complexity)]
    fn apply_chain(
        &mut self,
        tag_ref: &str,
        map: Hash,
        use_stop: bool,
        failed_packs: &mut HashMap<Hash, FailedPack>,
    ) -> Result<(bool, Vec<Hash>), (bool, ChainFailure)> {
        let stop = &self.stop;
        let walk = walk_pack_chain_until(self.source, self.observer, tag_ref, map, &|key| {
            use_stop && stop.contains(key)
        })
        .map_err(|e| (false, ChainFailure::from(e)))?;
        let stopped = walk.stopped;
        let keys = walk.keys;
        let chain = flatten_oldest_first(walk.nodes);
        if let Some(reason) = chain
            .iter()
            .find_map(|pack| Some(shared_refusal(pack, failed_packs.get(pack)?)))
        {
            return Err((stopped, ChainFailure::Refused(reason)));
        }
        let mut done = ChainApplied::default();
        let result = apply_pack_chain(
            self.store,
            self.source,
            self.observer,
            self.remote,
            tag_ref,
            &chain,
            self.applied,
            self.require_signed,
            &mut done,
        );
        self.report.packs_downloaded += done.packs;
        self.report.packs_already_applied += done.skipped;
        self.report.objects_unpacked += done.objects;
        let skipped = stopped || done.skipped > 0;
        if let Err(e) = result {
            let failure = ChainFailure::from(e);
            // Packs apply in chain order, so the one that failed follows
            // those applied or skipped.
            if let ChainFailure::Refused(reason) = &failure
                && let Some(pack) = chain.get(done.packs + done.skipped)
            {
                let name = tag_ref.strip_prefix(TAG_REF_PREFIX).unwrap_or(tag_ref);
                failed_packs.insert(*pack, (name.to_owned(), reason.clone()));
            }
            return Err((skipped, failure));
        }
        Ok((skipped, keys))
    }

    fn refuse(&mut self, name: String, reason: TagRejectReason) {
        self.report
            .tags_rejected
            .push(TagRejection { name, reason });
    }

    fn listing_failed(&mut self, failed: &ListingFailed) {
        self.report.tag_listing_failed = Some(format!(
            "tag listing failed (possibly too many tags): {}",
            failed.0
        ));
    }

    /// Publish every proved tag under one hold of the worktree lock, each as
    /// a create: a tag made locally meanwhile is refused, never moved.
    fn publish(self, publish: Vec<(String, Hash)>) -> Result<(), SyncError> {
        if publish.is_empty() {
            return Ok(());
        }
        let _lock = wait_for_worktree_lock(self.layout, self.observer, self.lock_wait)?;
        let mut first_error = None;
        for (name, value) in publish {
            match refs::update_tag(self.layout, &name, refs::RefWriteCondition::Missing, &value) {
                Ok(()) => self.report.tags_fetched.push(name),
                Err(refs::RefError::Conflict(_)) => {
                    // No tag at the name means the path is another tag's
                    // directory, as a case-folding file system shows `V1/rc`
                    // to `v1`.
                    let reason = match refs::read_tag(self.layout, &name) {
                        Ok(Some(_)) => TagRejectReason::WouldClobber,
                        Err(e) if !is_name_clash(&e) => TagRejectReason::WouldClobber,
                        _ => TagRejectReason::NameConflict { other: None },
                    };
                    self.report
                        .tags_rejected
                        .push(TagRejection { name, reason });
                }
                Err(e) if is_name_clash(&e) => {
                    self.report.tags_rejected.push(TagRejection {
                        name,
                        reason: TagRejectReason::NameConflict { other: None },
                    });
                }
                // A local write failed: the other tags still publish, and the
                // fetch then fails with the first error.
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        first_error.map_or(Ok(()), |e| Err(e.into()))
    }
}

/// A name in `names` that is a directory of `name`, or of which `name` is a
/// directory, as `v1` and `v1/rc` are.
fn name_conflict(names: &BTreeSet<String>, name: &str) -> Option<String> {
    for (at, _) in name.match_indices('/') {
        if let Some(parent) = names.get(&name[..at]) {
            return Some(parent.clone());
        }
    }
    let below = format!("{name}/");
    names
        .range(below.clone()..)
        .next()
        .filter(|other| other.starts_with(&below))
        .cloned()
}

#[cfg(test)]
mod tests;
