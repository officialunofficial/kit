//! Pushing tags (SPEC-TRANSPORT §7.2).
//!
//! A remote tag `refs/tags/<t>` has a tag map `refs/kit/tagmap/<t>`: the key
//! of a packlist node whose chain rebuilds the tag's closure. A push writes
//! the tag map before the tag, and every tag map write is a create or an
//! append that covers both the remote tag's current value and its new one,
//! so a tag map only grows and a reader of any earlier value is still
//! served, whatever order the two refs land in.
//!
//! A tag push handles its tags in one pass:
//!
//! 1. It refuses locally a name that cannot be pushed, an annotated tag whose
//!    object carries another name, and an unsigned annotated tag.
//! 2. It reads each tag's remote tag and tag map, from one listing of each
//!    or strongly, and picks the tag's row: create, repair (the tag is there
//!    without its tag map), a forced update, an append to a tag map left
//!    without its tag, up to date, or refused because the remote tag holds
//!    another value.
//! 3. The creates, repairs and forced updates without a tag map look for a
//!    base: the nearest branch tip of this remote, by the tracking refs, that
//!    the tag's history reaches. Tags with one base form a group.
//! 4. Each group is planned once against its base, uploaded once, and its
//!    node grafts on the base's packmap node, so a tag on a pushed commit
//!    sends only its tag objects. Every tag of the group takes that node as
//!    its tag map.
//! 5. A tag map append and a forced update over a tag map are planned per tag.
//!
//! A tag whose write loses a race is read again and placed anew, at most
//! [`PACKMAP_CAS_ATTEMPTS`] times. Every result is per tag: a refused tag does
//! not stop the others.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use kit_core::hash::{Hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::object::{Object, ObjectType};
use kit_core::ops::graph::{MAX_REACHABLE, check_closure_present};
use kit_core::protocol::{AdvanceOutcome, CommitOutcome, PackKey, RefListing, UploadLimits};
use kit_core::refs::{self, RefWriteCondition, TAG_REF_PREFIX, TAGMAP_REF_PREFIX};
use kit_core::store::{ObjectStore, StoreError};
use kit_core::transfer::PackPlan;
use kit_core::transfer::packmap::{ChainState, PlanError, plan_advance};

use super::packmap::PACKMAP_CAS_ATTEMPTS;
use super::{
    PushContext, PushError, build_and_upload_packs, dry_seal, estimate_pack_sizes,
    repository_operation_error,
};
use crate::packmap::packmap_ref;
use crate::{SourceError, SyncError};

/// The most bytes a push lets a remote's listing of `refs/tags/`, or of
/// `refs/kit/tagmap/`, reach on a remote whose listing comes in one frame
/// ([`RefListing::OneFrame`]), counted as `kit serve` counts a listing: each
/// name without its prefix, plus 48 bytes. 960 KiB keeps
/// each listing within `kit serve`'s frame of 1 MiB: about 17,000 short tags.
pub const MAX_TAG_LISTING_BYTES: usize = 960 * 1024;

/// The bytes an entry adds to a `kit serve` listing beyond its name.
const TAG_LISTING_ENTRY_BYTES: usize = 48;

/// The most commits one tag's base search visits that no earlier search of
/// the push visited. A tag that finds no base within it sends its whole
/// closure.
pub const MAX_BASE_WALK_COMMITS: usize = 100_000;

/// Which local tags a push sends.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TagSelection {
    /// Every local tag (`kit push --tags`).
    All,
    /// These tags, by name without `refs/tags/`.
    Named(Vec<String>),
}

/// What a push did with one tag.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TagPushResult {
    /// The tag's name, without `refs/tags/`.
    pub name: String,
    pub outcome: TagPushOutcome,
}

/// The outcome of one tag of a push.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TagPushOutcome {
    /// The remote did not hold the tag; it now holds `value`.
    Created { value: Hash },
    /// The remote held the tag at `value` already, with its tag map.
    UpToDate { value: Hash },
    /// The remote held the tag at `value` without its tag map, which the
    /// push wrote.
    Repaired { value: Hash },
    /// `--force` moved the remote tag from `old` to `value`.
    Forced { old: Hash, value: Hash },
    /// The push refused the tag, or the remote did.
    Rejected(TagPushRejection),
}

/// Why a push refused a tag. The other tags of the push go on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TagPushRejection {
    /// `refs/kit/tagmap/<t>` would not be a valid ref name (SPEC-REFS §3).
    #[error("{0}")]
    NotPushable(String),
    /// The annotated tag object carries another name than its ref.
    #[error(
        "tag object is named `{object_name}`; push it as `{object_name}` or make a lightweight tag"
    )]
    NameMismatch { object_name: String },
    /// An annotated tag that carries no signature.
    #[error(
        "the tag is unsigned; re-create it signed (`kit tag -d {tag}`, then `kit tag -s {tag} <commit>`), or push a lightweight tag"
    )]
    Unsigned { tag: String },
    /// The remote tag holds another value and the push does not force.
    #[error("the remote tag holds {} (use --force to replace it)", to_hex(.remote))]
    Exists { remote: Hash },
    /// A forced update over a remote tag without a tag map must send the
    /// remote's value too, and this repository lacks it or its history.
    #[error("the remote tag holds {} with no tag map; fetch the remote tag first, or delete it", to_hex(.remote))]
    OldValueNotLocal { remote: Hash },
    /// A new tag would take the remote's tag listing past
    /// [`MAX_TAG_LISTING_BYTES`].
    #[error("the remote holds too many tags to list")]
    TooManyTags,
    /// The tags of one group need more packs, or more objects, than one
    /// ticketed advance of this server carries.
    #[error("the tags need more than one advance carries; push the branch first, then the tags")]
    TooLarge,
    /// The tag lost every race for its refs.
    #[error("the remote tag changed under concurrent pushes; retry")]
    Contended,
    /// The remote refused the write.
    #[error("{0}")]
    Refused(String),
}

/// One local tag the push sends.
#[derive(Debug, Clone)]
struct Local {
    name: String,
    value: Hash,
}

impl Local {
    fn tag_ref(&self) -> String {
        format!("{TAG_REF_PREFIX}{}", self.name)
    }

    fn map_ref(&self) -> String {
        format!("{TAGMAP_REF_PREFIX}{}", self.name)
    }
}

/// The remote's tag and tag map of one name.
#[derive(Debug, Clone, Copy, Default)]
struct RemoteState {
    tag: Option<Hash>,
    map: Option<Hash>,
}

/// What a push writes for one tag.
#[derive(Debug, Clone, Copy)]
enum Row {
    /// Tag map `Missing → G`, then tag `Missing → v`.
    Create,
    /// Tag map `Missing → G`, with tag `Match(v) → v`.
    Repair,
    /// Tag map `Missing → G`, where `G` also rebuilds `old`, then tag
    /// `Match(old) → v`.
    ForcedFresh { old: Hash },
    /// Tag map `Match(map)` appended with the full closure of `v`, then tag
    /// `Missing → v`.
    Leftover { map: Hash },
    /// Tag map `Match(map)` appended with what `v` adds to `old`, then tag
    /// `Match(old) → v`.
    ForcedAppend { old: Hash, map: Hash },
}

impl Row {
    /// Whether the row's tag map is a create, which a group shares.
    fn creates_map(self) -> bool {
        matches!(self, Self::Create | Self::Repair | Self::ForcedFresh { .. })
    }

    fn conditions(self, value: Hash) -> (RefWriteCondition, RefWriteCondition) {
        match self {
            Self::Create => (RefWriteCondition::Missing, RefWriteCondition::Missing),
            Self::Repair => (RefWriteCondition::Match(value), RefWriteCondition::Missing),
            Self::ForcedFresh { old } => {
                (RefWriteCondition::Match(old), RefWriteCondition::Missing)
            }
            Self::Leftover { map } => (RefWriteCondition::Missing, RefWriteCondition::Match(map)),
            Self::ForcedAppend { old, map } => {
                (RefWriteCondition::Match(old), RefWriteCondition::Match(map))
            }
        }
    }

    fn landed(self, value: Hash) -> TagPushOutcome {
        match self {
            Self::Create | Self::Leftover { .. } => TagPushOutcome::Created { value },
            Self::Repair => TagPushOutcome::Repaired { value },
            Self::ForcedFresh { old } | Self::ForcedAppend { old, .. } => {
                TagPushOutcome::Forced { old, value }
            }
        }
    }
}

/// The row of a tag whose local value is `value`, or its outcome when the
/// push writes nothing for it.
fn classify(value: Hash, remote: RemoteState, force: bool) -> Result<Row, TagPushOutcome> {
    match (remote.tag, remote.map) {
        (None, None) => Ok(Row::Create),
        (None, Some(map)) => Ok(Row::Leftover { map }),
        (Some(tag), Some(_)) if tag == value => Err(TagPushOutcome::UpToDate { value }),
        (Some(tag), None) if tag == value => Ok(Row::Repair),
        (Some(remote), _) if !force => Err(TagPushOutcome::Rejected(TagPushRejection::Exists {
            remote,
        })),
        (Some(old), Some(map)) => Ok(Row::ForcedAppend { old, map }),
        (Some(old), None) => Ok(Row::ForcedFresh { old }),
    }
}

/// The remote's listings of `refs/tags/` and `refs/kit/tagmap/`, read once
/// per push, and the bytes a one-frame listing of each would take.
struct Listing {
    tags: BTreeMap<String, Hash>,
    maps: BTreeMap<String, Hash>,
    tag_bytes: usize,
    map_bytes: usize,
    /// Names this push already counted as new in each listing.
    new_tags: HashSet<String>,
    new_maps: HashSet<String>,
}

impl Listing {
    /// List the tags, then the tag maps: a tag map is written before its tag,
    /// so on an ordered listing a tag map listed after its tag covers it.
    fn read(tx: &PushContext<'_>) -> Result<Self, PushError> {
        let collect = |prefix: &str| -> Result<(BTreeMap<String, Hash>, usize), PushError> {
            let listed = tx
                .list_refs(prefix)
                .map_err(|error| repository_operation_error(tx, error))?;
            let bytes = listed
                .iter()
                .map(|r| r.name.len() + TAG_LISTING_ENTRY_BYTES)
                .sum();
            let refs = listed
                .into_iter()
                .filter_map(|r| Some((r.name, r.hash?)))
                .collect();
            Ok((refs, bytes))
        };
        let (tags, tag_bytes) = collect(TAG_REF_PREFIX)?;
        let (maps, map_bytes) = collect(TAGMAP_REF_PREFIX)?;
        Ok(Self {
            tags,
            maps,
            tag_bytes,
            map_bytes,
            new_tags: HashSet::new(),
            new_maps: HashSet::new(),
        })
    }

    fn state(&self, name: &str) -> RemoteState {
        RemoteState {
            tag: self.tags.get(name).copied(),
            map: self.maps.get(name).copied(),
        }
    }

    /// Count the refs that writing `row` for `name` adds to each listing, or
    /// refuse when either would pass [`MAX_TAG_LISTING_BYTES`].
    fn admit(&mut self, name: &str, row: Row) -> bool {
        let entry = name.len() + TAG_LISTING_ENTRY_BYTES;
        let new_tag = matches!(row, Row::Create | Row::Leftover { .. })
            && !self.tags.contains_key(name)
            && !self.new_tags.contains(name);
        let new_map =
            row.creates_map() && !self.maps.contains_key(name) && !self.new_maps.contains(name);
        if (new_tag && self.tag_bytes + entry > MAX_TAG_LISTING_BYTES)
            || (new_map && self.map_bytes + entry > MAX_TAG_LISTING_BYTES)
        {
            return false;
        }
        if new_tag {
            self.tag_bytes += entry;
            self.new_tags.insert(name.to_owned());
        }
        if new_map {
            self.map_bytes += entry;
            self.new_maps.insert(name.to_owned());
        }
        true
    }
}

/// A branch of the remote that a group of tags grafts on: its head, read
/// stably, and the packmap read between the two head reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Base {
    head: Hash,
    packmap: Hash,
}

/// The base search of one push: the remote's branch tips by their tracking
/// refs, a memo of where earlier searches led, and the stable read of each
/// candidate.
struct BaseSearch {
    /// Each tracked tip this store holds, and the branches at it.
    candidates: HashMap<Hash, Vec<String>>,
    /// Candidates whose stable read gave no base.
    excluded: HashSet<Hash>,
    /// A commit, and a candidate whose head serves as its base: one an
    /// earlier search reached below it, or, once seeded, one whose history
    /// holds it. `None` when no candidate serves it.
    memo: HashMap<Hash, Option<Hash>>,
    /// Whether the ancestries of the usable candidates are in the memo.
    seeded: bool,
    /// How many times the memo was seeded: at most
    /// [`PACKMAP_CAS_ATTEMPTS`] per push.
    seeds: u32,
    /// The stable read of each candidate, once per push.
    reads: HashMap<Hash, Option<Base>>,
    budget: usize,
}

impl BaseSearch {
    fn new(
        layout: &RepoLayout,
        store: &ObjectStore,
        remote: &str,
        budget: usize,
    ) -> Result<Self, PushError> {
        let mut candidates = HashMap::new();
        for tracked in refs::list_remote_refs(layout, remote)? {
            if let Some(tip) = tracked.hash
                && store.contains(&tip)
                && refs::check_pushable_branch(&tracked.name).is_ok()
            {
                candidates
                    .entry(tip)
                    .or_insert_with(Vec::new)
                    .push(tracked.name);
            }
        }
        Ok(Self {
            candidates,
            excluded: HashSet::new(),
            memo: HashMap::new(),
            seeded: false,
            seeds: 0,
            reads: HashMap::new(),
            budget,
        })
    }

    fn usable(&self, id: &Hash) -> bool {
        self.candidates.contains_key(id) && !self.excluded.contains(id)
    }

    /// The base of a tag on `target`: the first candidate a breadth-first
    /// walk of `target`'s ancestry meets whose stable read holds, or `None`.
    /// A tag on the history of a pushed branch, below its tip, would meet
    /// only a tip below it that way, or none: unless `target` is itself a
    /// candidate, the candidates' own ancestries are added to the memo first,
    /// once per push, so the walk stops at the first commit a branch holds.
    /// A candidate whose stable read gives no base is excluded, and the
    /// commits seeded for it are seeded again from the other candidates, so a
    /// branch that also holds them is tried next. Each walk visits at most
    /// `budget` commits the memo does not answer, and the memo is seeded at
    /// most [`PACKMAP_CAS_ATTEMPTS`] times per push.
    fn base_of(
        &mut self,
        tx: &PushContext<'_>,
        store: &ObjectStore,
        target: Hash,
    ) -> Result<Option<Base>, PushError> {
        if !self.seeded && !self.usable(&target) {
            self.seed(store)?;
        }
        loop {
            let mut budget = self.budget;
            while let Some(candidate) = self.nearest(store, target, &mut budget)? {
                if let Some(base) = self.stable_read(tx, store, candidate)? {
                    return Ok(Some(base));
                }
                self.exclude(candidate);
            }
            if self.seeded || self.seeds == PACKMAP_CAS_ATTEMPTS {
                return Ok(None);
            }
            self.seed(store)?;
        }
    }

    /// Pass over `candidate` from now on, and forget what the memo credits
    /// to it; the memo then needs seeding again when it credited any.
    fn exclude(&mut self, candidate: Hash) {
        self.excluded.insert(candidate);
        let before = self.memo.len();
        self.memo.retain(|_, served| *served != Some(candidate));
        if self.memo.len() != before {
            self.seeded = false;
        }
    }

    /// Add to the memo the commits the usable candidates reach, each with
    /// the nearest candidate above it, by one breadth-first walk from all of
    /// them of at most `budget` commits. Answers that no candidate serves a
    /// commit are dropped: a seeded commit may lie below them.
    fn seed(&mut self, store: &ObjectStore) -> Result<(), PushError> {
        self.seeded = true;
        self.seeds += 1;
        self.memo.retain(|_, candidate| candidate.is_some());
        if self.memo.len().saturating_add(self.budget) > MAX_REACHABLE {
            self.memo.clear();
        }
        let mut tips: Vec<Hash> = self
            .candidates
            .keys()
            .filter(|tip| !self.excluded.contains(*tip))
            .copied()
            .collect();
        tips.sort_unstable();
        let mut seen: HashSet<Hash> = tips.iter().copied().collect();
        let mut queue: VecDeque<(Hash, Hash)> = tips.iter().map(|tip| (*tip, *tip)).collect();
        let mut visited = 0usize;
        while let Some((id, candidate)) = queue.pop_front() {
            visited += 1;
            if visited > self.budget {
                break;
            }
            self.memo.insert(id, Some(candidate));
            for parent in parents(store, &id)? {
                if seen.insert(parent) {
                    queue.push_back((parent, candidate));
                }
            }
        }
        Ok(())
    }

    /// The nearest usable candidate that serves `start`, by a breadth-first
    /// walk that visits at most `budget` commits the memo does not answer,
    /// and takes them from `budget`.
    fn nearest(
        &mut self,
        store: &ObjectStore,
        start: Hash,
        budget: &mut usize,
    ) -> Result<Option<Hash>, PushError> {
        if self.candidates.len() == self.excluded.len() {
            return Ok(None);
        }
        // Each visited commit and the commit the walk reached it from.
        let mut from: HashMap<Hash, Option<Hash>> = HashMap::from([(start, None)]);
        let mut queue = VecDeque::from([start]);
        let mut found = None;
        while let Some(id) = queue.pop_front() {
            if self.usable(&id) {
                found = Some((id, id));
                break;
            }
            match self.memo.get(&id) {
                Some(Some(candidate)) if self.usable(candidate) => {
                    found = Some((id, *candidate));
                    break;
                }
                Some(None) => continue,
                _ => {}
            }
            if *budget == 0 {
                return Ok(None);
            }
            *budget -= 1;
            for parent in parents(store, &id)? {
                if let std::collections::hash_map::Entry::Vacant(slot) = from.entry(parent) {
                    slot.insert(Some(id));
                    queue.push_back(parent);
                }
            }
        }
        if self.memo.len().saturating_add(from.len()) > MAX_REACHABLE {
            self.memo.clear();
        }
        // The walk was whole: nothing it visited reaches a candidate.
        let Some((mut at, candidate)) = found else {
            self.memo.extend(from.into_keys().map(|id| (id, None)));
            return Ok(None);
        };
        // Every commit on the path from `start` to where the walk met the
        // candidate reaches it.
        loop {
            self.memo.insert(at, Some(candidate));
            match from.get(&at).copied().flatten() {
                Some(next) => at = next,
                None => break,
            }
        }
        Ok(Some(candidate))
    }

    /// Read the candidate's branch head, its packmap, then the head again.
    /// When both head reads agree on a head this store holds, that head and
    /// the packmap are the base: SPEC-TRANSPORT §7.2 makes a packmap read
    /// after a head rebuild that head. A head that moved is read again, up to
    /// [`PACKMAP_CAS_ATTEMPTS`] times.
    fn stable_read(
        &mut self,
        tx: &PushContext<'_>,
        store: &ObjectStore,
        candidate: Hash,
    ) -> Result<Option<Base>, PushError> {
        if let Some(read) = self.reads.get(&candidate) {
            return Ok(*read);
        }
        let mut base = None;
        for branch in &self.candidates[&candidate] {
            base = stable_read_branch(tx, store, branch)?;
            if base.is_some() {
                break;
            }
        }
        self.reads.insert(candidate, base);
        Ok(base)
    }
}

/// The stable read of one branch: its head, its packmap, then its head
/// again, up to [`PACKMAP_CAS_ATTEMPTS`] times.
fn stable_read_branch(
    tx: &PushContext<'_>,
    store: &ObjectStore,
    branch: &str,
) -> Result<Option<Base>, PushError> {
    let head_ref = format!("{}{branch}", refs::BRANCH_REF_PREFIX);
    let map_ref = packmap_ref(branch);
    let read = |name: &str| {
        tx.read_ref(name)
            .map_err(|error| repository_operation_error(tx, error))
    };
    for _ in 0..PACKMAP_CAS_ATTEMPTS {
        let first = read(&head_ref)?;
        let packmap = read(&map_ref)?;
        if read(&head_ref)? != first {
            continue;
        }
        return Ok(match (first, packmap) {
            (Some(head), Some(packmap)) if store.contains(&head) => Some(Base { head, packmap }),
            _ => None,
        });
    }
    Ok(None)
}

/// The parents of a commit or remix, or none for anything else and for an
/// object this store lacks.
fn parents(store: &ObjectStore, id: &Hash) -> Result<Vec<Hash>, PushError> {
    match store.object_type(id) {
        Ok(ObjectType::Commit | ObjectType::Remix) => {}
        Ok(_) | Err(StoreError::ObjectNotFound(_)) => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    }
    Ok(match store.read_object(id)? {
        Object::Commit(commit) => commit.parents,
        Object::Remix(remix) => remix.parents,
        _ => Vec::new(),
    })
}

/// `id` with its annotated tags peeled, as the planner peels them.
fn peel(store: &ObjectStore, id: Hash) -> Result<Hash, PushError> {
    Ok(kit_core::transfer::peeled_tip(store, id)?)
}

/// The tags `selection` names, sorted by name.
fn select(layout: &RepoLayout, selection: &TagSelection) -> Result<Vec<Local>, PushError> {
    let mut locals: Vec<Local> = match selection {
        TagSelection::All => refs::list_tags(layout)?
            .into_iter()
            .filter_map(|r| {
                Some(Local {
                    value: r.hash?,
                    name: r.name,
                })
            })
            .collect(),
        TagSelection::Named(names) => names
            .iter()
            .map(|name| {
                let value = refs::read_tag(layout, name)?
                    .ok_or_else(|| PushError::NoSuchTag(name.clone()))?;
                Ok(Local {
                    name: name.clone(),
                    value,
                })
            })
            .collect::<Result<_, PushError>>()?,
    };
    locals.sort_by(|a, b| a.name.cmp(&b.name));
    locals.dedup_by(|a, b| a.name == b.name);
    Ok(locals)
}

/// Why the push refuses `local` before it reads the remote: a name whose
/// tag map ref is not valid (W3), an annotated tag named otherwise (T5), and
/// an unsigned annotated tag.
fn local_refusal(
    store: &ObjectStore,
    local: &Local,
) -> Result<Option<TagPushRejection>, PushError> {
    if let Err(error) = refs::check_pushable_tag(&local.name) {
        return Ok(Some(TagPushRejection::NotPushable(error.to_string())));
    }
    match store.object_type(&local.value) {
        Ok(ObjectType::Tag) => {}
        Ok(_) => return Ok(None),
        Err(StoreError::ObjectNotFound(_)) => {
            return Ok(Some(TagPushRejection::NotPushable(format!(
                "its object {} is not in this repository",
                to_hex(&local.value)
            ))));
        }
        Err(error) => return Err(error.into()),
    }
    let Object::Tag(tag) = store.read_object(&local.value)? else {
        return Ok(None);
    };
    if tag.name != local.name.as_bytes() {
        return Ok(Some(TagPushRejection::NameMismatch {
            object_name: String::from_utf8_lossy(&tag.name).into_owned(),
        }));
    }
    if tag.signature == [0; 64] {
        return Ok(Some(TagPushRejection::Unsigned {
            tag: local.name.clone(),
        }));
    }
    let target = peel(store, local.value)?;
    if !store.contains(&target) {
        return Ok(Some(TagPushRejection::NotPushable(format!(
            "the object {} it names is not in this repository",
            to_hex(&target)
        ))));
    }
    Ok(None)
}

/// How one tag's two-ref write ended.
enum Advance {
    /// The remote tag holds the pushed value. `members` when its tag map
    /// holds this write's node, which a committed advance makes members of
    /// the repository with its packs; not when another push placed the tag.
    Landed { members: bool },
    /// A condition failed; the tag is read again and placed anew.
    Conflict,
    /// The remote refused the write: `scope` when it refused this caller's
    /// access to the ref, as a grant whose scopes miss it does.
    Refused { message: String, scope: bool },
    /// The remote refused the upload the write carried: its tickets
    /// expired, or its packs are not in the repository. It may be sent
    /// again once.
    Stale(String),
    /// The remote lacks a delta base the upload used. It may be planned
    /// again once, self-contained (SPEC-TRANSPORT-CONNECT §7.6).
    LostBase(String),
}

/// Whether a failed write is the remote's refusal of this write, which
/// refuses the tag, rather than a failure of the transport, which fails the
/// push.
fn refusal(error: &SourceError) -> bool {
    match error {
        SourceError::AccessDenied | SourceError::InvalidRef(_) | SourceError::Vetoed(_) => true,
        SourceError::Remote(remote) => matches!(
            remote.code.as_str(),
            "invalid_argument" | "permission_denied" | "failed_precondition"
        ),
        _ => false,
    }
}

/// Whether the remote refused this caller's access to the ref, as a grant
/// whose scopes do not match it does: that refuses the one tag.
fn scope_refusal(error: &SourceError) -> bool {
    match error {
        SourceError::AccessDenied => true,
        SourceError::Remote(remote) => remote.code == "permission_denied",
        _ => false,
    }
}

/// The remote's refusal inside a failed upload, as [`refusal`] reads it, and
/// whether it is a [`scope_refusal`].
fn refused_upload(error: &PushError) -> Option<(String, bool)> {
    match error {
        PushError::Sync(SyncError::Source(source)) if refusal(source) => {
            Some((source.to_string(), scope_refusal(source)))
        }
        _ => None,
    }
}

/// The state and the knobs one tag push shares.
struct TagPush<'a, 'b> {
    tx: &'a PushContext<'b>,
    store: &'a ObjectStore,
    limits: UploadLimits,
    payload_cap: u64,
    results: BTreeMap<String, TagPushOutcome>,
    /// Tags whose write lost a race this round.
    retry: Vec<Local>,
    /// Uploads of a ticketed group again after its ticket-carrying tag lost
    /// a race, across the push: at most [`PACKMAP_CAS_ATTEMPTS`].
    reuploads: u32,
}

impl TagPush<'_, '_> {
    fn finish(&mut self, local: &Local, outcome: TagPushOutcome) {
        self.results.insert(local.name.clone(), outcome);
    }

    fn reject(&mut self, local: &Local, rejection: TagPushRejection) {
        self.finish(local, TagPushOutcome::Rejected(rejection));
    }

    /// Whether the remote issues upload tickets, which bind an upload to the
    /// head ref it names.
    fn ticketed(&self) -> bool {
        self.limits.data_packs_per_advance.is_some()
    }

    /// Whether `plan` fits one ticketed advance: its packs within the
    /// ticket budget, by the estimate and then the exact dry seal, and its
    /// objects within what the server inspects.
    fn fits_one_advance(&self, plan: &PackPlan) -> Result<bool, PushError> {
        let Some(budget) = self.limits.data_packs_per_advance else {
            return Ok(true);
        };
        if self
            .tx
            .inspection_max_objects()
            .is_some_and(|max| plan.object_count() as u64 > max)
        {
            return Ok(false);
        }
        if estimate_pack_sizes(
            self.store,
            plan,
            self.payload_cap,
            self.limits.max_pack_bytes,
        )?
        .len()
            <= budget
        {
            return Ok(true);
        }
        match dry_seal(
            self.store,
            plan.clone(),
            self.payload_cap,
            self.limits,
            self.tx.observer,
        ) {
            Ok(_) => Ok(true),
            Err(PushError::PushTooLarge { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Upload `plan`'s packs under `head_ref` and a node that lists them
    /// after `chain`. Returns the node's key and the keys the advance commits.
    fn upload(
        &self,
        head_ref: &str,
        plan: PackPlan,
        chain: ChainState,
    ) -> Result<(Hash, Vec<PackKey>), PushError> {
        let packs = build_and_upload_packs(
            self.tx,
            head_ref,
            self.store,
            plan,
            self.payload_cap,
            self.limits,
        )?;
        let node = plan_advance(chain, &packs, None)
            .map_err(|error| match error {
                PlanError::Packlist(error) => PushError::from(error),
                PlanError::NodeTooLarge => unreachable!("no node-size limit configured"),
            })?
            .ok_or_else(|| PushError::from(SourceError::ProtocolError))?;
        self.tx
            .upload_blob(&node.bytes, &PackKey::from_hash(node.key), head_ref)
            .map_err(|error| repository_operation_error(self.tx, error))?;
        let keys = packs
            .into_iter()
            .chain(std::iter::once(node.key))
            .map(PackKey::from_hash)
            .collect();
        Ok((node.key, keys))
    }

    /// Write `local`'s tag map and tag together: the tag map first on a
    /// transport that orders the two writes.
    fn advance(
        &self,
        local: &Local,
        row: Row,
        map: Hash,
        keys: &[PackKey],
    ) -> Result<Advance, PushError> {
        let tag_ref = local.tag_ref();
        let (tag_condition, map_condition) = row.conditions(local.value);
        let outcome = match self.tx.advance_refs_committing(
            &tag_ref,
            tag_condition,
            &local.value,
            &local.map_ref(),
            map_condition,
            &map,
            keys,
        ) {
            Ok(outcome) => outcome,
            Err(error) if refusal(&error) => {
                return Ok(Advance::Refused {
                    message: error.to_string(),
                    scope: scope_refusal(&error),
                });
            }
            Err(error) => return Err(repository_operation_error(self.tx, error)),
        };
        let refused = match outcome {
            CommitOutcome::Advanced(AdvanceOutcome::Committed) => {
                return Ok(Advance::Landed { members: true });
            }
            // The tag map's condition failed: this write may have landed
            // already, through the retry ladder, or another push may have
            // placed the same value.
            CommitOutcome::Advanced(AdvanceOutcome::PackmapConflict) => {
                let state = self.read_state(local)?;
                if state.tag == Some(local.value) {
                    return Ok(Advance::Landed {
                        members: state.map == Some(map),
                    });
                }
                if state.map == Some(map) && state.tag.is_none() {
                    return self.place_tag(local, tag_condition);
                }
                return Ok(Advance::Conflict);
            }
            CommitOutcome::Advanced(AdvanceOutcome::HeadConflict) => None,
            CommitOutcome::TicketRejected => Some(PushError::TicketRejected),
            CommitOutcome::PacklistNotInRepository => Some(PushError::PacklistNotInRepository),
            CommitOutcome::DeltaBaseUnavailable => Some(PushError::DeltaBaseUnavailable),
            _ => return Err(PushError::from(SourceError::InvalidResponse)),
        };
        // The retry ladder may have re-sent a write that landed, or another
        // push placed the same value.
        let state = self.read_state(local)?;
        if state.tag == Some(local.value) {
            return Ok(Advance::Landed {
                members: state.map == Some(map),
            });
        }
        Ok(match refused {
            None => Advance::Conflict,
            Some(error @ (PushError::TicketRejected | PushError::PacklistNotInRepository)) => {
                Advance::Stale(error.to_string())
            }
            Some(error) => Advance::LostBase(error.to_string()),
        })
    }

    /// Write only the tag, when its tag map already holds the node this push
    /// wrote, or one equal to it.
    fn place_tag(&self, local: &Local, condition: RefWriteCondition) -> Result<Advance, PushError> {
        match self
            .tx
            .update_ref(&local.tag_ref(), condition, &local.value)
        {
            Ok(()) => Ok(Advance::Landed { members: true }),
            Err(SourceError::RefConflict) => Ok(Advance::Conflict),
            Err(error) if refusal(&error) => Ok(Advance::Refused {
                message: error.to_string(),
                scope: scope_refusal(&error),
            }),
            Err(error) => Err(repository_operation_error(self.tx, error)),
        }
    }

    /// Move only the tag, when its tag map already rebuilds the new value.
    fn move_tag(&self, local: &Local, old: Hash) -> Result<Advance, PushError> {
        match self.tx.update_ref(
            &local.tag_ref(),
            RefWriteCondition::Match(old),
            &local.value,
        ) {
            Ok(()) => Ok(Advance::Landed { members: true }),
            Err(SourceError::RefConflict) => {
                if self.read(&local.tag_ref())? == Some(local.value) {
                    Ok(Advance::Landed { members: false })
                } else {
                    Ok(Advance::Conflict)
                }
            }
            Err(error) if refusal(&error) => Ok(Advance::Refused {
                message: error.to_string(),
                scope: scope_refusal(&error),
            }),
            Err(error) => Err(repository_operation_error(self.tx, error)),
        }
    }

    fn read(&self, name: &str) -> Result<Option<Hash>, PushError> {
        self.tx
            .read_ref(name)
            .map_err(|error| repository_operation_error(self.tx, error))
    }

    /// A strong read of the tag, then its tag map.
    fn read_state(&self, local: &Local) -> Result<RemoteState, PushError> {
        let tag = self.read(&local.tag_ref())?;
        let map = self.read(&local.map_ref())?;
        Ok(RemoteState { tag, map })
    }

    fn record(&mut self, local: &Local, row: Row, advance: Advance) {
        match advance {
            Advance::Landed { .. } => self.finish(local, row.landed(local.value)),
            Advance::Conflict => self.retry.push(local.clone()),
            Advance::Refused { message, .. }
            | Advance::Stale(message)
            | Advance::LostBase(message) => {
                self.reject(local, TagPushRejection::Refused(message));
            }
        }
    }

    /// Refuse `local` and every member after it for `rejection`.
    fn reject_rest(
        &mut self,
        local: &Local,
        members: &mut VecDeque<(Local, Row)>,
        rejection: &TagPushRejection,
    ) {
        self.reject(local, rejection.clone());
        while let Some((local, _)) = members.pop_front() {
            self.reject(&local, rejection.clone());
        }
    }

    /// The tag map value and keys of a group planned as `plan` on `graft`:
    /// the branch's own node when nothing is new, or an upload under
    /// `local`'s tag ref.
    fn group_chain(
        &self,
        local: &Local,
        plan: &PackPlan,
        graft: Option<Base>,
    ) -> Result<(Hash, Vec<PackKey>), PushError> {
        match graft {
            Some(base) if plan.is_empty() => Ok((base.packmap, Vec::new())),
            _ => {
                let state = graft.map_or(ChainState::Missing, |base| ChainState::Graft {
                    tail: base.packmap,
                });
                self.upload(&local.tag_ref(), plan.clone(), state)
            }
        }
    }

    /// Plan, upload and write one group: the creates, repairs and forced
    /// updates without a tag map that share `base`.
    fn push_group(
        &mut self,
        base: Option<Base>,
        members: Vec<(Local, Row)>,
    ) -> Result<(), PushError> {
        let mut tips: Vec<Hash> = members.iter().map(|(local, _)| local.value).collect();
        // A forced update's new tag map must still rebuild the value a reader
        // may have read first.
        tips.extend(members.iter().filter_map(|(_, row)| match row {
            Row::ForcedFresh { old } => Some(*old),
            _ => None,
        }));
        tips.sort_unstable();
        tips.dedup();
        let mut plan = self
            .tx
            .deltas
            .plan_tips(self.store, &tips, base.map(|base| base.head))?;
        if !self.fits_one_advance(&plan)? {
            for (local, _) in &members {
                self.reject(local, TagPushRejection::TooLarge);
            }
            return Ok(());
        }
        let ticketed = self.ticketed();
        // The tag map value and the keys its advance commits, once uploaded.
        let mut chain: Option<(Hash, Vec<PackKey>)> = None;
        // Whether an advance of this group committed: its packs and node are
        // then in the repository.
        let mut landed = false;
        // Whether the last ticket-carrying advance lost a race, so that the
        // next upload counts against the push's bound.
        let mut lost = false;
        // Whether expired tickets were already uploaded again once.
        let mut renewed = false;
        // The branch the group grafts on; none once it is planned
        // self-contained.
        let mut graft = base;
        let mut members = VecDeque::from(members);
        while let Some((local, row)) = members.pop_front() {
            if self.tx.observer.cancelled() {
                return Err(SyncError::Interrupted.into());
            }
            // A ticket binds an upload to its head ref, so until an advance
            // commits, each ticket-carrying tag uploads the group again.
            if chain.is_none() || (ticketed && !landed) {
                let uploads = graft.is_none() || !plan.is_empty();
                if lost && uploads {
                    if self.reuploads == PACKMAP_CAS_ATTEMPTS {
                        self.reject(&local, TagPushRejection::Contended);
                        continue;
                    }
                    self.reuploads += 1;
                }
                lost = false;
                match self.group_chain(&local, &plan, graft) {
                    Ok(uploaded) => chain = Some(uploaded),
                    Err(error) => match refused_upload(&error) {
                        // A ticket names this tag's ref, which the remote may
                        // refuse to this caller alone: the next tag uploads
                        // the group again.
                        Some((message, true)) if ticketed => {
                            self.reject(&local, TagPushRejection::Refused(message));
                            continue;
                        }
                        Some((message, _)) => {
                            let refused = TagPushRejection::Refused(message);
                            self.reject_rest(&local, &mut members, &refused);
                            return Ok(());
                        }
                        None => return Err(error),
                    },
                }
            }
            let (map, keys) = chain.as_ref().expect("the group was uploaded");
            let advance = self.advance(&local, row, *map, keys)?;
            if ticketed && !landed {
                match &advance {
                    // Only this group's own commit makes its packs members;
                    // a value another push placed does not.
                    Advance::Landed { members } => {
                        landed = *members;
                        lost = !*members;
                    }
                    Advance::Conflict => lost = true,
                    // A refusal of this caller's access to the tag refuses
                    // that tag; the next one uploads again.
                    Advance::Refused { scope: true, .. } => {}
                    // Expired tickets: the same tag uploads again, once.
                    Advance::Stale(_) if !renewed => {
                        renewed = true;
                        members.push_front((local, row));
                        continue;
                    }
                    // A lost delta base: the group is planned again once,
                    // self-contained, and the same tag uploads it.
                    Advance::LostBase(_) if !renewed => {
                        renewed = true;
                        graft = None;
                        plan = self.tx.deltas.plan_tips(self.store, &tips, None)?;
                        if !self.fits_one_advance(&plan)? {
                            self.reject_rest(&local, &mut members, &TagPushRejection::TooLarge);
                            return Ok(());
                        }
                        members.push_front((local, row));
                        continue;
                    }
                    // Any other refusal of the ticket-carrying advance
                    // refuses the whole group: its packs are not members.
                    Advance::Refused { message, .. }
                    | Advance::Stale(message)
                    | Advance::LostBase(message) => {
                        let refused = TagPushRejection::Refused(message.clone());
                        self.reject_rest(&local, &mut members, &refused);
                        return Ok(());
                    }
                }
            }
            self.record(&local, row, advance);
        }
        Ok(())
    }

    /// Append to one tag's own tag map: a leftover without its tag, or a
    /// forced update over a tag map.
    fn push_append(&mut self, local: &Local, row: Row) -> Result<(), PushError> {
        let (old, map) = match row {
            Row::Leftover { map } => (None, map),
            Row::ForcedAppend { old, map } => (Some(old), map),
            _ => unreachable!("only appends are pushed alone"),
        };
        // Plan against the old value only when its whole closure is here;
        // otherwise send the new value's whole closure.
        let mut base = match old {
            Some(old) if store_holds_closure(self.store, old)? => Some(peel(self.store, old)?),
            _ => None,
        };
        let plan = self.tx.deltas.plan_tips(self.store, &[local.value], base)?;
        if plan.is_empty()
            && let Some(old) = old
        {
            // The tag map rebuilds every value the tag held, and the old
            // value's history holds all of the new one's.
            let advance = self.move_tag(local, old)?;
            self.record(local, row, advance);
            return Ok(());
        }
        let mut plan = Some(plan);
        // A refused upload goes again once: as it was, or self-contained
        // after a lost delta base.
        for again in [false, true] {
            let plan = match plan.take() {
                Some(plan) => plan,
                None => self.tx.deltas.plan_tips(self.store, &[local.value], base)?,
            };
            if !self.fits_one_advance(&plan)? {
                self.reject(local, TagPushRejection::TooLarge);
                return Ok(());
            }
            let uploaded = self.upload(
                &local.tag_ref(),
                plan,
                ChainState::Append {
                    head: map,
                    packs: HashSet::new(),
                },
            );
            let (node, keys) = match uploaded {
                Ok(uploaded) => uploaded,
                Err(error) => match refused_upload(&error) {
                    Some((message, _)) => {
                        self.reject(local, TagPushRejection::Refused(message));
                        return Ok(());
                    }
                    None => return Err(error),
                },
            };
            match self.advance(local, row, node, &keys)? {
                Advance::Stale(_) if !again => {}
                Advance::LostBase(_) if !again => base = None,
                advance => {
                    self.record(local, row, advance);
                    return Ok(());
                }
            }
        }
        unreachable!("the second attempt records its outcome")
    }
}

/// Whether this store holds `id` and its whole closure. A closure too large
/// to check counts as not held.
fn store_holds_closure(store: &ObjectStore, id: Hash) -> Result<bool, PushError> {
    if !store.contains(&id) {
        return Ok(false);
    }
    match check_closure_present(store, [&id]) {
        Ok(truncated) => Ok(!truncated),
        Err(StoreError::ObjectNotFound(_) | StoreError::Decode(_)) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Push the tags `selection` names to the remote of `tx`, and return one
/// result per tag, sorted by name.
pub(super) fn push_tags(
    layout: &RepoLayout,
    store: &ObjectStore,
    tx: &PushContext<'_>,
    remote_name: &str,
    selection: &TagSelection,
    force: bool,
    payload_cap: u64,
) -> Result<Vec<TagPushResult>, PushError> {
    push_tags_with(
        layout,
        store,
        tx,
        remote_name,
        selection,
        force,
        payload_cap,
        MAX_BASE_WALK_COMMITS,
    )
}

/// [`push_tags`] with the base search's budget, so a test can exhaust it.
#[allow(clippy::too_many_arguments)]
fn push_tags_with(
    layout: &RepoLayout,
    store: &ObjectStore,
    tx: &PushContext<'_>,
    remote_name: &str,
    selection: &TagSelection,
    force: bool,
    payload_cap: u64,
    base_budget: usize,
) -> Result<Vec<TagPushResult>, PushError> {
    let limits = tx.upload_limits();
    let mut push = TagPush {
        tx,
        store,
        limits,
        payload_cap: super::effective_payload_cap(payload_cap, limits.max_pack_bytes)?,
        results: BTreeMap::new(),
        retry: Vec::new(),
        reuploads: 0,
    };
    let mut work = Vec::new();
    for local in select(layout, selection)? {
        match local_refusal(store, &local)? {
            Some(rejection) => push.reject(&local, rejection),
            None => work.push(local),
        }
    }
    let listing_kind = tx.ref_listing();
    let mut listing = if work.is_empty() {
        None
    } else if matches!(selection, TagSelection::All) || listing_kind == RefListing::OneFrame {
        Some(Listing::read(tx)?)
    } else {
        None
    };
    let mut bases = BaseSearch::new(layout, store, remote_name, base_budget)?;
    let mut round = 0;
    while !work.is_empty() {
        if tx.observer.cancelled() {
            return Err(SyncError::Interrupted.into());
        }
        if round == PACKMAP_CAS_ATTEMPTS {
            for local in &work {
                push.reject(local, TagPushRejection::Contended);
            }
            break;
        }
        round += 1;
        let mut groups: BTreeMap<Option<Base>, Vec<(Local, Row)>> = BTreeMap::new();
        let mut appends = Vec::new();
        for local in std::mem::take(&mut work) {
            // `--tags` places its tags from the listing on the first round.
            // A named tag, a tag read again after a lost race, a tag listed
            // without its tag map, and a tag map on a listing that may lag
            // are read strongly.
            let state = match &listing {
                Some(listing) if round == 1 && matches!(selection, TagSelection::All) => {
                    let listed = listing.state(&local.name);
                    if (listed.tag.is_some() && listed.map.is_none())
                        || (listing_kind == RefListing::Eventual && listed.map.is_some())
                    {
                        push.read_state(&local)?
                    } else {
                        listed
                    }
                }
                _ => push.read_state(&local)?,
            };
            let row = match classify(local.value, state, force) {
                Ok(row) => row,
                Err(outcome) => {
                    push.finish(&local, outcome);
                    continue;
                }
            };
            if listing_kind == RefListing::OneFrame
                && let Some(listing) = &mut listing
                && !listing.admit(&local.name, row)
            {
                push.reject(&local, TagPushRejection::TooManyTags);
                continue;
            }
            if let Row::ForcedFresh { old } = row
                && !store_holds_closure(store, old)?
            {
                push.reject(&local, TagPushRejection::OldValueNotLocal { remote: old });
                continue;
            }
            if row.creates_map() {
                let base = bases.base_of(tx, store, peel(store, local.value)?)?;
                groups.entry(base).or_default().push((local, row));
            } else {
                appends.push((local, row));
            }
        }
        for (base, members) in groups {
            push.push_group(base, members)?;
        }
        for (local, row) in appends {
            if tx.observer.cancelled() {
                return Err(SyncError::Interrupted.into());
            }
            push.push_append(&local, row)?;
        }
        work = std::mem::take(&mut push.retry);
    }
    Ok(push
        .results
        .into_iter()
        .map(|(name, outcome)| TagPushResult { name, outcome })
        .collect())
}

#[cfg(test)]
mod tests;
