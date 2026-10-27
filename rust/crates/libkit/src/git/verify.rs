//! Correspondence and provenance verification of the bridge state.
//!
//! [`verify`] re-checks the staging repository of a state directory against
//! the local object store. Objects that the bridge translated shallow-verify
//! (SPEC-GIT-BRIDGE §10) and must reconstruct to their mapped kit twin.
//! Imported objects must have retained raw bytes that hash to their sha1, and
//! a twin that the pinned importer key signed (SPEC-GIT-IMPORT §4). With
//! `fork_audit`, every tree and blob that a bridge commit names must also
//! re-derive from its kit twin and reproduce the exact sha1
//! (SPEC-GIT-BRIDGE §14.3).

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use kit_core::Hash;
use kit_core::object::Object;
use kit_core::refs::ATTESTATIONS_REF;
use kit_core::store::ObjectStore;
use kit_git_bridge::gitobj::{GitObject, GitType, Sha1Id, sha1_hex};
use kit_git_bridge::gitsrc::{CatFileBatch, GitObjKind};
use kit_git_bridge::verify::ShallowVerdict;
use kit_git_bridge::{
    gitparse, import as bridge_import, map, reconstruct, verify as bridge_verify,
};

use super::state::{read_stamp, resolve};
use super::{Class, Error, open_repo, plain, step};

mod provenance;

pub use provenance::{ClaimBinding, claim_accepts};

/// What to verify.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The remote name of the state directory. With none, the only state.
    pub remote_name: Option<&'a str>,
    /// Whether to re-derive the content of every bridge commit.
    pub fork_audit: bool,
    /// The full names of the refs to verify. With none, every recorded ref.
    pub refs: &'a [String],
}

/// A ref that the verification walked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The ref name.
    pub ref_name: String,
    /// `exported` or `imported`.
    pub origin: &'static str,
    /// The git id of the tip.
    pub tip: Sha1Id,
}

/// The result of a verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The refs that were walked, in order.
    pub verified: Vec<Verified>,
    /// One line for each object that failed.
    pub failures: Vec<String>,
    /// The number of objects that the bridge translated.
    pub bridge: usize,
    /// The number of translated objects with no kit signature.
    pub unsigned: usize,
    /// The number of imported objects.
    pub imported: usize,
    /// The number of content objects that were re-derived.
    pub derived: usize,
    fork_audit: bool,
}

impl Report {
    /// The counts, as one line.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut summary = format!(
            "{} bridge-translated ({} unsigned), {} imported-vouched",
            self.bridge, self.unsigned, self.imported
        );
        if self.fork_audit {
            let _ = write!(summary, ", {} content-derived", self.derived);
        }
        summary
    }
}

#[derive(Default)]
struct Counts {
    bridge: usize,
    unsigned: usize,
    imported: usize,
    derived: usize,
}

struct Audit<'a> {
    raw_dir: PathBuf,
    batch: CatFileBatch,
    store: &'a ObjectStore,
    /// sha1 → kit twin (both directions of the unified map).
    inv: HashMap<Sha1Id, Hash>,
    pinned: Option<[u8; 32]>,
    deep: bool,
    failures: Vec<String>,
    counts: Counts,
    seen: HashSet<Sha1Id>,
}

impl Audit<'_> {
    fn fail(&mut self, id: &Sha1Id, why: &str) {
        self.failures.push(format!("{} {why}", sha1_hex(id)));
    }

    fn twin(&mut self, id: &Sha1Id) -> Option<Hash> {
        let t = self.inv.get(id).copied();
        if t.is_none() {
            self.fail(id, "no kit twin recorded in the map");
        }
        t
    }

    fn raw_path(&self, id: &Sha1Id) -> PathBuf {
        let hex = sha1_hex(id);
        self.raw_dir.join(&hex[..2]).join(&hex[2..])
    }

    /// Walk all commits reachable from `tip` in the staging repo,
    /// checking each (and, with `--fork-audit`, the content closure
    /// of every bridge commit).
    fn walk(&mut self, tip: &Sha1Id) {
        let mut stack = vec![*tip];
        while let Some(id) = stack.pop() {
            if self.seen.len() >= kit_core::ops::graph::MAX_REACHABLE {
                self.fail(&id, "audit closure exceeds the traversal limit");
                return;
            }
            if !self.seen.insert(id) {
                continue;
            }
            let (kind, body) = match self.batch.read(&id) {
                Ok(v) => v,
                Err(e) => {
                    self.fail(&id, &format!("unreadable in staging: {e}"));
                    continue;
                }
            };
            match kind {
                GitObjKind::Commit => {
                    let parsed = match gitparse::parse_commit(&body) {
                        Ok(p) => p,
                        Err(e) => {
                            self.fail(&id, &format!("unparsable commit: {e}"));
                            continue;
                        }
                    };
                    if self.raw_path(&id).exists() {
                        self.check_imported(&id, false, &body);
                        self.audit_object(&parsed.tree);
                    } else {
                        self.check_bridge_commit(&id, &body);
                        if self.deep {
                            self.audit_object(&parsed.tree);
                        }
                    }
                    for p in &parsed.parents {
                        stack.push(*p);
                    }
                }
                GitObjKind::Tag => {
                    if self.raw_path(&id).exists() {
                        self.check_imported(&id, true, &body);
                    } else {
                        self.check_bridge_tag(&id, &body);
                    }
                    if let Ok(t) = gitparse::parse_tag(&body) {
                        stack.push(t.object);
                    }
                }
                GitObjKind::Blob | GitObjKind::Tree => {
                    self.seen.remove(&id);
                    self.audit_object(&id);
                }
            }
        }
    }

    /// Check both the importer signature and the exact translation of the raw
    /// Git object. Cache lookup alone is never a correspondence proof.
    fn check_imported(&mut self, id: &Sha1Id, is_tag: bool, body: &[u8]) {
        let raw = read_retained(&self.raw_path(id));
        match raw {
            Ok(raw) => match GitObject::parse_raw(&raw) {
                Some(obj) if obj.id() == *id && obj.body == body => {}
                Some(_) => {
                    self.fail(
                        id,
                        "retained raw bytes hash to a DIFFERENT sha1 or differ from staging",
                    );
                    return;
                }
                None => {
                    self.fail(id, "retained raw bytes are not framed git bytes");
                    return;
                }
            },
            Err(e) => {
                self.fail(id, &format!("retained raw bytes unreadable: {e}"));
                return;
            }
        }
        let Some(twin) = self.twin(id) else { return };
        let Some(pin) = self.pinned else {
            self.fail(id, "imported object but no importer key pinned");
            return;
        };
        let expected = (|| {
            let resolve = |git_id: &Sha1Id| {
                self.inv.get(git_id).copied().ok_or_else(|| {
                    kit_git_bridge::BridgeError::Integrity("missing child correspondence".into())
                })
            };
            if is_tag {
                let parsed = gitparse::parse_tag(body)
                    .map_err(|e| kit_git_bridge::BridgeError::Integrity(e.to_string()))?;
                let target = resolve(&parsed.object)?;
                let kind = self
                    .store
                    .read_object(&target)
                    .map_err(|e| kit_git_bridge::BridgeError::Integrity(e.to_string()))?
                    .object_type();
                bridge_import::unsigned_tag(id, body, pin, target, Some(kind)).map(Object::Tag)
            } else {
                let parsed = gitparse::parse_commit(body)
                    .map_err(|e| kit_git_bridge::BridgeError::Integrity(e.to_string()))?;
                let tree = resolve(&parsed.tree)?;
                let parents = parsed
                    .parents
                    .iter()
                    .map(resolve)
                    .collect::<Result<Vec<_>, _>>()?;
                bridge_import::unsigned_commit(id, body, pin, tree, parents).map(Object::Commit)
            }
        })();
        let mut actual = match self.store.read_object(&twin) {
            Ok(o) => o,
            Err(e) => {
                self.fail(id, &format!("kit twin missing from store: {e}"));
                return;
            }
        };
        match &mut actual {
            Object::Commit(c) if !is_tag => {
                self.check_importer_sig(id, &c.signer, || kit_core::sign::verify_commit(c).is_ok());
                c.signature = [0; 64];
            }
            Object::Tag(t) if is_tag => {
                self.check_importer_sig(id, &t.signer, || kit_core::sign::verify_tag(t).is_ok());
                t.signature = [0; 64];
            }
            _ => self.fail(id, "kit twin has a different object kind"),
        }
        match expected {
            Ok(expected) if expected == actual => {}
            Ok(_) => self.fail(
                id,
                "signed twin is NOT the translation of the retained Git bytes",
            ),
            Err(e) => self.fail(id, &format!("cannot derive imported correspondence: {e}")),
        }
        self.counts.imported += 1;
    }

    fn check_importer_sig(&mut self, id: &Sha1Id, signer: &[u8; 32], ok: impl FnOnce() -> bool) {
        match self.pinned {
            Some(pin) if pin != *signer => {
                self.fail(id, "twin signer is NOT the pinned importer key");
            }
            None => self.fail(id, "imported object but no importer key pinned"),
            Some(_) => {
                if !ok() {
                    self.fail(id, "importer signature does not verify");
                }
            }
        }
    }

    /// §10 shallow verification + the twin/map correspondence.
    fn check_bridge_commit(&mut self, id: &Sha1Id, body: &[u8]) {
        let obj = GitObject {
            gtype: GitType::Commit,
            body: body.to_vec(),
        };
        self.check_bridge_obj(id, &obj, reconstruct::reconstruct_commit);
    }

    fn check_bridge_tag(&mut self, id: &Sha1Id, body: &[u8]) {
        let obj = GitObject {
            gtype: GitType::Tag,
            body: body.to_vec(),
        };
        self.check_bridge_obj(id, &obj, reconstruct::reconstruct_tag);
    }

    fn check_bridge_obj(
        &mut self,
        id: &Sha1Id,
        obj: &GitObject,
        rec: impl Fn(&[u8]) -> Result<reconstruct::Reconstructed, kit_git_bridge::BridgeError>,
    ) {
        match bridge_verify::shallow_verify(obj) {
            Ok(ShallowVerdict::Verified) => {}
            Ok(ShallowVerdict::Unsigned) => self.counts.unsigned += 1,
            Ok(ShallowVerdict::Failed) => self.fail(id, "embedded signature does NOT verify"),
            Err(e) => {
                self.fail(id, &format!("not bridge-shaped: {e}"));
                return;
            }
        }
        match rec(&obj.body) {
            Ok(r) => {
                if let Some(twin) = self.twin(id)
                    && r.hash != twin
                {
                    self.fail(id, "reconstructs to a hash OTHER than its mapped twin");
                }
                let edges_match = match &r.object {
                    Object::Commit(c) => gitparse::parse_commit(&obj.body).is_ok_and(|g| {
                        self.inv.get(&g.tree) == Some(&c.tree_hash)
                            && g.parents.len() == c.parents.len()
                            && g.parents
                                .iter()
                                .zip(&c.parents)
                                .all(|(g, m)| self.inv.get(g) == Some(m))
                    }),
                    Object::Tag(t) => gitparse::parse_tag(&obj.body)
                        .is_ok_and(|g| self.inv.get(&g.object) == Some(&t.target)),
                    _ => false,
                };
                if !edges_match {
                    self.fail(
                        id,
                        "Git tree/parent/target edges differ from the signed kit edges",
                    );
                }
                if let Err(e) = self.store.read_object(&r.hash) {
                    self.fail(id, &format!("reconstructed twin missing from store: {e}"));
                }
            }
            Err(e) => self.fail(id, &format!("reconstruction failed: {e}")),
        }
        self.counts.bridge += 1;
    }

    /// Validate content correspondences from Git bytes, including historic
    /// normalized modes. Traverse iteratively to bound stack use.
    fn audit_object(&mut self, id: &Sha1Id) {
        let mut pending = vec![(*id, 0usize)];
        while let Some((id, depth)) = pending.pop() {
            if depth > bridge_import::MAX_TREE_DEPTH
                || self.seen.len() >= kit_core::ops::graph::MAX_REACHABLE
            {
                self.fail(&id, "audit content exceeds the traversal limit");
                return;
            }
            if !self.seen.insert(id) {
                continue;
            }
            let Some(twin) = self.twin(&id) else { continue };
            let (kind, body) = match self.batch.read(&id) {
                Ok(v) => v,
                Err(e) => {
                    self.fail(&id, &e.to_string());
                    continue;
                }
            };
            let git = GitObject {
                gtype: kind.into(),
                body,
            };
            if git.id() != id {
                self.fail(&id, "staging content hash mismatch");
                continue;
            }
            let derived = match kind {
                GitObjKind::Blob => kit_core::worktree::hash_file_object(&git.body)
                    .map_err(|e| kit_git_bridge::BridgeError::Integrity(e.to_string())),
                GitObjKind::Tree => {
                    let result =
                        bridge_import::translate_tree_metadata(&id, &git.body, false, |child| {
                            let h = self.inv.get(child).copied().ok_or_else(|| {
                                kit_git_bridge::BridgeError::Integrity(
                                    "missing tree child mapping".into(),
                                )
                            })?;
                            let kind = self
                                .store
                                .read_object(&h)
                                .map_err(|e| kit_git_bridge::BridgeError::Integrity(e.to_string()))?
                                .object_type();
                            Ok((h, Some(kind)))
                        });
                    if let Ok(entries) = gitparse::parse_tree(&git.body) {
                        for entry in entries {
                            pending.push((entry.id, depth + 1));
                        }
                    }
                    result.and_then(|(tree, _)| {
                        Object::Tree(tree)
                            .id()
                            .map_err(|e| kit_git_bridge::BridgeError::Integrity(e.to_string()))
                    })
                }
                _ => Err(kit_git_bridge::BridgeError::Integrity(
                    "non-content Git object in tree".into(),
                )),
            };
            match derived {
                Ok(h) if h == twin => {
                    // Check the stored closure too: a manifest's identity alone
                    // cannot establish that its chunks are present.
                    if kind == GitObjKind::Blob {
                        match kit_core::worktree::read_blob(self.store, &twin) {
                            Ok(bytes) if bytes == git.body => {}
                            Ok(_) => self.fail(&id, "stored content differs from Git bytes"),
                            Err(e) => self.fail(&id, &e.to_string()),
                        }
                    } else if let Err(e) = self.store.read_object(&twin) {
                        self.fail(&id, &e.to_string());
                    }
                    self.counts.derived += 1;
                }
                Ok(_) => self.fail(&id, "content twin is NOT the translation of the Git bytes"),
                Err(e) => self.fail(&id, &e.to_string()),
            }
        }
    }
}

/// Verify the bridge state of the repository at `cwd`.
///
/// A broken object does not stop the walk. The report lists every failure.
///
/// # Errors
/// An error when `cwd` is not inside a kit repository, when the state does
/// not exist or has no staging repository, when a named ref is not recorded,
/// or when the recorded import version is not supported.
pub fn verify(cwd: &Path, request: &Request<'_>) -> Result<Report, Error> {
    let (layout, store) = open_repo(cwd)?;
    let (name, state) = resolve(&layout, request.remote_name)?;
    let staging = state.join("repo.git");
    if !staging.join("objects").is_dir() {
        return Err(plain(
            Class::NoInput,
            format!("state '{name}' has no staging repo to verify against"),
        ));
    }

    let targets = audit_targets(request, &state, &name)?;

    let mut audit = Audit {
        raw_dir: state.join("raw"),
        batch: CatFileBatch::open(&staging).map_err(|e| plain(Class::Unavailable, e))?,
        store: &store,
        inv: map::load_map_inverse(&state).map_err(|e| plain(Class::General, e))?,
        pinned: map::read_signer(&state).map_err(|e| plain(Class::Config, e))?,
        deep: request.fork_audit,
        failures: Vec::new(),
        counts: Counts::default(),
        seen: HashSet::new(),
    };

    let source = if audit.pinned.is_some() {
        let version = read_stamp(&state.join("import-spec"))
            .map_err(|e| step(Class::Data, "read import-spec", e))?;
        if version.trim() != bridge_import::IMPORT_SPEC_VERSION.to_string() {
            return Err(plain(
                Class::Data,
                "unsupported import-spec version for audit",
            ));
        }
        read_stamp(&state.join("source"))
            .map_err(|e| step(Class::Data, "read import source", e))?
            .trim()
            .to_owned()
    } else {
        String::new()
    };

    let mut verified = Vec::new();
    for (ref_name, tip, origin) in &targets {
        audit.walk(tip);
        // A required claim must establish the exact source/ref/head relation,
        // not just be a file in the head's attestation directory.
        if audit.raw_path(tip).exists()
            && let (Some(twin), Some(pin)) = (audit.inv.get(tip).copied(), audit.pinned)
        {
            let context = provenance::Context {
                layout: &layout,
                store: &store,
                source: &source,
                remote: &name,
                signer: pin,
            };
            if !context.matches(ref_name, tip, &twin) {
                audit.fail(
                    tip,
                    "no verified git-import/v1 attestation matches this head, ref and source",
                );
            }
        }
        verified.push(Verified {
            ref_name: ref_name.clone(),
            origin,
            tip: *tip,
        });
    }
    let c = audit.counts;
    Ok(Report {
        verified,
        failures: audit.failures,
        bridge: c.bridge,
        unsigned: c.unsigned,
        imported: c.imported,
        derived: c.derived,
        fork_audit: request.fork_audit,
    })
}

fn audit_targets(
    request: &Request<'_>,
    state: &Path,
    name: &str,
) -> Result<Vec<(String, Sha1Id, &'static str)>, Error> {
    // Refs to audit: explicit, else everything recorded (both
    // directions; in a fork dir the same name may have two tips).
    let mut targets: Vec<(String, Sha1Id, &'static str)> = Vec::new();
    let recorded_export = map::load_ref_state(state).map_err(|e| plain(Class::General, e))?;
    let recorded_import =
        map::load_import_ref_state(state).map_err(|e| plain(Class::General, e))?;
    for s in &recorded_export {
        if s.ref_name != ATTESTATIONS_REF {
            targets.push((s.ref_name.clone(), s.git_id, "exported"));
        }
    }
    for s in &recorded_import {
        if !targets
            .iter()
            .any(|(n, id, _)| *n == s.ref_name && *id == s.git_id)
        {
            targets.push((s.ref_name.clone(), s.git_id, "imported"));
        }
    }
    if !request.refs.is_empty() {
        targets.retain(|(n, _, _)| request.refs.iter().any(|r| r == n));
        for r in request.refs {
            if !targets.iter().any(|(n, _, _)| n == r) {
                return Err(plain(
                    Class::Usage,
                    format!("{r}: not recorded in state '{name}'"),
                ));
            }
        }
    }
    if targets.is_empty() {
        return Err(plain(
            Class::NoInput,
            format!("state '{name}' records no refs"),
        ));
    }

    Ok(targets)
}

fn read_retained(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let limit = kit_git_bridge::gitsrc::MAX_OBJECT_BYTES + 64;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other(
            "retained raw bytes exceed the object limit",
        ));
    }
    Ok(bytes)
}
