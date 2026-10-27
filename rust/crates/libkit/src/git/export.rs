//! Export of branches and tags to a git mirror (SPEC-GIT-BRIDGE).
//!
//! The translation goes into a bare staging repository under
//! `.kit/git/<remote>/repo.git`. One `git push` with a lease on each ref then
//! moves the mirror. A ref that the bridge refuses to translate is skipped
//! with a reason, and the export goes on with the other refs
//! (SPEC-GIT-BRIDGE §8, §12).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use kit_attest::{Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, Signer, statement, store as attest_store};
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::observer::Observer;
use kit_core::refs::{self, ATTESTATIONS_REF};
use kit_core::{Hash, ObjectStore};
use kit_git_bridge::gitobj::{GitObject, GitType, Sha1Id, sha1_from_hex, sha1_hex};
use kit_git_bridge::translate::translate_closure;
use kit_git_bridge::{BridgeError, map, refname};

use super::{
    Class, Error, Event, SignerError, Skipped, git_in, git_version, lock_state, plain,
    state::read_stamp, step, validate_url,
};

/// The predicate type of an export attestation (SPEC-GIT-BRIDGE §11).
const PREDICATE_TYPE: &str = "https://kit.storage/spec/predicate/git-bridge/v1";

/// Builds the signer for the attestations of an export. The export calls it
/// once, and only when it has a head to attest.
pub type SignerFactory<'a> = dyn FnMut() -> Result<Box<dyn Signer>, SignerError> + 'a;

/// What to export, and where to.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The git URL or the local path of the mirror. A missing local path is
    /// made as a bare repository.
    pub dest: &'a str,
    /// The remote name of the state directory.
    pub remote_name: &'a str,
    /// The full names of the refs to export. With none, every branch and tag.
    pub refs: &'a [String],
    /// Whether to mint and publish one attestation for each exported head.
    pub attest: bool,
    /// Whether to re-emit imported history as the original git objects
    /// (SPEC-GIT-BRIDGE §14). The state must hold an import.
    pub passthrough: bool,
}

/// One exported ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exported {
    /// The full ref name.
    pub ref_name: String,
    /// The kit hash of the head.
    pub kit_hash: Hash,
    /// The git id of the head.
    pub git_id: Sha1Id,
}

/// The result of an export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The refs that reached the mirror.
    pub exported: Vec<Exported>,
    /// The refs that the export skipped.
    pub skipped: Vec<Skipped>,
}

/// Export the refs of `layout` to the mirror in `request`.
///
/// # Errors
/// An error when the request or the recorded state contradict each other,
/// when `git` fails, when a ref cannot be translated for a reason other than a
/// refusal, or when every ref was skipped ([`Error::AllRefsSkipped`]).
#[allow(clippy::too_many_lines)] // linear pipeline; stages are commented
pub fn export(
    layout: &RepoLayout,
    request: &Request<'_>,
    signer: &mut SignerFactory<'_>,
    observer: &dyn Observer<Event>,
) -> Result<Outcome, Error> {
    let store = ObjectStore::open(layout).map_err(Error::OpenRepository)?;
    git_version()?;
    validate_url(request.dest)?;

    // ── per-remote bridge state + bare staging repo ────────────────
    let state = map::state_dir(layout, request.remote_name).map_err(|e| plain(Class::Usage, e))?;
    // One bridge operation per state dir at a time (shared with the
    // import side: fetch + passthrough export on a fork dir race the
    // staging mirror and the map).
    let _state_lock = lock_state(layout, request.remote_name)?;

    // ORIGIN GUARD (SPEC-GIT-BRIDGE §14.2), FIRST — before any state
    // is stamped or the dest is initialized, so a refusal has no side
    // effects. Export toward a recorded git-import source would pass
    // its ls-remote-seeded lease and force-replace upstream history
    // with a disconnected re-translation. The only supported path is
    // passthrough export through the SAME state that imported it
    // (whose map re-emits the upstream's own objects) — passthrough
    // through a DIFFERENT state is just as disconnected as a plain
    // export.
    let dest_identity = kit_git_bridge::remoteid::remote_identity(request.dest);
    if let Some(import_state) = recorded_import_source(layout, &dest_identity)
        && !(request.passthrough && import_state == request.remote_name)
    {
        return Err(Error::ImportSource {
            dest: request.dest.to_owned(),
            state: import_state,
        });
    }

    // Direction binding (SPEC-GIT-IMPORT §6): plain export owns its
    // state dir; --passthrough upgrades an IMPORT state dir to fork.
    if request.passthrough {
        if map::read_direction(&state).ok().flatten().is_none() {
            return Err(Error::PassthroughNeedsImport {
                remote: request.remote_name.to_owned(),
            });
        }
        // §3.3 stickiness: history imported with historic-mode
        // normalization cannot reproduce its original sha1s — a fork
        // built on it would fail every fork audit as false tampering.
        if map::read_normalized(&state).map_err(|e| plain(Class::General, e))? {
            return Err(Error::PassthroughNormalized {
                remote: request.remote_name.to_owned(),
            });
        }
        map::bind_direction(&state, map::Direction::Fork).map_err(|e| plain(Class::Usage, e))?;
    } else {
        // Validate the direction early (mismatch refusals must fire
        // before any work) but WRITE a fresh stamp only after the
        // push succeeds — a typo'd remote dest must not burn the
        // state name (mirrors the import side's validate-then-bind).
        match map::read_direction(&state).map_err(|e| plain(Class::General, e))? {
            None | Some(map::Direction::Export) => {}
            Some(other) => {
                return Err(Error::DirectionBound {
                    direction: other.as_str(),
                });
            }
        }
    }

    let staging = state.join("repo.git");
    if !staging.join("objects").is_dir() {
        if request.passthrough {
            return Err(plain(
                Class::Config,
                "fork-mode staging mirror missing — re-run `kit git import` to restore it",
            ));
        }
        // (Re)initializing staging invalidates the map cache: cached
        // sha1s would point at objects the fresh staging repo does not
        // have, wedging update-ref/push (§12.3: cache is disposable).
        let _ = std::fs::remove_file(state.join("map"));
        std::fs::create_dir_all(&staging)
            .map_err(|e| step(Class::CannotCreate, "create staging dir", e))?;
        git_in(&staging, &["init", "--bare", "--quiet", "."])
            .map_err(|e| step(Class::CannotCreate, "init staging repo", e))?;
    }
    let mut known = map::load_map(&state).map_err(|e| step(Class::General, "load map cache", e))?;
    let prior_state =
        map::load_ref_state(&state).map_err(|e| step(Class::General, "load ref state", e))?;

    // Validate/prepare the destination up front (before any signing or
    // state mutation). PLAIN export binds this state dir to one dest
    // by canonical identity (SPEC-GIT-IMPORT §8): recorded leases are
    // statements about one mirror and are wrong for another. FORK
    // mode does NOT bind — its leases come from a fresh per-push
    // observation guarded by the explicit fast-forward check, so the
    // triangular workflow (import upstream U, push fork F, later
    // contribute to U) stays possible; the last dest is recorded for
    // `kit git status` only.
    let push_dest = ensure_dest(request.dest)?;
    // A state dir is FRESH when nothing has ever bound it: if the
    // remote contact below fails, the whole dir (staging, map cache)
    // is removed so the name is not burned and a later import cannot
    // land on mixed leftovers.
    let fresh_state = !request.passthrough && !state.join("dest").exists();

    // Recompute AFTER ensure_dest: a fresh local mirror did not exist
    // when the origin-guard identity above was taken, so its lexical
    // fallback differs from the canonicalized spelling every later
    // run produces — binding the early value would wedge the state on
    // the second export. (The guard itself is unaffected: recorded
    // import sources always exist.)
    let bound_identity = kit_git_bridge::remoteid::remote_identity(request.dest);

    let dest_file = state.join("dest");
    if request.passthrough {
        map::write_binding(&state, "dest", &bound_identity)
            .map_err(|e| step(Class::CannotCreate, "record dest", e))?;
    } else {
        match read_stamp(&dest_file) {
            Ok(recorded) if recorded.trim() != bound_identity => {
                return Err(Error::StateBound {
                    name: request.remote_name.to_owned(),
                    recorded: recorded.trim().to_owned(),
                    target: request.dest.to_owned(),
                });
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Recorded after the push succeeds (see below).
            }
            Err(e) => return Err(step(Class::General, "read dest binding", e)),
        }
    }

    // ── ref selection (§12.1) ──────────────────────────────────────
    let requested = collect_refs(layout, request.refs)?;
    if requested.is_empty() {
        return Err(Error::NothingToExport);
    }

    let mut exported: Vec<Exported> = Vec::new();
    let mut skipped: Vec<Skipped> = Vec::new();
    let mut new_pairs: Vec<(Hash, Sha1Id)> = Vec::new();

    for (ref_name, head) in requested {
        if let Err(refusal) = refname::check_git_legal(&ref_name) {
            skip(observer, &mut skipped, &ref_name, refusal.to_string());
            continue;
        }
        let result = translate_closure(&store, &head, &mut known, &mut |h, g| {
            let id = g.write_loose(&staging)?;
            new_pairs.push((*h, id));
            Ok(())
        });
        match result {
            Ok(batch) => {
                // Fork mode writes under a private namespace so the
                // import mirror's own refs (upstream state) stay
                // untouched; the push refspec maps it back.
                let local_ref = if request.passthrough {
                    format!("refs/kit-export/{ref_name}")
                } else {
                    ref_name.clone()
                };
                git_in(
                    &staging,
                    &["update-ref", &local_ref, &sha1_hex(&batch.root)],
                )
                .map_err(|e| step(Class::General, format!("update-ref {ref_name}"), e))?;
                exported.push(Exported {
                    ref_name,
                    kit_hash: head,
                    git_id: batch.root,
                });
            }
            Err(BridgeError::Refused(r)) => {
                // Objects already written are harmless content-addressed
                // orphans; the map pairs stay valid (determinism).
                skip(observer, &mut skipped, &ref_name, r.to_string());
            }
            Err(e) => return Err(step(Class::General, format!("translate {ref_name}"), e)),
        }
    }

    map::append_map(&state, &new_pairs)
        .map_err(|e| step(Class::General, "persist map cache", e))?;

    if exported.is_empty() {
        return Err(Error::AllRefsSkipped { skipped });
    }

    // ── provenance attestations (§11) ──────────────────────────────
    // §11 scoping: fork-mode heads whose tip passed through (came
    // from the import map) carry no translation claim — their
    // provenance is git-import/v1.
    let attestable: Vec<&Exported> = exported
        .iter()
        .filter(|e| {
            if !request.passthrough {
                return true;
            }
            // An imported tip's raw git bytes are retained under
            // state/raw/ — that head passed through and its
            // provenance is git-import/v1, not a translation claim.
            let hex = sha1_hex(&e.git_id);
            !state.join("raw").join(&hex[..2]).join(&hex[2..]).exists()
        })
        .collect();
    let attest_head: Option<Sha1Id> = if !request.attest || attestable.is_empty() {
        None
    } else {
        Some(publish_attestations(
            layout,
            &store,
            &staging,
            request.dest,
            &attestable,
            signer,
            &prior_state,
        )?)
    };

    // ── push with per-ref CAS leases (§12.2) ───────────────────────
    // Lease expectation per ref: recorded state, else (state lost or
    // never recorded) the mirror's CURRENT value via ls-remote — a
    // fresh observation is still a CAS, and it is what makes wiped
    // bridge state rebuildable against an existing mirror (§12.3).
    let prior: HashMap<&str, &map::RefState> = prior_state
        .iter()
        .map(|s| (s.ref_name.as_str(), s))
        .collect();
    let mut to_push: Vec<(&str, Sha1Id)> = exported
        .iter()
        .map(|e| (e.ref_name.as_str(), e.git_id))
        .collect();
    if let Some(head) = attest_head {
        to_push.push((ATTESTATIONS_REF, head));
    }
    // Fork mode ALWAYS observes: it pushes to a repository kit does
    // not own, so the remote moving between exports is the normal
    // case — a recorded lease from our last push would go stale the
    // moment a third-party commit lands, and `kit git fetch` only
    // updates the import side. The fresh observation is safe to lease
    // against because the explicit fast-forward guard below refuses
    // anything we have not integrated. Plain export keeps recorded
    // leases (the mirror is owned by this repo; the lease IS the
    // tamper check) and observes only refs it has no lease for.
    let needs_observation =
        request.passthrough || to_push.iter().any(|(name, _)| !prior.contains_key(*name));
    let remote_refs: HashMap<String, Sha1Id> = if needs_observation {
        match ls_remote(&staging, &push_dest) {
            Ok(o) => o,
            Err(e) => {
                if fresh_state {
                    let _ = std::fs::remove_dir_all(&state);
                }
                return Err(e);
            }
        }
    } else {
        HashMap::new()
    };
    // One expectation rule shared by the FF guard and the push lease.
    // Passthrough: the observation is AUTHORITATIVE — fork mode is
    // not dest-bound, so a lease recorded against one destination is
    // meaningless for another (absent on the remote means "must not
    // exist", never "fall back to what we pushed elsewhere").
    let expectation = |name: &str| -> Option<Sha1Id> {
        if request.passthrough {
            remote_refs.get(name).copied()
        } else {
            prior
                .get(name)
                .map(|s| s.git_id)
                .or_else(|| remote_refs.get(name).copied())
        }
    };
    // Fork mode pushes to repositories kit does NOT own (the
    // upstream itself, or a real fork): a lease seeded from a fresh
    // ls-remote observation passes unconditionally, so require
    // fast-forward explicitly — the expected value must be an
    // ancestor of what we push, and tags must not move. Plain export
    // keeps the default mirror-owned semantics (the mirror is owned by this repo).
    if request.passthrough {
        for (name, new_id) in &to_push {
            if *name == ATTESTATIONS_REF {
                continue;
            }
            let Some(expect) = expectation(name) else {
                continue;
            };
            if expect == *new_id {
                continue;
            }
            if name.starts_with("refs/tags/") {
                return Err(Error::TagExists {
                    name: (*name).to_owned(),
                    dest: request.dest.to_owned(),
                });
            }
            let ff = kit_git_bridge::gitsrc::object_exists(&staging, &expect)
                .map_err(|e| plain(Class::General, e))?
                && kit_git_bridge::gitsrc::is_ancestor(&staging, &expect, new_id)
                    .map_err(|e| plain(Class::General, e))?;
            if !ff {
                return Err(Error::NotFastForward {
                    name: (*name).to_owned(),
                    dest: request.dest.to_owned(),
                    remote: request.remote_name.to_owned(),
                    branch: name.strip_prefix("refs/heads/").unwrap_or(name).to_owned(),
                });
            }
        }
    }

    // --atomic: either every ref (incl. attestations) lands or none
    // does, so recorded state can never go stale per-ref.
    let mut push_args: Vec<String> = vec!["push".into(), "--quiet".into(), "--atomic".into()];
    for (name, _) in &to_push {
        let expect = expectation(name)
            .map(|id| sha1_hex(&id))
            .unwrap_or_default();
        push_args.push(format!("--force-with-lease={name}:{expect}"));
    }
    push_args.push(push_dest.clone());
    for (name, _) in &to_push {
        if request.passthrough && *name != ATTESTATIONS_REF {
            push_args.push(format!("refs/kit-export/{name}:{name}"));
        } else {
            push_args.push(format!("{name}:{name}"));
        }
    }
    let push_arg_refs: Vec<&str> = push_args.iter().map(String::as_str).collect();
    git_in(&staging, &push_arg_refs).map_err(|e| {
        if fresh_state {
            let _ = std::fs::remove_dir_all(&state);
        }
        let hint = if e.contains("stale info") {
            "\nhint: the mirror moved since the last export; if that \
             change is yours/expected, remove .kit/git/<name>/refs to \
             reseed leases from the mirror and re-run"
        } else {
            ""
        };
        plain(
            Class::General,
            format!("push to {}: {e}{hint}", request.dest),
        )
    })?;

    // Push succeeded: record the fresh plain-export bindings the
    // validation above deferred (idempotent for already-bound dirs).
    if !request.passthrough {
        map::bind_direction(&state, map::Direction::Export)
            .map_err(|e| plain(Class::CannotCreate, e))?;
        if !dest_file.exists() {
            map::write_binding(&state, "dest", &bound_identity)
                .map_err(|e| step(Class::CannotCreate, "record dest", e))?;
        }
    }

    // ── record the new lease expectations ──────────────────────────
    // Merge over prior state: refs not in this export keep their
    // recorded leases (a --ref subset or a skip must not wipe them).
    let mut merged: Vec<map::RefState> = prior_state
        .iter()
        .filter(|s| !to_push.iter().any(|(n, _)| *n == s.ref_name))
        .cloned()
        .collect();
    merged.extend(exported.iter().map(|e| map::RefState {
        ref_name: e.ref_name.clone(),
        kit_hash: e.kit_hash,
        git_id: e.git_id,
    }));
    if let Some(head) = attest_head {
        merged.push(map::RefState {
            ref_name: ATTESTATIONS_REF.to_owned(),
            kit_hash: kit_core::hash::ZERO,
            git_id: head,
        });
    }
    merged.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));
    map::store_ref_state(&state, &merged)
        .map_err(|e| step(Class::General, "persist ref state", e))?;

    Ok(Outcome { exported, skipped })
}

fn skip(
    observer: &dyn Observer<Event>,
    skipped: &mut Vec<Skipped>,
    ref_name: &str,
    reason: String,
) {
    observer.event(&Event::RefSkipped {
        ref_name: ref_name.to_owned(),
        reason: reason.clone(),
    });
    skipped.push(Skipped {
        ref_name: ref_name.to_owned(),
        reason,
    });
}

/// Default export set: every branch and tag, as full ref names.
fn collect_refs(layout: &RepoLayout, explicit: &[String]) -> Result<Vec<(String, Hash)>, Error> {
    if !explicit.is_empty() {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for name in explicit {
            if !seen.insert(name.as_str()) {
                continue; // duplicate --ref would duplicate the refspec
            }
            let short = name
                .strip_prefix("refs/heads/")
                .or_else(|| name.strip_prefix("refs/tags/"));
            let Some(short) = short else {
                return Err(Error::BadRefName(name.clone()));
            };
            // read_ref/read_tag take namespace-relative short names.
            let hash = if name.starts_with("refs/heads/") {
                refs::read_ref(layout, short)
            } else {
                refs::read_tag(layout, short)
            }
            .map_err(|e| step(Class::General, format!("read {name}"), e))?
            .ok_or_else(|| Error::RefNotFound(name.clone()))?;
            out.push((name.clone(), hash));
        }
        return Ok(out);
    }
    let mut out = Vec::new();
    let branches = refs::list_refs_with(layout, kit_sync::worktree::fanout_read_batch)
        .map_err(|e| step(Class::General, "list branches", e))?;
    for r in branches {
        if let Some(h) = r.hash {
            out.push((format!("refs/heads/{}", r.name), h));
        }
    }
    let tags = refs::list_tags_with(layout, kit_sync::worktree::fanout_read_batch)
        .map_err(|e| step(Class::General, "list tags", e))?;
    for r in tags {
        if let Some(h) = r.hash {
            out.push((format!("refs/tags/{}", r.name), h));
        }
    }
    Ok(out)
}

/// Mint one DSSE attestation per exported head (subject = kit hash,
/// predicate carries the git locator), save it locally like `kit
/// attest` does, and publish the set on the staging repo's
/// `refs/kit/attestations` flat tree. Returns the staging ref's
/// resulting head — unchanged trees return the existing commit, so a
/// previously failed push retries with the same refspec instead of
/// silently dropping the attestations ref.
#[allow(clippy::too_many_lines)] // mint loop + tree/commit assembly; splitting would scatter §11
fn publish_attestations(
    layout: &RepoLayout,
    store: &ObjectStore,
    staging: &Path,
    dest: &str,
    exported: &[&Exported],
    signer: &mut SignerFactory<'_>,
    prior_state: &[map::RefState],
) -> Result<Sha1Id, Error> {
    // The signer of `kit attest` (SPEC-GIT-BRIDGE §11: "the
    // exporter's configured signer").
    let mut signer = signer().map_err(Error::Signer)?;

    // Existing published entries (name → blob id) so re-exports merge.
    let mut entries: Vec<(String, Sha1Id)> = Vec::new();
    let old_commit = read_ref_in(staging, ATTESTATIONS_REF)?;
    if let Some(old) = &old_commit {
        for (name, id) in ls_tree(staging, old)? {
            entries.push((name, id));
        }
    }

    // Mint only for new/moved heads: a head whose recorded state is
    // unchanged AND whose claim is already on the published ref needs
    // no fresh envelope. This keeps no-op re-exports no-op even with
    // nondeterministic signers (e.g. P-256), instead of growing the
    // tree and local store every run.
    let already_published = |e: &Exported| -> bool {
        old_commit.is_some()
            && prior_state.iter().any(|s| {
                s.ref_name == e.ref_name && s.kit_hash == e.kit_hash && s.git_id == e.git_id
            })
    };
    let mut max_ts = 0u64;
    for e in exported {
        if already_published(e) {
            max_ts = max_ts.max(head_timestamp(store, &e.kit_hash));
            continue;
        }
        // Deterministic synthetic-commit timestamp: newest exported head.
        max_ts = max_ts.max(head_timestamp(store, &e.kit_hash));
        let predicate = format!(
            "{{\"gitCommit\":\"{}\",\"mirror\":\"{}\",\"refName\":\"{}\",\"schemaVersion\":1,\"specVersion\":1}}",
            sha1_hex(&e.git_id),
            super::json_escape(dest),
            super::json_escape(&e.ref_name)
        );
        let head_bytes = store.read(&e.kit_hash).map_err(|err| {
            step(
                Class::General,
                format!("read {}", kit_core::to_hex(&e.kit_hash)),
                err,
            )
        })?;
        let stmt = statement::encode(&statement::Statement {
            subjects: vec![statement::Subject {
                name: Some(e.ref_name.clone()),
                digest_blake3_hex: kit_core::to_hex(&e.kit_hash),
                digest_sha256_hex: statement::sha256_hex(&head_bytes),
            }],
            predicate_type: PREDICATE_TYPE.to_owned(),
            predicate_jcs: predicate.as_bytes(),
        })
        .map_err(|e| step(Class::General, "encode statement", e))?;
        let pae = kit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, stmt.as_bytes());
        let sig = signer
            .sign(&pae)
            .map_err(|e| step(Class::General, "sign bridge attestation", e))?;
        let keyid = signer
            .keyid()
            .map_err(|e| step(Class::General, "bridge signer keyid", e))?;
        let envelope = Envelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
            payload: stmt.into_bytes(),
            signatures: vec![Sig { keyid, sig }],
        };
        let encoded = envelope
            .encode()
            .map_err(|e| step(Class::General, "encode envelope", e))?;
        attest_store::save(layout, &e.kit_hash, encoded.as_bytes())
            .map_err(|e| step(Class::CannotCreate, "save attestation", e))?;

        let blob = GitObject {
            gtype: GitType::Blob,
            body: encoded.into_bytes(),
        };
        let blob_id = blob
            .write_loose(staging)
            .map_err(|e| step(Class::CannotCreate, "write attestation blob", e))?;
        // Entry name = attestation id (BLAKE3 of the envelope bytes,
        // matching the local store's naming). Naming by git sha would
        // collide when two refs share a head — each ref still gets
        // its own envelope (distinct refName in the predicate).
        let att_id = kit_attest::attestation_id(blob.body.as_slice());
        let name = format!("{}.dsse", kit_core::to_hex(&att_id));
        entries.retain(|(n, _)| n != &name);
        entries.push((name, blob_id));
    }

    // Flat tree, git sort order (all blobs, so plain byte-lex).
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut tree_body = Vec::new();
    for (name, id) in &entries {
        tree_body.extend_from_slice(b"100644 ");
        tree_body.extend_from_slice(name.as_bytes());
        tree_body.push(0);
        tree_body.extend_from_slice(id);
    }
    let tree = GitObject {
        gtype: GitType::Tree,
        body: tree_body,
    };
    let tree_id = tree
        .write_loose(staging)
        .map_err(|e| step(Class::CannotCreate, "write attestation tree", e))?;

    // Unchanged tree ⇒ keep the existing commit (no new history; the
    // caller still pushes the ref so an earlier failed push retries).
    if let Some(old) = &old_commit
        && commit_tree_id(staging, old)? == Some(tree_id)
    {
        return Ok(*old);
    }

    let person = format!("kit-git-bridge <bridge@kit.invalid> {max_ts} +0000");
    let mut body = Vec::new();
    body.extend_from_slice(format!("tree {}\n", sha1_hex(&tree_id)).as_bytes());
    if let Some(old) = &old_commit {
        body.extend_from_slice(format!("parent {}\n", sha1_hex(old)).as_bytes());
    }
    body.extend_from_slice(format!("author {person}\ncommitter {person}\n").as_bytes());
    body.extend_from_slice(b"\nkit git-bridge attestations\n");
    let commit = GitObject {
        gtype: GitType::Commit,
        body,
    };
    let commit_id = commit
        .write_loose(staging)
        .map_err(|e| step(Class::CannotCreate, "write attestation commit", e))?;
    git_in(
        staging,
        &["update-ref", ATTESTATIONS_REF, &sha1_hex(&commit_id)],
    )
    .map_err(|e| step(Class::General, format!("update-ref {ATTESTATIONS_REF}"), e))?;
    Ok(commit_id)
}

fn head_timestamp(store: &ObjectStore, h: &Hash) -> u64 {
    match store.read_object(h) {
        Ok(Object::Commit(c)) => c.timestamp,
        Ok(Object::Tag(t)) => t.timestamp,
        _ => 0,
    }
}

/// Whether a git destination is a URL, and not a path. Git's own rule: `://`
/// means a URL, and otherwise a colon before the first slash means an
/// scp-style remote (the `user@` is optional). A DOS drive prefix (`C:\` or
/// `C:/`) is a path.
#[must_use]
pub fn is_remote_location(dest: &str) -> bool {
    let dos_drive = dest.len() >= 2
        && dest.as_bytes()[0].is_ascii_alphabetic()
        && dest.as_bytes()[1] == b':'
        && matches!(dest.as_bytes().get(2), None | Some(b'/' | b'\\'));
    !dos_drive
        && (dest.contains("://")
            || dest
                .split('/')
                .next()
                .is_some_and(|first| first.contains(':')))
}

/// A missing or empty *local path* destination is initialized as a
/// bare repo; URLs pass through untouched. Local paths come back
/// absolutized because the push runs `git -C <staging>`, which would
/// otherwise resolve them against the staging directory.
fn ensure_dest(dest: &str) -> Result<String, Error> {
    if is_remote_location(dest) {
        return Ok(dest.to_owned());
    }
    let path = PathBuf::from(dest);
    let needs_init = if path.exists() {
        let is_repo = kit_git_bridge::gitsrc::git_command(&path)
            .args(["rev-parse", "--git-dir"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if is_repo {
            false
        } else {
            let empty = std::fs::read_dir(&path)
                .map_err(|e| step(Class::Config, format!("read {dest}"), e))?
                .next()
                .is_none();
            if !empty {
                return Err(plain(
                    Class::CannotCreate,
                    format!("{dest} exists and is neither a git repository nor empty"),
                ));
            }
            true
        }
    } else {
        std::fs::create_dir_all(&path)
            .map_err(|e| step(Class::CannotCreate, format!("create {dest}"), e))?;
        true
    };
    if needs_init {
        git_in(&path, &["init", "--bare", "--quiet", "."])
            .map_err(|e| step(Class::CannotCreate, format!("init {dest}"), e))?;
    }
    let abs = path
        .canonicalize()
        .map_err(|e| step(Class::Config, format!("resolve {dest}"), e))?;
    Ok(abs.to_string_lossy().into_owned())
}

fn read_ref_in(repo: &Path, name: &str) -> Result<Option<Sha1Id>, Error> {
    let out = kit_git_bridge::gitsrc::git_command(repo)
        .args(["rev-parse", "--verify", "--quiet", name])
        .output()
        .map_err(|e| plain(Class::General, format!("spawn git: {e}")))?;
    if !out.status.success() {
        return Ok(None);
    }
    let hex = String::from_utf8_lossy(&out.stdout);
    Ok(sha1_from_hex(hex.trim()))
}

fn ls_tree(repo: &Path, commit: &Sha1Id) -> Result<Vec<(String, Sha1Id)>, Error> {
    let spec = format!("{}^{{tree}}", sha1_hex(commit));
    let out = git_in(repo, &["ls-tree", &spec]).map_err(|e| step(Class::General, "ls-tree", e))?;
    let mut entries = Vec::new();
    for line in out.lines() {
        // "<mode> blob <id>\t<name>"
        let Some((meta, name)) = line.split_once('\t') else {
            continue;
        };
        let Some(id_hex) = meta.split(' ').nth(2) else {
            continue;
        };
        if let Some(id) = sha1_from_hex(id_hex) {
            entries.push((name.to_owned(), id));
        }
    }
    Ok(entries)
}

fn commit_tree_id(repo: &Path, commit: &Sha1Id) -> Result<Option<Sha1Id>, Error> {
    let spec = format!("{}^{{tree}}", sha1_hex(commit));
    let out = kit_git_bridge::gitsrc::git_command(repo)
        .args(["rev-parse", "--verify", "--quiet", &spec])
        .output()
        .map_err(|e| plain(Class::General, format!("spawn git: {e}")))?;
    if !out.status.success() {
        return Ok(None);
    }
    let hex = String::from_utf8_lossy(&out.stdout);
    Ok(sha1_from_hex(hex.trim()))
}

/// Read the destination's current refs (one round-trip). Used to seed
/// lease expectations when recorded state is missing (§12.3).
fn ls_remote(staging: &Path, dest: &str) -> Result<HashMap<String, Sha1Id>, Error> {
    let out = git_in(staging, &["ls-remote", "--quiet", dest, "refs/*"])
        .map_err(|e| step(Class::General, format!("ls-remote {dest}"), e))?;
    let mut refs = HashMap::new();
    for line in out.lines() {
        let Some((hex, name)) = line.split_once('\t') else {
            continue;
        };
        if let Some(id) = sha1_from_hex(hex.trim()) {
            refs.insert(name.trim().to_owned(), id);
        }
    }
    Ok(refs)
}

/// The state-dir name whose recorded import `source` matches the
/// given canonical identity, if any.
fn recorded_import_source(layout: &RepoLayout, identity: &str) -> Option<String> {
    let entries = std::fs::read_dir(layout.git_state_dir()).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let src = entry.path().join("source");
        if let Ok(recorded) = read_stamp(&src)
            && recorded.trim() == identity
        {
            return Some(name);
        }
    }
    None
}
