//! Per-verb dispatch (SPEC-TRANSPORT §4.2). Every failure maps to one fixed
//! error frame, so no storage message reaches the ssh wire.
//!
//! | Verb | Failure | Frame |
//! |---|---|---|
//! | `PackExists` | any | `exists = false` |
//! | `ReadRef` | a name over 512 bytes | `INVALID_REQUEST "ref name too long"` |
//! | `ReadRef` | a valid name outside `refs/` | `INVALID_REQUEST`, [`REF_NAME_OUTSIDE_REFS`] |
//! | `ReadRef` | any other | `INTERNAL "read ref failed"` |
//! | `UpdateRef` | a name over 512 bytes | `INVALID_REQUEST "ref name too long"` |
//! | `UpdateRef` | a valid name outside `refs/` | `INVALID_REQUEST`, [`REF_NAME_OUTSIDE_REFS`] |
//! | `UpdateRef` | a CAS conflict | [`cas_conflict_body`] |
//! | `UpdateRef` | the write policy refuses the session | `INVALID_REQUEST "write not permitted"` |
//! | `UpdateRef` | any other | `INVALID_REQUEST "update ref failed"` |
//! | `ListRefs` | any | `INTERNAL "list refs failed"` |
//! | `DownloadPack` | any, before the header | `KEY_NOT_FOUND "pack not found"` |
//! | `DownloadPack` | a read, after the header | `INTERNAL "pack read failed"` |
//! | `UploadPack` | the write policy refuses the session | `INVALID_REQUEST "write not permitted"` |
//! | `UploadPack` | bytes that do not hash to `pack_id` | `INVALID_REQUEST`, [`UploadError::DigestMismatch`] text |
//! | `UploadPack` | any other | `INTERNAL "upload failed"` |
//!
//! A ref name over 512 bytes, or a valid name outside `refs/`, is refused by
//! name. A name that fails the ref grammar gets the generic reply of its
//! verb.

use kit_core::hash::Hash;
use kit_core::protocol::PackKey;
use kit_core::refs::{RefWriteCondition, validate_ref_name};
use kit_rpc::kit::common::v1::RefEntry;
use kit_rpc::kit::rpc::v1::ssh::{
    DownloadPack, DownloadPackHeader, ListRefsResponse, PackChunk, PackExistsResponse,
    ReadRefResponse, UpdateRef, UploadPack, UploadPackResponse, ssh_frame,
};
use kit_rpc::kit::rpc::v1::{Error as RpcError, ErrorCode};

use crate::budget::upload_limits;
use crate::packs::FinishError;
use crate::refs::{
    DigestField, MAX_REF_NAME_BYTES, REF_NAME_OUTSIDE_REFS, REF_NAME_TOO_LONG, condition, digest,
    is_served_ref_name,
};
use crate::repo::{RefUpdate, Repo};
use crate::session::{FrameIoError, FrameSink, FrameSource, Stop, emit_error, send_body};
use crate::upload::{UploadError, UploadValidator};

/// A verb's fixed rejection: the code and message of its error frame.
type VerbError = (ErrorCode, &'static str);

type Body = ssh_frame::Body;

/// The reply to a write that the write policy refuses.
const WRITE_NOT_PERMITTED: VerbError = (ErrorCode::InvalidRequest, "write not permitted");

/// The most bytes of `ListRefs` entries in one reply. A reply must fit one
/// frame, with room for the frame header.
const MAX_LISTING_BYTES: usize = kit_rpc::MAX_FRAME_BYTES as usize - 1024;

/// The most bytes that an entry adds to a listing beyond its name: the id,
/// the tags and the lengths.
const LISTING_ENTRY_OVERHEAD: usize = 48;

/// A request digest as a pack key.
fn pack_key(id: Option<&[u8]>) -> Result<PackKey, VerbError> {
    digest(DigestField::Pack, id)
        .map(PackKey::new)
        .map_err(|message| (ErrorCode::InvalidRequest, message))
}

/// A decoded `UpdateRef` request (SPEC-TRANSPORT §4.2.1): the name, the
/// condition and the new id. `new_id` is checked first. `expected_id` is read
/// for `MATCH` only.
fn decode_update_ref(req: &UpdateRef) -> Result<(String, RefWriteCondition, Hash), VerbError> {
    let bad = |message| (ErrorCode::InvalidRequest, message);
    let new = digest(
        DigestField::New,
        Some(req.new_id.as_deref().unwrap_or_default()),
    )
    .map_err(bad)?;
    let expectation = req.expectation.map_or(0, |e| e.to_i32());
    let condition =
        condition(expectation, req.expected_id.as_deref().unwrap_or_default()).map_err(bad)?;
    Ok((req.name.clone().unwrap_or_default(), condition, new))
}

/// The reply to a failed CAS (SPEC-TRANSPORT §4.2.1): `Error{INVALID_REQUEST}`
/// whose `details` is the current id of the ref, or empty when the ref is
/// absent. A strict client reads a non-empty `details` as a ref conflict.
#[must_use]
pub fn cas_conflict_body(current: Option<Hash>) -> ssh_frame::Body {
    let (details, message) = match current {
        Some(h) => (
            h.to_vec(),
            "ref update conflict: expectation does not match current ref value",
        ),
        None => (
            Vec::new(),
            "ref update conflict: expectation not met and ref is currently absent",
        ),
    };
    Body::Error(Box::new(
        RpcError::default()
            .with_code(ErrorCode::InvalidRequest)
            .with_message(message)
            .with_details(details),
    ))
}

/// Refuse by name a ref name over [`MAX_REF_NAME_BYTES`], or a valid name
/// outside `refs/`. A name that fails the grammar passes, to fail later with
/// the generic reply of its verb.
fn check_name(name: &str) -> Result<(), VerbError> {
    if name.len() > MAX_REF_NAME_BYTES {
        Err((ErrorCode::InvalidRequest, REF_NAME_TOO_LONG))
    } else if validate_ref_name(name) && !is_served_ref_name(name) {
        Err((ErrorCode::InvalidRequest, REF_NAME_OUTSIDE_REFS))
    } else {
        Ok(())
    }
}

/// Whether a listing of `refs` fits one reply frame.
fn listing_fits(refs: &[(String, Hash)]) -> bool {
    let mut total = 0usize;
    for (name, _) in refs {
        total = total.saturating_add(name.len() + LISTING_ENTRY_OVERHEAD);
        if total > MAX_LISTING_BYTES {
            return false;
        }
    }
    true
}

/// The verbs of one session: its repository and the key that the transport
/// asserted for it.
pub(crate) struct Verbs<'r> {
    repo: &'r Repo,
    key: Option<[u8; 32]>,
}

impl<'r> Verbs<'r> {
    pub(crate) const fn new(repo: &'r Repo, key: Option<[u8; 32]>) -> Self {
        Self { repo, key }
    }

    fn may_write(&self) -> bool {
        self.repo.policy().allows(self.key.as_ref())
    }

    /// Answer one top-level frame body. The upload verb reads its chunk
    /// frames from `src`.
    ///
    /// # Errors
    /// [`Stop`] when the sink fails or the source times out inside an
    /// upload.
    pub(crate) fn dispatch<S: FrameSource, K: FrameSink>(
        &mut self,
        body: Option<Body>,
        src: &mut S,
        sink: &mut K,
    ) -> Result<(), Stop> {
        let Some(body) = body else {
            return emit_error(sink, ErrorCode::InvalidRequest, "empty frame");
        };
        match body {
            Body::DownloadPack(req) => self.download(&req, sink),
            Body::UploadPack(header) => self.upload(&header, src, sink),
            Body::PackChunk(_) => {
                let message = "PackChunk arrived without UploadPack header";
                emit_error(sink, ErrorCode::InvalidRequest, message)
            }
            Body::Hello(_) => emit_error(sink, ErrorCode::InvalidRequest, "Hello after handshake"),
            other => match self.simple(&other) {
                Some(Ok(resp)) => send_body(sink, resp),
                Some(Err((code, message))) => emit_error(sink, code, message),
                None => emit_error(sink, ErrorCode::InvalidRequest, "unexpected request frame"),
            },
        }
    }

    /// The one-frame verbs; `None` for any other body.
    fn simple(&self, body: &Body) -> Option<Result<Body, VerbError>> {
        Some(match body {
            Body::PackExists(req) => pack_key(req.pack_id.as_deref()).map(|key| {
                Body::PackExistsResponse(Box::new(PackExistsResponse {
                    exists: Some(self.repo.pack_exists(&key)),
                    ..Default::default()
                }))
            }),
            Body::ReadRef(req) => self.read_ref(req.name.as_deref().unwrap_or_default()),
            Body::UpdateRef(req) => self.update_ref(req),
            Body::ListRefs(req) => self.list_refs(req.prefix.as_deref().unwrap_or_default()),
            _ => return None,
        })
    }

    fn read_ref(&self, name: &str) -> Result<Body, VerbError> {
        check_name(name)?;
        match self.repo.read_ref(name) {
            Ok(found) => Ok(Body::ReadRefResponse(Box::new(ReadRefResponse {
                object_id: Some(found.map(|h| h.to_vec()).unwrap_or_default()),
                ..Default::default()
            }))),
            Err(_) => Err((ErrorCode::Internal, "read ref failed")),
        }
    }

    fn update_ref(&self, req: &UpdateRef) -> Result<Body, VerbError> {
        let failed = (ErrorCode::InvalidRequest, "update ref failed");
        let (name, condition, new) = decode_update_ref(req)?;
        check_name(&name)?;
        if !is_served_ref_name(&name) {
            return Err(failed);
        }
        if !self.may_write() {
            return Err(WRITE_NOT_PERMITTED);
        }
        match self.repo.update_ref(&name, condition, &new) {
            Ok(RefUpdate::Committed) => Ok(Body::UpdateRefResponse(Box::default())),
            Ok(RefUpdate::Conflict { current }) => Ok(cas_conflict_body(current)),
            Err(_) => Err(failed),
        }
    }

    fn list_refs(&self, prefix: &str) -> Result<Body, VerbError> {
        let failed = (ErrorCode::Internal, "list refs failed");
        let listed = self.repo.list_refs(prefix).map_err(|_| failed)?;
        if !listing_fits(&listed) {
            return Err(failed);
        }
        Ok(Body::ListRefsResponse(Box::new(ListRefsResponse {
            refs: listed
                .into_iter()
                .map(|(name, id)| RefEntry {
                    name: Some(name),
                    object_id: Some(id.to_vec()),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })))
    }

    /// `DownloadPack`: a header with the length of the pack, then its
    /// chunks. Each chunk repeats the `pack_id` of the request, and only the
    /// final one is `last`.
    fn download<K: FrameSink>(&self, req: &DownloadPack, sink: &mut K) -> Result<(), Stop> {
        let key = match pack_key(req.pack_id.as_deref()) {
            Ok(key) => key,
            Err((code, message)) => return emit_error(sink, code, message),
        };
        let Ok(Some(mut pack)) = self.repo.open_pack(&key) else {
            return emit_error(sink, ErrorCode::KeyNotFound, "pack not found");
        };
        let header = DownloadPackHeader {
            total_bytes: Some(pack.len()),
            ..Default::default()
        };
        send_body(sink, Body::DownloadPackHeader(Box::new(header)))?;
        loop {
            let chunk = match pack.next_chunk() {
                Ok(Some(chunk)) => chunk,
                Ok(None) => return Ok(()),
                Err(_) => return emit_error(sink, ErrorCode::Internal, "pack read failed"),
            };
            let chunk = PackChunk {
                pack_id: req.pack_id.clone(),
                offset: Some(chunk.offset),
                data: Some(chunk.data),
                last: Some(chunk.last),
                ..Default::default()
            };
            send_body(sink, Body::PackChunk(Box::new(chunk)))?;
        }
    }

    /// `UploadPack`: the header, then `PackChunk` frames read from `src`
    /// until `last`. The chunk frames do not count against the session
    /// budget. The upload limits cap them.
    ///
    /// A framing error is answered at once with its message, like a read
    /// failure or a frame that is not a chunk (which the upload consumes).
    /// The partial pack is then discarded, so nothing becomes visible. A
    /// refused write or a storage failure does not end the stream early. The
    /// server reads and checks the rest of the stream, then answers, so the
    /// session stays in frame sync.
    fn upload<S: FrameSource, K: FrameSink>(
        &mut self,
        header: &UploadPack,
        src: &mut S,
        sink: &mut K,
    ) -> Result<(), Stop> {
        let mut framing = match UploadValidator::new(
            header.pack_id.as_deref(),
            header.total_bytes,
            upload_limits(),
        ) {
            Ok(framing) => framing,
            Err(e) => return emit_error(sink, ErrorCode::InvalidRequest, e.message()),
        };
        let mut refused: Option<VerbError> = None;
        let mut writer = if self.may_write() {
            self.repo.begin_upload(framing.key()).ok()
        } else {
            refused = Some(WRITE_NOT_PERMITTED);
            None
        };
        loop {
            let frame = match src.next_frame() {
                Ok(frame) => frame,
                Err(FrameIoError::Timeout) => return Err(Stop::Timeout),
                Err(_) => {
                    let message = UploadError::NoLast.message();
                    return emit_error(sink, ErrorCode::InvalidRequest, message);
                }
            };
            let Some(Body::PackChunk(chunk)) = frame.body else {
                let message = "expected PackChunk after UploadPack";
                return emit_error(sink, ErrorCode::InvalidRequest, message);
            };
            let mut chunk = *chunk;
            let data = chunk.data.take().unwrap_or_default();
            let last = chunk.last.unwrap_or(false);
            let progress =
                match framing.push(chunk.pack_id.as_deref(), chunk.offset, data.len(), last) {
                    Ok(progress) => progress,
                    Err(e) => return emit_error(sink, ErrorCode::InvalidRequest, e.message()),
                };
            if writer.as_mut().is_some_and(|w| w.write(&data).is_err()) {
                writer = None;
            }
            if progress.complete {
                break;
            }
        }
        let Some(writer) = writer else {
            let (code, message) = refused.unwrap_or((ErrorCode::Internal, "upload failed"));
            return emit_error(sink, code, message);
        };
        match writer.finish() {
            Ok(()) => send_body(
                sink,
                Body::UploadPackResponse(Box::<UploadPackResponse>::default()),
            ),
            Err(FinishError::DigestMismatch) => {
                let message = UploadError::DigestMismatch.message();
                emit_error(sink, ErrorCode::InvalidRequest, message)
            }
            Err(FinishError::Io) => emit_error(sink, ErrorCode::Internal, "upload failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use kit_rpc::kit::common::v1::RefExpectation;

    use super::*;

    #[test]
    fn conflict_body_carries_the_current_id() {
        let Body::Error(e) = cas_conflict_body(Some([7; 32])) else {
            panic!("an Error body");
        };
        assert!(e.code.is_some_and(|c| c == ErrorCode::InvalidRequest));
        assert_eq!(e.details.as_deref(), Some(&[7; 32][..]));
        assert_eq!(
            e.message.as_deref(),
            Some("ref update conflict: expectation does not match current ref value")
        );
        let Body::Error(e) = cas_conflict_body(None) else {
            panic!("an Error body");
        };
        assert_eq!(
            e.message.as_deref(),
            Some("ref update conflict: expectation not met and ref is currently absent")
        );
        assert_eq!(e.details.as_deref(), Some(&[][..]));
    }

    #[test]
    fn names_are_refused_by_name() {
        assert!(check_name("refs/heads/main").is_ok());
        // A name that fails the grammar passes: its verb answers it.
        assert!(check_name("refs/heads/.hidden").is_ok());
        assert!(check_name(".main").is_ok());
        assert_eq!(
            check_name("main"),
            Err((ErrorCode::InvalidRequest, REF_NAME_OUTSIDE_REFS))
        );
        let over = format!("refs/heads/{}", "a".repeat(MAX_REF_NAME_BYTES));
        assert_eq!(
            check_name(&over),
            Err((ErrorCode::InvalidRequest, REF_NAME_TOO_LONG))
        );
    }

    #[test]
    fn the_expectation_numbers_match_the_wire_enum() {
        let req = |e: RefExpectation| {
            UpdateRef::default()
                .with_name("refs/heads/a")
                .with_new_id(vec![1; 32])
                .with_expectation(e)
                .with_expected_id(vec![2; 32])
        };
        let cond = |e| decode_update_ref(&req(e)).unwrap().1;
        assert_eq!(cond(RefExpectation::Any), RefWriteCondition::Any);
        assert_eq!(cond(RefExpectation::Missing), RefWriteCondition::Missing);
        assert_eq!(
            cond(RefExpectation::Match),
            RefWriteCondition::Match([2; 32])
        );
    }

    #[test]
    fn a_listing_that_overflows_a_frame_is_refused() {
        let entry = |n: usize| ("a".repeat(n), [0u8; 32]);
        assert!(listing_fits(&[]));
        assert!(listing_fits(&vec![entry(100); 1000]));
        let per_entry = 100 + LISTING_ENTRY_OVERHEAD;
        assert!(listing_fits(&vec![
            entry(100);
            MAX_LISTING_BYTES / per_entry
        ]));
        assert!(!listing_fits(&vec![
            entry(100);
            MAX_LISTING_BYTES / per_entry + 1
        ]));
    }
}
