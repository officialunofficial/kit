const MAX_CHAIN_PACKS: usize = crate::read::MAX_CHAIN_PACKS;
const MAX_CHAIN_DEPTH: usize = crate::read::MAX_CHAIN_DEPTH;
use crate::calls;
use crate::connect::{Built, Opts, RESPONSE_LIMIT, Rpc, membership_lag, pending_delay};
use crate::seams::{NoObserver, Observer, RequestPolicy};
use crate::stream::BodyChunks;
use crate::{
    Clock, Destination, Error, HttpTransport, Plan, Signer,
    proto::{
        AdvanceOutcome, AdvanceRefsRequest, AdvanceRefsResponse, GetServerInfoRequest,
        GetServerInfoResponse, PackChunk, ReadRefRequest, ReadRefResponse, RefExpectation,
        UploadPackHeader, UploadPackRequest, UploadPartHeader, UploadPartRequest,
        begin_upload_response, upload_part_request,
    },
};
use buffa::Message;
use kit_core::hash::{hash, to_hex};
use kit_core::{
    hash::Hash,
    protocol::{PackBody, SliceBody},
    refs::{self, RefWriteCondition},
    transfer::packmap::{ChainState, PlanError, plan_advance},
    upload_parts::{PartHasher, PartPlan},
    write_auth::{ContentCommitment, PartCommitment},
};
use std::collections::HashSet;
use std::time::Duration;

const CHUNK_SIZE: usize = 800 * 1024;

/// The host certifies whether the supplied entries contain the whole closure.
/// Reset requires a self-contained plan and an atomic conditioned advance.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum PackmapMode {
    Append { self_contained: bool },
    ResetSelfContained,
}

/// Wire outcomes and reasons requiring host replanning. A conflict never
/// asserts that an earlier ambiguous operation did not commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    Committed,
    HeadConflict,
    PackmapContended,
    TicketRejected,
    PacklistNotInRepository,
    DeltaBaseUnavailable,
}

/// One ticketed advance. The host owns the head lease, input policy, deadline,
/// persistence and scheduling of subsequent advances.
#[derive(Debug)]
pub struct Push {
    destination: Destination,
    head_ref: String,
    packmap_ref: String,
    condition: RefWriteCondition,
    tip: Hash,
    mode: PackmapMode,
    plan: Plan,
    deadline_ms: i64,
}

impl Push {
    pub fn new(
        destination: Destination,
        branch: &str,
        condition: RefWriteCondition,
        tip: Hash,
        mode: PackmapMode,
        plan: Plan,
        deadline_ms: i64,
    ) -> Result<Self, Error> {
        let head_ref = format!("refs/heads/{branch}");
        let packmap_ref = format!("{}{branch}", refs::PACKMAP_REF_PREFIX);
        if !refs::validate_ref_name(&head_ref) || !refs::validate_ref_name(&packmap_ref) {
            return Err(Error::Invalid("ref name"));
        }
        if matches!(mode, PackmapMode::ResetSelfContained)
            && matches!(condition, RefWriteCondition::Any)
        {
            return Err(Error::Invalid("reset requires conditioned atomic advance"));
        }
        Ok(Self {
            destination,
            head_ref,
            packmap_ref,
            condition,
            tip,
            mode,
            plan,
            deadline_ms,
        })
    }

    /// Runs the operation over host boundaries, with no observer. The host
    /// transport may retry
    /// an exact signed request, journal it, add grants or stop on cancellation.
    /// The host clock schedules pending polls without requiring tokio.
    pub async fn run<T: HttpTransport, S: Signer, C: Clock>(
        &self,
        transport: &T,
        signer: &S,
        clock: &C,
    ) -> Result<Outcome, Error> {
        self.run_with(transport, signer, clock, &NoObserver).await
    }

    /// [`Push::run`] with host policy: `observer` runs before every write RPC
    /// of the push (`BeginUpload`, `UploadPack`, `UploadPart`, `CompleteUpload`,
    /// `AdvanceRefs`, `UpdateRef`), once per signed attempt, and the signer sees
    /// each operation. A veto or refusal ends the run with a typed error and
    /// nothing further is sent; earlier steps stay done (uploaded packs stay
    /// unreferenced until a later advance). An upload reports the objects its
    /// pack introduces when every entry of the plan's pack is a raw object.
    // One linear retry loop over upload, advance and head-conflict handling.
    #[allow(clippy::too_many_lines)]
    pub async fn run_with<T: HttpTransport, S: Signer, C: Clock, O: Observer>(
        &self,
        transport: &T,
        signer: &S,
        clock: &C,
        observer: &O,
    ) -> Result<Outcome, Error> {
        let mut rpc = Rpc::signed(
            transport,
            signer,
            clock,
            &self.destination,
            self.deadline_ms,
        )
        .observed(observer);
        let info: GetServerInfoResponse = rpc
            .unary("GetServerInfo", &GetServerInfoRequest::default())
            .await?;
        if info.spec_version != Some(2) || info.atomic_advance != Some(true) {
            return Err(Error::Invalid("ticketed atomic transport required"));
        }
        if self.plan.limits.max_pack_bytes > info.max_pack_bytes.unwrap_or(0)
            || self.plan.limits.max_parts > info.max_parts.unwrap_or(0)
            || self.plan.limits.ticket_threshold_bytes
                != info.begin_upload_threshold_bytes.unwrap_or(0)
            || self.plan.limits.max_tickets > crate::advance_ticket_limit(&info)
        {
            return Err(Error::Invalid("plan limits exceed server capabilities"));
        }
        if self.plan.packs.is_empty() {
            return commit_head(&rpc, &self.head_ref, self.condition, self.tip).await;
        }
        let mut tickets = Vec::new();
        for pack in &self.plan.packs {
            if let Some(ticket) = upload(
                &mut rpc,
                &self.head_ref,
                &pack.key,
                &pack.bytes,
                pack.objects.as_deref(),
                self.plan.limits,
            )
            .await?
            {
                tickets.push(ticket);
            }
        }
        let keys: Vec<_> = self.plan.pack_ids().copied().collect();
        for _ in 0..8 {
            let prior = read_ref(&rpc, &self.packmap_ref).await?;
            // The nodes and listed packs of the chain an appended node links to.
            let mut linked = None;
            let state = match self.mode {
                PackmapMode::ResetSelfContained => ChainState::Reset { prior },
                PackmapMode::Append { self_contained } => match prior {
                    None => ChainState::Missing,
                    Some(root) => match walk_chain(&rpc, root, &self.head_ref).await {
                        Ok((packs, nodes, listed)) => {
                            linked = Some((nodes, listed));
                            ChainState::Append { head: root, packs }
                        }
                        Err(Error::Packlist(_) | Error::Invalid(_)) if self_contained => {
                            ChainState::Reset { prior }
                        }
                        Err(Error::Remote(error))
                            if self_contained && error.code == "not_found" =>
                        {
                            ChainState::Reset { prior }
                        }
                        Err(error) => return Err(error),
                    },
                },
            };
            let node = plan_advance(state, &keys, Some(self.plan.limits.max_pack_bytes)).map_err(
                |error| match error {
                    PlanError::Packlist(error) => Error::Packlist(error),
                    PlanError::NodeTooLarge => Error::Limit("packmap node"),
                },
            )?;
            let Some(node) = node else {
                return commit_head(&rpc, &self.head_ref, self.condition, self.tip).await;
            };
            // An appended node lists every key. Refuse a chain a reader would
            // refuse to walk before the node is uploaded.
            if let Some((nodes, listed)) = linked
                && (nodes >= MAX_CHAIN_DEPTH || listed.saturating_add(keys.len()) > MAX_CHAIN_PACKS)
            {
                return Err(Error::Limit("packmap chain past the fetch bounds"));
            }
            let node_ticket = upload(
                &mut rpc,
                &self.head_ref,
                &node.key,
                &node.bytes,
                None,
                self.plan.limits,
            )
            .await?;
            let (head_expectation, head_expected_id) = condition(self.condition);
            let (packmap_expectation, packmap_expected_id) = condition(node.condition);
            let request = AdvanceRefsRequest {
                head_ref: Some(self.head_ref.clone()),
                head_expectation: Some(head_expectation.into()),
                head_expected_id,
                head_new_id: Some(self.tip.to_vec()),
                packmap_ref: Some(self.packmap_ref.clone()),
                packmap_expectation: Some(packmap_expectation.into()),
                packmap_expected_id,
                packmap_new_id: Some(node.key.to_vec()),
                ticket_ids: tickets
                    .iter()
                    .copied()
                    .chain(node_ticket)
                    .map(|id| id.to_vec())
                    .collect(),
                ..Default::default()
            };
            let result = advance(&rpc, &request).await;
            match result {
                Ok(response) => match response.outcome.and_then(|outcome| outcome.as_known()) {
                    Some(AdvanceOutcome::Committed) => return Ok(Outcome::Committed),
                    Some(AdvanceOutcome::PackmapConflict) => {}
                    Some(AdvanceOutcome::HeadConflict) => {
                        return head_conflict(&rpc, &self.head_ref, self.tip).await;
                    }
                    _ => return Err(Error::Invalid("advance outcome")),
                },
                Err(Error::Remote(error))
                    if error.code == "failed_precondition" && !request.ticket_ids.is_empty() =>
                {
                    if error.message == "delta base not available in this repository" {
                        return Ok(Outcome::DeltaBaseUnavailable);
                    }
                    if read_ref(&rpc, &self.head_ref).await? == Some(self.tip) {
                        return Ok(Outcome::Committed);
                    }
                    return Ok(Outcome::TicketRejected);
                }
                Err(Error::Remote(error))
                    if error.code == "invalid_argument"
                        && error.message
                            == "packlist lists a pack that is not in this repository" =>
                {
                    if read_ref(&rpc, &self.head_ref).await? == Some(self.tip) {
                        return Ok(Outcome::Committed);
                    }
                    return Ok(Outcome::PacklistNotInRepository);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Outcome::PackmapContended)
    }
}

// The upload steps share one ticket/deadline state across the single-part
// and multipart paths; splitting them would thread that state through helpers.
#[allow(clippy::too_many_lines)]
async fn upload<T: HttpTransport, S: Signer, C: Clock, O: Observer, P: RequestPolicy + ?Sized>(
    rpc: &mut Rpc<'_, T, S, C, O, P>,
    head_ref: &str,
    key: &Hash,
    bytes: &[u8],
    objects: Option<&[Hash]>,
    limits: crate::Limits,
) -> Result<Option<Hash>, Error> {
    let ticket = if bytes.len() as u64 >= limits.ticket_threshold_bytes {
        let (response, _) =
            calls::begin_upload(rpc, head_ref, key, bytes.len() as u64, objects, None).await?;
        match response.result {
            Some(begin_upload_response::Result::AlreadyPresent(_)) => return Ok(None),
            Some(begin_upload_response::Result::Ticket(ticket)) => Some(ticket),
            _ => return Err(Error::Invalid("BeginUpload outcome")),
        }
    } else {
        None
    };
    let id = if let Some(ticket) = &ticket {
        let id: Hash = ticket
            .id
            .as_deref()
            .ok_or(Error::Invalid("ticket id"))?
            .try_into()
            .map_err(|_| Error::Invalid("ticket id"))?;
        let part_size = ticket.part_size.ok_or(Error::Invalid("ticket part size"))?;
        if part_size < 8 * 1024 * 1024
            || !part_size.is_power_of_two()
            || ticket.token.as_deref().is_none_or(<[u8]>::is_empty)
        {
            return Err(Error::Invalid("ticket geometry/token"));
        }
        rpc.deadline_ms = rpc.deadline_ms.min(
            ticket
                .expires_unix_ms
                .ok_or(Error::Invalid("ticket expiry"))?,
        );
        if rpc
            .auth
            .is_some_and(|(_, clock)| rpc.deadline_ms <= clock.now_ms())
        {
            return Err(Error::Deadline);
        }
        Some(id)
    } else {
        None
    };
    if let (Some(ticket), Some(id)) = (&ticket, id)
        && bytes.len() as u64 > ticket.part_size.unwrap_or(0)
    {
        let plan = PartPlan::new(
            bytes.len() as u64,
            ticket.part_size.unwrap_or(0),
            limits.max_parts,
        )
        .map_err(|_| Error::Limit("multipart geometry"))?;
        let mut receipts = Vec::new();
        for index in 0..plan.count() {
            let (response, _) = calls::upload_part(
                rpc,
                id,
                ticket.token.clone(),
                &plan,
                index,
                &SliceBody(bytes),
                objects,
                None,
            )
            .await?;
            let receipt = response
                .receipt
                .filter(|receipt| !receipt.is_empty() && receipt.len() <= 512)
                .ok_or(Error::Invalid("part receipt"))?;
            receipts.push(receipt);
        }
        calls::complete_upload(rpc, Some(id), ticket.token.clone(), receipts, objects, None)
            .await?;
    } else {
        calls::upload_pack(
            rpc,
            key,
            &SliceBody(bytes),
            id,
            ticket.as_ref().and_then(|ticket| ticket.token.clone()),
            objects,
            None,
        )
        .await?;
    }
    Ok(id)
}

/// The `UploadPack` stream: a header, then ordered chunks ending in `last`,
/// read from `body` one chunk at a time. An empty pack sends one empty `last`
/// chunk.
pub(crate) fn pack_messages<'a>(
    key: &Hash,
    body: &'a dyn PackBody,
    ticket_token: Option<Vec<u8>>,
) -> impl Iterator<Item = Result<UploadPackRequest, Error>> + 'a {
    let key = *key;
    let total = body.len();
    let header = UploadPackRequest {
        body: Some(
            UploadPackHeader {
                pack_id: Some(key.to_vec()),
                total_bytes: Some(total),
                ticket_token,
                ..Default::default()
            }
            .into(),
        ),
        ..Default::default()
    };
    let mut chunks = BodyChunks::new(body, 0, total);
    let mut ended = false;
    let chunks = std::iter::from_fn(move || {
        if ended {
            return None;
        }
        let offset = chunks.position();
        let message = chunks.next_chunk(CHUNK_SIZE).map(|data| UploadPackRequest {
            body: Some(
                PackChunk {
                    pack_id: Some(key.to_vec()),
                    offset: Some(offset),
                    data: Some(data),
                    last: Some(chunks.done()),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        });
        ended = message.is_err() || chunks.done();
        Some(message)
    });
    std::iter::once(Ok(header)).chain(chunks)
}

pub(crate) fn pack_commitment(key: &Hash, body: &dyn PackBody) -> String {
    ContentCommitment::Pack {
        id: *key,
        len: body.len(),
    }
    .to_string()
}

/// The `UploadPart` stream: a header, then part `index` of `body` in chunks,
/// read one chunk at a time.
pub(crate) fn part_messages<'a>(
    ticket_token: Option<Vec<u8>>,
    plan: &PartPlan,
    index: u32,
    body: &'a dyn PackBody,
) -> Result<impl Iterator<Item = Result<UploadPartRequest, Error>> + 'a, Error> {
    let (offset, len) = part_range(plan, index)?;
    let header = UploadPartRequest {
        msg: Some(
            UploadPartHeader {
                ticket_token,
                index: Some(index),
                ..Default::default()
            }
            .into(),
        ),
        ..Default::default()
    };
    let mut chunks = BodyChunks::new(body, offset, len);
    let mut ended = false;
    let chunks = std::iter::from_fn(move || {
        if ended || chunks.done() {
            return None;
        }
        let message = chunks
            .next_chunk(CHUNK_SIZE)
            .map(|bytes| UploadPartRequest {
                msg: Some(upload_part_request::Msg::Chunk(bytes)),
                ..Default::default()
            });
        ended = message.is_err();
        Some(message)
    });
    Ok(std::iter::once(Ok(header)).chain(chunks))
}

/// The offset and length of part `index`.
fn part_range(plan: &PartPlan, index: u32) -> Result<(u64, u64), Error> {
    let offset = plan
        .offset(index)
        .map_err(|_| Error::Invalid("part offset"))?;
    let len = plan
        .expected_len(index)
        .map_err(|_| Error::Invalid("part length"))?;
    Ok((offset, len))
}

/// The signed commitment of part `index` of `body` (SPEC-TRANSPORT-CONNECT
/// §7.6), hashed from the body one chunk at a time.
pub(crate) fn part_commitment(
    ticket: Hash,
    plan: &PartPlan,
    index: u32,
    body: &dyn PackBody,
) -> Result<String, Error> {
    let (offset, len) = part_range(plan, index)?;
    let mut hasher = PartHasher::new(plan, index).map_err(|_| Error::Invalid("part hash"))?;
    let mut chunks = BodyChunks::new(body, offset, len);
    while !chunks.done() {
        hasher
            .update(&chunks.next_chunk(CHUNK_SIZE)?)
            .map_err(|_| Error::Invalid("part hash"))?;
    }
    Ok(ContentCommitment::Part(PartCommitment {
        ticket,
        index,
        subtree: hasher.finalize().map_err(|_| Error::Invalid("part hash"))?,
        len,
    })
    .to_string())
}

pub(crate) fn condition(condition: RefWriteCondition) -> (RefExpectation, Option<Vec<u8>>) {
    match condition {
        RefWriteCondition::Any => (RefExpectation::Any, None),
        RefWriteCondition::Missing => (RefExpectation::Missing, None),
        RefWriteCondition::Match(hash) => (RefExpectation::Match, Some(hash.to_vec())),
    }
}

async fn read_ref<T: HttpTransport, S: Signer, C: Clock, O: Observer, P: RequestPolicy + ?Sized>(
    rpc: &Rpc<'_, T, S, C, O, P>,
    name: &str,
) -> Result<Option<Hash>, Error> {
    let response: ReadRefResponse = rpc
        .unary(
            "ReadRef",
            &ReadRefRequest {
                name: Some(name.to_owned()),
                ..Default::default()
            },
        )
        .await?;
    match response.exists {
        Some(false) => Ok(None),
        Some(true) => response
            .object_id
            .as_deref()
            .ok_or(Error::Invalid("ref value"))?
            .try_into()
            .map(Some)
            .map_err(|_| Error::Invalid("ref value")),
        _ => Err(Error::Invalid("ref presence")),
    }
}

async fn walk_chain<
    T: HttpTransport,
    S: Signer,
    C: Clock,
    O: Observer,
    P: RequestPolicy + ?Sized,
>(
    rpc: &Rpc<'_, T, S, C, O, P>,
    root: Hash,
    head_ref: &str,
) -> Result<(HashSet<Hash>, usize, usize), Error> {
    let mut packs = HashSet::new();
    let (mut nodes, mut listed) = (0_usize, 0_usize);
    crate::read::walk_nodes(rpc, root, head_ref, |node| {
        nodes += 1;
        listed = listed.saturating_add(node.packs.len());
        packs.extend(node.packs.iter().copied());
        if packs.len() > MAX_CHAIN_PACKS {
            return Err(Error::Limit("packmap pack count"));
        }
        Ok(node.prev)
    })
    .await?;
    Ok((packs, nodes, listed))
}

/// One `AdvanceRefs` with the whole-push waits: poll a definitive pending or
/// membership-lag answer on the host clock, keeping the same signed identity
/// until it expires. Per-RPC calls never wait; this loop is the only place the
/// crate calls `Clock::wait`.
pub(crate) async fn advance<
    T: HttpTransport,
    S: Signer,
    C: Clock,
    O: Observer,
    P: RequestPolicy + ?Sized,
>(
    rpc: &Rpc<'_, T, S, C, O, P>,
    message: &AdvanceRefsRequest,
) -> Result<AdvanceRefsResponse, Error> {
    let (_, clock) = rpc.auth.ok_or(Error::Invalid("signed client required"))?;
    let body = message.encode_to_vec();
    let commitment = format!("body:{}", to_hex(&hash(&body)));
    let advance = calls::Advance::from_request(message)?;
    let intent = advance.intent();
    let opts = Opts {
        intent: Some(&intent),
        ..Opts::default()
    };
    // Each signing is a new attempt; resends of the same signed bytes are not.
    let attempts = std::cell::Cell::new(0_u32);
    let sign = || {
        attempts.set(attempts.get() + 1);
        rpc.build(
            "AdvanceRefs",
            body.clone(),
            &commitment,
            false,
            opts,
            attempts.get(),
        )
    };
    let expiry = |built: &Built| built.identity.map_or(i64::MAX, |id| id.expires_at_ms);
    let mut built = sign().await?;
    let mut expires = expiry(&built);
    let mut lag_start = None;
    let mut saw_pending = false;
    let mut renewed_after_unauthenticated = false;
    loop {
        let now = clock.now_ms();
        if now >= rpc.deadline_ms {
            return Err(Error::Deadline);
        }
        // Only a definitive pending/lag answer reaches this continuation.
        // Keep exactly the same nonce and timestamps until actual expiry.
        if now >= expires {
            built = sign().await?;
            expires = expiry(&built);
        }
        match rpc.send(&built.request, RESPONSE_LIMIT).await {
            Ok((bytes, _)) => {
                return AdvanceRefsResponse::decode_from_slice(&bytes)
                    .map_err(|_| Error::Invalid("advance protobuf"));
            }
            Err(Error::Remote(error)) => {
                // A post-pending authentication rejection is definitive,
                // including expiry in transit or a small server clock lead.
                // Recover once; an ambiguous transport error never reaches here.
                if saw_pending && !renewed_after_unauthenticated && error.code == "unauthenticated"
                {
                    renewed_after_unauthenticated = true;
                    built = sign().await?;
                    expires = expiry(&built);
                    continue;
                }
                let delay = if let Some(delay) = pending_delay(&error) {
                    lag_start = None;
                    renewed_after_unauthenticated = false;
                    delay
                } else if !message.ticket_ids.is_empty() && membership_lag(&error) {
                    let start = *lag_start.get_or_insert(now);
                    if now.saturating_sub(start) >= 60_000 {
                        return Err(Error::Remote(error));
                    }
                    Duration::from_secs(2)
                } else {
                    return Err(Error::Remote(error));
                };
                saw_pending = true;
                if now.saturating_add(i64::try_from(delay.as_millis()).unwrap_or(i64::MAX))
                    >= rpc.deadline_ms
                {
                    return Err(Error::Deadline);
                }
                clock.wait(delay).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn commit_head<
    T: HttpTransport,
    S: Signer,
    C: Clock,
    O: Observer,
    P: RequestPolicy + ?Sized,
>(
    rpc: &Rpc<'_, T, S, C, O, P>,
    name: &str,
    lease: RefWriteCondition,
    tip: Hash,
) -> Result<Outcome, Error> {
    match calls::update_ref(rpc, name, lease, Some(tip), None).await {
        Ok(_) => Ok(Outcome::Committed),
        Err(Error::Remote(error)) if error.code == "failed_precondition" => {
            head_conflict(rpc, name, tip).await
        }
        Err(error) => Err(error),
    }
}
async fn head_conflict<
    T: HttpTransport,
    S: Signer,
    C: Clock,
    O: Observer,
    P: RequestPolicy + ?Sized,
>(
    rpc: &Rpc<'_, T, S, C, O, P>,
    name: &str,
    tip: Hash,
) -> Result<Outcome, Error> {
    Ok(if read_ref(rpc, name).await? == Some(tip) {
        Outcome::Committed
    } else {
        Outcome::HeadConflict
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_upload_has_an_explicit_last_chunk() {
        let key = kit_core::pack::pack_key(b"");
        let messages: Vec<_> = pack_messages(&key, &SliceBody(b""), None)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(messages.len(), 2, "header plus empty final chunk");
        let Some(crate::proto::upload_pack_request::Body::Chunk(chunk)) = &messages[1].body else {
            panic!("missing final chunk");
        };
        assert_eq!(chunk.offset, Some(0));
        assert_eq!(chunk.data.as_deref(), Some(b"".as_slice()));
        assert_eq!(chunk.last, Some(true));
    }

    /// The streamed messages are the ones the in-memory builder sent: the
    /// same chunk size, offsets and `last` marker.
    #[test]
    fn upload_chunks_keep_their_size_offsets_and_last_marker() {
        let bytes: Vec<u8> = (0..(2 * CHUNK_SIZE + 7))
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let key = kit_core::pack::pack_key(&bytes);
        let messages: Vec<_> = pack_messages(&key, &SliceBody(&bytes), None)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(messages.len(), 4);
        let mut rebuilt = Vec::new();
        for (index, message) in messages[1..].iter().enumerate() {
            let Some(crate::proto::upload_pack_request::Body::Chunk(chunk)) = &message.body else {
                panic!("missing chunk");
            };
            assert_eq!(chunk.offset, Some((index * CHUNK_SIZE) as u64));
            assert_eq!(chunk.last, Some(index == 2));
            rebuilt.extend_from_slice(chunk.data.as_deref().unwrap());
        }
        assert_eq!(rebuilt, bytes);
    }
}
