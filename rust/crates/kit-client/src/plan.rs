use crate::{Error, proto::GetServerInfoResponse};
use kit_core::{
    hash::Hash,
    pack::{self, PackFill, PackWriter, serialized_bound, serialized_limit},
};

/// Ordered canonical input. Staging, closure selection, delta policy and
/// signature policy belong to the host. Delta bases must already be remote.
#[derive(Clone, Debug)]
pub enum Entry {
    Raw { id: Hash, bytes: Vec<u8> },
    Delta { base: Hash, stream: Vec<u8> },
}

/// Tickets one advance may name when the server advertises no limit.
pub const DEFAULT_TICKETS_PER_ADVANCE: u32 = 7;

/// The most tickets a client names in one advance, however many the server
/// advertises.
pub const MAX_TICKETS_PER_ADVANCE: u32 = 1024;

/// The tickets one advance may name: the server's advertised
/// `max_tickets_per_advance`, seven when it advertises none. One ticket is the
/// packmap node's, so a value below two leaves no room for data and is
/// ignored; a value above 1,024 is cut to 1,024.
#[must_use]
pub fn advance_ticket_limit(info: &GetServerInfoResponse) -> u32 {
    match info.max_tickets_per_advance {
        Some(limit) if limit >= 2 => limit.min(MAX_TICKETS_PER_ADVANCE),
        _ => DEFAULT_TICKETS_PER_ADVANCE,
    }
}

/// The data packs one advance may carry when it may name `max_tickets`
/// tickets: one ticket is the packmap node's. A value below two gives zero, so
/// the first ticketed data pack of a plan is refused.
#[must_use]
pub fn data_pack_budget(max_tickets: u32) -> usize {
    (max_tickets as usize).saturating_sub(1)
}

/// Explicit limits for one advance. Larger histories are scheduled as
/// separate advances by the host, with a fresh head lease for each step.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub payload_bytes: u64,
    pub max_pack_bytes: u64,
    pub max_parts: u32,
    pub ticket_threshold_bytes: u64,
    /// Peak retained sealed input, including the packlist node.
    pub max_staged_bytes: u64,
    /// The most upload tickets one advance may name, the packlist node's
    /// included. A plan with more ticketed data packs than one fewer than this
    /// is refused before anything is uploaded; below two, no ticketed data
    /// pack is allowed.
    pub max_tickets: u32,
}

impl Limits {
    pub fn from_server_info(
        info: &crate::proto::GetServerInfoResponse,
        payload_bytes: u64,
        max_staged_bytes: u64,
    ) -> Result<Self, Error> {
        if info.protocol.as_deref() != Some("kit.transport.v1")
            || info.spec_version != Some(2)
            || info.atomic_advance != Some(true)
        {
            return Err(Error::Invalid("ticketed atomic transport required"));
        }
        Ok(Self {
            payload_bytes,
            max_pack_bytes: info
                .max_pack_bytes
                .ok_or(Error::Invalid("server pack limit"))?,
            max_parts: info.max_parts.ok_or(Error::Invalid("server part limit"))?,
            ticket_threshold_bytes: info
                .begin_upload_threshold_bytes
                .ok_or(Error::Invalid("server ticket threshold"))?,
            max_staged_bytes,
            max_tickets: advance_ticket_limit(info),
        })
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            payload_bytes: pack::MAX_TOTAL_PAYLOAD,
            max_pack_bytes: pack::MAX_TOTAL_PAYLOAD,
            max_parts: 8192,
            ticket_threshold_bytes: 0,
            max_staged_bytes: 64 * 1024 * 1024,
            max_tickets: DEFAULT_TICKETS_PER_ADVANCE,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Pack {
    pub(crate) key: Hash,
    pub(crate) bytes: Vec<u8>,
    /// Ids of the objects the pack introduces, known only when every entry is
    /// a raw object (a delta entry's id needs the delta applied).
    pub(crate) objects: Option<Vec<Hash>>,
}

/// The entries of the pack being written, for the observer's object list.
struct Pending {
    ids: Vec<Hash>,
    all_raw: bool,
}
impl Pending {
    fn new() -> Self {
        Self {
            ids: Vec::new(),
            all_raw: true,
        }
    }
    fn take(&mut self) -> Option<Vec<Hash>> {
        let all_raw = std::mem::replace(&mut self.all_raw, true);
        let ids = std::mem::take(&mut self.ids);
        all_raw.then_some(ids)
    }
}

/// Deterministic, bounded sealed data packs. Reusing the same ordered input
/// and pack encoding yields the same pack ids, allowing safe restart.
#[derive(Clone, Debug)]
pub struct Plan {
    pub(crate) packs: Vec<Pack>,
    pub(crate) limits: Limits,
}

impl Plan {
    /// Greedy next-fit, using conservative entry sizes and exact serialized
    /// frame overhead, like the CLI. Does not upload a partial plan.
    pub fn prepare(
        entries: impl IntoIterator<Item = Entry>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.payload_bytes == 0 || limits.max_pack_bytes == 0 || limits.max_parts == 0 {
            return Err(Error::Limit("zero pack limit"));
        }
        // Reserve a prior pointer and the largest u32 length prefix. The
        // empty canonical node has a one-byte prefix, which can grow by four.
        let node_overhead =
            kit_core::transfer::encode_packlist(Some([0; 32]), &[])?.len() as u64 + 4;
        let mut writer = PackWriter::new();
        let mut pending = Pending::new();
        let mut packs = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut staged = 0_u64;
        let cap = limits.payload_bytes.min(pack::MAX_TOTAL_PAYLOAD);
        for entry in entries {
            let size = match &entry {
                Entry::Raw { bytes, .. } => bytes.len() as u64,
                Entry::Delta { stream, .. } => (32 + stream.len()) as u64,
            };
            let incoming = match &entry {
                Entry::Raw { .. } => pack::Incoming::raw(size, size),
                Entry::Delta { base, stream } => {
                    pack::Incoming::delta(size, stream, true, writer.newly_held(base))
                }
            };
            if PackFill::of(&writer).seals_before(
                incoming,
                cap,
                Some(limits.max_pack_bytes),
                pack::MAX_WRITE_ENTRIES,
            ) {
                seal(
                    &mut writer,
                    &mut pending,
                    &mut packs,
                    &mut seen,
                    &mut staged,
                    limits,
                )?;
            }
            // A delta the smallest reader cannot take alone: its result, its
            // stream and its base pass the decoded-byte budget.
            let unreadable =
                matches!(&entry, Entry::Delta { stream, .. } if !pack::delta_fits_reader(stream));
            if size > cap
                || unreadable
                || serialized_bound(size, 1) > serialized_limit(Some(limits.max_pack_bytes))
            {
                return Err(Error::Limit("one entry exceeds pack limit"));
            }
            // Bound memory before accepting an input entry, even if it
            // compresses dramatically. The caller owns its input allocation.
            let pack_count = packs.len().saturating_add(1) as u64;
            let node_bound = node_overhead.saturating_add(pack_count.saturating_mul(32));
            if pack_count > u64::from(kit_core::transfer::PACKLIST_MAX_ENTRIES)
                || node_bound > limits.max_pack_bytes
                || staged
                    .saturating_add(serialized_bound(
                        writer.total_payload().saturating_add(size),
                        writer.entry_count() + 1,
                    ))
                    .saturating_add(node_bound)
                    > limits.max_staged_bytes
            {
                return Err(Error::Limit("staged input/packmap limit"));
            }
            match entry {
                Entry::Raw { id, bytes } => {
                    writer.push_raw(id, &bytes)?;
                    pending.ids.push(id);
                }
                Entry::Delta { base, stream } => {
                    writer.push_delta(&base, &stream)?;
                    pending.all_raw = false;
                }
            }
        }
        seal(
            &mut writer,
            &mut pending,
            &mut packs,
            &mut seen,
            &mut staged,
            limits,
        )?;
        if !packs.is_empty() {
            // Reserve the largest node shape before any upload can reserve
            // server resources. A prior pointer adds 32 bytes.
            let ids: Vec<_> = packs.iter().map(|pack| pack.key).collect();
            let node = kit_core::transfer::encode_packlist(Some([0; 32]), &ids)?;
            if node.len() as u64 > limits.max_pack_bytes
                || staged.saturating_add(node.len() as u64) > limits.max_staged_bytes
            {
                return Err(Error::Limit("packmap node/staged input limit"));
            }
        }
        Ok(Self { packs, limits })
    }

    pub fn pack_ids(&self) -> impl Iterator<Item = &Hash> {
        self.packs.iter().map(|pack| &pack.key)
    }
}

fn seal(
    writer: &mut PackWriter,
    pending: &mut Pending,
    packs: &mut Vec<Pack>,
    seen: &mut std::collections::HashSet<Hash>,
    staged: &mut u64,
    limits: Limits,
) -> Result<(), Error> {
    if writer.entry_count() == 0 {
        return Ok(());
    }
    let bytes = std::mem::take(writer).finish()?;
    let objects = pending.take();
    let key = pack::pack_key(&bytes);
    if !seen.insert(key) {
        return Ok(());
    }
    *staged = staged.saturating_add(bytes.len() as u64);
    if bytes.len() as u64 > serialized_limit(Some(limits.max_pack_bytes))
        || *staged > limits.max_staged_bytes
    {
        return Err(Error::Limit("sealed input limit"));
    }
    // Always reserve one of the advance's ticket slots for the packlist node.
    if bytes.len() as u64 >= limits.ticket_threshold_bytes
        && packs
            .iter()
            .filter(|p| p.bytes.len() as u64 >= limits.ticket_threshold_bytes)
            .count()
            >= data_pack_budget(limits.max_tickets)
    {
        return Err(Error::Limit(
            "advance requires more ticketed data packs than the server allows",
        ));
    }
    packs.push(Pack {
        key,
        bytes,
        objects,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kit_core::{
        object::{Blob, Object},
        serialize::serialize,
    };

    #[test]
    fn ticket_budget_and_packmap_space_are_checked_before_upload() {
        let make = |salt| {
            let bytes = serialize(&Object::Blob(Blob {
                data: vec![salt; 10],
            }))
            .unwrap();
            Entry::Raw {
                id: kit_core::hash::hash(&bytes),
                bytes,
            }
        };
        let limits = Limits {
            payload_bytes: 30,
            max_pack_bytes: 1024,
            ..Limits::default()
        };
        assert!(Plan::prepare((0..6).map(make), limits).is_ok());
        assert!(matches!(
            Plan::prepare((0..7).map(make), limits),
            Err(Error::Limit(_))
        ));
        let limits = Limits {
            max_staged_bytes: 60,
            ..Limits::default()
        };
        assert!(matches!(
            Plan::prepare([make(1)], limits),
            Err(Error::Limit(_))
        ));
    }
    fn tiny_pack_entry(salt: u8) -> Entry {
        let bytes = serialize(&Object::Blob(Blob { data: vec![salt] })).unwrap();
        Entry::Raw {
            id: kit_core::hash::hash(&bytes),
            bytes,
        }
    }

    /// Limits that seal one pack for each entry of `tiny_pack_entry`.
    fn one_entry_per_pack(max_tickets: u32) -> Limits {
        Limits {
            payload_bytes: serialize(&Object::Blob(Blob { data: vec![0] }))
                .unwrap()
                .len() as u64,
            max_pack_bytes: 1024,
            ticket_threshold_bytes: 0,
            max_tickets,
            ..Limits::default()
        }
    }

    #[test]
    fn a_delta_the_smallest_reader_cannot_take_alone_is_refused() {
        // A header that claims a base and a result: a reader with a budget of
        // 1 GiB charges the result, the stream (a compressed entry) and the
        // base together.
        let stream = |base: u32, result: u32| {
            let mut stream = vec![0_u8; kit_core::delta::HEADER_LEN];
            stream[1..5].copy_from_slice(&base.to_le_bytes());
            stream[5..9].copy_from_slice(&result.to_le_bytes());
            stream
        };
        let delta = |base, result| Entry::Delta {
            base: [1; 32],
            stream: stream(base, result),
        };
        let limits = Limits::default();
        let half = 1_u32 << 29;
        // A base and a result of 16 bytes under 512 MiB each, and the nine
        // bytes of the stream, fit.
        assert!(Plan::prepare([delta(half - 16, half - 16)], limits).is_ok());
        // A base and a result of 512 MiB each do not.
        assert!(matches!(
            Plan::prepare([delta(half, half)], limits),
            Err(Error::Limit(_))
        ));
    }

    #[test]
    fn a_single_entry_is_refused_one_byte_over_a_pack_limit() {
        // Large enough that the pack is longer than the packmap node it needs.
        // Bytes zstd cannot shrink, so the pack is as long as its bound.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let data: Vec<u8> = (0..300)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect();
        let bytes = serialize(&Object::Blob(Blob { data })).unwrap();
        let len = bytes.len() as u64;
        let entry = Entry::Raw {
            id: kit_core::hash::hash(&bytes),
            bytes,
        };
        let fits = |payload_bytes, max_pack_bytes| {
            let limits = Limits {
                payload_bytes,
                max_pack_bytes,
                ..Limits::default()
            };
            Plan::prepare([entry.clone()], limits).is_ok()
        };
        let exact = serialized_bound(len, 1);
        assert!(fits(len, exact));
        // The payload cap alone.
        assert!(!fits(len - 1, u64::MAX));
        // The serialized limit alone, and the pack that lands on it.
        assert!(!fits(u64::MAX, exact - 1));
        // A limit above the body limit is cut to it, so a larger one changes nothing.
        assert!(fits(u64::MAX, u64::MAX));
    }

    #[test]
    fn a_pack_is_sealed_before_it_passes_a_limit_a_reader_applies() {
        // The pack ends at the entry bound, however large a pack the server takes.
        let entries = pack::MAX_WRITE_ENTRIES + 3;
        let limits = Limits {
            payload_bytes: pack::MAX_TOTAL_PAYLOAD,
            max_pack_bytes: u64::MAX,
            max_parts: u32::MAX,
            max_staged_bytes: u64::MAX,
            ticket_threshold_bytes: u64::MAX,
            ..Limits::default()
        };
        let plan = Plan::prepare(
            (0..entries as u64).map(|i| {
                let bytes = serialize(&Object::Blob(Blob {
                    data: i.to_le_bytes().to_vec(),
                }))
                .unwrap();
                Entry::Raw {
                    id: kit_core::hash::hash(&bytes),
                    bytes,
                }
            }),
            limits,
        )
        .unwrap();
        let counts: Vec<u32> = plan
            .packs
            .iter()
            .map(|p| u32::from_le_bytes(p.bytes[8..12].try_into().unwrap()))
            .collect();
        assert_eq!(counts, [u32::try_from(pack::MAX_WRITE_ENTRIES).unwrap(), 3]);
    }

    /// A plan whose packs are all below the ticket threshold names no ticket,
    /// and an empty plan uploads nothing. Neither needs a ticket allowance.
    #[test]
    fn a_plan_that_names_no_ticket_needs_no_ticket_allowance() {
        for tickets in [0, 1] {
            let limits = Limits {
                max_tickets: tickets,
                ticket_threshold_bytes: u64::MAX,
                ..Limits::default()
            };
            let one = Plan::prepare([tiny_pack_entry(1)], limits);
            assert!(
                one.is_ok(),
                "{tickets} tickets, one small pack: {:?}",
                one.err()
            );
            let none = Plan::prepare([], limits);
            assert!(
                none.is_ok(),
                "{tickets} tickets, no entry: {:?}",
                none.err()
            );
        }
    }

    #[test]
    fn fewer_than_two_tickets_leave_no_ticketed_data_pack() {
        for tickets in [0, 1] {
            let limits = Limits {
                max_tickets: tickets,
                ..Limits::default()
            };
            assert!(
                matches!(
                    Plan::prepare([tiny_pack_entry(1)], limits),
                    Err(Error::Limit(
                        "advance requires more ticketed data packs than the server allows"
                    ))
                ),
                "{tickets}"
            );
        }
        let limits = Limits {
            max_tickets: 2,
            ..Limits::default()
        };
        assert!(Plan::prepare([tiny_pack_entry(1)], limits).is_ok());
    }

    #[test]
    fn the_ticket_limit_is_the_advertised_value_within_bounds() {
        let limit = |advertised| {
            advance_ticket_limit(&GetServerInfoResponse {
                max_tickets_per_advance: advertised,
                ..GetServerInfoResponse::default()
            })
        };
        assert_eq!(limit(None), 7);
        assert_eq!(limit(Some(0)), 7);
        assert_eq!(limit(Some(1)), 7);
        assert_eq!(limit(Some(2)), 2);
        assert_eq!(limit(Some(8)), 8);
        assert_eq!(limit(Some(1024)), 1024);
        assert_eq!(limit(Some(2000)), 1024);
        assert_eq!(limit(Some(u32::MAX)), 1024);
    }

    #[test]
    fn the_data_pack_budget_is_the_allowance_minus_the_packmap_ticket() {
        assert_eq!(data_pack_budget(2), 1);
        assert_eq!(data_pack_budget(3), 2);
        assert_eq!(data_pack_budget(DEFAULT_TICKETS_PER_ADVANCE), 6);
        assert_eq!(data_pack_budget(1024), 1023);
        // Fewer than two tickets leave no room for a data pack.
        assert_eq!(data_pack_budget(1), 0);
        assert_eq!(data_pack_budget(0), 0);
    }

    #[test]
    fn limits_from_server_info_carry_the_ticket_limit() {
        let info = |advertised| GetServerInfoResponse {
            protocol: Some("kit.transport.v1".to_owned()),
            spec_version: Some(2),
            atomic_advance: Some(true),
            max_pack_bytes: Some(1 << 20),
            max_parts: Some(8),
            begin_upload_threshold_bytes: Some(0),
            max_tickets_per_advance: advertised,
            ..GetServerInfoResponse::default()
        };
        let tickets = |advertised| {
            Limits::from_server_info(&info(advertised), 1 << 16, 1 << 20)
                .unwrap()
                .max_tickets
        };
        assert_eq!(tickets(None), 7);
        assert_eq!(tickets(Some(1)), 7);
        assert_eq!(tickets(Some(2)), 2);
        assert_eq!(tickets(Some(8)), 8);
        assert_eq!(tickets(Some(2000)), 1024);
    }

    #[test]
    fn a_plan_is_refused_one_data_pack_past_the_advertised_limit() {
        // One ticket of the advance is the packlist node's.
        for fits in [1_u8, 2, 7, 15] {
            let limits = one_entry_per_pack(u32::from(fits) + 1);
            let plan = Plan::prepare((0..fits).map(tiny_pack_entry), limits).unwrap();
            assert_eq!(plan.packs.len(), usize::from(fits));
            assert!(
                matches!(
                    Plan::prepare((0..=fits).map(tiny_pack_entry), limits),
                    Err(Error::Limit(_))
                ),
                "{fits}"
            );
        }
    }

    #[test]
    fn a_plan_is_refused_before_the_whole_input_is_consumed() {
        let consumed = std::cell::Cell::new(0_usize);
        let entries = (0..100_u8).map(|salt| {
            consumed.set(consumed.get() + 1);
            tiny_pack_entry(salt)
        });
        assert!(matches!(
            Plan::prepare(entries, one_entry_per_pack(3)),
            Err(Error::Limit(_))
        ));
        assert!(consumed.get() < 10, "{}", consumed.get());
    }

    #[test]
    fn repeated_sealed_packs_keep_first_order_and_use_one_ticket_slot_each() {
        let make = |salt| {
            let bytes = serialize(&Object::Blob(Blob { data: vec![salt] })).unwrap();
            Entry::Raw {
                id: kit_core::hash::hash(&bytes),
                bytes,
            }
        };
        let limits = Limits {
            payload_bytes: serialize(&Object::Blob(Blob { data: vec![0] }))
                .unwrap()
                .len() as u64,
            max_pack_bytes: 1024,
            ticket_threshold_bytes: 0,
            ..Limits::default()
        };
        let expected = Plan::prepare([make(1), make(2)], limits).unwrap();
        let repeated = Plan::prepare((0..16).map(|index| make(1 + index % 2)), limits).unwrap();
        assert_eq!(
            repeated.pack_ids().collect::<Vec<_>>(),
            expected.pack_ids().collect::<Vec<_>>()
        );
        assert_eq!(repeated.packs.len(), 2);
    }
    #[test]
    fn tiny_entries_reject_before_buffering_the_whole_over_budget_plan() {
        let consumed = std::cell::Cell::new(0);
        let entries = (0..100).map(|byte| {
            consumed.set(consumed.get() + 1);
            let bytes = serialize(&Object::Blob(Blob { data: vec![byte] })).unwrap();
            Entry::Raw {
                id: kit_core::hash::hash(&bytes),
                bytes,
            }
        });
        // Payload alone fits exactly. Framing and the reserved packlist do not.
        let payload = serialize(&Object::Blob(Blob { data: vec![0] }))
            .unwrap()
            .len() as u64;
        let limits = Limits {
            max_staged_bytes: 100 * payload,
            ..Limits::default()
        };
        assert!(matches!(
            Plan::prepare(entries, limits),
            Err(Error::Limit(_))
        ));
        assert!(
            consumed.get() < 100,
            "buffered every entry before rejecting the plan"
        );
    }
}
