//! Test-local KDSP reference verifier; no product code or private KDPB types.
use super::*;

type Result<T> = std::result::Result<T, &'static str>;

#[derive(Debug)]
pub(super) struct Span {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub leaf: Hash,
    pub path: Vec<Vec<u8>>,
    pub signature_valid: bool,
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err("span_encoding");
        }
        let (bytes, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(bytes)
    }
    fn number(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn length(&mut self, cap: usize) -> Result<usize> {
        let mut value = 0u32;
        for i in 0..5 {
            let byte = self.take(1)?[0];
            if (i > 0 && byte == 0) || (i == 4 && byte > 15) {
                return Err("span_encoding");
            }
            value |= u32::from(byte & 127) << (7 * i);
            if byte & 128 == 0 {
                let n = value as usize;
                return if n <= cap {
                    Ok(n)
                } else {
                    Err("span_encoding")
                };
            }
        }
        Err("span_encoding")
    }
    fn vector(&mut self) -> Result<&'a [u8]> {
        let n = self.length(CAP.min(self.0.len()))?;
        self.take(n)
    }
}

struct Decoded<'a> {
    commit: Hash,
    offset: u64,
    len: u64,
    chunks: Vec<&'a [u8]>,
}

fn decode(input: &[u8]) -> Result<Decoded<'_>> {
    if input.len() > CAP {
        return Err("span_too_large");
    }
    let mut r = Reader(input);
    if r.take(4)? != b"KDSP" {
        return Err("span_magic");
    }
    if r.take(1)? != [2] {
        return Err("span_version");
    }
    let commit: Hash = r.take(32)?.try_into().unwrap();
    let offset = r.number()?;
    let len = r.number()?;
    let count = r.length(1_000_000)?;
    // Bound allocations by both the declared count and actual remaining input.
    if count > r.0.len() {
        return Err("span_encoding");
    }
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        chunks.push(r.vector()?);
    }
    if !r.0.is_empty() {
        return Err("span_trailing_bytes");
    }
    Ok(Decoded {
        commit,
        offset,
        len,
        chunks,
    })
}

pub(super) fn verify(trusted: &Hash, input: &[u8]) -> Result<Span> {
    let Decoded {
        commit,
        offset,
        len,
        chunks,
    } = decode(input)?;
    let count = chunks.len();
    if &commit != trusted {
        return Err("span_commit");
    }
    let end = offset
        .checked_add(len)
        .filter(|_| len != 0)
        .ok_or("span_range_arithmetic")?;
    if count < 2 {
        return Err("span_chunk_count");
    }
    // Validate in passes, preserving the specification's first-failure order.
    let disclosed: Vec<Disclosed> = chunks
        .iter()
        .map(|b| verify_disclosure(trusted, b).map_err(|_| "span_inner_invalid"))
        .collect::<Result<_>>()?;
    let mut parsed = Vec::with_capacity(count);
    for d in &disclosed {
        let DisclosedPayload::Chunk {
            total_size,
            chunk_size,
            index,
            start,
            end,
            bytes,
        } = &d.payload
        else {
            return Err("span_chunk_selector");
        };
        parsed.push((*total_size, *chunk_size, *index, *start, *end, bytes));
    }
    let first = &disclosed[0];
    if disclosed
        .iter()
        .any(|d| d.path != first.path || d.leaf_id != first.leaf_id)
    {
        return Err("span_leaf_context");
    }
    if disclosed.iter().zip(&parsed).any(|(d, p)| {
        (p.0, p.1, &d.chunk_inner_root) != (parsed[0].0, parsed[0].1, &first.chunk_inner_root)
    }) {
        return Err("span_chunk_context");
    }
    if parsed
        .iter()
        .enumerate()
        .any(|(i, p)| parsed[0].2.checked_add(u32::try_from(i).unwrap()) != Some(p.2))
    {
        return Err("span_chunk_order");
    }
    if parsed.windows(2).any(|pair| pair[0].4 != pair[1].3) {
        return Err("span_chunk_chain");
    }
    let (span_start, first_end) = (parsed[0].3, parsed[0].4);
    let (last_start, span_end) = (parsed[count - 1].3, parsed[count - 1].4);
    if offset < span_start || offset >= first_end || end > span_end {
        return Err("span_range_outside");
    }
    if end <= last_start {
        return Err("span_last_unneeded");
    }
    let mut output = Vec::new();
    for p in &parsed {
        // The inner bundle was verified, so its chunk is a Blob as long as
        // its span.
        let Object::Blob(blob) = deserialize(p.5).unwrap() else {
            unreachable!("a verified chunk is a Blob")
        };
        assert_eq!(blob.data.len() as u64, p.4 - p.3);
        let content = blob.data;
        let (from, to) = (offset.max(p.3), end.min(p.4));
        if from < to {
            output.extend_from_slice(
                &content[usize::try_from(from - p.3).unwrap()..usize::try_from(to - p.3).unwrap()],
            );
        }
    }
    Ok(Span {
        offset,
        bytes: output,
        leaf: first.leaf_id,
        path: first.path.iter().map(|(name, _)| name.clone()).collect(),
        signature_valid: first.signature_valid,
    })
}
