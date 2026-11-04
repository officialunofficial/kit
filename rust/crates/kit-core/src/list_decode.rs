//! Bounded decoding of hostile length-prefixed lists.
//!
//! The generic `Vec<T>` decode of `commonware-codec` reserves
//! `min(len, remaining)` elements before it reads the first one, where `len`
//! is the declared length and `remaining` is the number of unread input
//! bytes. A hostile prefix then reserves `size_of::<T>()` bytes for each
//! input byte, up to the length cap. [`read_list`] reserves at most what the
//! unread input can hold, so the reservation stays proportional to the input.

use commonware_codec::{Buf, Error as CodecError, RangeCfg, Read};

/// The number of elements to reserve for a list that declares `len`
/// elements of at least `min_encoded` bytes each, with `remaining` unread
/// bytes. No valid list holds more than `remaining / min_encoded` elements.
fn reservation(len: usize, remaining: usize, min_encoded: usize) -> usize {
    len.min(remaining / min_encoded.max(1))
}

/// Read a length-prefixed list of at most `max_len` elements.
///
/// `min_encoded` is the fewest bytes that one element occupies on the wire.
/// The length prefix and the elements decode exactly as the `Vec<T>` decode
/// does: an over-cap length is [`CodecError::InvalidLength`], and a list that
/// runs past the input is the error of the first element that does not fit.
/// Only the reservation differs: it never exceeds `remaining / min_encoded`
/// elements, whatever length the prefix declares.
pub(crate) fn read_list<T: Read>(
    reader: &mut impl Buf,
    max_len: usize,
    min_encoded: usize,
    cfg: &T::Cfg,
) -> Result<Vec<T>, CodecError> {
    let len = usize::read_cfg(reader, &RangeCfg::new(..=max_len))?;
    let mut list = Vec::with_capacity(reservation(len, reader.remaining(), min_encoded));
    for _ in 0..len {
        list.push(T::read_cfg(reader, cfg)?);
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf as _;
    use commonware_codec::{Copying, Encode as _, ReadExt as _};

    #[test]
    fn reservation_follows_the_input_not_the_declared_length() {
        // About 1 MB of input cannot hold 1,000,000 elements of 42 bytes.
        assert_eq!(reservation(1_000_000, 1_000_000, 42), 23_809);
        assert_eq!(reservation(1_000_000, 100, 42), 2);
        assert_eq!(reservation(1_000_000, 0, 42), 0);
        // A short declared length reserves only what it declares.
        assert_eq!(reservation(3, 1_000_000, 42), 3);
        // A zero minimum does not divide by zero.
        assert_eq!(reservation(10, 4, 0), 4);
    }

    #[test]
    fn declared_length_over_the_cap_is_rejected() {
        let bytes = 70_000usize.encode();
        let mut input = Copying(&bytes[..]);
        assert!(matches!(
            read_list::<[u8; 4]>(&mut input, 1_000, 4, &()),
            Err(CodecError::InvalidLength(70_000))
        ));
    }

    #[test]
    fn huge_declared_length_with_short_input_is_end_of_buffer() {
        // Declares 1,000,000 elements of 32 bytes, then holds 100 bytes.
        let mut bytes = 1_000_000usize.encode().to_vec();
        bytes.extend_from_slice(&[7u8; 100]);
        let mut input = Copying(&bytes[..]);
        assert!(matches!(
            read_list::<[u8; 32]>(&mut input, 1_000_000, 32, &()),
            Err(CodecError::EndOfBuffer)
        ));
    }

    #[test]
    fn a_valid_list_decodes_to_the_elements_in_order() {
        let mut bytes = 3usize.encode().to_vec();
        for n in 1u8..=3 {
            bytes.extend_from_slice(&[n; 32]);
        }
        let mut input = Copying(&bytes[..]);
        let list = read_list::<[u8; 32]>(&mut input, 10, 32, &()).unwrap();
        assert_eq!(list, vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        assert_eq!(list.capacity(), 3);
        assert_eq!(input.remaining(), 0);
        // The next read on the same buffer is a clean end of input.
        assert!(u8::read(&mut input).is_err());
    }
}
