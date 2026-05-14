//! Modern OP_MSG opcode (`2013`).
//!
//! Every command issued by current MongoDB drivers is carried in an OP_MSG.
//! The opcode supports a flag bitfield (see [`OperationMessageFlags`]),
//! multiple "sections" (only kind-0 / single document is implemented here),
//! and an optional CRC-32C checksum.

use std::num::NonZeroI32;

use bitflags::bitflags;
use tokio_util::bytes::{BufMut, BytesMut};

use crate::{header::MessageHeader, op_code::OPCode};

/// Mask of the bits the spec classifies as *required* (`0..16`).
///
/// Parsers MUST error on an unknown required bit. Unknown optional bits
/// (`16..32`) are silently cleared.
const REQUIRED_BITS_MASK: u32 = 0x0000_FFFF;

bitflags! {
    /// `flagBits` bitmask carried in the first four bytes of an OP_MSG body.
    ///
    /// The MongoDB wire spec splits the bits into two halves:
    ///
    /// * **required** (`0..16`) — parsers MUST error on an unknown bit set
    ///   here. Mutating proxies must preserve known required bits verbatim.
    /// * **optional** (`16..32`) — parsers MUST ignore unknown bits, and
    ///   proxies MUST clear unknown optional bits before forwarding.
    ///
    /// This crate implements both halves of that contract in
    /// [`OperationMessage::from_bytes`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperationMessageFlags: u32 {
        /// The message ends with a four-byte CRC-32C checksum.
        const CHECKSUM_PRESENT = 1 << 0;
        /// On a request: fire-and-forget — server will not reply.
        ///
        /// On a reply: another reply for the same request will follow on this
        /// socket without the client sending anything (streaming SDAM /
        /// exhaust cursors).
        const MORE_TO_COME = 1 << 1;
        /// On a request: the client is prepared to receive a stream of
        /// replies using `MORE_TO_COME`. Server will not stream unless the
        /// originating request had this set.
        const EXHAUST_ALLOWED = 1 << 16;
    }
}

/// Modern OP_MSG message body.
///
/// Only kind-0 (single BSON document) sections are modelled; kind-1
/// (document sequence) sections are not yet supported. Most user-visible
/// commands (`find`, `insert`, `aggregate`, etc.) use kind-0 in practice.
///
/// # Examples
///
/// Round-trip an OP_MSG body through the wire encoding:
///
/// ```
/// use bson::doc;
/// use mongod_proxy::header::MessageHeader;
/// use mongod_proxy::message::Message;
/// use mongod_proxy::operation::Operation;
/// use mongod_proxy::operation::op_msg::{OperationMessage, OperationMessageFlags};
/// use tokio_util::bytes::BytesMut;
///
/// let msg = Message {
///     request_id: 42,
///     response_to: None,
///     operation: Operation::Message(OperationMessage {
///         flags: OperationMessageFlags::MORE_TO_COME,
///         sections: doc! { "find": "movies", "$db": "sample" },
///         checksum: None,
///     }),
/// };
///
/// let mut buf = BytesMut::new();
/// msg.write_bytes(&mut buf).unwrap();
/// // Skip the header so we feed only the body bytes to OperationMessage.
/// let body = &buf[MessageHeader::size()..];
/// let parsed = OperationMessage::from_bytes(body).unwrap();
/// assert!(parsed.flags.contains(OperationMessageFlags::MORE_TO_COME));
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct OperationMessage {
    /// `flagBits` field controlling checksum, streaming, etc.
    pub flags: OperationMessageFlags,
    /// The kind-0 body section as a single BSON document. By convention the
    /// first key is the command name (`find`, `insert`, ...).
    pub sections: bson::Document,
    /// `Some(crc)` when [`OperationMessageFlags::CHECKSUM_PRESENT`] is set on
    /// the wire. The proxy preserves it across round-trips; it does not
    /// currently validate the CRC against the rest of the message.
    pub checksum: Option<u32>,
}

/// Failure modes for [`OperationMessage::from_bytes`].
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationMessageParseError {
    /// Body shorter than the unconditional minimum (flag bits + kind byte).
    #[error("not enough bytes, expected at least {min} bytes, got {actual}")]
    NotEnoughBytes { actual: usize, min: usize },
    /// One or more *required* flag bits (`0..16`) set are not understood.
    /// The included `u32` is the unknown bits only (known bits masked off).
    #[error("unknown required flag bits set: {0:#010x}")]
    UnknownRequiredBits(u32),
    /// First section's `kind` byte was not `0`. Only kind-0 (body) sections
    /// are implemented.
    #[error("invalid kind, expected 0, got {0}")]
    InvalidKind(u8),
    /// `CHECKSUM_PRESENT` flag set but fewer than four trailing bytes remain.
    #[error("checksum is missing")]
    MissingChecksum,
    /// BSON parsing of the section document failed.
    #[error("failed to parse bson: {0}")]
    InvalidBson(String),
}

/// Failure modes for [`OperationMessage::write_bytes`].
#[derive(Debug, thiserror::Error)]
pub enum OperationMessageWriteError {
    /// Serialising `sections` to BSON failed.
    #[error("failed to serialize sections: {0}")]
    SerializeError(#[from] bson::ser::Error),
}

impl OperationMessage {
    /// Smallest possible OP_MSG body size in bytes (`flagBits` + first
    /// section's `kind` byte). Empty BSON sections add more on top of this.
    pub const fn min_len() -> usize {
        size_of::<u32>() + size_of::<u8>()
    }

    /// Parses an OP_MSG body. `bytes` must NOT include the 16-byte
    /// [`MessageHeader`]; the caller is expected to have stripped it off.
    ///
    /// # Errors
    ///
    /// See [`OperationMessageParseError`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OperationMessageParseError> {
        let actual_len = bytes.len();
        let min_len = Self::min_len();

        if actual_len < min_len {
            return Err(OperationMessageParseError::NotEnoughBytes {
                actual: actual_len,
                min: min_len,
            });
        }

        let raw_flags = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let unknown_required =
            (raw_flags & REQUIRED_BITS_MASK) & !OperationMessageFlags::all().bits();
        if unknown_required != 0 {
            return Err(OperationMessageParseError::UnknownRequiredBits(
                unknown_required,
            ));
        }
        // from_bits_truncate clears unknown optional bits (16-31) per spec.
        let flags = OperationMessageFlags::from_bits_truncate(raw_flags);

        let kind = bytes[4];
        if kind != 0 {
            return Err(OperationMessageParseError::InvalidKind(kind));
        }

        let bytes = &bytes[min_len..];

        let (bytes, checksum) = if flags.contains(OperationMessageFlags::CHECKSUM_PRESENT) {
            let checksum_len = size_of::<u32>();
            if bytes.len() < checksum_len {
                return Err(OperationMessageParseError::MissingChecksum);
            }
            let body_len = bytes.len() - checksum_len;
            let (body, checksum_bytes) = bytes.split_at(body_len);
            let checksum = u32::from_le_bytes([
                checksum_bytes[0],
                checksum_bytes[1],
                checksum_bytes[2],
                checksum_bytes[3],
            ]);
            (body, Some(checksum))
        } else {
            (bytes, None)
        };

        let sections = bson::Document::from_reader(bytes)
            .map_err(|e| OperationMessageParseError::InvalidBson(e.to_string()))?;

        Ok(Self {
            checksum,
            flags,
            sections,
        })
    }

    /// Appends a full OP_MSG frame (header + body) to `dst`.
    ///
    /// The function unconditionally sets / clears
    /// [`OperationMessageFlags::CHECKSUM_PRESENT`] to match whether
    /// `self.checksum` is `Some` — so the bit and the trailing checksum
    /// bytes cannot disagree on the wire.
    ///
    /// # Errors
    ///
    /// See [`OperationMessageWriteError`].
    pub fn write_bytes(
        &self,
        dst: &mut BytesMut,
        request_id: i32,
        response_to: Option<NonZeroI32>,
    ) -> Result<(), OperationMessageWriteError> {
        let body_bytes = bson::to_vec(&self.sections)?;

        // Re-derive checksum-present flag from struct state to avoid mismatch.
        let mut flags = self.flags;
        flags.set(
            OperationMessageFlags::CHECKSUM_PRESENT,
            self.checksum.is_some(),
        );

        let checksum_len = if self.checksum.is_some() {
            size_of::<u32>()
        } else {
            0
        };

        let message_length = MessageHeader::size()
            + size_of::<u32>()
            + size_of::<u8>()
            + body_bytes.len()
            + checksum_len;

        dst.reserve(message_length);

        let header = MessageHeader {
            message_length: message_length as i32,
            op_code: OPCode::Msg,
            request_id,
            response_to,
        };
        header.write_bytes(dst);

        dst.put_u32_le(flags.bits());
        dst.put_u8(0);
        dst.put(body_bytes.as_slice());

        if let Some(checksum) = self.checksum {
            dst.put_u32_le(checksum);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    fn sample_doc() -> bson::Document {
        doc! { "hello": 1 }
    }

    #[test]
    fn round_trip_preserves_more_to_come_flag() {
        let msg = OperationMessage {
            flags: OperationMessageFlags::MORE_TO_COME,
            sections: sample_doc(),
            checksum: None,
        };
        let mut buf = BytesMut::new();
        msg.write_bytes(&mut buf, 1, None).unwrap();
        // Skip 16-byte header to reach flags.
        let raw_flags = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        assert_eq!(
            raw_flags,
            OperationMessageFlags::MORE_TO_COME.bits(),
            "self.flags must be written, not empty"
        );
    }

    #[test]
    fn round_trip_with_checksum() {
        let msg = OperationMessage {
            flags: OperationMessageFlags::empty(),
            sections: sample_doc(),
            checksum: Some(0xDEADBEEF),
        };
        let mut buf = BytesMut::new();
        msg.write_bytes(&mut buf, 1, None).unwrap();

        let body = &buf[MessageHeader::size()..];
        let parsed = OperationMessage::from_bytes(body).unwrap();
        assert_eq!(parsed.checksum, Some(0xDEADBEEF));
        assert!(
            parsed
                .flags
                .contains(OperationMessageFlags::CHECKSUM_PRESENT)
        );
        assert_eq!(parsed.sections, sample_doc());
    }

    #[test]
    fn parse_errors_on_unknown_required_bit() {
        let mut body = Vec::new();
        // Use bit 2 (unknown required).
        body.extend_from_slice(&(1u32 << 2).to_le_bytes());
        body.push(0); // kind
        let doc_bytes = bson::to_vec(&sample_doc()).unwrap();
        body.extend_from_slice(&doc_bytes);

        let err = OperationMessage::from_bytes(&body).unwrap_err();
        assert!(matches!(
            err,
            OperationMessageParseError::UnknownRequiredBits(_)
        ));
    }

    #[test]
    fn parse_clears_unknown_optional_bits() {
        let mut body = Vec::new();
        // Set bit 17 (unknown optional) — must be silently cleared per spec.
        body.extend_from_slice(&(1u32 << 17).to_le_bytes());
        body.push(0);
        let doc_bytes = bson::to_vec(&sample_doc()).unwrap();
        body.extend_from_slice(&doc_bytes);

        let parsed = OperationMessage::from_bytes(&body).unwrap();
        assert_eq!(parsed.flags, OperationMessageFlags::empty());
    }

    #[test]
    fn parse_round_trips_exhaust_allowed_at_bit_16() {
        let msg = OperationMessage {
            flags: OperationMessageFlags::EXHAUST_ALLOWED,
            sections: sample_doc(),
            checksum: None,
        };
        let mut buf = BytesMut::new();
        msg.write_bytes(&mut buf, 1, None).unwrap();
        let body = &buf[MessageHeader::size()..];
        let parsed = OperationMessage::from_bytes(body).unwrap();
        assert_eq!(parsed.flags, OperationMessageFlags::EXHAUST_ALLOWED);
    }
}
