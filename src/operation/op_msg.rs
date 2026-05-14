use std::num::NonZeroI32;

use bitflags::bitflags;
use tokio_util::bytes::{BufMut, BytesMut};

use crate::{header::MessageHeader, op_code::OPCode};

const REQUIRED_BITS_MASK: u32 = 0x0000_FFFF;

bitflags! {
    /// The flagBits integer is a bitmask encoding flags that modify the format and behavior of OP_MSG.
    /// The first 16 bits (0-15) are required and parsers MUST error if an unknown bit is set.
    /// The last 16 bits (16-31) are optional, and parsers MUST ignore any unknown set bits.
    /// Proxies and other message forwarders MUST clear any unknown optional bits before forwarding messages.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperationMessageFlags: u32 {
        /// The message ends with 4 bytes containing a CRC-32C checksum.
        const CHECKSUM_PRESENT = 1 << 0;
        /// Another message will follow this one without further action from the receiver.
        const MORE_TO_COME = 1 << 1;
        /// The client is prepared for multiple replies to this request using the moreToCome bit.
        const EXHAUST_ALLOWED = 1 << 16;
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OperationMessage {
    pub flags: OperationMessageFlags,
    pub sections: bson::Document,
    pub checksum: Option<u32>,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationMessageParseError {
    #[error("not enough bytes, expected at least {min} bytes, got {actual}")]
    NotEnoughBytes { actual: usize, min: usize },
    #[error("unknown required flag bits set: {0:#010x}")]
    UnknownRequiredBits(u32),
    #[error("invalid kind, expected 0, got {0}")]
    InvalidKind(u8),
    #[error("checksum is missing")]
    MissingChecksum,
    #[error("failed to parse bson: {0}")]
    InvalidBson(String),
}

#[derive(Debug, thiserror::Error)]
pub enum OperationMessageWriteError {
    #[error("failed to serialize sections: {0}")]
    SerializeError(#[from] bson::ser::Error),
}

impl OperationMessage {
    pub const fn min_len() -> usize {
        size_of::<u32>() + size_of::<u8>()
    }

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
