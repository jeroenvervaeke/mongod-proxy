use std::num::NonZeroI32;

use bitflags::bitflags;
use tokio_util::bytes::{BufMut, BytesMut};

use crate::{header::MessageHeader, op_code::OPCode};

bitflags! {
    /// The flagBits integer is a bitmask encoding flags that modify the format and behavior of OP_MSG.
    /// The first 16 bits (0-15) are required and parsers MUST error if an unknown bit is set.
    /// The last 16 bits (16-31) are optional, and parsers MUST ignore any unknown set bits. Proxies and other message forwarders MUST clear any unknown optional bits before forwarding messages.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperationMessageFlags: u32 {
        // The message ends with 4 bytes containing a CRC-32C [2] checksum. See Checksum for details.
        const CHECKSUM_PRESENT = 0b0000_0000_0000_0001;
        // Another message will follow this one without further action from the receiver. The receiver MUST NOT send another message until receiving one with moreToCome set to 0 as sends may block, causing deadlock. Requests with the moreToCome bit set will not receive a reply. Replies will only have this set in response to requests with the exhaustAllowed bit set.
        const MORE_TO_COME = 0b0000_0000_0000_0010;
        // The client is prepared for multiple replies to this request using the moreToCome bit. The server will never produce replies with the moreToCome bit set unless the request has this bit set.
        // This ensures that multiple replies are only sent when the network layer of the requester is prepared for them.
        const EXHAUST_ALLOWED = 0b1000_0000_0000_0000;
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
    #[error("invalid bitflags")]
    InvalidBitflags,
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
    pub fn min_len() -> usize {
        size_of::<OperationMessageFlags>() + size_of::<u8>()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OperationMessageParseError> {
        let actual_len = bytes.len();
        let min_len = Self::min_len();

        // verify minimum length
        if actual_len < min_len {
            return Err(OperationMessageParseError::NotEnoughBytes {
                actual: actual_len,
                min: min_len,
            });
        }

        // parse the messages flags
        let flags = OperationMessageFlags::from_bits(u32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))
        .ok_or_else(|| OperationMessageParseError::InvalidBitflags)?;

        // get the message kind
        let kind = bytes[4];

        // make sure the message kind is 0
        if kind != 0 {
            return Err(OperationMessageParseError::InvalidKind(kind));
        }

        // get rid of the prefix
        let bytes = &bytes[Self::min_len()..];

        // now split of the checksum if nesseseary
        let (bytes, checksum) = if flags.contains(OperationMessageFlags::CHECKSUM_PRESENT) {
            let checksum_len = size_of::<usize>();
            let bytes_len = bytes.len();
            if bytes_len < checksum_len {
                return Err(OperationMessageParseError::MissingChecksum);
            }

            let bytes_len = bytes_len - checksum_len;
            let (bytes, checksum) = bytes.split_at(bytes_len);
            (
                bytes,
                Some(u32::from_le_bytes([
                    checksum[0],
                    checksum[1],
                    checksum[2],
                    checksum[3],
                ])),
            )
        } else {
            (bytes, None)
        };

        // parse bson
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
        // Serialize sections
        let body_bytes = bson::to_vec(&self.sections)?;

        // Calculate the size of the message
        // - size of header (4 * i32 = 16 bytes)
        // - size of flags (i32 = 4 bytes)
        // - size of kind (u8 = 1 byte)
        // - size of body bytes
        // - no checksum => 0 bytes
        let message_length =
            MessageHeader::size() + size_of::<i32>() + size_of::<u8>() + body_bytes.len();

        // Allocate memory
        dst.reserve(message_length);

        // Write the header
        let header = MessageHeader {
            message_length: message_length as i32,
            op_code: OPCode::Msg,
            request_id,
            response_to,
        };

        header.write_bytes(dst);

        // Write the rest of the message
        // Flags
        dst.put_u32_le(OperationMessageFlags::empty().bits());
        // Kind
        dst.put_u8(0);
        // Data
        dst.put(body_bytes.as_slice());

        Ok(())
    }
}
