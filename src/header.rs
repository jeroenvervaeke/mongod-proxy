//! The fixed-size 16-byte header that prefixes every wire-protocol frame.

use std::num::NonZeroI32;

use tokio_util::bytes::BytesMut;

use crate::ids::{MessageLength, MessageLengthError, RequestId, ResponseTo};
use crate::op_code::{OPCode, OPCodeParseError};

/// Standard MongoDB wire-protocol message header.
///
/// Every frame on the wire begins with this header. Layout (little-endian
/// throughout):
///
/// | offset | size | field              |
/// |-------:|-----:|--------------------|
/// | 0      | 4    | `message_length`   |
/// | 4      | 4    | `request_id`       |
/// | 8      | 4    | `response_to`      |
/// | 12     | 4    | `op_code`          |
///
/// `message_length` is the *total* size of the frame including these 16 bytes.
/// `response_to` is zero on a fresh request (modelled here as `None`) or the
/// originating `request_id` on a reply (modelled as `Some(NonZeroI32)`).
///
/// # Examples
///
/// ```
/// use mongod_proxy::header::MessageHeader;
/// use mongod_proxy::ids::{MessageLength, RequestId, ResponseTo};
/// use mongod_proxy::op_code::OPCode;
/// use std::num::NonZeroI32;
/// use tokio_util::bytes::BytesMut;
///
/// let header = MessageHeader {
///     message_length: MessageLength::try_new(32).unwrap(),
///     request_id: RequestId::new(7),
///     response_to: NonZeroI32::new(3).map(ResponseTo::new),
///     op_code: OPCode::Msg,
/// };
/// let mut buf = BytesMut::new();
/// header.write_bytes(&mut buf);
/// assert_eq!(buf.len(), MessageHeader::size());
/// assert_eq!(MessageHeader::from_bytes(&buf), Ok(header));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    /// Total length of the frame in bytes, including the 16-byte header.
    pub message_length: MessageLength,
    /// Identifier chosen by the sender. Replies use this in [`Self::response_to`].
    pub request_id: RequestId,
    /// `Some(n)` if this is a reply to request `n`; `None` if it is a
    /// fresh request. Wraps [`NonZeroI32`] so the on-the-wire "no
    /// response_to" sentinel (`0`) cannot be confused with a valid id.
    pub response_to: Option<ResponseTo>,
    /// Identifies the wire-protocol operation this frame carries.
    pub op_code: OPCode,
}

/// Failure modes when parsing the first 16 bytes of a frame.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageHeaderParseError {
    /// Caller passed a buffer shorter than [`MessageHeader::size`]. The
    /// included `usize` is the actual length.
    #[error("size is too short, expected 4 bytes, got {0}")]
    TooFewBytes(usize),
    /// The four opcode bytes did not match any supported opcode.
    #[error("invalid opcode: {0}")]
    InvalidOPCode(#[from] OPCodeParseError),
    /// The `message_length` field did not satisfy the protocol envelope
    /// (less than 16 bytes or greater than 48 MiB).
    #[error("invalid message length: {0}")]
    InvalidMessageLength(#[from] MessageLengthError),
}

impl MessageHeader {
    /// On-the-wire size of a header in bytes (always 16).
    ///
    /// Exposed as a function rather than a constant so consumers don't have
    /// to import a hand-named constant in their `message_length` arithmetic.
    pub fn size() -> usize {
        16
    }

    /// Parses a header from the start of `bytes`.
    ///
    /// `bytes` may be longer than [`Self::size`] — the trailing data is
    /// ignored and presumed to be the message body, which the caller will
    /// hand to the matching `Operation::from_bytes`.
    ///
    /// # Errors
    ///
    /// * [`MessageHeaderParseError::TooFewBytes`] when fewer than 16 bytes
    ///   are available.
    /// * [`MessageHeaderParseError::InvalidOPCode`] when the opcode field
    ///   does not match any supported [`OPCode`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageHeaderParseError> {
        let len = bytes.len();
        if len < Self::size() {
            return Err(MessageHeaderParseError::TooFewBytes(len));
        }

        let raw_length = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let message_length = MessageLength::try_new(raw_length)?;
        let request_id =
            RequestId::new(i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
        let response_to = NonZeroI32::new(i32::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11],
        ]))
        .map(ResponseTo::new);
        let op_code = OPCode::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]])?;

        Ok(MessageHeader {
            message_length,
            request_id,
            response_to,
            op_code,
        })
    }

    /// Serialises the header into `dst` in little-endian wire order.
    ///
    /// Appends exactly [`Self::size`] bytes. Does not touch any existing
    /// contents of `dst`.
    pub fn write_bytes(&self, dst: &mut BytesMut) {
        let message_length_bytes = i32::to_le_bytes(self.message_length.into_inner());
        let request_id_bytes = i32::to_le_bytes(self.request_id.into_inner());
        let response_to_bytes =
            i32::to_le_bytes(self.response_to.map_or(0, |r| r.into_inner().get()));
        let op_code_bytes = self.op_code.to_le_bytes();

        dst.extend_from_slice(&message_length_bytes);
        dst.extend_from_slice(&request_id_bytes);
        dst.extend_from_slice(&response_to_bytes);
        dst.extend_from_slice(&op_code_bytes);
    }
}

#[cfg(test)]
mod tests {
    use rstest::*;

    use super::*;
    use crate::fixtures::headers::*;

    #[rstest]
    #[case::op_msg(op_msg_01::bytes(), Ok(op_msg_01::header()))]
    #[case::op_query(op_query_01::bytes(), Ok(op_query_01::header()))]
    fn decode(
        #[case] bytes: &[u8],
        #[case] expected: Result<MessageHeader, MessageHeaderParseError>,
    ) {
        assert_eq!(expected, MessageHeader::from_bytes(bytes));
    }

    #[rstest]
    #[case::op_msg(op_msg_01::header(), op_msg_01::bytes())]
    #[case::op_query(op_query_01::header(), op_query_01::bytes())]
    fn encode(#[case] message: MessageHeader, #[case] expected: &[u8]) {
        let mut dst = BytesMut::new();
        message.write_bytes(&mut dst);
        assert_eq!(expected, dst.as_ref());
    }

    #[rstest]
    #[case::op_msg(op_msg_01::bytes())]
    #[case::op_query(op_query_01::bytes())]
    fn encode_decode(#[case] bytes: &[u8]) {
        let header = MessageHeader::from_bytes(bytes).expect("encode should succeed");
        let mut dst = BytesMut::new();
        header.write_bytes(&mut dst);
        assert_eq!(dst.as_ref(), bytes);
    }
}
