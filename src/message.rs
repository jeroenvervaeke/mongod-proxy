//! Top-level wire-protocol message: a [`MessageHeader`] plus an [`Operation`].
//!
//! [`Message`] is what the proxy reads from / writes to the network. The
//! header bits that carry framing (`message_length`, `op_code`) are derived
//! from the operation at write time and are not stored on the struct.

use std::num::NonZeroI32;

use tokio_util::bytes::BytesMut;

use crate::{
    header::{MessageHeader, MessageHeaderParseError},
    operation::{Operation, OperationParseError, OperationWriteError},
};

/// One framed MongoDB message: identification fields plus the typed body.
///
/// `request_id` and `response_to` are carried at the [`Message`] level rather
/// than on the inner [`Operation`] because they are shared by every opcode.
///
/// The `op_code` and `message_length` from [`MessageHeader`] are *derived*
/// from `operation` and only materialised when [`Message::write_bytes`] runs,
/// so they can never drift out of sync with the body.
///
/// # Examples
///
/// ```
/// use bson::doc;
/// use mongod_proxy::message::Message;
/// use mongod_proxy::operation::Operation;
/// use mongod_proxy::operation::op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags};
/// use tokio_util::bytes::BytesMut;
///
/// let msg = Message {
///     request_id: 1,
///     response_to: None,
///     operation: Operation::Message(OperationMessage {
///         flags: OperationMessageFlags::empty(),
///         sections: vec![OpMsgSection::Body(doc! { "ping": 1, "$db": "admin" })],
///         checksum: None,
///     }),
/// };
///
/// let mut buf = BytesMut::new();
/// msg.write_bytes(&mut buf).unwrap();
/// let roundtripped = Message::from_bytes(&buf).unwrap();
/// assert_eq!(msg, roundtripped);
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    /// Sender-chosen identifier. Replies reference this in their
    /// [`response_to`](Self::response_to).
    pub request_id: i32,
    /// `Some(n)` if this is a reply to request `n`; `None` for a fresh
    /// request. Using `NonZeroI32` rules out confusing the sentinel `0`
    /// with a real id.
    pub response_to: Option<NonZeroI32>,
    /// The typed body. Determines the on-the-wire opcode at write time.
    pub operation: Operation,
}

/// Failure modes for [`Message::from_bytes`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageParseError {
    /// The first 16 bytes could not be parsed as a [`MessageHeader`].
    #[error("failed to parse header")]
    FailedToParseHeader(#[from] MessageHeaderParseError),
    /// The header parsed but the body did not.
    #[error("failed to parse message body: {0}")]
    FailedToParseMessageBody(#[from] MessageAndHeaderParseError),
}

/// Failure modes for [`Message::from_headers_and_bytes`], i.e. parsing when
/// the header is already known.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageAndHeaderParseError {
    /// The header claims `expected` bytes but only `actual` are available.
    #[error("not enough bytes, expected={expected}, actual={actual}")]
    NotEnoughBytes { actual: usize, expected: usize },
    /// The body bytes did not parse as the [`Operation`] indicated by the
    /// header's opcode.
    #[error("failed to parse operation: {0}")]
    FailedToParseOperation(#[from] OperationParseError),
}

/// Failure modes for [`Message::write_bytes`].
#[derive(Debug, thiserror::Error)]
pub enum MessageWriteError {
    /// Serialising the operation body failed (e.g. BSON encoding error).
    #[error("failed to write operation: {0}")]
    FailedToWriteOperation(#[from] OperationWriteError),
}

impl Message {
    /// Parses a complete message — header *and* body — from a single buffer.
    ///
    /// The buffer must be at least `message_length` bytes long; any trailing
    /// bytes beyond that are ignored (which matches the framing model used by
    /// [`WireDecoder`](crate::decoder::WireDecoder)).
    ///
    /// # Errors
    ///
    /// See [`MessageParseError`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageParseError> {
        let header = MessageHeader::from_bytes(bytes)?;
        let message = Self::from_headers_and_bytes(header, bytes)?;

        Ok(message)
    }

    /// Parses the body when the header has already been decoded.
    ///
    /// `bytes` must include the original header bytes too — the function
    /// trims the leading [`MessageHeader::size`] off internally. This shape
    /// matches what [`WireDecoder`](crate::decoder::WireDecoder) hands in
    /// after a successful peek.
    ///
    /// # Errors
    ///
    /// See [`MessageAndHeaderParseError`].
    pub fn from_headers_and_bytes(
        header: MessageHeader,
        bytes: &[u8],
    ) -> Result<Self, MessageAndHeaderParseError> {
        let actual_bytes = bytes.len();
        let expected_bytes = header.message_length as usize;

        if actual_bytes < expected_bytes {
            return Err(MessageAndHeaderParseError::NotEnoughBytes {
                actual: actual_bytes,
                expected: expected_bytes,
            });
        }

        // we don't need the first bytes which contain the header, which is already parsed
        let bytes = &bytes[MessageHeader::size()..];

        // parse the operation
        let operation = Operation::from_bytes(header.op_code, bytes)?;

        // extract header values
        let MessageHeader {
            request_id,
            response_to,
            ..
        } = header;

        // return full message
        Ok(Self {
            request_id,
            response_to,
            operation,
        })
    }

    /// Appends the full wire encoding of this message to `dst`.
    ///
    /// The header (including the derived `message_length` and `op_code`) is
    /// written first, immediately followed by the operation body. Any
    /// existing contents of `dst` are preserved.
    ///
    /// # Errors
    ///
    /// See [`MessageWriteError`]; the only realistic failure path is BSON
    /// serialisation of the operation body.
    pub fn write_bytes(&self, dst: &mut BytesMut) -> Result<(), MessageWriteError> {
        self.operation
            .write_bytes(dst, self.request_id, self.response_to)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    use super::*;
    use crate::fixtures::messages::*;

    #[rstest]
    #[case::plain_query_request(msg_00_query_request::bytes(), Ok(msg_00_query_request::message()))]
    #[case::plain_query_response(
        msg_00_query_response::bytes(),
        Ok(msg_00_query_response::message())
    )]
    #[case::legacy_op_query(msg_01_legacy_op_query::bytes(), Ok(msg_01_legacy_op_query::message()))]
    #[case::legacy_op_query(msg_01_legacy_op_reply::bytes(), Ok(msg_01_legacy_op_reply::message()))]
    fn deserialize(#[case] bytes: &[u8], #[case] expected: Result<Message, MessageParseError>) {
        let actual = Message::from_bytes(bytes);

        assert_eq!(expected, actual);
    }

    #[rstest]
    #[case::plain_query_request(msg_00_query_request::message(), msg_00_query_request::bytes())]
    #[case::plain_query_response(msg_00_query_response::message(), msg_00_query_response::bytes())]
    #[case::legacy_op_query(msg_01_legacy_op_query::message(), msg_01_legacy_op_query::bytes())]
    #[case::legacy_op_reply(msg_01_legacy_op_reply::message(), msg_01_legacy_op_reply::bytes())]
    fn serialize(#[case] message: Message, #[case] expected: &[u8]) {
        let mut bytes = BytesMut::new();
        message.write_bytes(&mut bytes).expect("write succeeds");

        assert_eq!(expected, bytes.as_ref());
    }

    #[test]
    fn from_headers_and_bytes_errors_when_actual_lt_expected() {
        use crate::header::MessageHeader;
        use crate::op_code::OPCode;
        let header = MessageHeader {
            message_length: 100,
            request_id: 1,
            response_to: None,
            op_code: OPCode::Msg,
        };
        // 20-byte slice but header claims 100.
        let bytes = [0u8; 20];
        let err = Message::from_headers_and_bytes(header, &bytes).unwrap_err();
        match err {
            MessageAndHeaderParseError::NotEnoughBytes { actual, expected } => {
                assert_eq!(actual, 20);
                assert_eq!(expected, 100);
            }
            other => panic!("expected NotEnoughBytes, got {other:?}"),
        }
    }
}
