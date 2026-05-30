//! [`tokio_util::codec::Decoder`] implementation that frames a TCP byte
//! stream into typed [`Message`] values.

use tokio_util::{bytes::BytesMut, codec::Decoder};

use crate::{
    header::{MessageHeader, MessageHeaderParseError},
    ids::MessageLengthError,
    message::{Message, MessageAndHeaderParseError},
    op_code::OPCodeParseError,
};

/// Stateful decoder that turns a stream of wire-protocol bytes into
/// [`Message`] values.
///
/// Combine with [`tokio_util::codec::FramedRead`] to read messages off an
/// `AsyncRead` (typically a `TcpStream` half).
///
/// The decoder is bounded-memory: it parses the header lazily and caches it
/// until the rest of the frame has been received. If the buffer doesn't yet
/// contain a full header or full body, `decode` returns `Ok(None)` and
/// `FramedRead` will call again after more bytes arrive.
///
/// # Examples
///
/// ```
/// use bson::doc;
/// use mongod_proxy::decoder::WireDecoder;
/// use mongod_proxy::ids::RequestId;
/// use mongod_proxy::message::Message;
/// use mongod_proxy::operation::Operation;
/// use mongod_proxy::operation::op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags};
/// use tokio_util::bytes::BytesMut;
/// use tokio_util::codec::Decoder;
///
/// // Build a frame to feed in.
/// let msg = Message {
///     request_id: RequestId::new(1),
///     response_to: None,
///     operation: Operation::Message(OperationMessage {
///         flags: OperationMessageFlags::empty(),
///         sections: vec![OpMsgSection::Body(doc! { "ping": 1 })],
///         checksum: None,
///     }),
/// };
/// let mut buf = BytesMut::new();
/// msg.write_bytes(&mut buf).unwrap();
///
/// let mut decoder = WireDecoder::default();
/// let decoded = decoder.decode(&mut buf).unwrap().unwrap();
/// assert_eq!(decoded.request_id, RequestId::new(1));
/// assert!(buf.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct WireDecoder {
    next_header: Option<MessageHeader>,
}

/// Failure modes emitted by [`WireDecoder`].
#[derive(Debug, thiserror::Error)]
pub enum WireDecoderError {
    /// Underlying [`std::io::Error`] surfaced by [`tokio_util::codec`].
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// Header carried an opcode the proxy does not implement.
    #[error("invalid opcode: {0}")]
    InvalidOpcode(#[from] OPCodeParseError),
    /// The frame body could not be parsed against the header's opcode.
    #[error("failed to parse message: {0}")]
    MessageParse(#[from] MessageAndHeaderParseError),
    /// The header's `message_length` was outside the protocol envelope.
    #[error("invalid message length: {0}")]
    InvalidMessageLength(#[from] MessageLengthError),
}

impl Decoder for WireDecoder {
    type Item = Message;
    type Error = WireDecoderError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // If we didn't parse a header yet and we can parse a header, do so
        if self.next_header.is_none() {
            match MessageHeader::from_bytes(buf) {
                Ok(header) => {
                    self.next_header = Some(header);
                }
                Err(err) => match err {
                    MessageHeaderParseError::TooFewBytes(_) => { /* ignore */ }
                    MessageHeaderParseError::InvalidOPCode(opcode_parse_error) => {
                        return Err(opcode_parse_error.into());
                    }
                    MessageHeaderParseError::InvalidMessageLength(length_err) => {
                        return Err(length_err.into());
                    }
                },
            }
        }

        // If we don't have a header or don't have enough data yet, wait
        // for more data. Peek the length without consuming so we can
        // return `Ok(None)` before taking ownership.
        let frame_len = match &self.next_header {
            Some(h) => h.message_length.as_usize(),
            None => return Ok(None),
        };
        if buf.len() < frame_len {
            return Ok(None);
        }

        // Header + body present: take ownership of the header and split
        // the frame off. The earlier match proves `next_header.is_some()`,
        // but use `let-else` rather than `.expect()` so this stays
        // panic-free even under refactor: an unexpected `None` falls
        // through to "wait for more data".
        let Some(header) = self.next_header.take() else {
            return Ok(None);
        };
        let message_bytes = buf.split_to(frame_len);

        // Parse message based on header and bytes
        Ok(Some(Message::from_headers_and_bytes(
            header,
            &message_bytes,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::messages::*;

    #[test]
    fn decode() {
        // Create a new decoder and message bytes
        let mut decoder = WireDecoder::default();
        let mut buf = BytesMut::from(
            [
                msg_00_query_request::bytes(),
                msg_00_query_response::bytes(),
            ]
            .concat()
            .as_slice(),
        );

        // Calculate total expected bytes length
        let total_length =
            msg_00_query_request::bytes().len() + msg_00_query_response::bytes().len();
        assert_eq!(total_length, buf.len());

        // Decode the first message
        assert_eq!(
            Some(msg_00_query_request::message()),
            decoder.decode(&mut buf).expect("decode succeeds")
        );

        // Remaining number of bytes should be equal to second message
        assert_eq!(msg_00_query_response::bytes().len(), buf.len());

        // Decode the second message
        assert_eq!(
            Some(msg_00_query_response::message()),
            decoder.decode(&mut buf).expect("decode succeeds")
        );

        // Remaining buffer should be empty
        assert!(buf.is_empty());

        // Make sure nothings left
        assert_eq!(None, decoder.decode(&mut buf).expect("decode succeeds"));
    }

    #[test]
    fn decode_returns_none_on_partial_header() {
        let mut decoder = WireDecoder::default();
        let mut buf = BytesMut::from(&[0u8; 8][..]);
        assert_eq!(None, decoder.decode(&mut buf).expect("partial header"));
        assert_eq!(8, buf.len(), "buffer must be preserved");
    }

    #[test]
    fn decode_errors_on_invalid_opcode() {
        let mut decoder = WireDecoder::default();
        let mut header = Vec::new();
        header.extend_from_slice(&16i32.to_le_bytes()); // length
        header.extend_from_slice(&1i32.to_le_bytes()); // request_id
        header.extend_from_slice(&0i32.to_le_bytes()); // response_to
        header.extend_from_slice(&0xAAi32.to_le_bytes()); // unknown opcode
        let mut buf = BytesMut::from(header.as_slice());
        let err = decoder.decode(&mut buf).unwrap_err();
        assert!(matches!(err, WireDecoderError::InvalidOpcode(_)));
    }
}
