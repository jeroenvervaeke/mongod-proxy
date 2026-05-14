//! [`tokio_util::codec::Encoder`] implementation that serialises typed
//! [`Message`] values onto a TCP byte stream.

use tokio_util::{bytes::BytesMut, codec::Encoder};

use crate::message::{Message, MessageWriteError};

/// Stateless encoder that writes [`Message`] values onto an `AsyncWrite`
/// via [`tokio_util::codec::FramedWrite`].
///
/// All encoding state lives in the [`Message`] itself; the encoder simply
/// delegates to [`Message::write_bytes`].
///
/// # Examples
///
/// ```
/// use bson::doc;
/// use mongod_proxy::encoder::WireEncoder;
/// use mongod_proxy::message::Message;
/// use mongod_proxy::operation::Operation;
/// use mongod_proxy::operation::op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags};
/// use tokio_util::bytes::BytesMut;
/// use tokio_util::codec::Encoder;
///
/// let msg = Message {
///     request_id: 1,
///     response_to: None,
///     operation: Operation::Message(OperationMessage {
///         flags: OperationMessageFlags::empty(),
///         sections: vec![OpMsgSection::Body(doc! { "ping": 1 })],
///         checksum: None,
///     }),
/// };
///
/// let mut buf = BytesMut::new();
/// WireEncoder::default().encode(msg, &mut buf).unwrap();
/// assert!(!buf.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct WireEncoder {}

/// Failure modes for [`WireEncoder::encode`].
#[derive(Debug, thiserror::Error)]
pub enum WireEncoderError {
    /// Underlying [`std::io::Error`] surfaced by [`tokio_util::codec`].
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// Serialising the message body failed (typically BSON encoding).
    #[error("Failed to write error: {0}")]
    MessageWriteError(#[from] MessageWriteError),
}

impl Encoder<Message> for WireEncoder {
    type Error = WireEncoderError;

    fn encode(&mut self, message: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        message.write_bytes(dst)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::messages::*;

    #[test]
    fn encode_multiple_op_msg() {
        let mut encoder = WireEncoder::default();
        let mut buf = BytesMut::new();

        encoder
            .encode(msg_00_query_request::message(), &mut buf)
            .expect("encode succeeds");
        assert_eq!(BytesMut::from(msg_00_query_request::bytes()), buf);

        encoder
            .encode(msg_00_query_response::message(), &mut buf)
            .expect("encode succeeds");
        assert_eq!(
            BytesMut::from(
                [
                    msg_00_query_request::bytes(),
                    msg_00_query_response::bytes(),
                ]
                .concat()
                .as_slice(),
            ),
            buf
        );
    }

    #[test]
    fn encode_legacy_op_query_and_reply() {
        let mut encoder = WireEncoder::default();
        let mut buf = BytesMut::new();

        encoder
            .encode(msg_01_legacy_op_query::message(), &mut buf)
            .expect("encode succeeds");
        assert_eq!(BytesMut::from(msg_01_legacy_op_query::bytes()), buf);

        encoder
            .encode(msg_01_legacy_op_reply::message(), &mut buf)
            .expect("encode succeeds");
        assert_eq!(
            BytesMut::from(
                [
                    msg_01_legacy_op_query::bytes(),
                    msg_01_legacy_op_reply::bytes(),
                ]
                .concat()
                .as_slice(),
            ),
            buf
        );
    }
}
