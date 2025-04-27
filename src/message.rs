use crate::{header::MessageHeader, operation::Operation};

#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub header: MessageHeader,
    pub operation: Operation,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageParseError {
    #[error("not enough bytes, expected={expected}, actual={actual}")]
    NotEnoughBytes { actual: usize, expected: usize },
}

impl Message {
    pub fn from_headers_and_bytes(
        header: MessageHeader,
        bytes: &[u8],
    ) -> Result<Self, MessageParseError> {
        let actual_bytes = bytes.len();
        let expected_bytes = header.message_length as usize;

        if expected_bytes < actual_bytes {
            return Err(MessageParseError::NotEnoughBytes {
                actual: actual_bytes,
                expected: expected_bytes,
            });
        }

        // We don't need the first bytes which contain the header, which is already parsed
        let bytes = &bytes[MessageHeader::size()..];

        //

        todo!()
    }

    fn write_bytes(&self, dst: &mut tokio_util::bytes::BytesMut) {
        todo!()
    }
}
