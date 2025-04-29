use std::num::NonZeroI32;

use tokio_util::bytes::BytesMut;

use crate::{
    header::{MessageHeader, MessageHeaderParseError},
    operation::{Operation, OperationParseError},
};

#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub request_id: i32,
    pub response_to: Option<NonZeroI32>,
    pub operation: Operation,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageParseError {
    #[error("failed to parse header")]
    FailedToParseHeader(#[from] MessageHeaderParseError),
    #[error("failed to parse message body: {0}")]
    FailedToParseMessageBody(#[from] MessageAndHeaderParseError),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageAndHeaderParseError {
    #[error("not enough bytes, expected={expected}, actual={actual}")]
    NotEnoughBytes { actual: usize, expected: usize },
    #[error("failed to parse operation: {0}")]
    FailedToParseOperation(#[from] OperationParseError),
}

impl Message {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageParseError> {
        let header = MessageHeader::from_bytes(bytes)?;
        let message = Self::from_headers_and_bytes(header, bytes)?;

        Ok(message)
    }

    pub fn from_headers_and_bytes(
        header: MessageHeader,
        bytes: &[u8],
    ) -> Result<Self, MessageAndHeaderParseError> {
        let actual_bytes = bytes.len();
        let expected_bytes = header.message_length as usize;

        if expected_bytes < actual_bytes {
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

    fn write_bytes(&self, dst: &mut BytesMut) {
        self.operation.write_bytes(dst);
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::fixtures::messages::*;

    #[rstest]
    #[case::plain_query_request(msg_00_query_request::bytes(), Ok(msg_00_query_request::message()))]
    #[case::plain_query_response(
        msg_00_query_response::bytes(),
        Ok(msg_00_query_response::message())
    )]
    fn deserialize(#[case] bytes: &[u8], #[case] expected: Result<Message, MessageParseError>) {
        let actual = Message::from_bytes(bytes);

        assert_eq!(expected, actual);
    }
}
