use std::num::NonZeroI32;

use tokio_util::bytes::BytesMut;

use crate::op_code::{OPCode, OPCodeParseError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    pub message_length: i32,
    pub request_id: i32,
    pub response_to: Option<NonZeroI32>,
    pub op_code: OPCode,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageHeaderParseError {
    #[error("size is too short, expected 4 bytes, got {0}")]
    TooFewBytes(usize),
    #[error("invalid opcode: {0}")]
    InvalidOPCode(#[from] OPCodeParseError),
}

impl MessageHeader {
    pub fn size() -> usize {
        16
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageHeaderParseError> {
        let len = bytes.len();
        if len < Self::size() {
            return Err(MessageHeaderParseError::TooFewBytes(len));
        }

        Ok(MessageHeader {
            message_length: i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            request_id: i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            response_to: NonZeroI32::new(i32::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
            ])),
            op_code: OPCode::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]])?,
        })
    }

    pub fn write_bytes(&self, dst: &mut BytesMut) {
        let message_length_bytes = i32::to_le_bytes(self.message_length);
        let request_id_bytes = i32::to_le_bytes(self.request_id);
        let response_to_bytes = i32::to_le_bytes(self.response_to.map_or(0, i32::from));
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
