use std::num::NonZeroI32;

use tokio_util::bytes::BytesMut;

use crate::{
    ByteDeSerializer,
    op_code::{OPCode, OPCodeParseError},
};

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

impl ByteDeSerializer for MessageHeader {
    type ParseError = MessageHeaderParseError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::ParseError> {
        let len = bytes.len();
        if len < 16 {
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

    fn write_bytes(&self, dst: &mut BytesMut) {
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
    use super::*;
    use rstest::*;

    mod op_msg_01 {
        use super::*;

        pub fn header() -> MessageHeader {
            MessageHeader {
                message_length: 163,
                request_id: 25,
                response_to: None,
                op_code: OPCode::Msg,
            }
        }

        pub fn bytes() -> &'static [u8] {
            include_bytes!("./fixtures/headers/OP_MSG_01_request.bin")
        }
    }

    mod op_msg_02 {
        use super::*;

        pub fn header() -> MessageHeader {
            MessageHeader {
                message_length: 240,
                request_id: 26,
                response_to: NonZeroI32::new(25),
                op_code: OPCode::Compressed,
            }
        }

        pub fn bytes() -> &'static [u8] {
            include_bytes!("./fixtures/headers/OP_MSG_02_response.bin")
        }
    }

    #[rstest]
    #[case::plain_request_message(op_msg_01::bytes(), Ok(op_msg_01::header()))]
    #[case::conpressed_response_message(op_msg_02::bytes(), Ok(op_msg_02::header()))]
    fn decode(
        #[case] bytes: &[u8],
        #[case] expected: Result<MessageHeader, MessageHeaderParseError>,
    ) {
        assert_eq!(expected, MessageHeader::from_bytes(bytes));
    }

    #[rstest]
    #[case::plain_request_message(op_msg_01::header(), op_msg_01::bytes())]
    #[case::conpressed_response_message(op_msg_02::header(), op_msg_02::bytes())]
    fn encode(#[case] message: MessageHeader, #[case] expected: &[u8]) {
        let mut dst = BytesMut::new();
        message.write_bytes(&mut dst);
        assert_eq!(expected, dst.as_ref());
    }

    #[rstest]
    #[case::plain_request_message(op_msg_01::bytes())]
    #[case::conpressed_response_message(op_msg_02::bytes())]
    fn encode_decode(#[case] bytes: &[u8]) {
        let header = MessageHeader::from_bytes(bytes).expect("encode should succeed");
        let mut dst = BytesMut::new();
        header.write_bytes(&mut dst);
        assert_eq!(dst.as_ref(), bytes);
    }
}
