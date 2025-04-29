use std::num::NonZeroI32;

use crate::{header::MessageHeader, op_code::OPCode};

pub mod op_msg_01 {

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
        include_bytes!("./OP_MSG_01_request.bin")
    }
}

pub mod op_msg_02 {

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
        include_bytes!("./OP_MSG_02_response.bin")
    }
}
