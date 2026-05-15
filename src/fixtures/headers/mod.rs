use std::num::NonZeroI32;

use crate::{
    header::MessageHeader,
    ids::{MessageLength, RequestId, ResponseTo},
    op_code::OPCode,
};

pub mod op_msg_01 {

    use super::*;

    pub fn header() -> MessageHeader {
        MessageHeader {
            message_length: MessageLength::try_new(163).unwrap(),
            request_id: RequestId::new(25),
            response_to: None,
            op_code: OPCode::Msg,
        }
    }

    pub fn bytes() -> &'static [u8] {
        include_bytes!("./OP_MSG.bin")
    }
}

pub mod op_query_01 {

    use super::*;

    pub fn header() -> MessageHeader {
        MessageHeader {
            message_length: MessageLength::try_new(240).unwrap(),
            request_id: RequestId::new(26),
            response_to: NonZeroI32::new(25).map(ResponseTo::new),
            op_code: OPCode::Query,
        }
    }

    pub fn bytes() -> &'static [u8] {
        include_bytes!("./OP_QUERY.bin")
    }
}
