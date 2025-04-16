use tokio_util::bytes::BytesMut;

use crate::header::MessageHeader;

pub struct Message {
    pub header: MessageHeader,
    pub body: BytesMut,
}

impl Message {
    pub fn new(header: MessageHeader, body: BytesMut) -> Self {
        Self { header, body }
    }
}
