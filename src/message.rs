use bitflags::bitflags;
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

pub enum Operation {
    Compressed(),
    Message(),
}

bitflags! {
    /// The flagBits integer is a bitmask encoding flags that modify the format and behavior of OP_MSG.
    /// The first 16 bits (0-15) are required and parsers MUST error if an unknown bit is set.
    /// The last 16 bits (16-31) are optional, and parsers MUST ignore any unknown set bits. Proxies and other message forwarders MUST clear any unknown optional bits before forwarding messages.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperationMessageFlags: u32 {
        // The message ends with 4 bytes containing a CRC-32C [2] checksum. See Checksum for details.
        const CHECKSUM_PRESENT = 0b0000_0000_0000_0001;
        // Another message will follow this one without further action from the receiver. The receiver MUST NOT send another message until receiving one with moreToCome set to 0 as sends may block, causing deadlock. Requests with the moreToCome bit set will not receive a reply. Replies will only have this set in response to requests with the exhaustAllowed bit set.
        const MORE_TO_COME = 0b0000_0000_0000_0010;
        // The client is prepared for multiple replies to this request using the moreToCome bit. The server will never produce replies with the moreToCome bit set unless the request has this bit set.
        // This ensures that multiple replies are only sent when the network layer of the requester is prepared for them.
        const EXHAUST_ALLOWED = 0b1000_0000_0000_0000;
    }
}

pub struct OperationMessage {
    pub flags: OperationMessageFlags,
    pub sections: Vec<Section>,
    pub checksum: Option<u32>,
}

pub struct Section {}
