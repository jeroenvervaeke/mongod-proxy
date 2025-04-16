use tokio_util::bytes::BytesMut;

#[derive(Debug)]
pub struct MessageHeader {
    pub message_length: i32,
    pub request_id: i32,
    pub response_to: i32,
    pub op_code: i32,
}

impl MessageHeader {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        (bytes.len() >= 16).then(|| MessageHeader {
            message_length: i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            request_id: i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            response_to: i32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            op_code: i32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        })
    }

    pub fn write_bytes(&self, dst: &mut BytesMut) {
        let message_length_bytes = i32::to_le_bytes(self.message_length);
        let request_id_bytes = i32::to_le_bytes(self.request_id);
        let response_to_bytes = i32::to_le_bytes(self.response_to);
        let op_code_bytes = i32::to_le_bytes(self.op_code);

        dst.extend_from_slice(&message_length_bytes);
        dst.extend_from_slice(&request_id_bytes);
        dst.extend_from_slice(&response_to_bytes);
        dst.extend_from_slice(&op_code_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE_HEADER_1_BYTES: [u8; 16] = [
        0x73, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd4, 0x7, 0x0, 0x0,
    ];

    #[test]
    fn decode_message_header_1() {
        // Decode the message
        let message_header = MessageHeader::from_bytes(&MESSAGE_HEADER_1_BYTES).unwrap();

        // Check the message header
        assert_eq!(message_header.message_length, 371);
        assert_eq!(message_header.request_id, 1);
        assert_eq!(message_header.response_to, 0);
        assert_eq!(message_header.op_code, 2004);
    }

    #[test]
    fn encode_message_header_1() {
        // Decode the message
        let mut dst = BytesMut::new();
        let message_header = MessageHeader {
            message_length: 371,
            request_id: 1,
            response_to: 0,
            op_code: 2004,
        };
        message_header.write_bytes(&mut dst);

        // Check the message header
        assert_eq!(dst.as_ref(), MESSAGE_HEADER_1_BYTES);
    }

    #[test]
    fn encode_decode() {
        let message_header = MessageHeader::from_bytes(&MESSAGE_HEADER_1_BYTES).unwrap();
        let mut dst = BytesMut::new();
        message_header.write_bytes(&mut dst);
        assert_eq!(dst.as_ref(), MESSAGE_HEADER_1_BYTES);
    }
}
