use tokio_util::{bytes::BytesMut, codec::Encoder};

use crate::message::{Message, MessageWriteError};

#[derive(Debug, Default)]
pub struct WireEncoder {}

#[derive(Debug, thiserror::Error)]
pub enum WireEncoderError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
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
    fn emcode() {
        // Create a new decoder and message bytes
        let mut encoder = WireEncoder::default();
        let mut buf = BytesMut::new();
        /*let mut buf = BytesMut::from(
            [
                msg_00_query_request::bytes(),
                msg_00_query_response::bytes(),
            ]
            .concat()
            .as_slice(),
        );*/

        // Encode the first message
        encoder
            .encode(msg_00_query_request::message(), &mut buf)
            .expect("encode succeeds");
        assert_eq!(BytesMut::from(msg_00_query_request::bytes()), buf);

        // Encode the second message
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
}
