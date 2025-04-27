use tokio_util::bytes::BytesMut;

pub mod decoder;
pub mod header;
pub mod message;
pub mod op_code;

trait ByteDeSerializer: Sized {
    type ParseError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::ParseError>;
    fn write_bytes(&self, dst: &mut BytesMut);
}
