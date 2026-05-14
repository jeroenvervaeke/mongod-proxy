use std::{io::Cursor, num::NonZeroI32};

use bitflags::bitflags;
use bson::Document;
use tokio_util::bytes::{BufMut, BytesMut};

use crate::{header::MessageHeader, op_code::OPCode};

#[derive(Clone, Debug, PartialEq)]
pub struct OperationReply {
    pub flags: OperationReplyFlags,
    pub cursor_id: i64,
    pub starting_from: i32,
    pub documents: Vec<Document>,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperationReplyFlags: u32 {
        const CURSOR_NOT_FOUND = 1 << 0;
        const QUERY_FAILURE = 1 << 1;
        const SHARD_CONFIG_STALE = 1 << 2;
        const AWAIT_CAPABLE = 1 << 3;
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationReplyParseError {
    #[error("not enough bytes, expected at least {min} bytes, got {actual}")]
    NotEnoughBytes { actual: usize, min: usize },
    #[error("unknown reply flag bits set: {0:#010x}")]
    UnknownFlagBits(u32),
    #[error("failed to parse document (n={n}), message: {message}")]
    FailedToParseDocument { n: usize, message: String },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationReplyWriteError {
    #[error("failed to serialize document: {0}")]
    SerializeDocumentError(String),
    #[error("document count {0} exceeds i32::MAX")]
    TooManyDocuments(usize),
}

impl OperationReply {
    pub const fn min_len() -> usize {
        size_of::<u32>() + size_of::<i64>() + size_of::<i32>() + size_of::<i32>()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OperationReplyParseError> {
        let actual_len = bytes.len();
        let min_len = Self::min_len();

        if actual_len < min_len {
            return Err(OperationReplyParseError::NotEnoughBytes {
                actual: actual_len,
                min: min_len,
            });
        }

        let raw_flags = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let flags = OperationReplyFlags::from_bits(raw_flags).ok_or(
            OperationReplyParseError::UnknownFlagBits(
                raw_flags & !OperationReplyFlags::all().bits(),
            ),
        )?;

        let cursor_id = i64::from_le_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ]);
        let starting_from = i32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let number_returned = i32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);

        let mut reader = Cursor::new(&bytes[min_len..]);
        let num_docs = number_returned.max(0) as usize;
        let mut documents = Vec::with_capacity(num_docs);

        for n in 0..num_docs {
            let doc = Document::from_reader(&mut reader).map_err(|e| {
                OperationReplyParseError::FailedToParseDocument {
                    n,
                    message: e.to_string(),
                }
            })?;
            documents.push(doc);
        }

        Ok(Self {
            flags,
            cursor_id,
            starting_from,
            documents,
        })
    }

    pub fn write_bytes(
        &self,
        dst: &mut BytesMut,
        request_id: i32,
        response_to: Option<NonZeroI32>,
    ) -> Result<(), OperationReplyWriteError> {
        let number_returned: i32 = self
            .documents
            .len()
            .try_into()
            .map_err(|_| OperationReplyWriteError::TooManyDocuments(self.documents.len()))?;

        // Serialize each doc directly into a single buffer to avoid Vec<Vec<u8>> flattening.
        let mut documents_bytes = Vec::new();
        for document in &self.documents {
            document
                .to_writer(&mut documents_bytes)
                .map_err(|e| OperationReplyWriteError::SerializeDocumentError(e.to_string()))?;
        }

        let message_length = MessageHeader::size() + Self::min_len() + documents_bytes.len();

        dst.reserve(message_length);

        let header = MessageHeader {
            message_length: message_length as i32,
            op_code: OPCode::Reply,
            request_id,
            response_to,
        };
        header.write_bytes(dst);

        dst.put_u32_le(self.flags.bits());
        dst.put_i64_le(self.cursor_id);
        dst.put_i32_le(self.starting_from);
        dst.put_i32_le(number_returned);
        dst.put(documents_bytes.as_slice());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    #[test]
    fn round_trip_multiple_documents() {
        let reply = OperationReply {
            flags: OperationReplyFlags::AWAIT_CAPABLE,
            cursor_id: 42,
            starting_from: 7,
            documents: vec![doc! { "a": 1 }, doc! { "b": 2 }, doc! { "c": 3 }],
        };
        let mut buf = BytesMut::new();
        reply.write_bytes(&mut buf, 1, None).unwrap();
        let body = &buf[MessageHeader::size()..];
        let parsed = OperationReply::from_bytes(body).unwrap();
        assert_eq!(parsed, reply);
    }

    #[test]
    fn parse_errors_on_unknown_flag_bit() {
        let mut body = Vec::new();
        body.extend_from_slice(&(1u32 << 8).to_le_bytes()); // unknown bit
        body.extend_from_slice(&0i64.to_le_bytes()); // cursor_id
        body.extend_from_slice(&0i32.to_le_bytes()); // starting_from
        body.extend_from_slice(&0i32.to_le_bytes()); // number_returned
        let err = OperationReply::from_bytes(&body).unwrap_err();
        assert!(matches!(err, OperationReplyParseError::UnknownFlagBits(_)));
    }
}
