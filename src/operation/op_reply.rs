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
    pub number_returned: i32,
    pub documents: Vec<Document>,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperationReplyFlags: u32 {
        const CURSOR_NOT_FOUND = 0b0000_0000_0000_0001;
        const QUERY_FAILURE = 0b0000_0000_0000_0010;
        const SHARD_CONFIG_STALE = 0b0000_0000_0000_0100;
        const AWAIT_CAPABLE = 0b0000_0000_0000_1000;
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationReplyParseError {
    #[error("not enough bytes, expected at least {min} bytes, got {actual}")]
    NotEnoughBytes { actual: usize, min: usize },
    #[error("failed to parse document (n={n}), message: {message}")]
    FailedToParseDocument { n: usize, message: String },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationReplyWriteError {
    #[error("failed to serialize document: {0}")]
    SerializeDocumentError(String),
}

impl OperationReply {
    pub fn min_len() -> usize {
        // flags
        size_of::<OperationReplyFlags>()
        // cursor id
        + size_of::<i64>()
        // starting from
        + size_of::<i32>()
        // number to return
        + size_of::<i32>()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OperationReplyParseError> {
        let actual_len = bytes.len();
        let min_len = Self::min_len();

        // verify minimum length
        if actual_len < min_len {
            return Err(OperationReplyParseError::NotEnoughBytes {
                actual: actual_len,
                min: min_len,
            });
        }

        let flags = OperationReplyFlags::from_bits(u32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))
        .unwrap_or(OperationReplyFlags::empty());

        let bytes = &bytes[4..];

        let cursor_id = i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let starting_from = i32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let number_returned = i32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        // verify length now that we know the number of expected documents
        let min_len = min_len * size_of::<i32>();
        if actual_len < min_len {
            return Err(OperationReplyParseError::NotEnoughBytes {
                actual: actual_len,
                min: min_len,
            });
        }

        // parse all `number_returned` bson documents
        let bytes = &bytes[16..];
        let mut reader = Cursor::new(bytes);
        let num_docs = number_returned as usize;
        let mut documents = Vec::with_capacity(num_docs);

        for n in 0..num_docs {
            documents.push(bson::Document::from_reader(&mut reader).map_err(|e| {
                OperationReplyParseError::FailedToParseDocument {
                    n,
                    message: e.to_string(),
                }
            })?);
        }

        Ok(Self {
            flags,
            cursor_id,
            starting_from,
            number_returned,
            documents,
        })
    }

    pub fn write_bytes(
        &self,
        dst: &mut BytesMut,
        request_id: i32,
        response_to: Option<NonZeroI32>,
    ) -> Result<(), OperationReplyWriteError> {
        let mut documents_bytes = Vec::with_capacity(self.documents.len());

        for document in &self.documents {
            let document_bytes = bson::to_vec(&document)
                .map_err(|e| OperationReplyWriteError::SerializeDocumentError(e.to_string()))?;

            documents_bytes.push(document_bytes);
        }

        // flatten from vec<vec<u8>> to vec<u8>
        let documents_bytes = documents_bytes.into_iter().flatten().collect::<Vec<_>>();

        // Calculate the size of the message
        // - size of header (4 * i32 = 16 bytes)
        // - size of flags (i32 = 4 bytes)
        // - size of cursorID (i64 = 8 bytes)
        // - size of starting_from (i32 = 4 bytes)
        // - size of number returned (i32 = 4 bytes)
        // - size of documents_bytes bytes
        let message_length = MessageHeader::size()
            + size_of::<OperationReplyFlags>()
            + size_of::<i64>()
            + size_of::<i32>()
            + size_of::<i32>()
            + documents_bytes.len();

        // Allocate memory
        dst.reserve(message_length);

        // Write the header
        let header = MessageHeader {
            message_length: message_length as i32,
            op_code: OPCode::Replay,
            request_id,
            response_to,
        };

        header.write_bytes(dst);

        // Write the rest of the message
        dst.put_u32_le(self.flags.bits());
        dst.put_i64_le(self.cursor_id);
        dst.put_i32_le(self.starting_from);
        dst.put_i32_le(self.number_returned);
        dst.put(documents_bytes.as_slice());

        Ok(())
    }
}
