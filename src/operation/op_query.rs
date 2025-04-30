use std::{
    ffi::{CStr, CString, FromBytesUntilNulError, NulError},
    io::Cursor,
    num::NonZeroI32,
    str::Utf8Error,
};

use bitflags::bitflags;
use bson::Document;
use tokio_util::bytes::{Buf, BufMut, BytesMut};

use crate::{header::MessageHeader, op_code::OPCode};

#[derive(Clone, Debug, PartialEq)]
pub struct OperationQuery {
    pub flags: OperationQueryFlags,
    pub full_collection_name: String,
    pub number_to_skip: i32,
    pub number_to_return: i32,
    pub query: Document,
    pub return_fields_selector: Option<Document>,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperationQueryFlags: u32 {
        const TAILABLE_CURSOR = 0b0000_0000_0000_0000;
        const SLAVE_OK = 0b0000_0000_0000_0010;
        const OPLOG_REPLAY = 0b0000_0000_0000_0100;
        const NO_CURSOR_TIMEOUT = 0b0000_0000_0000_1000;
        const AWAIT_DATA = 0b0000_0000_0001_0000;
        const EXHAUST = 0b0000_0000_0010_0000;
        const PARTIAL = 0b0000_0000_0100_0000;
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationQueryParseError {
    #[error("not enough bytes, expected at least {min} bytes, got {actual}")]
    NotEnoughBytes { actual: usize, min: usize },
    #[error("invalid collection name: {0}")]
    InvalidCollectionName(#[from] FromBytesUntilNulError),
    #[error("invalid utf8 collection name: {0}")]
    InvalidUtf8CollectionName(#[from] Utf8Error),
    #[error("failed to parse query: {0}")]
    FailedToParseQuery(String),
    #[error("failed to parse return fields selector: {0}")]
    FailedToParseReturnFieldsSelector(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationQueryWriteError {
    #[error("failed to serialize query: {0}")]
    SerializeQueryError(String),
    #[error("failed to serialize return field selector: {0}")]
    SerializeReturnFieldSelectorError(String),
    #[error("collection name contains null byte: {0}")]
    CollectionNameContainsNullByte(#[from] NulError),
}

impl OperationQuery {
    pub fn min_len() -> usize {
        // flags
        size_of::<OperationQueryFlags>()
        // min cstring
        + size_of::<u8>()
        // number to skip
        + size_of::<i32>()
        // number to return
        + size_of::<i32>()
        // min size of document
        + size_of::<i32>()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OperationQueryParseError> {
        let actual_len = bytes.len();
        let min_len = Self::min_len();

        // verify minimum length
        if actual_len < min_len {
            return Err(OperationQueryParseError::NotEnoughBytes {
                actual: actual_len,
                min: min_len,
            });
        }

        let flags = OperationQueryFlags::from_bits(u32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))
        .unwrap_or(OperationQueryFlags::empty());

        let bytes = &bytes[4..];
        let full_collection_name_cstr = CStr::from_bytes_until_nul(bytes)?;
        let full_collection_name = full_collection_name_cstr.to_str()?.to_string();

        let bytes = &bytes[full_collection_name_cstr.count_bytes() + 1..];
        if bytes.is_empty() {
            return Err(OperationQueryParseError::NotEnoughBytes {
                actual: actual_len,
                min: min_len + 9,
            });
        }

        let number_to_skip = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let number_to_return = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let bytes = &bytes[8..];
        let mut reader = Cursor::new(bytes);

        // parse bson

        let query = bson::Document::from_reader(&mut reader)
            .map_err(|e| OperationQueryParseError::FailedToParseQuery(e.to_string()))?;

        let return_fields_selector = if reader.has_remaining() {
            Some(bson::Document::from_reader(reader).map_err(|e| {
                OperationQueryParseError::FailedToParseReturnFieldsSelector(e.to_string())
            })?)
        } else {
            None
        };

        Ok(Self {
            flags,
            full_collection_name,
            number_to_skip,
            number_to_return,
            query,
            return_fields_selector,
        })
    }

    pub fn write_bytes(
        &self,
        dst: &mut BytesMut,
        request_id: i32,
        response_to: Option<NonZeroI32>,
    ) -> Result<(), OperationQueryWriteError> {
        // Serialize query and return_fields_selector
        let query_bytes = bson::to_vec(&self.query)
            .map_err(|e| OperationQueryWriteError::SerializeQueryError(e.to_string()))?;

        let return_fields_selector_bytes =
            if let Some(return_fields_selector) = &self.return_fields_selector {
                bson::to_vec(return_fields_selector).map_err(|e| {
                    OperationQueryWriteError::SerializeReturnFieldSelectorError(e.to_string())
                })?
            } else {
                vec![]
            };

        let full_collection_name = CString::new(self.full_collection_name.clone())?;
        let full_collection_name_bytes = full_collection_name.as_bytes_with_nul();

        // Calculate the size of the message
        // - size of header (4 * i32 = 16 bytes)
        // - size of flags (i32 = 4 bytes)
        // - size of collection name cstr
        // - size of number_to_skip (i32 = 4 bytes)
        // - size of number_to_return (i32 = 4 bytes)
        // - size of query bytes
        // - size of return_fields_selector bytes
        let message_length = MessageHeader::size()
            + size_of::<i32>()
            + full_collection_name_bytes.len()
            + size_of::<i32>()
            + size_of::<i32>()
            + query_bytes.len()
            + return_fields_selector_bytes.len();

        // Allocate memory
        dst.reserve(message_length);

        // Write the header
        let header = MessageHeader {
            message_length: message_length as i32,
            op_code: OPCode::Query,
            request_id,
            response_to,
        };

        header.write_bytes(dst);

        // Write the rest of the message
        dst.put_u32_le(self.flags.bits());
        dst.put(full_collection_name_bytes);
        dst.put_i32_le(self.number_to_skip);
        dst.put_i32_le(self.number_to_return);
        dst.put(query_bytes.as_slice());
        dst.put(return_fields_selector_bytes.as_slice());

        Ok(())
    }
}
