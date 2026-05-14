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
    /// Legacy OP_QUERY flag bits. Bit 0 is reserved and MUST be 0.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperationQueryFlags: u32 {
        const TAILABLE_CURSOR = 1 << 1;
        const SLAVE_OK = 1 << 2;
        const OPLOG_REPLAY = 1 << 3;
        const NO_CURSOR_TIMEOUT = 1 << 4;
        const AWAIT_DATA = 1 << 5;
        const EXHAUST = 1 << 6;
        const PARTIAL = 1 << 7;
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationQueryParseError {
    #[error("not enough bytes, expected at least {min} bytes, got {actual}")]
    NotEnoughBytes { actual: usize, min: usize },
    #[error("unknown query flag bits set: {0:#010x}")]
    UnknownFlagBits(u32),
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
    /// Minimum size: flags(4) + null-terminated cstring(1) + skip(4) + return(4) + min-bson-doc(5).
    pub const fn min_len() -> usize {
        size_of::<u32>() + 1 + size_of::<i32>() + size_of::<i32>() + 5
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OperationQueryParseError> {
        let actual_len = bytes.len();
        let min_len = Self::min_len();

        if actual_len < min_len {
            return Err(OperationQueryParseError::NotEnoughBytes {
                actual: actual_len,
                min: min_len,
            });
        }

        let raw_flags = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let flags = OperationQueryFlags::from_bits(raw_flags).ok_or(
            OperationQueryParseError::UnknownFlagBits(
                raw_flags & !OperationQueryFlags::all().bits(),
            ),
        )?;

        let bytes = &bytes[4..];
        let full_collection_name_cstr = CStr::from_bytes_until_nul(bytes)?;
        let full_collection_name = full_collection_name_cstr.to_str()?.to_string();

        let bytes = &bytes[full_collection_name_cstr.count_bytes() + 1..];

        // Need at least skip(4) + return(4) + min-bson-doc(5) = 13 bytes after collection name.
        const TAIL_MIN: usize = size_of::<i32>() + size_of::<i32>() + 5;
        if bytes.len() < TAIL_MIN {
            return Err(OperationQueryParseError::NotEnoughBytes {
                actual: actual_len,
                min: actual_len - bytes.len() + TAIL_MIN,
            });
        }

        let number_to_skip = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let number_to_return = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut reader = Cursor::new(&bytes[8..]);

        let query = Document::from_reader(&mut reader)
            .map_err(|e| OperationQueryParseError::FailedToParseQuery(e.to_string()))?;

        let return_fields_selector = if reader.has_remaining() {
            Some(Document::from_reader(reader).map_err(|e| {
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
        let query_bytes = bson::to_vec(&self.query)
            .map_err(|e| OperationQueryWriteError::SerializeQueryError(e.to_string()))?;

        let return_fields_selector_bytes = match &self.return_fields_selector {
            Some(doc) => bson::to_vec(doc).map_err(|e| {
                OperationQueryWriteError::SerializeReturnFieldSelectorError(e.to_string())
            })?,
            None => Vec::new(),
        };

        let full_collection_name = CString::new(self.full_collection_name.as_str())?;
        let full_collection_name_bytes = full_collection_name.as_bytes_with_nul();

        let message_length = MessageHeader::size()
            + size_of::<u32>()
            + full_collection_name_bytes.len()
            + size_of::<i32>()
            + size_of::<i32>()
            + query_bytes.len()
            + return_fields_selector_bytes.len();

        dst.reserve(message_length);

        let header = MessageHeader {
            message_length: message_length as i32,
            op_code: OPCode::Query,
            request_id,
            response_to,
        };
        header.write_bytes(dst);

        dst.put_u32_le(self.flags.bits());
        dst.put(full_collection_name_bytes);
        dst.put_i32_le(self.number_to_skip);
        dst.put_i32_le(self.number_to_return);
        dst.put(query_bytes.as_slice());
        dst.put(return_fields_selector_bytes.as_slice());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    #[test]
    fn round_trip_with_return_fields_selector() {
        let query = OperationQuery {
            flags: OperationQueryFlags::SLAVE_OK | OperationQueryFlags::PARTIAL,
            full_collection_name: "db.coll".into(),
            number_to_skip: 5,
            number_to_return: 10,
            query: doc! { "x": 1 },
            return_fields_selector: Some(doc! { "_id": 0, "name": 1 }),
        };
        let mut buf = BytesMut::new();
        query.write_bytes(&mut buf, 1, None).unwrap();
        let body = &buf[MessageHeader::size()..];
        let parsed = OperationQuery::from_bytes(body).unwrap();
        assert_eq!(parsed, query);
    }

    #[test]
    fn parse_errors_on_unknown_flag_bit() {
        let mut body = Vec::new();
        body.extend_from_slice(&(1u32 << 9).to_le_bytes()); // unknown bit
        body.push(b'a');
        body.push(0); // null terminator
        body.extend_from_slice(&0i32.to_le_bytes()); // skip
        body.extend_from_slice(&0i32.to_le_bytes()); // return
        let doc_bytes = bson::to_vec(&doc! {}).unwrap();
        body.extend_from_slice(&doc_bytes);
        let err = OperationQuery::from_bytes(&body).unwrap_err();
        assert!(matches!(err, OperationQueryParseError::UnknownFlagBits(_)));
    }

    #[test]
    fn parse_errors_when_truncated_after_collection_name() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // flags
        body.extend_from_slice(b"db\0");
        // missing skip + return + bson doc
        let err = OperationQuery::from_bytes(&body).unwrap_err();
        assert!(matches!(
            err,
            OperationQueryParseError::NotEnoughBytes { .. }
        ));
    }
}
