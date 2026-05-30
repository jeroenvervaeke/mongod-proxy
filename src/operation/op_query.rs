//! Legacy OP_QUERY opcode (`2004`).
//!
//! Modern drivers no longer use OP_QUERY for application commands, but the
//! initial handshake (`isMaster` / `hello`) is still issued via OP_QUERY
//! because the driver does not yet know which wire version the server
//! supports. The proxy must therefore understand it.

use std::{
    ffi::{CStr, CString, FromBytesUntilNulError, NulError},
    io::Cursor,
    str::Utf8Error,
};

use bitflags::bitflags;
use bson::Document;
use tokio_util::bytes::{Buf, BufMut, BytesMut};

use crate::{
    header::MessageHeader,
    ids::{MessageLength, RequestId, ResponseTo},
    op_code::OPCode,
};

/// Legacy OP_QUERY message body.
///
/// Carries a namespace (database.collection), pagination hints, and the
/// query / projection BSON documents. Even though modern drivers only use
/// it for the handshake, this struct models the full layout so the proxy
/// is forward-compatible with traffic from older drivers.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationQuery {
    /// Bit flags controlling cursor behaviour.
    pub flags: OperationQueryFlags,
    /// Fully qualified namespace (e.g. `"admin.$cmd"`). Null-terminated on
    /// the wire; the Rust string here has the terminator stripped.
    pub full_collection_name: String,
    /// Number of leading documents to skip on the cursor.
    pub number_to_skip: i32,
    /// Maximum documents to return. Negative or zero are special-cased by
    /// the server; see the MongoDB wire spec.
    pub number_to_return: i32,
    /// The query document (the filter / command BSON).
    pub query: Document,
    /// Optional projection / field selector document.
    pub return_fields_selector: Option<Document>,
}

bitflags! {
    /// Legacy OP_QUERY flag bits.
    ///
    /// Bit 0 is reserved and MUST be 0. The bit positions deliberately match
    /// the MongoDB wire spec (`TailableCursor = 1<<1`, etc.); see
    /// <https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/>.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperationQueryFlags: u32 {
        /// Cursor is not closed when its last result is returned.
        const TAILABLE_CURSOR = 1 << 1;
        /// Allow query on non-primary replica set members.
        const SLAVE_OK = 1 << 2;
        /// Internal replication use only.
        const OPLOG_REPLAY = 1 << 3;
        /// Server should not time out the cursor after idle.
        const NO_CURSOR_TIMEOUT = 1 << 4;
        /// Use with [`TAILABLE_CURSOR`](Self::TAILABLE_CURSOR) to block on
        /// `getMore` rather than returning empty immediately.
        const AWAIT_DATA = 1 << 5;
        /// Stream the entire cursor without further `getMore` round-trips.
        const EXHAUST = 1 << 6;
        /// Return partial results if some shards are unreachable.
        const PARTIAL = 1 << 7;
    }
}

/// Failure modes for [`OperationQuery::from_bytes`].
#[derive(Debug, thiserror::Error)]
pub enum OperationQueryParseError {
    /// Body shorter than the unconditional minimum.
    #[error("not enough bytes, expected at least {min} bytes, got {actual}")]
    NotEnoughBytes { actual: usize, min: usize },
    /// One or more unknown flag bits were set on the wire. The `u32` carries
    /// the unknown bits only.
    #[error("unknown query flag bits set: {0:#010x}")]
    UnknownFlagBits(u32),
    /// `full_collection_name` did not contain a NUL terminator.
    #[error("invalid collection name: {0}")]
    InvalidCollectionName(#[from] FromBytesUntilNulError),
    /// `full_collection_name` bytes were not valid UTF-8.
    #[error("invalid utf8 collection name: {0}")]
    InvalidUtf8CollectionName(#[from] Utf8Error),
    /// BSON parsing of the query document failed.
    #[error("failed to parse query: {0}")]
    FailedToParseQuery(#[source] bson::error::Error),
    /// BSON parsing of the projection document failed.
    #[error("failed to parse return fields selector: {0}")]
    FailedToParseReturnFieldsSelector(#[source] bson::error::Error),
}

/// Failure modes for [`OperationQuery::write_bytes`].
#[derive(Debug, thiserror::Error)]
pub enum OperationQueryWriteError {
    /// BSON serialisation of `query` failed.
    #[error("failed to serialize query: {0}")]
    SerializeQueryError(#[source] bson::error::Error),
    /// BSON serialisation of `return_fields_selector` failed.
    #[error("failed to serialize return field selector: {0}")]
    SerializeReturnFieldSelectorError(#[source] bson::error::Error),
    /// `full_collection_name` contained an interior NUL byte and so cannot
    /// be encoded as a C string.
    #[error("collection name contains null byte: {0}")]
    CollectionNameContainsNullByte(#[from] NulError),
    /// The fully assembled frame exceeded the wire-envelope upper bound.
    #[error("message length {0} exceeds wire-envelope upper bound")]
    MessageTooLarge(usize),
}

impl OperationQuery {
    /// Smallest possible OP_QUERY body size in bytes:
    /// `flags(4) + null-terminated cstring(1) + skip(4) + return(4) + min-bson-doc(5)`.
    pub const fn min_len() -> usize {
        size_of::<u32>() + 1 + size_of::<i32>() + size_of::<i32>() + 5
    }

    /// Parses an OP_QUERY body. `bytes` must NOT include the
    /// [`MessageHeader`].
    ///
    /// # Errors
    ///
    /// See [`OperationQueryParseError`].
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
            .map_err(OperationQueryParseError::FailedToParseQuery)?;

        let return_fields_selector = if reader.has_remaining() {
            Some(
                Document::from_reader(reader)
                    .map_err(OperationQueryParseError::FailedToParseReturnFieldsSelector)?,
            )
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

    /// Appends a full OP_QUERY frame (header + body) to `dst`.
    ///
    /// `request_id` and `response_to` are folded into the header that
    /// precedes the body. The body itself is composed of: flags,
    /// null-terminated collection name, skip/return ints, query document,
    /// optional projection document.
    ///
    /// # Errors
    ///
    /// See [`OperationQueryWriteError`].
    pub fn write_bytes(
        &self,
        dst: &mut BytesMut,
        request_id: RequestId,
        response_to: Option<ResponseTo>,
    ) -> Result<(), OperationQueryWriteError> {
        let query_bytes = bson::serialize_to_vec(&self.query)
            .map_err(OperationQueryWriteError::SerializeQueryError)?;

        let return_fields_selector_bytes = match &self.return_fields_selector {
            Some(doc) => bson::serialize_to_vec(doc)
                .map_err(OperationQueryWriteError::SerializeReturnFieldSelectorError)?,
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

        let message_length_i32 = i32::try_from(message_length)
            .map_err(|_| OperationQueryWriteError::MessageTooLarge(message_length))?;
        let header = MessageHeader {
            message_length: MessageLength::try_new(message_length_i32)
                .map_err(|_| OperationQueryWriteError::MessageTooLarge(message_length))?,
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
        query
            .write_bytes(&mut buf, RequestId::new(1), None)
            .unwrap();
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
        let doc_bytes = bson::serialize_to_vec(&doc! {}).unwrap();
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
