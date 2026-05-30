//! Modern OP_MSG opcode (`2013`).
//!
//! Every command issued by current MongoDB drivers is carried in an OP_MSG.
//! The opcode supports a flag bitfield (see [`OperationMessageFlags`]), one
//! or more sections (both kind-0 *body* sections and kind-1 *document
//! sequence* sections are supported), and an optional CRC-32C checksum.

use std::{
    ffi::{CStr, CString, FromBytesUntilNulError, NulError},
    io::Cursor,
    str::Utf8Error,
};

use bitflags::bitflags;
use bson::Document;
use tokio_util::bytes::{BufMut, BytesMut};

use crate::{
    header::MessageHeader,
    ids::{MessageLength, RequestId, ResponseTo},
    op_code::OPCode,
};

/// Mask of the bits the spec classifies as *required* (`0..16`).
///
/// Parsers MUST error on an unknown required bit. Unknown optional bits
/// (`16..32`) are silently cleared.
const REQUIRED_BITS_MASK: u32 = 0x0000_FFFF;

bitflags! {
    /// `flagBits` bitmask carried in the first four bytes of an OP_MSG body.
    ///
    /// The MongoDB wire spec splits the bits into two halves:
    ///
    /// * **required** (`0..16`) — parsers MUST error on an unknown bit set
    ///   here. Mutating proxies must preserve known required bits verbatim.
    /// * **optional** (`16..32`) — parsers MUST ignore unknown bits, and
    ///   proxies MUST clear unknown optional bits before forwarding.
    ///
    /// This crate implements both halves of that contract in
    /// [`OperationMessage::from_bytes`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct OperationMessageFlags: u32 {
        /// The message ends with a four-byte CRC-32C checksum.
        const CHECKSUM_PRESENT = 1 << 0;
        /// On a request: fire-and-forget — server will not reply.
        ///
        /// On a reply: another reply for the same request will follow on this
        /// socket without the client sending anything (streaming SDAM /
        /// exhaust cursors).
        const MORE_TO_COME = 1 << 1;
        /// On a request: the client is prepared to receive a stream of
        /// replies using `MORE_TO_COME`. Server will not stream unless the
        /// originating request had this set.
        const EXHAUST_ALLOWED = 1 << 16;
    }
}

/// One section in an OP_MSG body.
///
/// An OP_MSG always carries at least one [`OpMsgSection::Body`] section
/// (the command document). Bulk-write commands (`insert`, `update`,
/// `delete`) additionally carry one or more [`OpMsgSection::DocumentSequence`]
/// sections that contain the array of documents / updates / deletes, lifted
/// out of the body for wire efficiency.
#[derive(Clone, Debug, PartialEq)]
pub enum OpMsgSection {
    /// Kind-0: a single BSON document (the "body"). By convention the first
    /// key of the document is the command name (`find`, `insert`, ...).
    Body(Document),
    /// Kind-1: a named sequence of BSON documents. The driver uses this for
    /// large arrays such as `insert.documents`, `update.updates`,
    /// `delete.deletes`.
    DocumentSequence {
        /// Field name the documents would have occupied if inlined into the
        /// body document.
        identifier: String,
        /// The documents themselves, in order.
        documents: Vec<Document>,
    },
}

impl OpMsgSection {
    /// Returns `Some(&doc)` if this section is a [`OpMsgSection::Body`].
    pub fn as_body(&self) -> Option<&Document> {
        match self {
            OpMsgSection::Body(doc) => Some(doc),
            OpMsgSection::DocumentSequence { .. } => None,
        }
    }

    /// Consumes the section, returning the inner [`Document`] when the section
    /// is a [`OpMsgSection::Body`]. Companion to [`as_body`](Self::as_body) for
    /// callers that own the section and want to move the document out.
    pub fn into_body(self) -> Option<Document> {
        match self {
            OpMsgSection::Body(doc) => Some(doc),
            OpMsgSection::DocumentSequence { .. } => None,
        }
    }
}

/// Modern OP_MSG message body.
///
/// `sections` always has at least one element; the first element is
/// conventionally a [`OpMsgSection::Body`] carrying the command document.
/// Bulk-write commands append one or more [`OpMsgSection::DocumentSequence`]
/// sections after it.
///
/// # Examples
///
/// Round-trip an OP_MSG body through the wire encoding:
///
/// ```
/// use bson::doc;
/// use mongod_proxy::header::MessageHeader;
/// use mongod_proxy::ids::RequestId;
/// use mongod_proxy::message::Message;
/// use mongod_proxy::operation::Operation;
/// use mongod_proxy::operation::op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags};
/// use tokio_util::bytes::BytesMut;
///
/// let msg = Message {
///     request_id: RequestId::new(42),
///     response_to: None,
///     operation: Operation::Message(OperationMessage {
///         flags: OperationMessageFlags::MORE_TO_COME,
///         sections: vec![OpMsgSection::Body(doc! { "find": "movies", "$db": "sample" })],
///         checksum: None,
///     }),
/// };
///
/// let mut buf = BytesMut::new();
/// msg.write_bytes(&mut buf).unwrap();
/// let body = &buf[MessageHeader::size()..];
/// let parsed = OperationMessage::from_bytes(body).unwrap();
/// assert!(parsed.flags.contains(OperationMessageFlags::MORE_TO_COME));
/// assert_eq!(parsed.command_name(), Some("find"));
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct OperationMessage {
    /// `flagBits` field controlling checksum, streaming, etc.
    pub flags: OperationMessageFlags,
    /// Body and document-sequence sections in their on-the-wire order.
    pub sections: Vec<OpMsgSection>,
    /// `Some(crc)` when [`OperationMessageFlags::CHECKSUM_PRESENT`] is set on
    /// the wire. The proxy preserves it across round-trips; it does not
    /// currently validate the CRC against the rest of the message.
    pub checksum: Option<u32>,
}

/// Failure modes for [`OperationMessage::from_bytes`].
#[derive(Debug, thiserror::Error)]
pub enum OperationMessageParseError {
    /// Body shorter than the unconditional minimum (flag bits + first kind byte).
    #[error("not enough bytes, expected at least {min} bytes, got {actual}")]
    NotEnoughBytes { actual: usize, min: usize },
    /// One or more *required* flag bits (`0..16`) set are not understood.
    /// The included `u32` is the unknown bits only (known bits masked off).
    #[error("unknown required flag bits set: {0:#010x}")]
    UnknownRequiredBits(u32),
    /// A section's `kind` byte was neither `0` (body) nor `1` (document sequence).
    #[error("invalid section kind, expected 0 or 1, got {0}")]
    InvalidKind(u8),
    /// `CHECKSUM_PRESENT` flag set but fewer than four trailing bytes remain.
    #[error("checksum is missing")]
    MissingChecksum,
    /// A kind-1 section's self-declared size did not fit in the buffer.
    #[error("document sequence section size {size} out of range")]
    InvalidDocumentSequenceSize { size: i32 },
    /// A kind-1 section's identifier ended without a NUL terminator.
    #[error("document sequence identifier missing NUL terminator: {0}")]
    DocumentSequenceIdentifierMissingNul(#[from] FromBytesUntilNulError),
    /// A kind-1 section's identifier was not valid UTF-8.
    #[error("document sequence identifier is not valid UTF-8: {0}")]
    DocumentSequenceIdentifierNotUtf8(#[from] Utf8Error),
    /// BSON parsing of a section document failed.
    #[error("failed to parse bson: {0}")]
    InvalidBson(#[from] bson::error::Error),
}

/// Failure modes for [`OperationMessage::write_bytes`].
#[derive(Debug, thiserror::Error)]
pub enum OperationMessageWriteError {
    /// Serialising a section's BSON document failed.
    #[error("failed to serialize sections: {0}")]
    SerializeError(#[from] bson::error::Error),
    /// A document-sequence section's identifier contained an interior NUL
    /// byte and so could not be written as a C string.
    #[error("document sequence identifier contains null byte: {0}")]
    IdentifierContainsNullByte(#[from] NulError),
    /// A kind-1 document sequence section exceeded the `i32` size field
    /// limit (≥ 2 GiB). Carries the actual byte size.
    #[error("document sequence section size {0} exceeds i32::MAX")]
    SectionTooLarge(usize),
    /// The fully assembled frame exceeded the wire-envelope upper bound
    /// (48 MiB). Carries the actual byte size.
    #[error("message length {0} exceeds wire-envelope upper bound")]
    MessageTooLarge(usize),
}

impl OperationMessage {
    /// Smallest possible OP_MSG body size in bytes (`flagBits` + first
    /// section's `kind` byte). Empty BSON sections add more on top of this.
    pub const fn min_len() -> usize {
        size_of::<u32>() + size_of::<u8>()
    }

    /// Returns the command name carried by this message, if one can be
    /// identified.
    ///
    /// By convention the first key of the first [`OpMsgSection::Body`]
    /// section is the command name (e.g. `"find"`, `"insert"`). Server
    /// responses don't carry a command name and return `None`.
    pub fn command_name(&self) -> Option<&str> {
        self.sections
            .iter()
            .find_map(OpMsgSection::as_body)
            .and_then(|d| d.keys().next())
            .map(String::as_str)
    }

    /// Parses an OP_MSG body. `bytes` must NOT include the 16-byte
    /// [`MessageHeader`]; the caller is expected to have stripped it off.
    ///
    /// # Errors
    ///
    /// See [`OperationMessageParseError`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OperationMessageParseError> {
        let actual_len = bytes.len();
        let min_len = Self::min_len();

        if actual_len < min_len {
            return Err(OperationMessageParseError::NotEnoughBytes {
                actual: actual_len,
                min: min_len,
            });
        }

        let raw_flags = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let unknown_required =
            (raw_flags & REQUIRED_BITS_MASK) & !OperationMessageFlags::all().bits();
        if unknown_required != 0 {
            return Err(OperationMessageParseError::UnknownRequiredBits(
                unknown_required,
            ));
        }
        // from_bits_truncate clears unknown optional bits (16-31) per spec.
        let flags = OperationMessageFlags::from_bits_truncate(raw_flags);

        // Split off the trailing checksum (if any) before iterating sections.
        let after_flags = &bytes[4..];
        let (sections_bytes, checksum) = if flags.contains(OperationMessageFlags::CHECKSUM_PRESENT)
        {
            let checksum_len = size_of::<u32>();
            if after_flags.len() < checksum_len {
                return Err(OperationMessageParseError::MissingChecksum);
            }
            let body_len = after_flags.len() - checksum_len;
            let (body, checksum_bytes) = after_flags.split_at(body_len);
            let checksum = u32::from_le_bytes([
                checksum_bytes[0],
                checksum_bytes[1],
                checksum_bytes[2],
                checksum_bytes[3],
            ]);
            (body, Some(checksum))
        } else {
            (after_flags, None)
        };

        let sections = parse_sections(sections_bytes)?;

        Ok(Self {
            checksum,
            flags,
            sections,
        })
    }

    /// Appends a full OP_MSG frame (header + body) to `dst`.
    ///
    /// The function unconditionally sets / clears
    /// [`OperationMessageFlags::CHECKSUM_PRESENT`] to match whether
    /// `self.checksum` is `Some` — so the bit and the trailing checksum
    /// bytes cannot disagree on the wire.
    ///
    /// # Errors
    ///
    /// See [`OperationMessageWriteError`].
    pub fn write_bytes(
        &self,
        dst: &mut BytesMut,
        request_id: RequestId,
        response_to: Option<ResponseTo>,
    ) -> Result<(), OperationMessageWriteError> {
        // Pre-serialise every section so we know the on-the-wire length up
        // front (the header carries the total message_length).
        let mut sections_bytes = Vec::new();
        for section in &self.sections {
            write_section(section, &mut sections_bytes)?;
        }

        // Re-derive checksum-present flag from struct state to avoid mismatch.
        let mut flags = self.flags;
        flags.set(
            OperationMessageFlags::CHECKSUM_PRESENT,
            self.checksum.is_some(),
        );

        let checksum_len = if self.checksum.is_some() {
            size_of::<u32>()
        } else {
            0
        };

        let message_length =
            MessageHeader::size() + size_of::<u32>() + sections_bytes.len() + checksum_len;

        dst.reserve(message_length);

        let message_length_i32 = i32::try_from(message_length)
            .map_err(|_| OperationMessageWriteError::MessageTooLarge(message_length))?;
        let header = MessageHeader {
            message_length: MessageLength::try_new(message_length_i32)
                .map_err(|_| OperationMessageWriteError::MessageTooLarge(message_length))?,
            op_code: OPCode::Msg,
            request_id,
            response_to,
        };
        header.write_bytes(dst);

        dst.put_u32_le(flags.bits());
        dst.put(sections_bytes.as_slice());

        if let Some(checksum) = self.checksum {
            dst.put_u32_le(checksum);
        }

        Ok(())
    }
}

fn parse_sections(bytes: &[u8]) -> Result<Vec<OpMsgSection>, OperationMessageParseError> {
    let mut cursor = Cursor::new(bytes);
    let mut sections = Vec::new();
    while (cursor.position() as usize) < bytes.len() {
        let pos = cursor.position() as usize;
        let kind = bytes[pos];
        cursor.set_position(pos as u64 + 1);
        match kind {
            0 => {
                let doc = Document::from_reader(&mut cursor)?;
                sections.push(OpMsgSection::Body(doc));
            }
            1 => {
                let section_start = cursor.position() as usize;
                if bytes.len() < section_start + 4 {
                    return Err(OperationMessageParseError::InvalidDocumentSequenceSize {
                        size: 0,
                    });
                }
                let size = i32::from_le_bytes([
                    bytes[section_start],
                    bytes[section_start + 1],
                    bytes[section_start + 2],
                    bytes[section_start + 3],
                ]);
                if size < 5 || (section_start + size as usize) > bytes.len() {
                    return Err(OperationMessageParseError::InvalidDocumentSequenceSize { size });
                }
                // Section payload (identifier + docs) excludes the kind byte
                // and includes the size field itself.
                let payload_end = section_start + size as usize;
                cursor.set_position(section_start as u64 + 4);

                let identifier_bytes = &bytes[cursor.position() as usize..payload_end];
                let identifier_cstr = CStr::from_bytes_until_nul(identifier_bytes)?;
                let identifier = identifier_cstr.to_str()?.to_owned();
                cursor.set_position(cursor.position() + identifier_cstr.count_bytes() as u64 + 1);

                let mut documents = Vec::new();
                while (cursor.position() as usize) < payload_end {
                    let doc = Document::from_reader(&mut cursor)?;
                    documents.push(doc);
                }
                sections.push(OpMsgSection::DocumentSequence {
                    identifier,
                    documents,
                });
            }
            other => return Err(OperationMessageParseError::InvalidKind(other)),
        }
    }
    Ok(sections)
}

fn write_section(
    section: &OpMsgSection,
    out: &mut Vec<u8>,
) -> Result<(), OperationMessageWriteError> {
    match section {
        OpMsgSection::Body(doc) => {
            out.push(0);
            doc.to_writer(&mut *out)?;
        }
        OpMsgSection::DocumentSequence {
            identifier,
            documents,
        } => {
            out.push(1);
            let identifier_cstring = CString::new(identifier.as_str())?;
            let identifier_bytes = identifier_cstring.as_bytes_with_nul();

            // We need the size up front, so serialise docs into a scratch
            // buffer first.
            let mut docs_bytes = Vec::new();
            for doc in documents {
                doc.to_writer(&mut docs_bytes)?;
            }

            let size_field = size_of::<i32>();
            let section_size = size_field + identifier_bytes.len() + docs_bytes.len();
            // The size field is the size INCLUDING itself, NOT including the
            // leading kind byte. The wire format encodes it as i32, so reject
            // sections that would silently wrap on cast.
            let section_size_i32 = i32::try_from(section_size)
                .map_err(|_| OperationMessageWriteError::SectionTooLarge(section_size))?;
            out.extend_from_slice(&section_size_i32.to_le_bytes());
            out.extend_from_slice(identifier_bytes);
            out.extend_from_slice(&docs_bytes);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    fn sample_body() -> OpMsgSection {
        OpMsgSection::Body(doc! { "hello": 1 })
    }

    fn sample_sections() -> Vec<OpMsgSection> {
        vec![sample_body()]
    }

    #[test]
    fn into_body_consumes_body_section() {
        let s = OpMsgSection::Body(doc! { "ping": 1 });
        let d = s.into_body().expect("body returns Some");
        assert_eq!(d, doc! { "ping": 1 });
    }

    #[test]
    fn into_body_returns_none_for_document_sequence() {
        let s = OpMsgSection::DocumentSequence {
            identifier: "documents".to_owned(),
            documents: vec![doc! { "x": 1 }],
        };
        assert!(s.into_body().is_none());
    }

    #[test]
    fn round_trip_preserves_more_to_come_flag() {
        let msg = OperationMessage {
            flags: OperationMessageFlags::MORE_TO_COME,
            sections: sample_sections(),
            checksum: None,
        };
        let mut buf = BytesMut::new();
        msg.write_bytes(&mut buf, RequestId::new(1), None).unwrap();
        // Skip 16-byte header to reach flags.
        let raw_flags = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        assert_eq!(
            raw_flags,
            OperationMessageFlags::MORE_TO_COME.bits(),
            "self.flags must be written, not empty"
        );
    }

    #[test]
    fn round_trip_with_checksum() {
        let msg = OperationMessage {
            flags: OperationMessageFlags::empty(),
            sections: sample_sections(),
            checksum: Some(0xDEADBEEF),
        };
        let mut buf = BytesMut::new();
        msg.write_bytes(&mut buf, RequestId::new(1), None).unwrap();

        let body = &buf[MessageHeader::size()..];
        let parsed = OperationMessage::from_bytes(body).unwrap();
        assert_eq!(parsed.checksum, Some(0xDEADBEEF));
        assert!(
            parsed
                .flags
                .contains(OperationMessageFlags::CHECKSUM_PRESENT)
        );
        assert_eq!(parsed.sections, sample_sections());
    }

    #[test]
    fn parse_errors_on_unknown_required_bit() {
        let mut body = Vec::new();
        // Use bit 2 (unknown required).
        body.extend_from_slice(&(1u32 << 2).to_le_bytes());
        body.push(0); // kind
        let doc_bytes = bson::serialize_to_vec(&doc! { "hello": 1 }).unwrap();
        body.extend_from_slice(&doc_bytes);

        let err = OperationMessage::from_bytes(&body).unwrap_err();
        assert!(matches!(
            err,
            OperationMessageParseError::UnknownRequiredBits(_)
        ));
    }

    #[test]
    fn parse_clears_unknown_optional_bits() {
        let mut body = Vec::new();
        // Set bit 17 (unknown optional) — must be silently cleared per spec.
        body.extend_from_slice(&(1u32 << 17).to_le_bytes());
        body.push(0);
        let doc_bytes = bson::serialize_to_vec(&doc! { "hello": 1 }).unwrap();
        body.extend_from_slice(&doc_bytes);

        let parsed = OperationMessage::from_bytes(&body).unwrap();
        assert_eq!(parsed.flags, OperationMessageFlags::empty());
    }

    #[test]
    fn parse_round_trips_exhaust_allowed_at_bit_16() {
        let msg = OperationMessage {
            flags: OperationMessageFlags::EXHAUST_ALLOWED,
            sections: sample_sections(),
            checksum: None,
        };
        let mut buf = BytesMut::new();
        msg.write_bytes(&mut buf, RequestId::new(1), None).unwrap();
        let body = &buf[MessageHeader::size()..];
        let parsed = OperationMessage::from_bytes(body).unwrap();
        assert_eq!(parsed.flags, OperationMessageFlags::EXHAUST_ALLOWED);
    }

    #[test]
    fn round_trip_body_plus_document_sequence() {
        // This is the shape a driver-emitted `insert` takes: the command
        // lives in a kind-0 body section, the documents-to-insert in a
        // kind-1 document-sequence section called "documents".
        let msg = OperationMessage {
            flags: OperationMessageFlags::empty(),
            sections: vec![
                OpMsgSection::Body(doc! { "insert": "movies", "$db": "sample" }),
                OpMsgSection::DocumentSequence {
                    identifier: "documents".to_owned(),
                    documents: vec![
                        doc! { "_id": 1, "title": "Movie 1" },
                        doc! { "_id": 2, "title": "Movie 2" },
                        doc! { "_id": 3, "title": "Movie 3" },
                    ],
                },
            ],
            checksum: None,
        };
        let mut buf = BytesMut::new();
        msg.write_bytes(&mut buf, RequestId::new(7), None).unwrap();
        let body = &buf[MessageHeader::size()..];
        let parsed = OperationMessage::from_bytes(body).unwrap();
        assert_eq!(parsed, msg);
        assert_eq!(parsed.command_name(), Some("insert"));
    }

    #[test]
    fn parse_errors_on_unknown_section_kind() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // flags
        body.push(99); // unknown kind
        let err = OperationMessage::from_bytes(&body).unwrap_err();
        assert!(matches!(err, OperationMessageParseError::InvalidKind(99)));
    }
}
