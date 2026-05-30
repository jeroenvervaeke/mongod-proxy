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
#[derive(Clone, PartialEq)]
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

impl std::fmt::Debug for OpMsgSection {
    /// Renders structural metadata, routing every embedded BSON document
    /// through [`RedactedDoc`](crate::redact::RedactedDoc) so credential-bearing
    /// payloads (e.g. `saslStart`) never reach logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpMsgSection::Body(doc) => f
                .debug_tuple("Body")
                .field(&crate::redact::RedactedDoc(doc))
                .finish(),
            OpMsgSection::DocumentSequence {
                identifier,
                documents,
            } => f
                .debug_struct("DocumentSequence")
                .field("identifier", identifier)
                .field("document_count", &documents.len())
                .field(
                    "documents",
                    &documents
                        .iter()
                        .map(crate::redact::RedactedDoc)
                        .collect::<Vec<_>>(),
                )
                .finish(),
        }
    }
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
#[derive(Clone, PartialEq)]
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

impl std::fmt::Debug for OperationMessage {
    /// Renders flags, section/command metadata, and the checksum. Every
    /// embedded BSON document is redacted via [`OpMsgSection`]'s own
    /// credential-aware [`Debug`] impl.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationMessage")
            .field("flags", &self.flags)
            .field("section_count", &self.sections.len())
            .field("command_name", &self.command_name())
            .field("sections", &self.sections)
            .field("checksum", &self.checksum)
            .finish()
    }
}

/// Failure modes for [`OperationMessage::from_bytes`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OperationMessageParseError {
    /// Body shorter than the unconditional minimum (flag bits + first kind byte).
    #[error("not enough bytes, expected at least {min} bytes, got {actual}")]
    NotEnoughBytes {
        /// Number of body bytes actually available.
        actual: usize,
        /// Minimum number of bytes required to begin parsing.
        min: usize,
    },
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
    InvalidDocumentSequenceSize {
        /// The out-of-range section size declared in the kind-1 header.
        size: i32,
    },
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
#[non_exhaustive]
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
        // #46: carry robustness in the type system rather than relying on a
        // re-derived `pos < bytes.len()` invariant. `pos` came straight from
        // `cursor.position()` which the loop guard bounds, but bounds-checked
        // `get` keeps that guarantee local and refactor-proof.
        let kind = *bytes
            .get(pos)
            .ok_or(OperationMessageParseError::NotEnoughBytes {
                actual: bytes.len(),
                min: pos + 1,
            })?;
        cursor.set_position(pos as u64 + 1);
        match kind {
            0 => {
                let doc = Document::from_reader(&mut cursor)?;
                sections.push(OpMsgSection::Body(doc));
            }
            1 => {
                let section_start = cursor.position() as usize;
                // The 4-byte size prefix must be fully present.
                let size_bytes = bytes
                    .get(section_start..section_start + 4)
                    .ok_or(OperationMessageParseError::InvalidDocumentSequenceSize { size: 0 })?;
                let size = i32::from_le_bytes([
                    size_bytes[0],
                    size_bytes[1],
                    size_bytes[2],
                    size_bytes[3],
                ]);
                // The size field counts itself (>= 4) plus a NUL-terminated
                // identifier (>= 1), so the smallest valid section is 5 bytes.
                // It must also fit inside the remaining buffer.
                if size < 5 {
                    return Err(OperationMessageParseError::InvalidDocumentSequenceSize { size });
                }
                let payload_end = section_start
                    .checked_add(size as usize)
                    .filter(|&end| end <= bytes.len())
                    .ok_or(OperationMessageParseError::InvalidDocumentSequenceSize { size })?;

                // Identifier lives between the size field and the first doc.
                let ident_start = section_start + 4;
                let identifier_bytes = bytes
                    .get(ident_start..payload_end)
                    .ok_or(OperationMessageParseError::InvalidDocumentSequenceSize { size })?;
                let identifier_cstr = CStr::from_bytes_until_nul(identifier_bytes)?;
                let identifier = identifier_cstr.to_str()?.to_owned();
                let ident_end = ident_start + identifier_cstr.count_bytes() + 1;

                // #45: parse the document sequence from a sub-slice bounded by
                // `payload_end`, so a doc whose internal length prefix points
                // past the section boundary (but still inside the outer buffer)
                // physically cannot be read across the declared section.
                let docs_bytes = bytes
                    .get(ident_end..payload_end)
                    .ok_or(OperationMessageParseError::InvalidDocumentSequenceSize { size })?;
                let mut reader = Cursor::new(docs_bytes);
                let mut documents = Vec::new();
                while (reader.position() as usize) < docs_bytes.len() {
                    let doc = Document::from_reader(&mut reader)?;
                    documents.push(doc);
                }
                sections.push(OpMsgSection::DocumentSequence {
                    identifier,
                    documents,
                });

                // Advance the outer cursor past the whole section.
                cursor.set_position(payload_end as u64);
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

    /// #45 regression: a kind-1 document-sequence whose inner BSON doc declares
    /// a length prefix that runs past the section's declared `payload_end` (but
    /// still inside the outer buffer) must NOT be read across the section
    /// boundary into whatever follows. Parsing must error rather than consume
    /// the next section's bytes.
    #[test]
    fn parse_kind1_doc_cannot_overrun_section_boundary() {
        // Build the document-sequence payload by hand so we can lie about the
        // inner doc length.
        let identifier = b"documents\0";

        // Inner doc claims to be 12 bytes long but we only place it inside a
        // section sized to hold an 8-byte doc body, so the doc reader would
        // have to read past `payload_end` to satisfy the (lying) length.
        let mut doc_with_overrunning_len = Vec::new();
        doc_with_overrunning_len.extend_from_slice(&12i32.to_le_bytes()); // length lies (too big)
        doc_with_overrunning_len.extend_from_slice(&[0u8; 3]); // only 3 of the claimed bytes present in-section

        // Section size counts: size field (4) + identifier + the in-section doc bytes.
        let section_size = 4 + identifier.len() + doc_with_overrunning_len.len();

        let mut section = Vec::new();
        section.extend_from_slice(&(section_size as i32).to_le_bytes());
        section.extend_from_slice(identifier);
        section.extend_from_slice(&doc_with_overrunning_len);

        // Append a *valid* trailing body section. If the kind-1 parser overran,
        // it would start consuming these bytes instead of erroring.
        let trailing = bson::serialize_to_vec(&doc! { "next": "section" }).unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // flags
        body.push(1); // kind-1
        body.extend_from_slice(&section);
        body.push(0); // kind-0 trailing body
        body.extend_from_slice(&trailing);

        // Must error (the in-section doc is malformed/truncated), and crucially
        // must not have read across into the trailing section.
        let err = OperationMessage::from_bytes(&body).unwrap_err();
        assert!(matches!(err, OperationMessageParseError::InvalidBson(_)));
    }

    /// #45 regression (boundary stop): a well-formed kind-1 section followed by
    /// another section must parse the document sequence only up to its own
    /// declared boundary, leaving the following section intact.
    #[test]
    fn parse_kind1_stops_at_section_boundary() {
        let msg = OperationMessage {
            flags: OperationMessageFlags::empty(),
            sections: vec![
                OpMsgSection::DocumentSequence {
                    identifier: "documents".to_owned(),
                    documents: vec![doc! { "a": 1 }],
                },
                OpMsgSection::Body(doc! { "after": 2 }),
            ],
            checksum: None,
        };
        let mut buf = BytesMut::new();
        msg.write_bytes(&mut buf, RequestId::new(1), None).unwrap();
        let body = &buf[MessageHeader::size()..];
        let parsed = OperationMessage::from_bytes(body).unwrap();
        assert_eq!(parsed, msg);
    }

    /// #40 regression: formatting an `OperationMessage` whose body carries a
    /// `saslStart` payload must not leak the secret payload into the output.
    #[test]
    fn debug_redacts_sasl_payload() {
        let msg = OperationMessage {
            flags: OperationMessageFlags::empty(),
            sections: vec![OpMsgSection::Body(doc! {
                "saslStart": 1,
                "payload": "SECRET",
            })],
            checksum: None,
        };
        let shown = format!("{msg:?}");
        assert!(
            !shown.contains("SECRET"),
            "debug output leaked payload: {shown}"
        );
        // Structural metadata is still present.
        assert!(shown.contains("saslStart"));
        assert!(shown.contains("OperationMessage"));
    }

    /// #46 regression: a truncated section header (the leading kind byte is the
    /// last byte of the buffer, with a kind-1 size prefix that does not fit)
    /// must surface a structured error rather than panic on direct indexing.
    #[test]
    fn parse_errors_on_truncated_section_header() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // flags
        body.push(1); // kind-1, but no 4-byte size prefix follows
        body.extend_from_slice(&[0u8, 0u8]); // only 2 of the 4 size bytes
        let err = OperationMessage::from_bytes(&body).unwrap_err();
        assert!(matches!(
            err,
            OperationMessageParseError::InvalidDocumentSequenceSize { .. }
        ));
    }
}
