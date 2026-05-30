//! Typed wire-protocol operation bodies (everything after the 16-byte header).
//!
//! The MongoDB wire protocol uses a small set of opcodes. Each opcode has its
//! own body layout, modelled here:
//!
//! * [`op_msg::OperationMessage`] — modern OP_MSG; the only opcode used for
//!   user-visible commands on current servers.
//! * [`op_query::OperationQuery`] — legacy OP_QUERY; still used for the
//!   initial `isMaster` / `hello` handshake.
//! * [`op_reply::OperationReply`] — legacy OP_REPLY; paired with OP_QUERY.
//!
//! The [`Operation`] enum is the discriminated union the rest of the crate
//! uses to talk about an operation body abstractly.

use op_msg::{OperationMessage, OperationMessageParseError, OperationMessageWriteError};
use op_query::{OperationQuery, OperationQueryParseError, OperationQueryWriteError};
use op_reply::{OperationReply, OperationReplyParseError, OperationReplyWriteError};
use tokio_util::bytes::BytesMut;

use crate::ids::{RequestId, ResponseTo};
use crate::op_code::OPCode;

pub mod op_msg;
pub mod op_query;
pub mod op_reply;

/// Typed wire-protocol operation, selected by [`OPCode`].
///
/// A [`Message`](crate::message::Message) owns exactly one of these.
#[derive(Clone, Debug, PartialEq)]
pub enum Operation {
    /// Legacy OP_QUERY body. Drivers still emit this for the initial
    /// `isMaster` / `hello` handshake before the wire version is known.
    Query(OperationQuery),
    /// Modern OP_MSG body. Every post-handshake command uses this format.
    Message(OperationMessage),
    /// Legacy OP_REPLY body. Servers emit this in response to OP_QUERY.
    Reply(OperationReply),
}

/// Failure modes for [`Operation::from_bytes`].
///
/// Each variant flattens the per-opcode parse error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OperationParseError {
    /// The OP_MSG body could not be parsed.
    #[error("failed to parse message: {0}")]
    FailedToParseMessage(#[from] OperationMessageParseError),
    /// The OP_QUERY body could not be parsed.
    #[error("failed to parse query: {0}")]
    FailedToParseQuery(#[from] OperationQueryParseError),
    /// The OP_REPLY body could not be parsed.
    #[error("failed to parse reply: {0}")]
    FailedToParseReply(#[from] OperationReplyParseError),
}

/// Failure modes for [`Operation::write_bytes`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OperationWriteError {
    /// Encoding an OP_MSG body failed (typically BSON serialisation).
    #[error("failed to write message operation: {0}")]
    FailedToWriteOperationMessage(#[from] OperationMessageWriteError),
    /// Encoding an OP_QUERY body failed.
    #[error("failed to write query operation: {0}")]
    FailedToWriteOperationQuery(#[from] OperationQueryWriteError),
    /// Encoding an OP_REPLY body failed.
    #[error("failed to write reply operation: {0}")]
    FailedToWriteOperationReply(#[from] OperationReplyWriteError),
}

impl Operation {
    /// Returns the wire-protocol kind label for this operation.
    ///
    /// Useful for structured logging without having to match the [`Operation`]
    /// enum at every call site.
    pub const fn op_kind(&self) -> &'static str {
        match self {
            Operation::Message(_) => "OP_MSG",
            Operation::Query(_) => "OP_QUERY",
            Operation::Reply(_) => "OP_REPLY",
        }
    }

    /// Returns the BSON command name driving this operation, when one is
    /// identifiable.
    ///
    /// For OP_MSG the first key of the first body section is the command
    /// name (e.g. `"find"`, `"insert"`, `"hello"`). For OP_QUERY the first
    /// key of the query document is used. Server replies (OP_REPLY) don't
    /// carry a command name and return `None`.
    pub fn command_name(&self) -> Option<&str> {
        match self {
            Operation::Message(m) => m.command_name(),
            Operation::Query(q) => q.query.keys().next().map(String::as_str),
            Operation::Reply(_) => None,
        }
    }

    /// Parses the body bytes that follow a [`MessageHeader`](crate::header::MessageHeader),
    /// dispatching on the opcode the header announced.
    ///
    /// `bytes` should contain *only* the body — the caller (typically
    /// [`Message::from_headers_and_bytes`](crate::message::Message::from_headers_and_bytes))
    /// is responsible for stripping the header off first.
    ///
    /// # Errors
    ///
    /// See [`OperationParseError`].
    pub fn from_bytes(op_code: OPCode, bytes: &[u8]) -> Result<Self, OperationParseError> {
        Ok(match op_code {
            OPCode::Msg => Operation::Message(OperationMessage::from_bytes(bytes)?),
            OPCode::Query => Operation::Query(OperationQuery::from_bytes(bytes)?),
            OPCode::Reply => Operation::Reply(OperationReply::from_bytes(bytes)?),
        })
    }

    /// Appends the full wire encoding (header + body) for this operation to
    /// `dst`.
    ///
    /// The function delegates to the variant-specific writer, which builds
    /// the matching [`MessageHeader`](crate::header::MessageHeader) (with
    /// the correct `op_code` and the derived `message_length`) and the body
    /// itself.
    ///
    /// # Errors
    ///
    /// See [`OperationWriteError`].
    pub fn write_bytes(
        &self,
        dst: &mut BytesMut,
        request_id: RequestId,
        response_to: Option<ResponseTo>,
    ) -> Result<(), OperationWriteError> {
        match self {
            Operation::Message(operation_message) => {
                operation_message.write_bytes(dst, request_id, response_to)?;
                Ok(())
            }
            Operation::Query(query_message) => {
                query_message.write_bytes(dst, request_id, response_to)?;
                Ok(())
            }
            Operation::Reply(operation_reply) => {
                operation_reply.write_bytes(dst, request_id, response_to)?;
                Ok(())
            }
        }
    }
}
