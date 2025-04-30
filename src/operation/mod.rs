use std::num::NonZeroI32;

use op_msg::{OperationMessage, OperationMessageParseError, OperationMessageWriteError};
use op_query::{OperationQuery, OperationQueryParseError, OperationQueryWriteError};
use tokio_util::bytes::BytesMut;

use crate::op_code::OPCode;

pub mod op_msg;
pub mod op_query;

#[derive(Clone, Debug, PartialEq)]
pub enum Operation {
    Query(OperationQuery),
    Message(OperationMessage),
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationParseError {
    #[error("failed to parse message: {0}")]
    FailedToParseMessage(#[from] OperationMessageParseError),
    #[error("failed to parse query: {0}")]
    FailedToParseQuery(#[from] OperationQueryParseError),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationWriteError {
    #[error("failed to write message operation: {0}")]
    FailedToWriteOperationMessage(#[from] OperationMessageWriteError),
    #[error("failed to write query operation: {0}")]
    FailedToWriteOperationQuery(#[from] OperationQueryWriteError),
}

impl Eq for OperationMessageWriteError {}

impl PartialEq for OperationMessageWriteError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                OperationMessageWriteError::SerializeError(_),
                OperationMessageWriteError::SerializeError(_),
            ) => true,
        }
    }
}

impl Operation {
    pub fn from_bytes(op_code: OPCode, bytes: &[u8]) -> Result<Self, OperationParseError> {
        Ok(match op_code {
            OPCode::Msg => Operation::Message(OperationMessage::from_bytes(bytes)?),
            OPCode::Query => Operation::Query(OperationQuery::from_bytes(bytes)?),
        })
    }

    pub fn write_bytes(
        &self,
        dst: &mut BytesMut,
        request_id: i32,
        response_to: Option<NonZeroI32>,
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
        }
    }
}
