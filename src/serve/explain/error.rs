//! Error types for the explain inspector.
//!
//! Split across three layers:
//!   - [`ExplainParseError`] — wire reply could not be parsed.
//!   - [`ExplainServerError`] — server replied with `ok=0` (typed rejection).
//!   - [`ExplainError<E>`] — top-level union, generic over the inner
//!     service's error type so typed source preservation (rule 18) survives
//!     end-to-end.
//!
//! Disjointness invariant: `ExplainParseError` does NOT carry a
//! `ServerRejected` variant. Server rejections live exclusively on
//! [`ExplainError::Server`].

use super::model::{ErrorLabel, MalformedOkShape, ServerErrorCode, ServerErrorCodeName};

/// Wire-reply parse failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExplainParseError {
    #[error("explain reply has no body section")]
    MissingBody,
    #[error("explain reply `ok` field is malformed: {0:?}")]
    MalformedOk(MalformedOkShape),
    #[error("explain reply deserialise failed (preview: {raw_preview}): {source}")]
    Deserialise {
        raw_preview: String,
        #[source]
        source: bson::de::Error,
    },
    #[error("explain reply with ok=0 had malformed error body (preview: {raw_preview}): {source}")]
    MalformedServerError {
        raw_preview: String,
        #[source]
        source: bson::de::Error,
    },
    #[error("plan node at depth {depth} had both inputStage and inputStages")]
    BothChildrenShapesPresent { depth: usize },
    #[error("namespace in queryPlanner could not be parsed: {0}")]
    BadNamespace(#[from] super::model::NamespaceParseError),
    #[error(transparent)]
    NegativeDuration(#[from] NegativeDurationError),
}

/// Typed `ok=0` server rejection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExplainServerError {
    #[error(
        "server returned error: {message} (code={code:?}, code_name={code_name:?}, labels={labels:?})"
    )]
    Rejected {
        message: String,
        code: Option<ServerErrorCode>,
        code_name: Option<ServerErrorCodeName>,
        labels: Vec<ErrorLabel>,
    },
}

/// Raised when [`alloc_request_id`](super::layer) cannot allocate a fresh
/// strictly-negative id (counter reached `i32::MIN` or crossed zero).
#[derive(Debug, thiserror::Error)]
#[error("explain request id space exhausted")]
pub struct RequestIdExhausted;

/// Raised by `i64_ms_to_duration` when the wire field carried a negative
/// millisecond value. Carries the offending field name and value so the
/// site is identifiable from logs.
#[derive(Debug, thiserror::Error)]
#[error("duration must be non-negative, got {value} ms in field {field}")]
pub struct NegativeDurationError {
    pub field: &'static str,
    pub value: i64,
}

/// Top-level explain-branch failure, generic over the inner service's
/// error type `E` so the typed-source rule survives the whole pipeline.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExplainError<E: std::error::Error> {
    #[error("inner service error during explain")]
    InnerService(#[source] E),
    #[error(transparent)]
    Parse(#[from] ExplainParseError),
    #[error(transparent)]
    Server(#[from] ExplainServerError),
    #[error(transparent)]
    RequestIdExhausted(#[from] RequestIdExhausted),
    #[error("unsupported command shape: {0}")]
    UnsupportedShape(#[from] super::model::UnsupportedShape),
}
