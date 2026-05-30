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
    /// The explain reply contained no body (kind-0) section to inspect.
    #[error("explain reply has no body section")]
    MissingBody,
    /// The reply's `ok` field was present but not a recognisable boolean/number.
    #[error("explain reply `ok` field is malformed: {0:?}")]
    MalformedOk(MalformedOkShape),
    /// The reply body failed to deserialise into the explain model.
    #[error("explain reply deserialise failed (preview: {raw_preview}): {source}")]
    Deserialise {
        /// Truncated textual preview of the offending reply body, for logs.
        raw_preview: String,
        /// The underlying BSON deserialisation error.
        #[source]
        source: bson::error::Error,
    },
    /// An `ok=0` reply was seen but its error body did not match the expected shape.
    #[error("explain reply with ok=0 had malformed error body (preview: {raw_preview}): {source}")]
    MalformedServerError {
        /// Truncated textual preview of the offending error body, for logs.
        raw_preview: String,
        /// The underlying BSON deserialisation error.
        #[source]
        source: bson::error::Error,
    },
    /// A plan node declared both `inputStage` and `inputStages`, which is ambiguous.
    #[error("plan node at depth {depth} had both inputStage and inputStages")]
    BothChildrenShapesPresent {
        /// Depth of the offending node in the plan tree.
        depth: usize,
    },
    /// The `queryPlanner` namespace string could not be parsed.
    #[error("namespace in queryPlanner could not be parsed: {0}")]
    BadNamespace(#[from] super::model::NamespaceParseError),
    /// A timing field carried a negative millisecond value.
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
    /// The server replied `ok=0`, rejecting the explain command.
    Rejected {
        /// Human-readable `errmsg` text from the server.
        message: String,
        /// Numeric error `code`, if present.
        code: Option<ServerErrorCode>,
        /// Symbolic `codeName`, if present.
        code_name: Option<ServerErrorCodeName>,
        /// `errorLabels` attached to the rejection, if any.
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
    /// Name of the wire field that carried the negative value.
    pub field: &'static str,
    /// The offending negative millisecond value.
    pub value: i64,
}

/// Top-level explain-branch failure, generic over the inner service's
/// error type `E` so the typed-source rule survives the whole pipeline.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExplainError<E: std::error::Error> {
    /// The wrapped inner service failed while the explain branch was running.
    #[error("inner service error during explain")]
    InnerService(#[source] E),
    /// The explain reply could not be parsed.
    #[error(transparent)]
    Parse(#[from] ExplainParseError),
    /// The server rejected the explain command with `ok=0`.
    #[error(transparent)]
    Server(#[from] ExplainServerError),
    /// The sideband request-id space was exhausted.
    #[error(transparent)]
    RequestIdExhausted(#[from] RequestIdExhausted),
    /// The intercepted command had a shape the inspector does not support.
    #[error("unsupported command shape: {0}")]
    UnsupportedShape(#[from] super::model::UnsupportedShape),
}
