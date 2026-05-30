//! Explain inspector — captures MongoDB query plans via sideband `explain`
//! operations and emits typed events through a user-supplied sink.

pub(crate) mod build;
pub(crate) mod classify;
pub mod error;
pub mod layer;
pub mod model;
pub(crate) mod parse;
pub mod sink;
pub(crate) mod util;
pub(crate) mod wire;

pub use error::{
    ExplainError, ExplainParseError, ExplainServerError, NegativeDurationError, RequestIdExhausted,
};
pub use layer::{ExplainLayer, ExplainService, ReplayStream};
pub use model::{
    AggregateTime, AndKind, BoundValue, Collection, CollectionError, Command, Database,
    DatabaseError, Direction, DocsExamined, DocsExaminedError, DocsReturned, DocsReturnedError,
    ErrorLabel, ExplainEvent, ExplainTotals, Filter, Inclusivity, IndexBoundRange, IndexBounds,
    IndexBoundsParseError, IndexFieldKind, IndexName, IndexNameError, KeyPattern, KeyPatternField,
    KeysExamined, KeysExaminedError, MalformedOkShape, Namespace, NamespaceParseError,
    NamespaceParseErrorKind, NodeTime, OtherName, PlanNode, ProjectionKind, ServerErrorCode,
    ServerErrorCodeError, ServerErrorCodeName, Stage, UnsupportedShape,
};
pub use sink::{ExplainSink, TracingOnly};
