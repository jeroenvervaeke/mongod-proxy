//! Public typed model produced by the explain inspector.

pub mod event;
pub mod namespace;
pub mod newtypes;
pub mod open_vocab;
pub mod plan_details;
pub mod stage;

pub use event::{ExplainEvent, ExplainTotals, MalformedOkShape, PlanNode, UnsupportedShape};
pub use namespace::{Namespace, NamespaceParseError, NamespaceParseErrorKind};
pub use newtypes::{
    AggregateTime, Collection, CollectionError, Database, DatabaseError, DocsExamined,
    DocsExaminedError, DocsReturned, DocsReturnedError, IndexName, IndexNameError, KeysExamined,
    KeysExaminedError, NodeTime, OtherName, ServerErrorCode, ServerErrorCodeError,
};
pub use open_vocab::{Command, Direction, ErrorLabel, ServerErrorCodeName};
pub use plan_details::{
    BoundValue, Filter, Inclusivity, IndexBoundRange, IndexBounds, IndexBoundsParseError,
    IndexFieldKind, KeyPattern, KeyPatternField,
};
pub use stage::{AndKind, ProjectionKind, Stage};
