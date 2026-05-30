//! Public output types produced by the explain inspector for the success
//! and "unsupported shape" / "malformed reply" paths.

use crate::ids::{ExplainRequestId, RequestId};

use super::{
    namespace::Namespace,
    newtypes::{AggregateTime, DocsExamined, DocsReturned, IndexName, KeysExamined, NodeTime},
    open_vocab::{Command, Direction},
    plan_details::{Filter, IndexBounds, KeyPattern},
    stage::Stage,
};

/// One node in the executed plan tree.
///
/// `children` is flat (no wire-shape enum): `inputStage` becomes a
/// one-element vec, `inputStages` becomes the multi-element vec, leaf
/// stages have an empty vec.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PlanNode {
    /// The plan stage this node executes (e.g. `IXSCAN`, `FETCH`).
    pub stage: Stage,
    /// Per-stage execution time (server's `executionTimeMillisEstimate`).
    /// Optional because the wire field is optional; we never silently
    /// default to zero.
    pub execution_time: Option<NodeTime>,
    /// Documents returned by this stage (`nReturned`).
    pub n_returned: DocsReturned,
    /// Documents examined by this stage (`docsExamined`), when reported.
    pub docs_examined: Option<DocsExamined>,
    /// Index keys examined by this stage (`keysExamined`), when reported.
    pub keys_examined: Option<KeysExamined>,
    /// Name of the index this stage used, for index-backed stages.
    pub index_name: Option<IndexName>,
    /// Key pattern of the index this stage used.
    pub key_pattern: Option<KeyPattern>,
    /// Scanned index bounds, for index-scan stages.
    pub index_bounds: Option<IndexBounds>,
    /// Scan direction. Present on most scan stages.
    pub direction: Option<Direction>,
    /// Residual filter applied by this stage, if any.
    pub filter: Option<Filter>,
    /// Child plan nodes feeding into this stage (empty for leaves).
    pub children: Vec<PlanNode>,
}

/// Server-reported aggregate counters for the whole plan execution.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct ExplainTotals {
    /// Total documents returned by the plan (`nReturned`).
    pub n_returned: DocsReturned,
    /// Total documents examined across the plan (`totalDocsExamined`).
    pub docs_examined: DocsExamined,
    /// Total index keys examined across the plan (`totalKeysExamined`).
    pub keys_examined: KeysExamined,
    /// Total execution time for the plan (`executionTimeMillis`).
    pub execution_time: AggregateTime,
}

/// One typed event delivered to `ExplainSink::record`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ExplainEvent {
    /// Command that was explained (e.g. `find`, `aggregate`).
    pub command: Command,
    /// Collection the command ran against.
    pub namespace: Namespace,
    /// Aggregate execution counters for the whole plan.
    pub total: ExplainTotals,
    /// Root of the executed plan tree.
    pub plan: PlanNode,
    /// `request_id` from the original client OP_MSG that triggered this
    /// explain. Lets sinks correlate explain output with the wider
    /// client-traffic flow.
    pub client_request_id: RequestId,
    /// `request_id` the proxy stamped on the sideband explain request
    /// it issued upstream. Always strictly negative — disjoint from
    /// driver-assigned ids by type. `None` when the request id space was
    /// exhausted and no explain was issued.
    pub explain_request_id: Option<ExplainRequestId>,
}

/// Classification of an `ok` field that is neither a valid success nor a
/// valid rejection — every non-numeric or non-finite shape lands here.
///
/// Used inside `ExplainParseError::MalformedOk` so consumers can match on
/// the BSON shape that surprised us rather than substring-matching an
/// error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MalformedOkShape {
    /// `ok` field absent.
    Missing,
    /// `ok` was BSON null.
    Null,
    /// `ok` was a string.
    StringValue,
    /// `ok` was a boolean.
    Bool,
    /// `ok` was an array.
    Array,
    /// `ok` was a sub-document.
    Document,
    /// `NaN`, `+Infinity` or `-Infinity` — any non-finite double.
    NonFinite,
    /// Some other BSON type tag we did not enumerate explicitly.
    Other(bson::spec::ElementType),
}

impl MalformedOkShape {
    /// Classify a non-numeric BSON value. Total — caller must have already
    /// dispatched the numeric variants (Int32/Int64/finite-Double) in
    /// `probe_ok`. Used only from the `other =>` arm where numeric forms
    /// are unreachable.
    pub(crate) fn from_non_numeric_bson(b: &bson::Bson) -> MalformedOkShape {
        use bson::Bson;
        match b {
            Bson::Null => MalformedOkShape::Null,
            Bson::String(_) => MalformedOkShape::StringValue,
            Bson::Boolean(_) => MalformedOkShape::Bool,
            Bson::Array(_) => MalformedOkShape::Array,
            Bson::Document(_) => MalformedOkShape::Document,
            // Numeric variants pre-filtered by probe_ok; defensive fallback.
            Bson::Int32(_) | Bson::Int64(_) | Bson::Double(_) => MalformedOkShape::NonFinite,
            other => MalformedOkShape::Other(other.element_type()),
        }
    }
}

/// Reasons `build_explain` cannot construct an explain envelope for a
/// command that `classify` admitted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedShape {
    /// Command carried multiple write ops; the server cannot explain a
    /// bulk write batch, so no sideband explain is issued.
    #[error("multi-op write batch (server does not support explaining bulk writes)")]
    MultiOpWriteBatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::{Bson, doc};

    #[test]
    fn malformed_ok_shape_from_null() {
        assert_eq!(
            MalformedOkShape::from_non_numeric_bson(&Bson::Null),
            MalformedOkShape::Null,
        );
    }

    #[test]
    fn malformed_ok_shape_from_string() {
        assert_eq!(
            MalformedOkShape::from_non_numeric_bson(&Bson::String("yes".into())),
            MalformedOkShape::StringValue,
        );
    }

    #[test]
    fn malformed_ok_shape_from_bool() {
        assert_eq!(
            MalformedOkShape::from_non_numeric_bson(&Bson::Boolean(true)),
            MalformedOkShape::Bool,
        );
    }

    #[test]
    fn malformed_ok_shape_from_array() {
        assert_eq!(
            MalformedOkShape::from_non_numeric_bson(&Bson::Array(vec![])),
            MalformedOkShape::Array,
        );
    }

    #[test]
    fn malformed_ok_shape_from_document() {
        assert_eq!(
            MalformedOkShape::from_non_numeric_bson(&Bson::Document(doc! {})),
            MalformedOkShape::Document,
        );
    }
}
