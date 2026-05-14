//! Public output types produced by the explain inspector for the success
//! and "unsupported shape" / "malformed reply" paths.

use super::{
    namespace::Namespace,
    newtypes::{AggregateTime, DocsExamined, DocsReturned, IndexName, KeysExamined, NodeTime},
    open_vocab::Command,
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
    pub stage: Stage,
    /// Per-stage execution time (server's `executionTimeMillisEstimate`).
    /// Optional because the wire field is optional; we never silently
    /// default to zero.
    pub execution_time: Option<NodeTime>,
    pub n_returned: DocsReturned,
    pub docs_examined: Option<DocsExamined>,
    pub keys_examined: Option<KeysExamined>,
    pub index_name: Option<IndexName>,
    pub key_pattern: Option<KeyPattern>,
    pub index_bounds: Option<IndexBounds>,
    /// `"forward"` or `"backward"`. Present on most scan stages.
    pub direction: Option<String>,
    pub filter: Option<Filter>,
    pub children: Vec<PlanNode>,
}

/// Server-reported aggregate counters for the whole plan execution.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct ExplainTotals {
    pub n_returned: DocsReturned,
    pub docs_examined: DocsExamined,
    pub keys_examined: KeysExamined,
    pub execution_time: AggregateTime,
}

/// One typed event delivered to `ExplainSink::record`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ExplainEvent {
    pub command: Command,
    pub namespace: Namespace,
    pub total: ExplainTotals,
    pub plan: PlanNode,
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
    Null,
    StringValue,
    Bool,
    Array,
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
    #[allow(dead_code)]
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
