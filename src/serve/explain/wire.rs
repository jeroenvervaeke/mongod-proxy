//! Raw wire types — `serde::Deserialize`d directly from the explain reply
//! body via `bson::from_document`.
//!
//! These are `pub(crate)`: downstream code only ever sees the public typed
//! model in [`super::model`]. The raw types are the boundary layer where
//! parse-don't-validate happens.

use serde::Deserialize;

use super::model::{
    DocsExamined, DocsReturned, ErrorLabel, IndexName, KeysExamined, ServerErrorCode,
    ServerErrorCodeName, Stage,
};

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawExplainReply {
    pub query_planner: RawQueryPlanner,
    pub execution_stats: RawExecutionStats,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawQueryPlanner {
    /// Wire `namespace` string, e.g. `"sample.movies"`. Parsed into the
    /// public typed [`Namespace`](super::model::Namespace) by
    /// `try_into_event` — *not* by serde — so the typed
    /// `NamespaceParseError` survives intact.
    pub namespace: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawExecutionStats {
    /// Raw `i64` milliseconds — converted to [`AggregateTime`](super::model::AggregateTime)
    /// via `i64_ms_to_duration` so a negative value surfaces as the typed
    /// `NegativeDurationError` rather than being laundered through
    /// `serde::de::Error::custom`.
    pub execution_time_millis: i64,
    pub n_returned: DocsReturned,
    pub total_docs_examined: DocsExamined,
    pub total_keys_examined: KeysExamined,
    pub execution_stages: RawPlanNode,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawPlanNode {
    pub stage: Stage,
    /// Raw `i64` ms; converted by `to_plan_node`.
    #[serde(default)]
    pub execution_time_millis_estimate: Option<i64>,
    pub n_returned: DocsReturned,
    #[serde(default)]
    pub docs_examined: Option<DocsExamined>,
    #[serde(default)]
    pub keys_examined: Option<KeysExamined>,
    #[serde(default)]
    pub index_name: Option<IndexName>,
    /// Wire field `inputStage` (single-child case).
    #[serde(default, rename = "inputStage")]
    pub input_stage: Option<Box<RawPlanNode>>,
    /// Wire field `inputStages` (branching case).
    #[serde(default, rename = "inputStages")]
    pub input_stages: Option<Vec<RawPlanNode>>,
}

/// Body of an `ok: 0` reply. Carried through to
/// [`ExplainServerError::Rejected`](super::error::ExplainServerError) as
/// typed fields.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawServerError {
    #[serde(rename = "errmsg")]
    pub message: String,
    pub code: Option<ServerErrorCode>,
    pub code_name: Option<ServerErrorCodeName>,
    #[serde(default)]
    pub error_labels: Vec<ErrorLabel>,
}
