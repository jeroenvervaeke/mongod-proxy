//! Parse explain reply bytes → typed [`ExplainEvent`] / [`ExplainServerError`].
//!
//! Three-outcome dispatch:
//!   - probe `ok` directly on the borrowed `bson::Document` (no clone),
//!   - on success deserialise [`RawExplainReply`] then map to [`ExplainEvent`],
//!   - on `ok=0` deserialise [`RawServerError`] then map to [`ExplainServerError`].

use std::time::Duration;

use bson::{Bson, Document};

use super::error::{ExplainParseError, ExplainServerError, NegativeDurationError};
use super::model::{
    AggregateTime, ErrorLabel, ExplainEvent, ExplainTotals, MalformedOkShape, Namespace, NodeTime,
    PlanNode, ServerErrorCode, ServerErrorCodeName,
};
use super::wire::{RawExplainReply, RawPlanNode, RawServerError};

/// Three explicit outcomes of probing the `ok` field of an explain reply.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
enum OkOutcome {
    Success,
    Rejected,
    Malformed(MalformedOkShape),
}

/// Probe the `ok` field directly on the borrowed [`Document`] without
/// cloning it. Only valid numeric forms (Int32/Int64/finite-Double)
/// produce `Success`/`Rejected`; anything else is `Malformed(_)`.
#[allow(dead_code)]
fn probe_ok(doc: &Document) -> OkOutcome {
    let Some(b) = doc.get("ok") else {
        return OkOutcome::Malformed(MalformedOkShape::Missing);
    };
    match b {
        Bson::Int32(n) => {
            if *n != 0 {
                OkOutcome::Success
            } else {
                OkOutcome::Rejected
            }
        }
        Bson::Int64(n) => {
            if *n != 0 {
                OkOutcome::Success
            } else {
                OkOutcome::Rejected
            }
        }
        Bson::Double(f) if !f.is_finite() => OkOutcome::Malformed(MalformedOkShape::NonFinite),
        Bson::Double(f) => {
            if *f != 0.0 {
                OkOutcome::Success
            } else {
                OkOutcome::Rejected
            }
        }
        other => OkOutcome::Malformed(MalformedOkShape::from_non_numeric_bson(other)),
    }
}

/// Dispatch an explain reply body document into one of three outcomes:
///
///   - `Ok(Ok(reply))`  — server returned a successful explain reply.
///   - `Ok(Err(srv))`   — server returned `ok=0`; typed rejection.
///   - `Err(parse_err)` — wire-level parse failure (malformed `ok`,
///     deserialise failure, or malformed error body).
#[allow(dead_code)]
pub(crate) fn parse_reply_doc(
    doc: Document,
) -> Result<Result<RawExplainReply, ExplainServerError>, ExplainParseError> {
    match probe_ok(&doc) {
        OkOutcome::Malformed(shape) => Err(ExplainParseError::MalformedOk(shape)),
        OkOutcome::Rejected => {
            // Compute the preview BEFORE consuming `doc` into from_document.
            let preview = super::util::truncate_doc_preview(&doc, 256);
            match bson::from_document::<RawServerError>(doc) {
                Ok(raw) => Ok(Err(ExplainServerError::Rejected {
                    message: raw.message,
                    code: raw.code,
                    code_name: raw.code_name,
                    labels: raw.error_labels,
                })),
                Err(source) => Err(ExplainParseError::MalformedServerError {
                    raw_preview: preview,
                    source,
                }),
            }
        }
        OkOutcome::Success => {
            let preview = super::util::truncate_doc_preview(&doc, 256);
            match bson::from_document::<RawExplainReply>(doc) {
                Ok(reply) => Ok(Ok(reply)),
                Err(source) => Err(ExplainParseError::Deserialise {
                    raw_preview: preview,
                    source,
                }),
            }
        }
    }
}

/// Convert wire `i64` ms into a typed [`Duration`], producing a typed
/// [`NegativeDurationError`] (not `serde::de::Error::custom`) on failure.
#[allow(dead_code)]
pub(crate) fn i64_ms_to_duration(
    field: &'static str,
    ms: i64,
) -> Result<Duration, NegativeDurationError> {
    let nz: u64 = ms
        .try_into()
        .map_err(|_| NegativeDurationError { field, value: ms })?;
    Ok(Duration::from_millis(nz))
}

/// Recursively map [`RawPlanNode`] → [`PlanNode`]. Rejects "both children
/// shapes present" with [`ExplainParseError::BothChildrenShapesPresent`]
/// carrying the depth at which the violation was found.
#[allow(dead_code)]
pub(crate) fn to_plan_node(r: RawPlanNode, depth: usize) -> Result<PlanNode, ExplainParseError> {
    let execution_time = match r.execution_time_millis_estimate {
        None => None,
        Some(ms) => Some(NodeTime::from(i64_ms_to_duration(
            "executionTimeMillisEstimate",
            ms,
        )?)),
    };
    let children = match (r.input_stage, r.input_stages) {
        (Some(_), Some(_)) => {
            return Err(ExplainParseError::BothChildrenShapesPresent { depth });
        }
        (Some(s), None) => vec![to_plan_node(*s, depth + 1)?],
        (None, Some(v)) => v
            .into_iter()
            .map(|n| to_plan_node(n, depth + 1))
            .collect::<Result<Vec<_>, _>>()?,
        (None, None) => Vec::new(),
    };
    Ok(PlanNode {
        stage: r.stage,
        execution_time,
        n_returned: r.n_returned,
        docs_examined: r.docs_examined,
        keys_examined: r.keys_examined,
        index_name: r.index_name,
        children,
    })
}

/// Map a [`RawExplainReply`] to a public [`ExplainEvent`], parsing the
/// namespace explicitly so the typed [`NamespaceParseError`](super::model::NamespaceParseError)
/// survives as [`ExplainParseError::BadNamespace`].
#[allow(dead_code)]
pub(crate) fn raw_into_event(
    command: super::model::Command,
    raw: RawExplainReply,
) -> Result<ExplainEvent, ExplainParseError> {
    let namespace = Namespace::parse(raw.query_planner.namespace)?;
    let execution_time = AggregateTime::from(i64_ms_to_duration(
        "executionTimeMillis",
        raw.execution_stats.execution_time_millis,
    )?);
    let plan = to_plan_node(raw.execution_stats.execution_stages, 0)?;
    Ok(ExplainEvent {
        command,
        namespace,
        total: ExplainTotals {
            n_returned: raw.execution_stats.n_returned,
            docs_examined: raw.execution_stats.total_docs_examined,
            keys_examined: raw.execution_stats.total_keys_examined,
            execution_time,
        },
        plan,
    })
}

// Suppress unused-import warning for ErrorLabel / ServerErrorCode etc.
// referenced only through `parse_reply_doc`'s match arms — the symbols
// are required for compile-time type checking of the Rejected variant.
const _: fn() = || {
    let _: Option<ErrorLabel> = None;
    let _: Option<ServerErrorCode> = None;
    let _: Option<ServerErrorCodeName> = None;
};

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    #[test]
    fn probe_ok_int32_one_is_success() {
        let d = doc! { "ok": 1i32 };
        assert_eq!(probe_ok(&d), OkOutcome::Success);
    }

    #[test]
    fn probe_ok_int32_zero_is_rejected() {
        let d = doc! { "ok": 0i32 };
        assert_eq!(probe_ok(&d), OkOutcome::Rejected);
    }

    #[test]
    fn probe_ok_int64_one_is_success() {
        let d = doc! { "ok": 1i64 };
        assert_eq!(probe_ok(&d), OkOutcome::Success);
    }

    #[test]
    fn probe_ok_double_one_is_success() {
        let d = doc! { "ok": 1.0_f64 };
        assert_eq!(probe_ok(&d), OkOutcome::Success);
    }

    #[test]
    fn probe_ok_double_zero_is_rejected() {
        let d = doc! { "ok": 0.0_f64 };
        assert_eq!(probe_ok(&d), OkOutcome::Rejected);
    }

    #[test]
    fn probe_ok_nan_is_malformed_nonfinite() {
        let d = doc! { "ok": f64::NAN };
        assert_eq!(
            probe_ok(&d),
            OkOutcome::Malformed(MalformedOkShape::NonFinite)
        );
    }

    #[test]
    fn probe_ok_infinity_is_malformed_nonfinite() {
        let d = doc! { "ok": f64::INFINITY };
        assert_eq!(
            probe_ok(&d),
            OkOutcome::Malformed(MalformedOkShape::NonFinite)
        );
    }

    #[test]
    fn probe_ok_missing_is_malformed_missing() {
        let d = doc! { "x": 1 };
        assert_eq!(
            probe_ok(&d),
            OkOutcome::Malformed(MalformedOkShape::Missing)
        );
    }

    #[test]
    fn probe_ok_string_is_malformed_stringvalue() {
        let d = doc! { "ok": "yes" };
        assert_eq!(
            probe_ok(&d),
            OkOutcome::Malformed(MalformedOkShape::StringValue)
        );
    }

    #[test]
    fn probe_ok_bool_is_malformed_bool() {
        let d = doc! { "ok": true };
        assert_eq!(probe_ok(&d), OkOutcome::Malformed(MalformedOkShape::Bool));
    }

    #[test]
    fn probe_ok_array_is_malformed_array() {
        let d = doc! { "ok": [1, 2, 3] };
        assert_eq!(probe_ok(&d), OkOutcome::Malformed(MalformedOkShape::Array));
    }

    #[test]
    fn i64_ms_to_duration_zero_is_zero_duration() {
        assert_eq!(
            i64_ms_to_duration("f", 0).unwrap(),
            Duration::from_millis(0)
        );
    }

    #[test]
    fn i64_ms_to_duration_positive_is_milliseconds() {
        assert_eq!(
            i64_ms_to_duration("f", 16).unwrap(),
            Duration::from_millis(16)
        );
    }

    #[test]
    fn i64_ms_to_duration_negative_carries_field_and_value() {
        let err = i64_ms_to_duration("executionTimeMillis", -5).unwrap_err();
        assert_eq!(err.field, "executionTimeMillis");
        assert_eq!(err.value, -5);
    }

    #[test]
    fn parse_reply_doc_missing_ok_is_malformed_missing() {
        let d = doc! { "queryPlanner": {} };
        let err = parse_reply_doc(d).unwrap_err();
        assert!(matches!(
            err,
            ExplainParseError::MalformedOk(MalformedOkShape::Missing)
        ));
    }

    #[test]
    fn parse_reply_doc_ok_zero_returns_typed_server_error() {
        let d = doc! {
            "ok": 0,
            "errmsg": "NamespaceNotFound: foo.bar",
            "code": 26,
            "codeName": "NamespaceNotFound",
        };
        let outer = parse_reply_doc(d).expect("parse-side ok");
        let server_err = outer.expect_err("server-side err");
        match server_err {
            ExplainServerError::Rejected {
                message,
                code,
                code_name,
                ..
            } => {
                assert_eq!(message, "NamespaceNotFound: foo.bar");
                assert_eq!(code, Some(ServerErrorCode::try_new(26).unwrap()));
                assert_eq!(code_name, Some(ServerErrorCodeName::NamespaceNotFound));
            }
        }
    }

    #[test]
    fn parse_reply_doc_ok_zero_with_malformed_body_is_malformed_server_error() {
        // ok=0 but `errmsg` missing — RawServerError deserialisation fails.
        let d = doc! { "ok": 0 };
        let err = parse_reply_doc(d).unwrap_err();
        match err {
            ExplainParseError::MalformedServerError { raw_preview, .. } => {
                assert!(raw_preview.contains("ok"));
            }
            other => panic!("expected MalformedServerError, got {other:?}"),
        }
    }
}
