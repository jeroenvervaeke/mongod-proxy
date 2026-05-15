//! Sink trait + built-in implementations for consuming typed
//! [`ExplainEvent`]s and typed [`ExplainError<E>`]s.
//!
//! No `Send + Sync + 'static` bound on the trait — bounds live on the
//! `Layer<S>` / `Service<Message>` impl blocks of [`ExplainLayer`] where
//! they actually matter. This lets `Rc<RefCell<_>>` test sinks compile.

use super::error::ExplainError;
use super::model::ExplainEvent;

/// Receives explain events and typed failures.
///
/// Generic over `E` = the inner service's error type so the typed-source
/// rule survives end-to-end (rule 18). Closures, channel senders, and
/// [`TracingOnly`] impl this for any `E`; typed sinks pick concrete `E`
/// and can match on the inner-service error variant in `record_error`.
///
/// `record` is non-blocking — the built-in `mpsc::Sender` impl drops on
/// full (no backpressure). Users wanting backpressure should size the
/// channel for peak burst or build a blocking wrapper.
///
/// `Clone` is invoked once per accepted connection in `Layer::layer`;
/// impls MUST keep this O(1) (refcount or `Copy`).
pub trait ExplainSink<E>
where
    E: std::error::Error,
{
    fn record(&self, event: ExplainEvent);
    fn record_error(&self, _err: &ExplainError<E>) {}
}

impl<F, E> ExplainSink<E> for F
where
    F: Fn(ExplainEvent),
    E: std::error::Error,
{
    fn record(&self, event: ExplainEvent) {
        self(event)
    }
}

impl<E> ExplainSink<E> for tokio::sync::mpsc::Sender<ExplainEvent>
where
    E: std::error::Error,
{
    fn record(&self, event: ExplainEvent) {
        use tokio::sync::mpsc::error::TrySendError;
        match self.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => tracing::warn!(
                target: "mongod_proxy::serve::explain",
                "explain sink channel full; event dropped",
            ),
            Err(TrySendError::Closed(_)) => tracing::warn!(
                target: "mongod_proxy::serve::explain",
                "explain sink channel receiver dropped; event lost",
            ),
        }
    }
}

#[cfg(feature = "unbounded-sink")]
impl<E> ExplainSink<E> for tokio::sync::mpsc::UnboundedSender<ExplainEvent>
where
    E: std::error::Error,
{
    fn record(&self, event: ExplainEvent) {
        if self.send(event).is_err() {
            tracing::warn!(
                target: "mongod_proxy::serve::explain",
                "unbounded explain sink receiver dropped",
            );
        }
    }
}

/// No-op sink. The default `ExplainLayer::new()` constructs one — users
/// who only want `tracing` output do not need to wire a sink.
#[derive(Clone, Copy, Debug, Default)]
pub struct TracingOnly;

impl<E> ExplainSink<E> for TracingOnly
where
    E: std::error::Error,
{
    fn record(&self, _: ExplainEvent) {}
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::*;
    use crate::serve::explain::model::{
        AggregateTime, Command, Database, DocsExamined, DocsReturned, ExplainTotals, KeysExamined,
        Namespace, NodeTime, PlanNode, Stage,
    };

    /// Build a minimal `ExplainEvent` for tests.
    fn dummy_event() -> ExplainEvent {
        ExplainEvent {
            command: Command::Find,
            namespace: Namespace::new(
                Database::try_new("test".to_owned()).unwrap(),
                crate::serve::explain::model::Collection::try_new("movies".to_owned()).unwrap(),
            ),
            total: ExplainTotals {
                n_returned: DocsReturned::try_new(0).unwrap(),
                docs_examined: DocsExamined::try_new(0).unwrap(),
                keys_examined: KeysExamined::try_new(0).unwrap(),
                execution_time: AggregateTime::from(std::time::Duration::from_millis(1)),
            },
            plan: PlanNode {
                stage: Stage::Collscan,
                execution_time: Some(NodeTime::from(std::time::Duration::from_millis(1))),
                n_returned: DocsReturned::try_new(0).unwrap(),
                docs_examined: None,
                keys_examined: None,
                index_name: None,
                key_pattern: None,
                index_bounds: None,
                direction: None,
                filter: None,
                children: vec![],
            },
            client_request_id: crate::ids::RequestId::new(1),
            explain_request_id: crate::ids::ExplainRequestId::try_new(-1).unwrap(),
        }
    }

    /// Pin `std::io::Error` as the inner-service E for sink-trait checks.
    type E = std::io::Error;

    #[test]
    fn closure_sink_records_event() {
        let captured: Arc<Mutex<Vec<ExplainEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = captured.clone();
        let sink = move |e: ExplainEvent| {
            cap.lock().unwrap().push(e);
        };
        <_ as ExplainSink<E>>::record(&sink, dummy_event());
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    #[test]
    fn tracing_only_default_swallows() {
        let s = TracingOnly;
        <TracingOnly as ExplainSink<E>>::record(&s, dummy_event());
    }

    #[tokio::test]
    async fn mpsc_sender_delivers_event() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ExplainEvent>(4);
        <_ as ExplainSink<E>>::record(&tx, dummy_event());
        let _e = rx.recv().await.expect("event");
    }
}
