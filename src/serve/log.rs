use crate::message::Message;
use crate::operation::Operation;
use futures::{TryFutureExt, future::MapOk};
use tower_layer::Layer;
use tower_service::Service;
use tracing::{Instrument, info, instrument::Instrumented};

#[derive(Clone, Default)]
pub struct LogLayer;

impl<S> Layer<S> for LogLayer {
    type Service = LogService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LogService { service: inner }
    }
}

pub struct LogService<S> {
    service: S,
}

impl<S> Service<Message> for LogService<S>
where
    S: Service<Message, Response = Message> + Send,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Instrumented<MapOk<S::Future, fn(S::Response) -> S::Response>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let op_kind = op_kind(&req.operation);
        let command = command_name(&req.operation).unwrap_or("");
        info!(
            direction = "request",
            op = op_kind,
            command,
            request_id = req.request_id,
            ?req,
            "received request"
        );

        self.service
            .call(req)
            .map_ok(log_message as fn(S::Response) -> S::Response)
            .in_current_span()
    }
}

fn log_message(message: Message) -> Message {
    let op_kind = op_kind(&message.operation);
    info!(
        direction = "response",
        op = op_kind,
        request_id = message.response_to,
        response_id = message.request_id,
        ?message,
        "received response"
    );
    message
}

fn op_kind(op: &Operation) -> &'static str {
    match op {
        Operation::Message(_) => "OP_MSG",
        Operation::Query(_) => "OP_QUERY",
        Operation::Reply(_) => "OP_REPLY",
    }
}

/// Returns the BSON command name driving this operation, when one is identifiable.
/// For OP_MSG/OP_QUERY the convention is that the first key of the body document
/// is the command name (e.g. "find", "insert", "hello").
fn command_name(op: &Operation) -> Option<&str> {
    match op {
        Operation::Message(m) => m.sections.keys().next().map(String::as_str),
        Operation::Query(q) => q.query.keys().next().map(String::as_str),
        Operation::Reply(_) => None,
    }
}
