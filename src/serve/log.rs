use crate::message::Message;
use futures::{TryFutureExt, future::MapOk};
use tower_layer::Layer;
use tower_service::Service;
use tracing::{Instrument, info, instrument::Instrumented};

#[derive(Clone)]
pub struct LogLayer {}

impl LogLayer {
    pub fn new() -> Self {
        Self {}
    }
}

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
        info!(type = "request", request_id = req.request_id, ?req, "received request");

        self.service
            .call(req)
            .map_ok(log_message as fn(S::Response) -> S::Response)
            .in_current_span()
    }
}

fn log_message(message: Message) -> Message {
    info!(
        type = "response",
        request_id = message.response_to,
        response_id = message.request_id,
        ?message,
        "received response"
    );
    message
}
