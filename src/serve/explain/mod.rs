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

pub use error::*;
pub use layer::{ExplainLayer, ExplainService, ReplayStream};
pub use model::*;
pub use sink::{ExplainSink, TracingOnly};
