//! Explain inspector — captures MongoDB query plans via sideband `explain`
//! operations and emits typed events through a user-supplied sink.

pub mod model;

pub use model::*;
