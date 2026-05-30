//! Tracing subscriber setup for the logger binary.
//!
//! Verbosity is controlled at runtime through the standard `RUST_LOG`
//! environment variable (see [`tracing_subscriber::EnvFilter`]). When
//! `RUST_LOG` is unset (or fails to parse) the subscriber defaults to the
//! `info` level.
//!
//! Output format is selected by the `MONGOD_PROXY_LOG_FORMAT` environment
//! variable, consistent with the other `MONGOD_PROXY_*` variables used by the
//! binary. Setting `MONGOD_PROXY_LOG_FORMAT=json` emits machine-readable JSON
//! lines; any other value (or unset) yields the human-friendly `pretty`
//! format.

use std::env;
use std::io::{self, IsTerminal};

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt};

/// Environment variable selecting the log output format.
const ENV_LOG_FORMAT: &str = "MONGOD_PROXY_LOG_FORMAT";

/// Build the [`EnvFilter`] from the standard `RUST_LOG` environment variable.
///
/// Defaults to the `info` level when `RUST_LOG` is unset or cannot be parsed.
fn make_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Return `true` when the given format value selects JSON output.
///
/// JSON is selected when the value equals `json` (case-insensitive); any other
/// value (including `None`) selects the `pretty` format.
fn want_json(format: Option<&str>) -> bool {
    format.is_some_and(|value| value.eq_ignore_ascii_case("json"))
}

/// Build the formatting layer, choosing JSON or pretty output.
///
/// `use_ansi` is only honoured by the pretty formatter; JSON output never
/// emits ANSI escape codes.
fn make_fmt_layer<S>(json: bool, use_ansi: bool) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    if json {
        fmt::layer()
            .json()
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .boxed()
    } else {
        fmt::layer()
            .pretty()
            .with_ansi(use_ansi)
            .with_file(false)
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .boxed()
    }
}

/// Install the global tracing subscriber.
///
/// Reads `RUST_LOG` for verbosity (default `info`) and
/// `MONGOD_PROXY_LOG_FORMAT` for the output format (`json` or `pretty`,
/// default `pretty`). This must only be called once per process.
pub fn setup() {
    let filter = make_env_filter();
    let json = want_json(env::var(ENV_LOG_FORMAT).ok().as_deref());
    let use_ansi = io::stdout().is_terminal();
    let fmt_layer = make_fmt_layer(json, use_ansi);

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_filter_builds() {
        // Default construction must succeed regardless of RUST_LOG.
        let _filter = make_env_filter();
    }

    #[test]
    fn want_json_detects_format() {
        assert!(want_json(Some("json")));
        assert!(want_json(Some("JSON")));
        assert!(want_json(Some("Json")));
        assert!(!want_json(Some("pretty")));
        assert!(!want_json(Some("")));
        assert!(!want_json(None));
    }

    #[test]
    fn fmt_layer_builds_for_both_formats() {
        // Both arms must produce a layer of the same boxed type.
        let _json_layer = make_fmt_layer::<tracing_subscriber::Registry>(true, false);
        let _pretty_layer = make_fmt_layer::<tracing_subscriber::Registry>(false, true);
    }
}
