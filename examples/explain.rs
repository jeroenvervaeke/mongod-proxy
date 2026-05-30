//! Sample binary: a proxy that records the executed query plan for every
//! explainable client command and pretty-prints it.
//!
//! Run with:
//!
//! ```text
//! cargo run --example explain
//! # or, override defaults via env:
//! MONGOD_PROXY_LISTEN=127.0.0.1:27018 \
//! MONGOD_PROXY_UPSTREAM_HOST=127.0.0.1 \
//! MONGOD_PROXY_UPSTREAM_PORT=27017 \
//! cargo run --example explain
//! ```
//!
//! Point your MongoDB driver at the proxy's listen address and watch the
//! plan tree, per-stage timing, and aggregate counters land in stdout for
//! every explainable command.

use std::env;
use std::io::{self, IsTerminal};

use anyhow::{Context, Result};
use mongod_proxy::{
    Direction, ExplainEvent, Filter, Inclusivity, IndexBounds, IndexFieldKind, KeyPattern,
    PlanNode, Proxy, Stage, TlsConfig, serve,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const ENV_LISTEN: &str = "MONGOD_PROXY_LISTEN";
const ENV_UPSTREAM_HOST: &str = "MONGOD_PROXY_UPSTREAM_HOST";
const ENV_UPSTREAM_PORT: &str = "MONGOD_PROXY_UPSTREAM_PORT";
const ENV_TLS: &str = "MONGOD_PROXY_TLS";

const DEFAULT_LISTEN: &str = "127.0.0.1:27018";
const DEFAULT_UPSTREAM_HOST: &str = "127.0.0.1";
const DEFAULT_UPSTREAM_PORT: u16 = 27017;
const DEFAULT_TLS: bool = false;

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();

    let listen_addr = env::var(ENV_LISTEN).unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let upstream_host =
        env::var(ENV_UPSTREAM_HOST).unwrap_or_else(|_| DEFAULT_UPSTREAM_HOST.to_owned());
    let upstream_port = match env::var(ENV_UPSTREAM_PORT) {
        Ok(v) => v
            .parse::<u16>()
            .with_context(|| format!("invalid {ENV_UPSTREAM_PORT}: {v}"))?,
        Err(_) => DEFAULT_UPSTREAM_PORT,
    };
    let use_tls = match env::var(ENV_TLS) {
        Ok(v) => v
            .parse::<bool>()
            .with_context(|| format!("invalid {ENV_TLS}: {v}"))?,
        Err(_) => DEFAULT_TLS,
    };

    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("bind tcp socket on {listen_addr}"))?;

    eprintln!("explain inspector:");
    eprintln!("  listening on {listen_addr}");
    eprintln!("  forwarding to {upstream_host}:{upstream_port} (tls={use_tls})");
    eprintln!("  point your driver at: mongodb://{listen_addr}/");

    let (tx, mut rx) = mpsc::channel::<ExplainEvent>(1024);

    // Spawn the consumer: prints each event with the plan tree walked
    // recursively. Graceful shutdown: when all senders drop (the proxy
    // exits or all connections close), `rx.recv()` returns `None` and the
    // task exits naturally.
    let consumer = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            print_event(&event);
        }
    });

    let tls = if use_tls {
        TlsConfig::System
    } else {
        TlsConfig::Disabled
    };
    let proxy = Proxy::with_tls(upstream_host, upstream_port, tls).enable_explain_with_sink(tx);

    serve(listener, proxy).await.context("run mongodb proxy")?;
    let _ = consumer.await;
    Ok(())
}

fn print_event(event: &ExplainEvent) {
    let total_ms = std::time::Duration::from(event.total.execution_time).as_millis();
    let explain_req = event
        .explain_request_id
        .map(|r| r.to_string())
        .unwrap_or_else(|| "<none>".to_owned());
    println!(
        "\n[{:?}] {}.{}  client_req={} explain_req={}  → {} docs in {}ms  (examined: {} docs, {} keys)",
        event.command,
        event.namespace.database(),
        event.namespace.collection(),
        event.client_request_id,
        explain_req,
        event.total.n_returned,
        total_ms,
        event.total.docs_examined,
        event.total.keys_examined,
    );
    walk(&event.plan, 1);
}

fn walk(node: &PlanNode, depth: usize) {
    let indent: String = std::iter::repeat_n("  ", depth).collect();
    let stage = stage_label(&node.stage);
    let per_stage_ms = node
        .execution_time
        .map(|t| std::time::Duration::from(t).as_millis() as i64)
        .unwrap_or(-1);
    let index = node
        .index_name
        .as_ref()
        .map(|i| format!(" idx={}", i))
        .unwrap_or_default();
    let direction = node
        .direction
        .as_ref()
        .map(|d| format!(" dir={}", format_direction(d)))
        .unwrap_or_default();
    println!(
        "{}{stage} n={}{}{} ms={}",
        indent, node.n_returned, index, direction, per_stage_ms,
    );
    if let Some(kp) = &node.key_pattern {
        println!("{}  keyPattern: {}", indent, format_key_pattern(kp));
    }
    if let Some(b) = &node.index_bounds {
        println!("{}  bounds:     {}", indent, format_index_bounds(b));
    }
    if let Some(f) = &node.filter {
        println!("{}  filter:     {}", indent, format_filter(f));
    }
    for child in &node.children {
        walk(child, depth + 1);
    }
}

fn format_key_pattern(kp: &KeyPattern) -> String {
    match kp {
        KeyPattern::Document(fields) => {
            let pairs: Vec<String> = fields
                .iter()
                .map(|f| format!("{}: {}", f.field, format_field_kind(&f.kind)))
                .collect();
            format!("{{ {} }}", pairs.join(", "))
        }
        KeyPattern::Express(s) => format!("(express) {s}"),
        _ => "<unknown KeyPattern variant>".to_owned(),
    }
}

fn format_field_kind(k: &IndexFieldKind) -> &'static str {
    match k {
        IndexFieldKind::Ascending => "1",
        IndexFieldKind::Descending => "-1",
        IndexFieldKind::Hashed => "\"hashed\"",
        IndexFieldKind::Text => "\"text\"",
        IndexFieldKind::TwoDSphere => "\"2dsphere\"",
        IndexFieldKind::TwoD => "\"2d\"",
        IndexFieldKind::Other(_) => "<other>",
        _ => "<unknown>",
    }
}

fn format_index_bounds(b: &IndexBounds) -> String {
    match b {
        IndexBounds::Document(map) => {
            let entries: Vec<String> = map
                .iter()
                .map(|(field, ranges)| {
                    let rs: Vec<String> = ranges.iter().map(format_range).collect();
                    format!("{field}: [{}]", rs.join(", "))
                })
                .collect();
            format!("{{ {} }}", entries.join(", "))
        }
        IndexBounds::Raw(s) => format!("(raw) {s}"),
        _ => "<unknown IndexBounds variant>".to_owned(),
    }
}

fn format_range(r: &mongod_proxy::IndexBoundRange) -> String {
    let lo = format_bound_value(&r.lower);
    let hi = format_bound_value(&r.upper);
    let open = match r.lower_inclusivity {
        Inclusivity::Inclusive => '[',
        Inclusivity::Exclusive => '(',
    };
    let close = match r.upper_inclusivity {
        Inclusivity::Inclusive => ']',
        Inclusivity::Exclusive => ')',
    };
    format!("{open}{lo}, {hi}{close}")
}

fn format_direction(d: &Direction) -> &'static str {
    match d {
        Direction::Forward => "forward",
        Direction::Backward => "backward",
        _ => "<other>",
    }
}

fn format_bound_value(v: &mongod_proxy::BoundValue) -> String {
    match v {
        mongod_proxy::BoundValue::Inf => "inf".to_owned(),
        mongod_proxy::BoundValue::NegInf => "-inf".to_owned(),
        mongod_proxy::BoundValue::MinKey => "MinKey".to_owned(),
        mongod_proxy::BoundValue::MaxKey => "MaxKey".to_owned(),
        mongod_proxy::BoundValue::Literal(s) => s.clone(),
        _ => "<unknown>".to_owned(),
    }
}

fn format_filter(f: &Filter) -> String {
    match f {
        Filter::MatchExpression(d) => format!("{d:?}")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
        Filter::SbeExpression(s) => format!("(sbe) {s}"),
        _ => "<unknown Filter variant>".to_owned(),
    }
}

fn stage_label(s: &Stage) -> String {
    format!("{s:?}")
}

fn setup_tracing() {
    let use_ansi = io::stdout().is_terminal();
    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::from_level(
            Level::INFO,
        ))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(use_ansi)
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false),
        )
        .init();
}
