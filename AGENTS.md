# AGENTS.md

Conventions for agents (and humans) writing code in this repo. The lints
below are CI-enforced — these are not preferences.

## No panics in library code

`.unwrap()`, `.expect()`, `panic!()`, `unreachable!()`, `todo!()`, and
`unimplemented!()` are denied in every file under `src/` (and `logger/src/`)
**outside** `#[cfg(test)]` modules. Enforced by `clippy::unwrap_used`,
`clippy::expect_used`, `clippy::panic`, `clippy::unreachable`,
`clippy::todo`, and `clippy::unimplemented` configured in the
workspace-root `Cargo.toml`. CI runs
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
so any new occurrence fails the build.

### How to satisfy the lint

For `Option`:

```rust
// don't
let host = hosts.into_iter().next().expect("non-empty by construction");

// do — defensively map to an error your function already returns
let host = hosts.into_iter().next().ok_or(MyError::NoRecords)?;

// or — restructure so the type system carries the invariant
let Some(host) = hosts.into_iter().next() else {
    // handle the absent case without panicking
    return Ok(default());
};
```

For `Result`:

```rust
// don't
let parsed = thing.expect("infallible per the type contract");

// do — propagate
let parsed = thing?;

// or — map the (impossible) variant to a domain error
let parsed = thing.map_err(|_| MyError::Internal)?;
```

For "this can never happen" invariants: don't assert them at runtime.
Either restructure to make the unreachable branch type-impossible, or
return a defensive error/default. Comments saying "infallible because
of the check above" are precisely what the lint targets — those
invariants drift with refactors.

### What's exempt

- `#[cfg(test)] mod tests { ... }` blocks inside `src/`. Assertion
  failures *are* panics — that's how Rust's test harness signals
  failure — so `assert!`, `.unwrap()`, and `.expect()` remain available.
  The exemption is configured in `clippy.toml` via
  `allow-unwrap-in-tests = true` (and friends).
- Integration tests in `tests/`. Some have a file-level
  `#![allow(clippy::unwrap_used, ...)]` for helper code that isn't
  inside `#[test]` functions; new tests should prefer
  `async fn ... -> Result<(), Box<dyn Error>>` and `?` for fallible
  setup, keeping `assert!` for actual assertions (see
  `tests/e2e_from_uri.rs` for the pattern).
- Doctests (` /// ` examples). `.unwrap()` is idiomatic in `no_run`
  examples to keep them readable.

### Why

Panics are unrecoverable at the call site and their messages can leak
context — for example, a `format!("mongodb://{user}:{pass}@…")` URI
echoed into a panic message would surface credentials in CI logs that
GitHub's secret masker doesn't catch (it only matches the exact stored
secret value, not derived strings). Returning `Result` keeps every
fallible path explicit and recoverable.

## Other house style

- New module-level docs use the existing `//!` voice: short, declarative,
  explain the *why* alongside the *what*. See `src/srv.rs` and
  `src/uri.rs` for examples.
- New errors use `thiserror::Error` with named-field variants where the
  variant carries context the caller will want to inspect (`hostname`,
  `target`, etc.). Avoid wrapping `Box<dyn Error>` in public types —
  keep errors structured.
- CI checks (`fmt`, `clippy`, `build`, `test`, `docs`, `deny`, `fuzz`,
  `msrv`) are all required. `cargo fmt --all --check` and
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  must pass locally before pushing.
