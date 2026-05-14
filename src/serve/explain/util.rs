//! Bounded `Debug`-formatter helper used for raw-doc previews in error
//! messages.
//!
//! Naive `format!("{doc:?}")` materialises the entire `Debug` rendering
//! before truncation, which is ruinous for a 16 MiB cursor batch.
//! [`truncate_doc_preview`] writes into a short-circuiting buffer that
//! stops rendering as soon as the cap is reached.

use std::fmt::Write;

struct BoundedWrite<'a> {
    buf: &'a mut String,
    cap: usize,
}

impl Write for BoundedWrite<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        if self.buf.len() >= self.cap {
            return Err(std::fmt::Error);
        }
        let remaining = self.cap - self.buf.len();
        if s.len() <= remaining {
            self.buf.push_str(s);
            Ok(())
        } else {
            // Find the highest char boundary that fits within `remaining`
            // so we never split a UTF-8 codepoint.
            let mut end = remaining;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            self.buf.push_str(&s[..end]);
            Err(std::fmt::Error)
        }
    }
}

/// Render the `Debug` formatting of `doc` into a `String` capped at `cap`
/// bytes, appending `…[truncated]` when the cap was hit. The implementation
/// short-circuits via [`std::fmt::Error`] so a huge document is never fully
/// materialised in memory.
#[allow(dead_code)]
pub(crate) fn truncate_doc_preview(doc: &bson::Document, cap: usize) -> String {
    let mut buf = String::with_capacity(cap + 32);
    let mut bw = BoundedWrite { buf: &mut buf, cap };
    // The intentional short-circuit signal returns Err once the buffer
    // fills. We observe completion via buf.len(), not the Result.
    if write!(bw, "{doc:?}").is_err() {
        buf.push_str("…[truncated]");
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    #[test]
    fn truncate_short_doc_renders_in_full() {
        let d = doc! { "ping": 1 };
        let out = truncate_doc_preview(&d, 512);
        assert_eq!(out, format!("{d:?}"));
        assert!(!out.ends_with("…[truncated]"));
    }

    #[test]
    fn truncate_long_doc_is_capped() {
        let mut d = bson::Document::new();
        for i in 0..1000 {
            d.insert(format!("k{i}"), i);
        }
        let out = truncate_doc_preview(&d, 64);
        // 64 cap + "…[truncated]" (12 bytes) — total bounded.
        assert!(out.len() <= 64 + "…[truncated]".len());
        assert!(out.ends_with("…[truncated]"));
    }

    #[test]
    fn truncate_at_utf8_boundary_does_not_panic() {
        // Insert a multi-byte UTF-8 string and choose a cap that would land
        // mid-codepoint with naive slicing.
        let d = doc! { "emoji": "🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀" };
        // 33 is mid-emoji byte. Function MUST not panic.
        let out = truncate_doc_preview(&d, 33);
        assert!(out.ends_with("…[truncated]"));
        // The truncated body must be valid UTF-8 (String guarantees this
        // but we double-check by re-encoding).
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }
}
