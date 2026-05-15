//! Fuzz target for the wire-protocol decoder.
//!
//! Feeds arbitrary attacker-controlled byte streams into `WireDecoder`,
//! splitting them across random `BytesMut` chunks so we also exercise the
//! short-read paths through `tokio_util::codec::Decoder::decode`.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run wire_decoder
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use mongod_proxy::decoder::WireDecoder;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::Decoder;

// Cap the streaming buffer to a small bound. The proxy's real `WireDecoder`
// is bounded by `MessageLength` (≤ 48 MiB per frame), but a fuzz harness that
// keeps appending random bytes between `decode` calls will eventually trip
// libFuzzer's OOM detector with no bug in the decoder itself. We bound the
// buffer here so the target only exercises parsing — not unbounded growth.
const MAX_BUF_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let mut decoder = WireDecoder::default();
    let mut buf = BytesMut::new();

    // First byte (if any) selects a chunk size in 1..=64, so we exercise
    // streamed feeds — not just one big push. The decoder must remain bounded
    // and deterministic regardless of how bytes are split.
    let (chunk, rest) = match data.split_first() {
        Some((first, rest)) => ((*first as usize % 64) + 1, rest),
        None => return,
    };

    let mut i = 0;
    while i < rest.len() {
        let end = (i + chunk).min(rest.len());
        buf.extend_from_slice(&rest[i..end]);
        i = end;
        // We don't care about the result — only that `decode` neither panics
        // nor loops forever. Any structured Err is fine; what matters is the
        // absence of memory unsafety inside the decoder.
        let _ = decoder.decode(&mut buf);
        if buf.len() > MAX_BUF_BYTES {
            // Decoder is waiting for more bytes for a header it parsed as
            // claiming a huge length. That's its documented behavior — drop
            // the synthetic backlog and resume on the next iteration.
            buf.clear();
        }
    }
    let _ = decoder.decode_eof(&mut buf);
});
