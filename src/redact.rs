//! Credential-safe [`Debug`] rendering for BSON wire payloads.
//!
//! MongoDB authenticates *in band*: `saslStart` / `saslContinue` and the
//! `speculativeAuthenticate` sub-document of `hello` / `isMaster` carry the
//! SCRAM nonces and `clientProof` (and, for the `PLAIN` mechanism, the
//! cleartext username and password) inside ordinary BSON documents that flow
//! over the same wire the proxy parses. Rendering those documents with the
//! derived [`Debug`] — as the logging layer used to — leaks the secrets into
//! any log sink at whatever level the event fires.
//!
//! [`RedactedDoc`] wraps a [`bson::Document`] and provides a [`Debug`] impl
//! that walks the document recursively and replaces the *value* of any key on
//! a small denylist (and the contents of known auth sub-documents) with
//! `"<redacted>"`, while leaving structure and non-sensitive scalars intact so
//! the output stays useful for debugging. It allocates nothing and borrows the
//! document, so it is cheap to drop into a `tracing` field as
//! `redacted = ?RedactedDoc(&doc)`.
//!
//! This is deliberately a *denylist*: the wire protocol is open-vocabulary and
//! we would rather over-render a future non-sensitive field than under-render a
//! future credential, so the denylist errs toward the keys that are known to
//! carry auth material across every command that uses them.

use std::fmt;

use bson::{Bson, Document};

/// Placeholder substituted for the value of any redacted field.
const REDACTED: &str = "<redacted>";

/// Returns `true` if a field with this key name must have its value redacted.
///
/// Matching is ASCII case-insensitive because the wire protocol is not
/// consistent about casing across commands (`pwd` vs `pwd`, `payload` always
/// lower, but driver-synthesised fields vary).
fn is_sensitive_key(key: &str) -> bool {
    // Keep this list focused on keys that are *known* to carry credential
    // material. Each entry is matched case-insensitively against the full key.
    const DENYLIST: &[&str] = &[
        "payload",                 // saslStart / saslContinue SCRAM+PLAIN blob
        "pwd",                     // authenticate / createUser / updateUser
        "password",                // belt-and-braces alias
        "key",                     // legacy MONGODB-CR / nonce key
        "clientproof",             // SCRAM client proof
        "serversignature",         // SCRAM server signature
        "speculativeauthenticate", // hello/isMaster embedded saslStart
        "saslstart",               // nested handshake doc
        "saslcontinue",            // nested handshake doc
        "authorization",           // generic bearer/aws style
        "sessiontoken",            // AWS session token
        "token",                   // generic
        "secret",                  // generic
    ];

    DENYLIST.iter().any(|d| key.eq_ignore_ascii_case(d))
}

/// A [`Debug`]-redacting view over a borrowed [`bson::Document`].
///
/// Formatting a `RedactedDoc` renders the same shape as the document's own
/// [`Debug`] but substitutes `"<redacted>"` for the value of every sensitive
/// key (see the [module docs](self)). Nested documents and arrays are walked
/// recursively, so a credential buried in `hello.speculativeAuthenticate` is
/// redacted just like a top-level `saslStart`.
///
/// ```
/// use bson::doc;
/// use mongod_proxy::redact::RedactedDoc;
///
/// let d = doc! { "saslStart": 1, "mechanism": "PLAIN", "payload": "c2VjcmV0" };
/// let rendered = format!("{:?}", RedactedDoc(&d));
/// assert!(!rendered.contains("c2VjcmV0"));
/// assert!(rendered.contains("<redacted>"));
/// // Non-sensitive structure is preserved.
/// assert!(rendered.contains("mechanism"));
/// ```
#[derive(Clone, Copy)]
pub struct RedactedDoc<'a>(pub &'a Document);

impl fmt::Debug for RedactedDoc<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (key, value) in self.0 {
            if is_sensitive_key(key) {
                map.entry(&key, &RedactedScalar);
            } else {
                map.entry(&key, &RedactedValue(value));
            }
        }
        map.finish()
    }
}

/// A single non-document BSON value rendered with nested redaction applied to
/// any documents or arrays it contains.
struct RedactedValue<'a>(&'a Bson);

impl fmt::Debug for RedactedValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Bson::Document(doc) => fmt::Debug::fmt(&RedactedDoc(doc), f),
            Bson::Array(items) => {
                let mut list = f.debug_list();
                for item in items {
                    list.entry(&RedactedValue(item));
                }
                list.finish()
            }
            // Scalars cannot themselves nest a sensitive key, so the BSON
            // value's own Debug is safe and most informative here.
            other => fmt::Debug::fmt(other, f),
        }
    }
}

/// Renders as the bare `<redacted>` placeholder (no surrounding quotes), so a
/// redacted entry reads `"payload": <redacted>` rather than `"\"<redacted>\""`.
struct RedactedScalar;

impl fmt::Debug for RedactedScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    #[test]
    fn redacts_top_level_payload() {
        let d = doc! { "saslStart": 1, "mechanism": "SCRAM-SHA-256", "payload": "TOPSECRET" };
        let s = format!("{:?}", RedactedDoc(&d));
        assert!(!s.contains("TOPSECRET"), "payload leaked: {s}");
        assert!(s.contains("<redacted>"), "no redaction marker: {s}");
        assert!(s.contains("mechanism"), "structure lost: {s}");
        assert!(s.contains("SCRAM-SHA-256"), "non-sensitive value lost: {s}");
    }

    #[test]
    fn redacts_nested_speculative_authenticate() {
        let d = doc! {
            "hello": 1,
            "speculativeAuthenticate": { "saslStart": 1, "payload": "NESTEDSECRET" },
        };
        let s = format!("{:?}", RedactedDoc(&d));
        assert!(!s.contains("NESTEDSECRET"), "nested payload leaked: {s}");
    }

    #[test]
    fn redacts_pwd_case_insensitively() {
        let d = doc! { "createUser": "bob", "PWD": "hunter2" };
        let s = format!("{:?}", RedactedDoc(&d));
        assert!(!s.contains("hunter2"), "pwd leaked: {s}");
    }

    #[test]
    fn redacts_inside_arrays() {
        let d = doc! { "docs": [ { "password": "leak-me" } ] };
        let s = format!("{:?}", RedactedDoc(&d));
        assert!(!s.contains("leak-me"), "array-nested secret leaked: {s}");
    }

    #[test]
    fn leaves_non_sensitive_documents_intact() {
        let d = doc! { "find": "users", "filter": { "age": 30 } };
        let s = format!("{:?}", RedactedDoc(&d));
        assert!(s.contains("find"));
        assert!(s.contains("users"));
        assert!(s.contains("age"));
        assert!(s.contains("30"));
        assert!(!s.contains("<redacted>"), "over-redacted: {s}");
    }
}
