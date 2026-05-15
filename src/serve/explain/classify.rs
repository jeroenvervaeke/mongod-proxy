//! Borrowing classifier: inspect a [`Message`] to decide whether the
//! explain inspector should issue a sideband explain for it, returning
//! the typed projection ([`ClassifiedRequest`]) the request rewriter
//! needs.

use bson::Document;

use crate::message::Message;
use crate::operation::Operation;
use crate::operation::op_msg::{OpMsgSection, OperationMessageFlags};

use super::model::{Command, Database};

/// Typed view over a classified explainable request — borrowed from the
/// source [`Message`] to keep classification allocation-free except for
/// the single `Database` newtype.
#[derive(Debug)]
pub(crate) struct ClassifiedRequest<'a> {
    pub(crate) command: Command,
    pub(crate) database: Database,
    pub(crate) body: &'a Document,
    pub(crate) doc_sequences: &'a [OpMsgSection],
}

impl<'a> ClassifiedRequest<'a> {
    pub fn command(&self) -> &Command {
        &self.command
    }
    pub fn database(&self) -> &Database {
        &self.database
    }
    pub fn body(&self) -> &'a Document {
        self.body
    }
    pub fn doc_sequences(&self) -> &'a [OpMsgSection] {
        self.doc_sequences
    }
    /// Consume the plan, moving the owned [`Command`] out (avoids a clone
    /// when the caller wants to construct an [`ExplainEvent`] from `self`).
    pub fn into_command(self) -> Command {
        self.command
    }
}

/// Classify a wire-protocol request. Returns `None` for any request the
/// inspector cannot or should not explain (fire-and-forget, OP_QUERY /
/// OP_REPLY, unknown command, missing `$db`, malformed `$db`).
///
/// Borrows from `req`; the only allocation on the happy path is the
/// [`Database`] newtype's owned `String`.
pub(crate) fn classify(req: &Message) -> Option<ClassifiedRequest<'_>> {
    let Operation::Message(op_msg) = &req.operation else {
        return None;
    };
    if op_msg.flags.contains(OperationMessageFlags::MORE_TO_COME) {
        return None;
    }
    let raw_name = op_msg.command_name()?;
    let command = Command::from_command_name(raw_name)?;
    let body = op_msg.sections.iter().find_map(OpMsgSection::as_body)?;
    let db_str = body.get_str("$db").ok()?;
    let database = match Database::try_new(db_str.to_owned()) {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!(
                target: "mongod_proxy::serve::explain",
                command = ?command,
                error = %e,
                "malformed $db; skipping explain",
            );
            return None;
        }
    };
    Some(ClassifiedRequest {
        command,
        database,
        body,
        doc_sequences: &op_msg.sections,
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use bson::doc;

    use super::*;
    use crate::ids::{RequestId, ResponseTo};
    use crate::operation::op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags};
    use crate::operation::op_query::{OperationQuery, OperationQueryFlags};

    fn msg(op: Operation) -> Message {
        Message {
            request_id: RequestId::new(1),
            response_to: None,
            operation: op,
        }
    }

    fn body(d: bson::Document) -> Message {
        msg(Operation::Message(OperationMessage {
            flags: OperationMessageFlags::empty(),
            sections: vec![OpMsgSection::Body(d)],
            checksum: None,
        }))
    }

    #[test]
    fn classifies_find_with_db() {
        let m = body(doc! { "find": "movies", "$db": "sample" });
        let plan = classify(&m).expect("find is explainable");
        assert_eq!(plan.command(), &Command::Find);
        assert_eq!(plan.database().as_ref(), "sample");
    }

    #[test]
    fn classifies_aggregate_with_db() {
        let m = body(doc! { "aggregate": "movies", "$db": "sample", "pipeline": [] });
        let plan = classify(&m).expect("aggregate is explainable");
        assert_eq!(plan.command(), &Command::Aggregate);
    }

    #[test]
    fn classifies_find_and_modify_alias() {
        let m = body(doc! { "findandmodify": "movies", "$db": "sample" });
        let plan = classify(&m).expect("findandmodify is explainable");
        assert_eq!(plan.command(), &Command::FindAndModify);
    }

    #[test]
    fn skips_hello() {
        let m = body(doc! { "hello": 1, "$db": "admin" });
        assert!(classify(&m).is_none());
    }

    #[test]
    fn skips_ping() {
        let m = body(doc! { "ping": 1, "$db": "admin" });
        assert!(classify(&m).is_none());
    }

    #[test]
    fn skips_insert() {
        let m = body(doc! { "insert": "movies", "$db": "sample" });
        assert!(classify(&m).is_none());
    }

    #[test]
    fn skips_get_more() {
        let m = body(doc! { "getMore": 42i64, "$db": "sample" });
        assert!(classify(&m).is_none());
    }

    #[test]
    fn skips_fire_and_forget() {
        let m = msg(Operation::Message(OperationMessage {
            flags: OperationMessageFlags::MORE_TO_COME,
            sections: vec![OpMsgSection::Body(
                doc! { "find": "movies", "$db": "sample" },
            )],
            checksum: None,
        }));
        assert!(classify(&m).is_none());
    }

    #[test]
    fn skips_op_query() {
        let m = msg(Operation::Query(OperationQuery {
            flags: OperationQueryFlags::empty(),
            full_collection_name: "admin.$cmd".into(),
            number_to_skip: 0,
            number_to_return: 1,
            query: doc! { "hello": 1 },
            return_fields_selector: None,
        }));
        assert!(classify(&m).is_none());
    }

    #[test]
    fn skips_when_db_missing() {
        let m = body(doc! { "find": "movies" });
        assert!(classify(&m).is_none());
    }

    #[test]
    fn classify_does_not_panic_with_response_to() {
        let m = Message {
            request_id: RequestId::new(2),
            response_to: NonZeroI32::new(1).map(ResponseTo::new),
            operation: Operation::Message(OperationMessage {
                flags: OperationMessageFlags::empty(),
                sections: vec![OpMsgSection::Body(
                    doc! { "find": "movies", "$db": "sample" },
                )],
                checksum: None,
            }),
        };
        let plan = classify(&m).expect("explainable regardless of response_to");
        assert_eq!(plan.command(), &Command::Find);
    }
}
