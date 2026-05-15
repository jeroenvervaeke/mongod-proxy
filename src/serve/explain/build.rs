//! Construct an OP_MSG `Message` that wraps a classified client request
//! in `{ explain: <inner>, verbosity: "executionStats", $db: <db> }`.

use bson::{Bson, Document};

use crate::ids::{ExplainRequestId, RequestId};
use crate::message::Message;
use crate::operation::Operation;
use crate::operation::op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags};

use super::classify::ClassifiedRequest;
use super::model::{Command, UnsupportedShape};

/// Outcome of [`build_explain`]. `Built` carries the explain message ready
/// to send; `UnsupportedShape` flags routine cases that classify admitted
/// but the server cannot actually explain (multi-op write batches).
pub(crate) enum BuildExplainOutcome {
    Built(Box<Message>),
    UnsupportedShape(UnsupportedShape),
}

const EXPLAIN_VERBOSITY: &str = "executionStats";

/// Rewrite the classified plan into an explain Message stamped with the
/// supplied [`ExplainRequestId`].
pub(crate) fn build_explain(
    plan: &ClassifiedRequest<'_>,
    request_id: ExplainRequestId,
) -> BuildExplainOutcome {
    if is_multi_op_write_batch(plan.command(), plan.doc_sequences()) {
        return BuildExplainOutcome::UnsupportedShape(UnsupportedShape::MultiOpWriteBatch);
    }

    let mut inner = Document::new();
    for (k, v) in plan.body() {
        if should_strip_from_inner(k) {
            continue;
        }
        inner.insert(k.clone(), v.clone());
    }

    // For single-op write batches, fold the (single) doc-sequence entry
    // into the inner command. The wire form normally lifts these out into
    // a kind-1 document sequence; explain expects them inlined.
    fold_single_op_doc_sequence(plan.command(), plan.doc_sequences(), &mut inner);

    let mut envelope = Document::new();
    envelope.insert("explain", Bson::Document(inner));
    envelope.insert("verbosity", EXPLAIN_VERBOSITY);
    envelope.insert("$db", plan.database().as_ref());

    let req_id: RequestId = request_id.into();

    BuildExplainOutcome::Built(Box::new(Message {
        request_id: req_id,
        response_to: None,
        operation: Operation::Message(OperationMessage {
            flags: OperationMessageFlags::empty(),
            sections: vec![OpMsgSection::Body(envelope)],
            checksum: None,
        }),
    }))
}

/// `true` iff the wrapped command + doc sequences look like a multi-op
/// `update` or `delete` (or `findAndModify` with multiple ops, which is
/// unusual but defended against).
fn is_multi_op_write_batch(command: &Command, sections: &[OpMsgSection]) -> bool {
    let ident = match command {
        Command::Update => "updates",
        Command::Delete => "deletes",
        _ => return false,
    };
    for s in sections {
        if let OpMsgSection::DocumentSequence {
            identifier,
            documents,
        } = s
            && identifier == ident
        {
            return documents.len() > 1;
        }
    }
    false
}

fn fold_single_op_doc_sequence(command: &Command, sections: &[OpMsgSection], inner: &mut Document) {
    let ident = match command {
        Command::Update => "updates",
        Command::Delete => "deletes",
        _ => return,
    };
    for s in sections {
        if let OpMsgSection::DocumentSequence {
            identifier,
            documents,
        } = s
            && identifier == ident
            && let Some(only) = documents.first()
            && documents.len() == 1
        {
            inner.insert(ident, vec![Bson::Document(only.clone())]);
            return;
        }
    }
}

/// Fields stripped from the inner wrapped command. They either belong on
/// the outer envelope (`$db`) or attach the explain to client transaction
/// / session state we don't want to inherit.
fn should_strip_from_inner(key: &str) -> bool {
    matches!(
        key,
        "$db"
            | "lsid"
            | "txnNumber"
            | "autocommit"
            | "$clusterTime"
            | "$readPreference"
            | "$readConcern"
            | "readConcern"
            | "startTransaction"
            | "stmtId"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::RequestId;
    use crate::message::Message;
    use crate::operation::op_msg::OpMsgSection;
    use bson::doc;

    fn classified<'a>(
        cmd: Command,
        db: &str,
        body: &'a Document,
        seqs: &'a [OpMsgSection],
    ) -> ClassifiedRequest<'a> {
        ClassifiedRequest {
            command: cmd,
            database: crate::serve::explain::model::Database::try_new(db.to_owned()).unwrap(),
            body,
            doc_sequences: seqs,
        }
    }

    fn into_body(msg: Message) -> Document {
        let Operation::Message(op_msg) = msg.operation else {
            panic!("expected OP_MSG");
        };
        op_msg
            .sections
            .into_iter()
            .find_map(OpMsgSection::into_body)
            .expect("body present")
    }

    fn explain_id(n: i32) -> ExplainRequestId {
        ExplainRequestId::try_new(n).unwrap()
    }

    #[test]
    fn build_explain_lifts_db_to_envelope() {
        let body = doc! { "find": "movies", "$db": "sample", "filter": { "year": 1999 } };
        let plan = classified(Command::Find, "sample", &body, &[]);
        let outcome = build_explain(&plan, explain_id(-1));
        let BuildExplainOutcome::Built(msg) = outcome else {
            panic!("expected Built");
        };
        let envelope = into_body(*msg);
        assert_eq!(envelope.get_str("$db").unwrap(), "sample");
        // Inner command must NOT carry $db.
        let inner = envelope.get_document("explain").unwrap();
        assert!(inner.get("$db").is_none());
        assert_eq!(inner.get_str("find").unwrap(), "movies");
    }

    #[test]
    fn build_explain_sets_verbosity_execution_stats() {
        let body = doc! { "find": "movies", "$db": "sample" };
        let plan = classified(Command::Find, "sample", &body, &[]);
        let BuildExplainOutcome::Built(msg) = build_explain(&plan, explain_id(-1)) else {
            panic!("expected Built");
        };
        let envelope = into_body(*msg);
        assert_eq!(envelope.get_str("verbosity").unwrap(), "executionStats");
    }

    #[test]
    fn build_explain_strips_session_and_cluster_fields() {
        let body = doc! {
            "find": "movies",
            "$db": "sample",
            "lsid": { "id": "abc" },
            "txnNumber": 7i64,
            "autocommit": false,
            "$clusterTime": { "clusterTime": 1i32 },
            "$readPreference": { "mode": "primary" },
            "$readConcern": { "level": "majority" },
            "readConcern": { "level": "majority" },
            "startTransaction": true,
            "stmtId": 1i32,
        };
        let plan = classified(Command::Find, "sample", &body, &[]);
        let BuildExplainOutcome::Built(msg) = build_explain(&plan, explain_id(-1)) else {
            panic!("expected Built");
        };
        let envelope = into_body(*msg);
        let inner = envelope.get_document("explain").unwrap();
        for k in [
            "lsid",
            "txnNumber",
            "autocommit",
            "$clusterTime",
            "$readPreference",
            "$readConcern",
            "readConcern",
            "startTransaction",
            "stmtId",
        ] {
            assert!(inner.get(k).is_none(), "inner command must not carry {k:?}");
        }
    }

    #[test]
    fn build_explain_stamps_request_id_on_header() {
        let body = doc! { "find": "movies", "$db": "sample" };
        let plan = classified(Command::Find, "sample", &body, &[]);
        let BuildExplainOutcome::Built(msg) = build_explain(&plan, explain_id(-42)) else {
            panic!("expected Built");
        };
        assert_eq!(msg.request_id, RequestId::new(-42));
    }

    #[test]
    fn build_explain_folds_single_op_update_doc_sequence() {
        let body = doc! { "update": "movies", "$db": "sample" };
        let sequences = vec![OpMsgSection::DocumentSequence {
            identifier: "updates".to_owned(),
            documents: vec![doc! { "q": { "_id": 1 }, "u": { "$set": { "x": 1 } } }],
        }];
        let plan = classified(Command::Update, "sample", &body, &sequences);
        let BuildExplainOutcome::Built(msg) = build_explain(&plan, explain_id(-1)) else {
            panic!("expected Built");
        };
        let envelope = into_body(*msg);
        let inner = envelope.get_document("explain").unwrap();
        let arr = inner.get_array("updates").unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn build_explain_multi_op_write_batch_is_unsupported() {
        let body = doc! { "update": "movies", "$db": "sample" };
        let sequences = vec![OpMsgSection::DocumentSequence {
            identifier: "updates".to_owned(),
            documents: vec![
                doc! { "q": { "_id": 1 }, "u": { "$set": { "x": 1 } } },
                doc! { "q": { "_id": 2 }, "u": { "$set": { "x": 2 } } },
            ],
        }];
        let plan = classified(Command::Update, "sample", &body, &sequences);
        match build_explain(&plan, explain_id(-1)) {
            BuildExplainOutcome::UnsupportedShape(UnsupportedShape::MultiOpWriteBatch) => {}
            BuildExplainOutcome::Built(_) => panic!("expected UnsupportedShape"),
        }
    }
}
