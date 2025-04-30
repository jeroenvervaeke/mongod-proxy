use crate::operation::op_msg::{OperationMessage, OperationMessageFlags};
use crate::{message::Message, operation::Operation};

use bson::{DateTime, Uuid, doc, oid::ObjectId};
use std::num::NonZeroI32;

pub mod msg_00_query_request {
    use super::*;

    pub fn message() -> Message {
        let uuid = Uuid::from_bytes([
            91, 106, 64, 108, 211, 154, 77, 196, 174, 190, 152, 194, 44, 80, 165, 37,
        ]);
        Message {
            request_id: 17,
            response_to: None,
            operation: Operation::Message(OperationMessage {
                flags: OperationMessageFlags::empty(),
                sections: doc! {
                    "find": "softwares",
                    "filter": {},
                    "sort": {
                        "netScore": -1
                    },
                    "skip": 0,
                    "limit": 10,
                        "lsid": {
                        "id": uuid
                    },
                    "$db": "msoftware"
                },
                checksum: None,
            }),
        }
    }

    pub fn bytes() -> &'static [u8] {
        include_bytes!("./00_OP_MSG_request.bin")
    }
}

pub mod msg_00_query_response {
    use super::*;

    pub fn message() -> Message {
        Message {
            request_id: 21,
            response_to: NonZeroI32::new(17),
            operation: Operation::Message(OperationMessage {
                flags: OperationMessageFlags::empty(),
                sections: doc! {
                    "cursor": {
                        "firstBatch": vec![
                            doc! {
                                "_id": ObjectId::parse_str("680bbf06983e8304b20d142e").unwrap(),
                                "name": "React",
                                "description": "A JavaScript library for building user interfaces.",
                                "website": "https://reactjs.org/",
                                "category": "Development",
                                "tags": vec!["javascript", "frontend", "ui", "library"],
                                "upvotes": 151,
                                "downvotes": 5,
                                "netScore": 146,
                                "__v": 0,
                                "createdAt": DateTime::from_millis(1745600262292),
                                "updatedAt": DateTime::from_millis(1745778049680)
                            },
                            doc! {
                                "_id": ObjectId::parse_str("680bbf06983e8304b20d142f").unwrap(),
                                "name": "Node.js",
                                "description": "A JavaScript runtime built on Chrome's V8 JavaScript engine.",
                                "website": "https://nodejs.org/",
                                "category": "Development",
                                "tags": vec!["javascript", "runtime", "server"],
                                "upvotes": 130,
                                "downvotes": 8,
                                "netScore": 122,
                                "__v": 0,
                                "createdAt": DateTime::from_millis(1745600262292),
                                "updatedAt": DateTime::from_millis(1745600262292)
                            },
                            doc! {
                                "_id": ObjectId::parse_str("680bbf06983e8304b20d142c").unwrap(),
                                "name": "Visual Studio Code",
                                "description": "A lightweight but powerful source code editor that runs on your desktop.",
                                "website": "https://code.visualstudio.com/",
                                "category": "Development",
                                "tags": vec!["editor", "ide", "microsoft", "javascript"],
                                "upvotes": 120,
                                "downvotes": 10,
                                "netScore": 110,
                                "__v": 0,
                                "createdAt": DateTime::from_millis(1745600262291),
                                "updatedAt": DateTime::from_millis(1745600262291)
                            },
                            doc! {
                                "_id": ObjectId::parse_str("680bbf06983e8304b20d1430").unwrap(),
                                "name": "TypeScript",
                                "description": "A typed superset of JavaScript that compiles to plain JavaScript.",
                                "website": "https://www.typescriptlang.org/",
                                "category": "Development",
                                "tags": vec!["javascript", "typed", "microsoft"],
                                "upvotes": 110,
                                "downvotes": 12,
                                "netScore": 98,
                                "__v": 0,
                                "createdAt": DateTime::from_millis(1745600262293),
                                "updatedAt": DateTime::from_millis(1745600262293)
                            },
                            doc! {
                                "_id": ObjectId::parse_str("680bbf06983e8304b20d142d").unwrap(),
                                "name": "MongoDB",
                                "description": "A document database with the scalability and flexibility that you want with the querying and indexing that you need.",
                                "website": "https://www.mongodb.com/",
                                "category": "Database",
                                "tags": vec!["nosql", "database", "json"],
                                "upvotes": 95,
                                "downvotes": 15,
                                "netScore": 80,
                                "__v": 0,
                                "createdAt": DateTime::from_millis(1745600262292),
                                "updatedAt": DateTime::from_millis(1745600262292)
                            },
                            doc! {
                                "_id": ObjectId::parse_str("680bc968a397baec7932b769").unwrap(),
                                "name": "Add test",
                                "description": "jev",
                                "website": "http://proxy.jev.sh",
                                "category": "Development",
                                "tags": vec!["free", "open-source"],
                                "upvotes": 0,
                                "downvotes": 0,
                                "netScore": 0,
                                "createdAt": DateTime::from_millis(1745602920235),
                                "updatedAt": DateTime::from_millis(1745602920235),
                                "__v": 0
                            }
                        ],
                        "id": 0_i64,
                        "ns": "msoftware.softwares"
                    },
                    "ok": 1.0
                },
                checksum: None,
            }),
        }
    }

    pub fn bytes() -> &'static [u8] {
        include_bytes!("./00_OP_MSG_response.bin")
    }
}

pub mod msg_01_legacy_op_query {
    use crate::operation::op_query::{OperationQuery, OperationQueryFlags};

    use super::*;

    pub fn message() -> Message {
        Message {
            request_id: 1,
            response_to: None,
            operation: Operation::Query(OperationQuery {
                flags: OperationQueryFlags::empty(),
                full_collection_name: "admin.$cmd".into(),
                number_to_skip: 0,
                number_to_return: -1,
                query: doc! {
                    "ismaster": 1,
                    "helloOk": true,
                    "client": {
                        "driver": {
                            "name": "nodejs",
                            "version": "5.1.0",
                        },
                        "os": {
                            "type": "Linux",
                            "name": "linux",
                            "architecture": "x64",
                            "version": "6.14.3-arch1-1",
                        },
                        "platform": "Node.js v16.17.1, LE (unified)|Node.js v16.17.1, LE (unified)",
                        "application": {
                            "name": "MongoDB Compass",
                        }
                    },
                    "compression": [ "none" ],
                },
                return_fields_selector: None,
            }),
        }
    }

    pub fn bytes() -> &'static [u8] {
        include_bytes!("./01_LEGACY_OP_QUERY.bin")
    }
}
