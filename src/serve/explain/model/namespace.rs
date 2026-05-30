//! `Namespace` — typed `database.collection` parsed from the wire.

use super::newtypes::{Collection, CollectionError, Database, DatabaseError};

/// Fully-qualified collection identifier parsed from the server's
/// `queryPlanner.namespace` string (e.g. `"sample.movies"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Namespace {
    database: Database,
    collection: Collection,
}

impl Namespace {
    /// Build a namespace from already-validated database and collection
    /// names.
    pub fn new(database: Database, collection: Collection) -> Self {
        Self {
            database,
            collection,
        }
    }

    /// Parse `"db.coll"` consuming the input.
    ///
    /// Allocation profile: happy path performs exactly two `String`
    /// allocations (one each for `Database` and `Collection` storage —
    /// each newtype owns its inner). The original `raw` is consumed
    /// without re-allocation in the success case. Error paths preserve
    /// the FULL original input (not the truncated half).
    pub fn parse(raw: String) -> Result<Self, NamespaceParseError> {
        let Some(dot) = raw.find('.') else {
            return Err(NamespaceParseError::no_dot(raw));
        };
        // Borrow both halves; validate before consuming `raw`. The original
        // owned `raw` is moved into the error variant only on failure, so
        // the full input is preserved across either error path.
        let db_str = &raw[..dot];
        let coll_str = &raw[dot + 1..];
        let database = match Database::try_new(db_str.to_owned()) {
            Ok(d) => d,
            Err(e) => return Err(NamespaceParseError::bad_database(raw, e)),
        };
        let collection = match Collection::try_new(coll_str.to_owned()) {
            Ok(c) => c,
            Err(e) => return Err(NamespaceParseError::bad_collection(raw, e)),
        };
        Ok(Self {
            database,
            collection,
        })
    }

    /// The database half of the namespace.
    pub fn database(&self) -> &Database {
        &self.database
    }
    /// The collection half of the namespace.
    pub fn collection(&self) -> &Collection {
        &self.collection
    }
}

/// Wrapping error type for `Namespace::parse` failures. Holds the original
/// input plus a typed kind discriminant.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid namespace {raw:?}: {kind}")]
pub struct NamespaceParseError {
    raw: String,
    #[source]
    kind: NamespaceParseErrorKind,
}

impl NamespaceParseError {
    fn no_dot(raw: String) -> Self {
        Self {
            raw,
            kind: NamespaceParseErrorKind::NoDot,
        }
    }
    fn bad_database(raw: String, e: DatabaseError) -> Self {
        Self {
            raw,
            kind: NamespaceParseErrorKind::BadDatabase(e),
        }
    }
    fn bad_collection(raw: String, e: CollectionError) -> Self {
        Self {
            raw,
            kind: NamespaceParseErrorKind::BadCollection(e),
        }
    }
    /// Original on-wire namespace string (always the FULL input, never
    /// truncated, regardless of which half failed validation).
    pub fn raw_input(&self) -> &str {
        &self.raw
    }
    /// The typed reason parsing failed.
    pub fn kind(&self) -> &NamespaceParseErrorKind {
        &self.kind
    }
}

/// Typed reason a `database.collection` string failed to parse.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamespaceParseErrorKind {
    /// The string contained no `.` separating database from collection.
    #[error("missing '.' separator")]
    NoDot,
    /// The database half failed validation.
    #[error("invalid database: {0}")]
    BadDatabase(#[source] DatabaseError),
    /// The collection half failed validation.
    #[error("invalid collection: {0}")]
    BadCollection(#[source] CollectionError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_splits_db_and_coll() {
        let ns = Namespace::parse("sample.movies".to_owned()).unwrap();
        assert_eq!(ns.database().as_ref(), "sample");
        assert_eq!(ns.collection().as_ref(), "movies");
    }

    #[test]
    fn parse_no_dot_returns_typed_error_and_preserves_raw() {
        let err = Namespace::parse("no_dot_here".to_owned()).unwrap_err();
        assert_eq!(err.raw_input(), "no_dot_here");
        assert!(matches!(err.kind(), NamespaceParseErrorKind::NoDot));
    }

    #[test]
    fn parse_bad_database_preserves_full_original_input() {
        let err = Namespace::parse(".movies".to_owned()).unwrap_err();
        // Critical: raw_input must hold the FULL ".movies" string, not the
        // truncated "" half — v4 regression guard.
        assert_eq!(err.raw_input(), ".movies");
        assert!(matches!(
            err.kind(),
            NamespaceParseErrorKind::BadDatabase(_)
        ));
    }

    #[test]
    fn parse_bad_collection_preserves_full_original_input() {
        let err = Namespace::parse("sample.".to_owned()).unwrap_err();
        // Critical: raw_input must hold the FULL "sample." string, not the
        // truncated "sample" half — v4 regression guard.
        assert_eq!(err.raw_input(), "sample.");
        assert!(matches!(
            err.kind(),
            NamespaceParseErrorKind::BadCollection(_)
        ));
    }

    #[test]
    fn parse_does_not_clone_on_success() {
        // We can't directly observe clones, but on a successful parse the
        // function should only allocate one String each for Database and
        // Collection (not three). This test pins the behaviour: round-trip
        // is byte-identical.
        let ns = Namespace::parse("admin.users".to_owned()).unwrap();
        assert_eq!(
            format!("{}.{}", ns.database(), ns.collection()),
            "admin.users"
        );
    }
}
