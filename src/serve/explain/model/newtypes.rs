//! Domain-distinct newtypes used by the explain inspector model.
//!
//! Each concept gets its own type so the compiler prevents cross-assignment
//! even when the backing representation is identical (e.g. count newtypes all
//! wrap `i64` but cannot be assigned to each other).

use nutype::nutype;

/// A database name was empty (or whitespace-only) after trimming.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("database name must be non-empty after trimming")]
pub struct DatabaseError;

fn validate_database(s: &str) -> Result<(), DatabaseError> {
    if s.trim().is_empty() {
        Err(DatabaseError)
    } else {
        Ok(())
    }
}

/// MongoDB database name parsed from the wire (e.g. `"sample_mflix"`).
/// Trimmed and non-empty by construction.
#[nutype(
    derive(Debug, Clone, PartialEq, Eq, Hash, AsRef, Display),
    sanitize(trim),
    validate(with = validate_database, error = DatabaseError),
)]
pub struct Database(String);

/// A collection name was empty (or whitespace-only) after trimming.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("collection name must be non-empty after trimming")]
pub struct CollectionError;

fn validate_collection(s: &str) -> Result<(), CollectionError> {
    if s.trim().is_empty() {
        Err(CollectionError)
    } else {
        Ok(())
    }
}

/// MongoDB collection name parsed from the wire (e.g. `"movies"`).
/// Trimmed and non-empty by construction.
#[nutype(
    derive(Debug, Clone, PartialEq, Eq, Hash, AsRef, Display),
    sanitize(trim),
    validate(with = validate_collection, error = CollectionError),
)]
pub struct Collection(String);

/// An index name was the empty string.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("index name must be non-empty")]
pub struct IndexNameError;

fn validate_index_name(s: &str) -> Result<(), IndexNameError> {
    if s.is_empty() {
        Err(IndexNameError)
    } else {
        Ok(())
    }
}

/// MongoDB index name from a plan's `IXSCAN` stage (e.g. `"year_1"`).
#[nutype(
    derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, AsRef, Display),
    validate(with = validate_index_name, error = IndexNameError),
)]
pub struct IndexName(String);

/// A `DocsReturned` count was negative; carries the offending value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("DocsReturned must be non-negative, got {0}")]
pub struct DocsReturnedError(pub i64);

fn validate_docs_returned(n: &i64) -> Result<(), DocsReturnedError> {
    if *n >= 0 {
        Ok(())
    } else {
        Err(DocsReturnedError(*n))
    }
}

/// Number of documents returned by a stage / plan total.
#[nutype(
    derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Display, Into),
    validate(with = validate_docs_returned, error = DocsReturnedError),
)]
pub struct DocsReturned(i64);

/// A `DocsExamined` count was negative; carries the offending value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("DocsExamined must be non-negative, got {0}")]
pub struct DocsExaminedError(pub i64);

fn validate_docs_examined(n: &i64) -> Result<(), DocsExaminedError> {
    if *n >= 0 {
        Ok(())
    } else {
        Err(DocsExaminedError(*n))
    }
}

/// Number of documents examined (visited during execution).
#[nutype(
    derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Display, Into),
    validate(with = validate_docs_examined, error = DocsExaminedError),
)]
pub struct DocsExamined(i64);

/// A `KeysExamined` count was negative; carries the offending value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("KeysExamined must be non-negative, got {0}")]
pub struct KeysExaminedError(pub i64);

fn validate_keys_examined(n: &i64) -> Result<(), KeysExaminedError> {
    if *n >= 0 {
        Ok(())
    } else {
        Err(KeysExaminedError(*n))
    }
}

/// Number of index keys examined during execution.
#[nutype(
    derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Display, Into),
    validate(with = validate_keys_examined, error = KeysExaminedError),
)]
pub struct KeysExamined(i64);

/// Aggregate execution time (server's `executionTimeMillis`, sum over the
/// whole plan). `Duration` does not implement `Display`, so the newtype
/// exposes the inner value via `Into<Duration>` for formatting.
#[nutype(derive(Debug, Clone, Copy, PartialEq, Eq, Hash, From, Into))]
pub struct AggregateTime(std::time::Duration);

/// Per-stage execution time (server's `executionTimeMillisEstimate`).
#[nutype(derive(Debug, Clone, Copy, PartialEq, Eq, Hash, From, Into))]
pub struct NodeTime(std::time::Duration);

/// A server error code was not positive; carries the offending value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("server error code must be positive, got {0}")]
pub struct ServerErrorCodeError(pub i32);

fn validate_server_error_code(n: &i32) -> Result<(), ServerErrorCodeError> {
    if *n > 0 {
        Ok(())
    } else {
        Err(ServerErrorCodeError(*n))
    }
}

/// MongoDB server error code (e.g. `11000` for duplicate key).
#[nutype(
    derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Display, Into),
    validate(with = validate_server_error_code, error = ServerErrorCodeError),
)]
pub struct ServerErrorCode(i32);

/// Lowercase-normalised free-form name carried inside open-vocabulary
/// enums' `Other(_)` variant. Lowercasing prevents `Other("FindAndModify")`
/// and `Other("findandmodify")` from being treated as distinct values.
#[nutype(
    derive(Debug, Clone, PartialEq, Eq, Hash, Display, AsRef),
    sanitize(lowercase)
)]
pub struct OtherName(String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_trims_whitespace() {
        let d = Database::try_new("  sample  ".to_owned()).unwrap();
        assert_eq!(d.as_ref(), "sample");
    }

    #[test]
    fn database_rejects_empty() {
        assert!(Database::try_new(String::new()).is_err());
    }

    #[test]
    fn database_rejects_whitespace_only() {
        assert!(Database::try_new("   ".to_owned()).is_err());
    }

    #[test]
    fn collection_trims_and_accepts() {
        let c = Collection::try_new(" movies ".to_owned()).unwrap();
        assert_eq!(c.as_ref(), "movies");
    }

    #[test]
    fn collection_rejects_empty() {
        assert!(Collection::try_new(String::new()).is_err());
    }

    #[test]
    fn index_name_accepts_non_empty() {
        let i = IndexName::try_new("year_1".to_owned()).unwrap();
        assert_eq!(i.as_ref(), "year_1");
    }

    #[test]
    fn index_name_rejects_empty() {
        assert!(IndexName::try_new(String::new()).is_err());
    }

    #[test]
    fn docs_returned_accepts_non_negative() {
        assert_eq!(DocsReturned::try_new(0).unwrap().into_inner(), 0);
        assert_eq!(DocsReturned::try_new(42).unwrap().into_inner(), 42);
    }

    #[test]
    fn docs_returned_rejects_negative() {
        let err = DocsReturned::try_new(-1).unwrap_err();
        assert_eq!(err, DocsReturnedError(-1));
    }

    #[test]
    fn docs_examined_rejects_negative() {
        let err = DocsExamined::try_new(-5).unwrap_err();
        assert_eq!(err, DocsExaminedError(-5));
    }

    #[test]
    fn keys_examined_rejects_negative() {
        let err = KeysExamined::try_new(-1).unwrap_err();
        assert_eq!(err, KeysExaminedError(-1));
    }

    #[test]
    fn aggregate_time_wraps_duration() {
        use std::time::Duration;
        let a = AggregateTime::new(Duration::from_millis(16));
        assert_eq!(a.into_inner(), Duration::from_millis(16));
    }

    #[test]
    fn node_time_distinct_from_aggregate_time() {
        // Compile-only check: cannot assign one to the other.
        use std::time::Duration;
        let n = NodeTime::new(Duration::from_millis(4));
        let a = AggregateTime::new(Duration::from_millis(4));
        // Both wrap the same Duration value, but the types differ.
        assert_eq!(n.into_inner(), a.into_inner());
    }

    #[test]
    fn server_error_code_accepts_positive() {
        assert_eq!(ServerErrorCode::try_new(11000).unwrap().into_inner(), 11000);
    }

    #[test]
    fn server_error_code_rejects_zero_and_negative() {
        assert!(ServerErrorCode::try_new(0).is_err());
        assert!(ServerErrorCode::try_new(-1).is_err());
    }

    #[test]
    fn other_name_lowercases_input() {
        let n = OtherName::new("FindAndModify".to_owned());
        assert_eq!(n.as_ref(), "findandmodify");
    }
}
