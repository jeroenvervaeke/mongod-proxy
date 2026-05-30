//! Wire-level identifier newtypes used throughout the MongoDB wire protocol.

use nutype::nutype;

/// Wire-level request id from the MongoDB message header.
///
/// Unrestricted `i32` — the wire protocol permits `request_id == 0` on fresh
/// client requests, so no non-zero validation is imposed. See [`ExplainRequestId`]
/// for the proxy-allocated subset that excludes the driver's positive id space.
#[nutype(derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, Into))]
pub struct RequestId(i32);

/// Proxy-allocated request id used for sideband explain operations.
///
/// Validated strictly negative — disjoint from the driver's typical positive
/// id space by type construction. Converts infallibly to wire-level
/// [`RequestId`] via `From`.
#[nutype(
    derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, Into),
    validate(predicate = |&n: &i32| n < 0),
)]
pub struct ExplainRequestId(i32);

impl From<ExplainRequestId> for RequestId {
    fn from(e: ExplainRequestId) -> Self {
        // Infallible: ExplainRequestId is strictly negative; RequestId accepts any i32.
        RequestId::new(e.into_inner())
    }
}

/// `response_to` field from the MongoDB message header — only present on
/// server replies, never on fresh client requests. Wraps [`std::num::NonZeroI32`]
/// to preserve the niche optimisation on `Option<ResponseTo>`.
#[nutype(derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, Into))]
pub struct ResponseTo(std::num::NonZeroI32);

/// Total frame length in bytes, validated against the wire-protocol envelope:
/// at least 16 bytes (the header itself) and at most 48 MiB (MongoDB's default
/// `maxMessageSizeBytes` server limit).
#[nutype(
    derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, Into),
    validate(predicate = |&n: &i32| (16..=48 * 1024 * 1024).contains(&n)),
)]
pub struct MessageLength(i32);

impl MessageLength {
    /// Returns the validated length as a `usize`.
    ///
    /// The inner value is validated to lie in `16..=48 MiB`, so it is always
    /// non-negative and the `usize::try_from` conversion can never fail; the
    /// `unwrap_or(0)` is therefore unreachable and exists only to keep this
    /// method panic-free (no `unwrap`/`expect`) under all targets.
    pub fn as_usize(&self) -> usize {
        usize::try_from(self.into_inner()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_round_trips_through_new_and_into_inner() {
        let id = RequestId::new(42);
        let inner: i32 = id.into_inner();
        assert_eq!(inner, 42);
    }

    #[test]
    fn request_id_accepts_zero() {
        // Wire protocol permits request_id == 0 on fresh client requests.
        let id = RequestId::new(0);
        assert_eq!(id.into_inner(), 0);
    }

    #[test]
    fn request_id_accepts_negative() {
        let id = RequestId::new(-1);
        assert_eq!(id.into_inner(), -1);
    }

    #[test]
    fn explain_request_id_accepts_negative() {
        let id = ExplainRequestId::try_new(-1).expect("negative is valid");
        assert_eq!(id.into_inner(), -1);
    }

    #[test]
    fn explain_request_id_rejects_zero() {
        let err = ExplainRequestId::try_new(0).expect_err("zero must be rejected");
        assert!(matches!(err, ExplainRequestIdError::PredicateViolated));
    }

    #[test]
    fn explain_request_id_rejects_positive() {
        let err = ExplainRequestId::try_new(42).expect_err("positive must be rejected");
        assert!(matches!(err, ExplainRequestIdError::PredicateViolated));
    }

    #[test]
    fn explain_request_id_converts_to_request_id() {
        let e = ExplainRequestId::try_new(-7).unwrap();
        let r: RequestId = e.into();
        assert_eq!(r.into_inner(), -7);
    }

    #[test]
    fn response_to_constructed_from_nonzero_i32() {
        use std::num::NonZeroI32;
        let nz = NonZeroI32::new(7).unwrap();
        let r = ResponseTo::new(nz);
        let back: NonZeroI32 = r.into_inner();
        assert_eq!(back.get(), 7);
    }

    #[test]
    fn message_length_accepts_minimum_16() {
        let m = MessageLength::try_new(16).unwrap();
        assert_eq!(m.into_inner(), 16);
    }

    #[test]
    fn message_length_accepts_max_48mib() {
        let max = 48 * 1024 * 1024;
        let m = MessageLength::try_new(max).unwrap();
        assert_eq!(m.into_inner(), max);
    }

    #[test]
    fn message_length_rejects_below_16() {
        assert!(MessageLength::try_new(15).is_err());
        assert!(MessageLength::try_new(0).is_err());
        assert!(MessageLength::try_new(-1).is_err());
    }

    #[test]
    fn message_length_rejects_above_48mib() {
        let over = 48 * 1024 * 1024 + 1;
        assert!(MessageLength::try_new(over).is_err());
    }

    #[test]
    fn message_length_as_usize_matches_inner() {
        let m = MessageLength::try_new(1234).unwrap();
        assert_eq!(m.as_usize(), 1234usize);

        let min = MessageLength::try_new(16).unwrap();
        assert_eq!(min.as_usize(), 16usize);

        let max = MessageLength::try_new(48 * 1024 * 1024).unwrap();
        assert_eq!(max.as_usize(), (48 * 1024 * 1024) as usize);
    }
}
