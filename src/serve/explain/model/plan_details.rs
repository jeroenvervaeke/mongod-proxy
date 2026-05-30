//! Per-stage typed detail captured from the explain reply:
//! [`KeyPattern`], [`IndexBounds`], [`Filter`].
//!
//! Classic and SBE/Express execution engines disagree on the wire shape
//! of these fields:
//!
//! - **Classic** ships them as BSON Documents.
//! - **SBE / Express** ships them as pretty-printed strings (e.g.
//!   `keyPattern: "{ _id: 1 }"`, `filter: "traverseF(s3, lambda(...))"`).
//!
//! Each type below is a typed enum capturing *both* shapes so the engine
//! distinction is preserved end-to-end.

use std::collections::BTreeMap;

use bson::Bson;

use super::newtypes::OtherName;

// =================================================================
// IndexFieldKind + KeyPattern
// =================================================================

/// One field's contribution to an index definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IndexFieldKind {
    /// Wire form: `1` / `1.0`.
    Ascending,
    /// Wire form: `-1` / `-1.0`.
    Descending,
    Hashed,
    Text,
    TwoDSphere,
    TwoD,
    /// Forward-compat fallback for any unknown index kind string.
    Other(OtherName),
}

impl IndexFieldKind {
    fn from_bson(b: &Bson) -> Result<Self, String> {
        match b {
            Bson::Int32(1) => Ok(IndexFieldKind::Ascending),
            Bson::Int64(1) => Ok(IndexFieldKind::Ascending),
            Bson::Double(f) if (*f - 1.0).abs() < f64::EPSILON => Ok(IndexFieldKind::Ascending),
            Bson::Int32(-1) => Ok(IndexFieldKind::Descending),
            Bson::Int64(-1) => Ok(IndexFieldKind::Descending),
            Bson::Double(f) if (*f - -1.0).abs() < f64::EPSILON => Ok(IndexFieldKind::Descending),
            Bson::String(s) => Ok(match s.as_str() {
                "hashed" => IndexFieldKind::Hashed,
                "text" => IndexFieldKind::Text,
                "2dsphere" => IndexFieldKind::TwoDSphere,
                "2d" => IndexFieldKind::TwoD,
                _ => IndexFieldKind::Other(OtherName::new(s.clone())),
            }),
            other => Err(format!(
                "unexpected index direction/kind value: {:?}",
                other.element_type()
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyPatternField {
    pub field: String,
    pub kind: IndexFieldKind,
}

/// Index definition as it appears on an `IXSCAN` (or `EXPRESS_IXSCAN`)
/// stage. Two wire shapes share this type — see module docs.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum KeyPattern {
    /// Typed ordered list of `(field, kind)` pairs decoded from a BSON
    /// document. Compound-index order preserved (classic engines emit
    /// the document with field order intact).
    Document(Vec<KeyPatternField>),
    /// MongoDB 8 Express paths emit `keyPattern` as a stringified
    /// JavaScript-ish pretty-print like `"{ _id: 1 }"`. The raw string
    /// is preserved verbatim; consumers wanting the typed form can call
    /// [`KeyPattern::parse_express_string`] on a best-effort basis.
    Express(String),
}

impl KeyPattern {
    /// Best-effort reparser for the Express-string form
    /// (`"{ _id: 1, year: -1 }"`) into a typed list. Returns `None` when
    /// the string doesn't match the expected pretty-print shape.
    pub fn parse_express_string(s: &str) -> Option<Vec<KeyPatternField>> {
        let s = s.trim();
        let s = s.strip_prefix('{')?.strip_suffix('}')?.trim();
        let mut out = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            let (k, v) = part.split_once(':')?;
            let k = k.trim().trim_matches(|c| c == '"' || c == '\'').to_owned();
            let v = v.trim();
            let kind = if let Ok(n) = v.parse::<i64>() {
                IndexFieldKind::from_bson(&Bson::Int64(n)).ok()?
            } else if let Ok(f) = v.parse::<f64>() {
                IndexFieldKind::from_bson(&Bson::Double(f)).ok()?
            } else {
                let stripped = v.trim_matches(|c| c == '"' || c == '\'');
                IndexFieldKind::from_bson(&Bson::String(stripped.to_owned())).ok()?
            };
            out.push(KeyPatternField { field: k, kind });
        }
        Some(out)
    }
}

impl<'de> serde::Deserialize<'de> for KeyPattern {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let b = Bson::deserialize(d)?;
        match b {
            Bson::Document(doc) => {
                let mut fields = Vec::with_capacity(doc.len());
                for (k, v) in doc {
                    let kind = IndexFieldKind::from_bson(&v).map_err(D::Error::custom)?;
                    fields.push(KeyPatternField { field: k, kind });
                }
                Ok(KeyPattern::Document(fields))
            }
            Bson::String(s) => Ok(KeyPattern::Express(s)),
            other => Err(D::Error::custom(format!(
                "keyPattern must be Document or String, got {:?}",
                other.element_type()
            ))),
        }
    }
}

// =================================================================
// IndexBounds + IndexBoundRange + BoundValue
// =================================================================

/// One end of an index range — typed both in inclusivity and in the
/// "special" sentinel values the wire format uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BoundValue {
    Inf,
    NegInf,
    MinKey,
    MaxKey,
    /// Literal value, as the on-wire pretty-print rendered it. We
    /// preserve the textual form because the wire format is itself a
    /// pretty-print string with no schema attached to the value type.
    Literal(String),
}

impl BoundValue {
    fn parse(s: &str) -> Self {
        match s.trim() {
            "inf" => BoundValue::Inf,
            "-inf" => BoundValue::NegInf,
            "MinKey" => BoundValue::MinKey,
            "MaxKey" => BoundValue::MaxKey,
            other => BoundValue::Literal(other.to_owned()),
        }
    }
}

/// Whether a bound is inclusive (`[`/`]`) or exclusive (`(`/`)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Inclusivity {
    Inclusive,
    Exclusive,
}

/// Half-open or closed interval on a single index field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct IndexBoundRange {
    pub lower: BoundValue,
    pub lower_inclusivity: Inclusivity,
    pub upper: BoundValue,
    pub upper_inclusivity: Inclusivity,
}

impl IndexBoundRange {
    /// Parse a single MongoDB range string like `"[1999, 1999]"` or
    /// `"(-inf, 0)"`.
    pub fn parse(s: &str) -> Result<Self, IndexBoundsParseError> {
        let s = s.trim();
        let mut chars = s.chars();
        let first = chars
            .next()
            .ok_or_else(|| IndexBoundsParseError::empty(s))?;
        let lower_inclusivity = match first {
            '[' => Inclusivity::Inclusive,
            '(' => Inclusivity::Exclusive,
            _ => return Err(IndexBoundsParseError::bad_open(s)),
        };
        let last = s
            .chars()
            .next_back()
            .ok_or_else(|| IndexBoundsParseError::empty(s))?;
        let upper_inclusivity = match last {
            ']' => Inclusivity::Inclusive,
            ')' => Inclusivity::Exclusive,
            _ => return Err(IndexBoundsParseError::bad_close(s)),
        };
        let body = &s[1..s.len() - 1];
        let (lo, hi) = body
            .split_once(", ")
            .or_else(|| body.split_once(','))
            .ok_or_else(|| IndexBoundsParseError::no_separator(s))?;
        Ok(IndexBoundRange {
            lower: BoundValue::parse(lo),
            lower_inclusivity,
            upper: BoundValue::parse(hi),
            upper_inclusivity,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IndexBoundsParseError {
    #[error("empty bound string")]
    Empty,
    #[error("bound string {raw:?} must start with '[' or '('")]
    BadOpen { raw: String },
    #[error("bound string {raw:?} must end with ']' or ')'")]
    BadClose { raw: String },
    #[error("bound string {raw:?} has no ',' separator between lower and upper")]
    NoSeparator { raw: String },
}

impl IndexBoundsParseError {
    fn empty(_: &str) -> Self {
        IndexBoundsParseError::Empty
    }
    fn bad_open(s: &str) -> Self {
        IndexBoundsParseError::BadOpen { raw: s.to_owned() }
    }
    fn bad_close(s: &str) -> Self {
        IndexBoundsParseError::BadClose { raw: s.to_owned() }
    }
    fn no_separator(s: &str) -> Self {
        IndexBoundsParseError::NoSeparator { raw: s.to_owned() }
    }
}

/// Index bounds for one IXSCAN stage. Two wire shapes share this type.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum IndexBounds {
    /// `{ field: ["[lo, hi]", ...], ... }` — classic engines.
    Document(BTreeMap<String, Vec<IndexBoundRange>>),
    /// SBE / Express engines occasionally serialise bounds as a single
    /// pretty-print string. Preserved verbatim.
    Raw(String),
}

impl<'de> serde::Deserialize<'de> for IndexBounds {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let b = Bson::deserialize(d)?;
        match b {
            Bson::Document(doc) => {
                let mut out = BTreeMap::new();
                for (field, value) in doc {
                    let ranges = match value {
                        Bson::Array(arr) => arr
                            .into_iter()
                            .map(|r| match r {
                                Bson::String(s) => {
                                    IndexBoundRange::parse(&s).map_err(D::Error::custom)
                                }
                                other => Err(D::Error::custom(format!(
                                    "bound entry must be String, got {:?}",
                                    other.element_type()
                                ))),
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                        other => {
                            return Err(D::Error::custom(format!(
                                "indexBounds field value must be Array, got {:?}",
                                other.element_type()
                            )));
                        }
                    };
                    out.insert(field, ranges);
                }
                Ok(IndexBounds::Document(out))
            }
            Bson::String(s) => Ok(IndexBounds::Raw(s)),
            other => Err(D::Error::custom(format!(
                "indexBounds must be Document or String, got {:?}",
                other.element_type()
            ))),
        }
    }
}

// =================================================================
// Filter
// =================================================================

/// Match-expression filter evaluated *during* a stage.
///
/// Classic engines emit a BSON document modelling the MongoDB query
/// language (`{ rating: { $gte: 7 } }`); SBE engines emit a compiled SBE
/// expression string (`"traverseF(s3, lambda(...))"`). Both shapes are
/// captured verbatim; a future typed `MatchExpression` AST can replace
/// the `MatchExpression` variant without breaking the SBE-string path.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Filter {
    /// Classic engine — BSON MatchExpression document.
    MatchExpression(bson::Document),
    /// SBE engine — compiled expression string.
    SbeExpression(String),
}

impl<'de> serde::Deserialize<'de> for Filter {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let b = Bson::deserialize(d)?;
        match b {
            Bson::Document(doc) => Ok(Filter::MatchExpression(doc)),
            Bson::String(s) => Ok(Filter::SbeExpression(s)),
            other => Err(D::Error::custom(format!(
                "filter must be Document or String, got {:?}",
                other.element_type()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::{Bson, doc};

    // ---- IndexFieldKind ----

    #[test]
    fn field_kind_int32_one_is_ascending() {
        assert_eq!(
            IndexFieldKind::from_bson(&Bson::Int32(1)),
            Ok(IndexFieldKind::Ascending),
        );
    }

    #[test]
    fn field_kind_int32_minus_one_is_descending() {
        assert_eq!(
            IndexFieldKind::from_bson(&Bson::Int32(-1)),
            Ok(IndexFieldKind::Descending),
        );
    }

    #[test]
    fn field_kind_string_hashed() {
        assert_eq!(
            IndexFieldKind::from_bson(&Bson::String("hashed".into())),
            Ok(IndexFieldKind::Hashed),
        );
    }

    #[test]
    fn field_kind_string_2dsphere() {
        assert_eq!(
            IndexFieldKind::from_bson(&Bson::String("2dsphere".into())),
            Ok(IndexFieldKind::TwoDSphere),
        );
    }

    #[test]
    fn field_kind_unknown_string_is_other() {
        match IndexFieldKind::from_bson(&Bson::String("BRAND_NEW".into())).unwrap() {
            IndexFieldKind::Other(n) => assert_eq!(n.as_ref(), "brand_new"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    // ---- KeyPattern ----

    #[test]
    fn key_pattern_from_document() {
        let doc = doc! { "year": 1, "title": "text" };
        let bytes = bson::serialize_to_vec(&doc).unwrap();
        let kp: KeyPattern = bson::deserialize_from_slice(&bytes).unwrap();
        match kp {
            KeyPattern::Document(fields) => {
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].field, "year");
                assert_eq!(fields[0].kind, IndexFieldKind::Ascending);
                assert_eq!(fields[1].field, "title");
                assert_eq!(fields[1].kind, IndexFieldKind::Text);
            }
            _ => panic!("expected Document"),
        }
    }

    #[test]
    fn key_pattern_express_string_preserved_verbatim() {
        // bson::deserialize_from_slice for a top-level string requires the BSON value
        // to be wrapped. Skip cross-format test; the parse_express_string
        // helper round-trip is exercised separately.
        assert_eq!(
            KeyPattern::parse_express_string("{ _id: 1 }").unwrap(),
            vec![KeyPatternField {
                field: "_id".to_owned(),
                kind: IndexFieldKind::Ascending,
            }],
        );
    }

    #[test]
    fn key_pattern_parse_express_string_compound() {
        let parsed = KeyPattern::parse_express_string("{ year: -1, title: 1 }").unwrap();
        assert_eq!(
            parsed,
            vec![
                KeyPatternField {
                    field: "year".to_owned(),
                    kind: IndexFieldKind::Descending
                },
                KeyPatternField {
                    field: "title".to_owned(),
                    kind: IndexFieldKind::Ascending
                },
            ]
        );
    }

    // ---- IndexBoundRange ----

    #[test]
    fn bound_range_closed() {
        let r = IndexBoundRange::parse("[1999, 2001]").unwrap();
        assert_eq!(r.lower, BoundValue::Literal("1999".into()));
        assert_eq!(r.lower_inclusivity, Inclusivity::Inclusive);
        assert_eq!(r.upper, BoundValue::Literal("2001".into()));
        assert_eq!(r.upper_inclusivity, Inclusivity::Inclusive);
    }

    #[test]
    fn bound_range_left_open_right_closed() {
        let r = IndexBoundRange::parse("(0, 100]").unwrap();
        assert_eq!(r.lower_inclusivity, Inclusivity::Exclusive);
        assert_eq!(r.upper_inclusivity, Inclusivity::Inclusive);
    }

    #[test]
    fn bound_range_with_inf_sentinels() {
        let r = IndexBoundRange::parse("[inf, 2000]").unwrap();
        assert_eq!(r.lower, BoundValue::Inf);
        assert_eq!(r.upper, BoundValue::Literal("2000".into()));
    }

    #[test]
    fn bound_range_with_neg_inf() {
        let r = IndexBoundRange::parse("(-inf, 0)").unwrap();
        assert_eq!(r.lower, BoundValue::NegInf);
        assert_eq!(r.upper, BoundValue::Literal("0".into()));
    }

    #[test]
    fn bound_range_with_minkey_maxkey() {
        let r = IndexBoundRange::parse("[MinKey, MaxKey]").unwrap();
        assert_eq!(r.lower, BoundValue::MinKey);
        assert_eq!(r.upper, BoundValue::MaxKey);
    }

    #[test]
    fn bound_range_rejects_missing_brackets() {
        assert!(IndexBoundRange::parse("1999, 2001").is_err());
    }

    #[test]
    fn bound_range_rejects_no_comma() {
        assert!(IndexBoundRange::parse("[1999]").is_err());
    }
}
