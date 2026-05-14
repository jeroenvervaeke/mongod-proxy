//! `Stage` — open-vocabulary enum of MongoDB plan-tree stage kinds.
//!
//! Cannot use the [`open_vocab_enum!`] macro because some variants carry
//! sub-enums (`Project(ProjectionKind)`, `And(AndKind)`).

use super::newtypes::OtherName;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProjectionKind {
    Default,
    Simple,
    Covered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AndKind {
    Sorted,
    Hash,
}

/// A node's `stage` field in `executionStages` (e.g. `"COLLSCAN"`,
/// `"IXSCAN"`, `"PROJECTION_DEFAULT"`).
///
/// Known variants are exhaustive over the stages the explain inspector
/// recognises; unmodelled values land in [`Stage::Other`] as a
/// lowercase-normalised [`OtherName`] so forward compatibility is
/// preserved when MongoDB ships new stage kinds.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Stage {
    // -------- Classic query-plan engine (uppercase wire names) --------
    Collscan,
    Ixscan,
    Fetch,
    Sort,
    SortMerge,
    Limit,
    Skip,
    Group,
    Project(ProjectionKind),
    Or,
    And(AndKind),
    Subplan,
    ShardingFilter,
    ReturnKey,
    Count,
    CountScan,
    DistinctScan,
    UpdateStage,
    DeleteStage,

    // -------- Slot-Based Execution engine (MongoDB 8+, lowercase wire names) --------
    //
    // SBE stages are kept distinct from their classic counterparts so
    // consumers can tell which engine actually executed the query.
    // Folding `scan` into `Collscan` would lie about the execution
    // engine.
    SbeScan,
    SbeIxscan,
    SbeIxseek,
    SbeFetch,
    SbeFilter,
    SbeProject,
    SbeGroup,
    SbeSort,
    SbeLimit,
    SbeSkip,
    SbeOr,
    SbeUnwind,
    SbeHashLookup,
    SbeMerge,

    // -------- MongoDB 8 "express" fast paths (single-document by `_id`). --------
    ExpressIxscan,
    ExpressClusteredIxscan,
    ExpressUpdate,
    ExpressDelete,

    Other(OtherName),
}

impl<'de> serde::Deserialize<'de> for Stage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Stage;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a MongoDB plan stage name")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Stage, E> {
                Ok(Stage::from_wire_str(s))
            }
            fn visit_string<E: serde::de::Error>(self, s: String) -> Result<Stage, E> {
                // Reuse from_wire_str then consume the owned String only for Other.
                match Stage::from_wire_str(&s) {
                    Stage::Other(_) => Ok(Stage::Other(super::newtypes::OtherName::new(s))),
                    known => Ok(known),
                }
            }
        }
        d.deserialize_str(V)
    }
}

impl Stage {
    /// Single source of truth: wire-string → [`Stage`]. Used by both the
    /// custom `serde::Deserialize` impl and any internal classifier.
    #[allow(dead_code)]
    pub(crate) fn from_wire_str(s: &str) -> Self {
        match s {
            // Classic query-plan engine (uppercase).
            "COLLSCAN" => Stage::Collscan,
            "IXSCAN" => Stage::Ixscan,
            "FETCH" => Stage::Fetch,
            "SORT" => Stage::Sort,
            "SORT_MERGE" => Stage::SortMerge,
            "LIMIT" => Stage::Limit,
            "SKIP" => Stage::Skip,
            "GROUP" => Stage::Group,
            "PROJECTION_DEFAULT" => Stage::Project(ProjectionKind::Default),
            "PROJECTION_SIMPLE" => Stage::Project(ProjectionKind::Simple),
            "PROJECTION_COVERED" => Stage::Project(ProjectionKind::Covered),
            "OR" => Stage::Or,
            "AND_SORTED" => Stage::And(AndKind::Sorted),
            "AND_HASH" => Stage::And(AndKind::Hash),
            "SUBPLAN" => Stage::Subplan,
            "SHARDING_FILTER" => Stage::ShardingFilter,
            "RETURN_KEY" => Stage::ReturnKey,
            "COUNT" => Stage::Count,
            "COUNT_SCAN" => Stage::CountScan,
            "DISTINCT_SCAN" => Stage::DistinctScan,
            "UPDATE" => Stage::UpdateStage,
            "DELETE" => Stage::DeleteStage,

            // SBE engine (lowercase; MongoDB 8+).
            "scan" => Stage::SbeScan,
            "ixscan" => Stage::SbeIxscan,
            "ixseek" => Stage::SbeIxseek,
            "fetch" => Stage::SbeFetch,
            "filter" => Stage::SbeFilter,
            "project" => Stage::SbeProject,
            "group" => Stage::SbeGroup,
            "sort" => Stage::SbeSort,
            "limit" => Stage::SbeLimit,
            "skip" => Stage::SbeSkip,
            "or" => Stage::SbeOr,
            "unwind" => Stage::SbeUnwind,
            "hash_lookup" => Stage::SbeHashLookup,
            "merge" => Stage::SbeMerge,

            // MongoDB 8 express fast paths — server emits both upper and
            // lower-case forms across releases.
            "EXPRESS_IXSCAN" | "express_ixscan" => Stage::ExpressIxscan,
            "EXPRESS_CLUSTERED_IXSCAN" | "express_clustered_ixscan" => {
                Stage::ExpressClusteredIxscan
            }
            "EXPRESS_UPDATE" | "express_update" => Stage::ExpressUpdate,
            "EXPRESS_DELETE" | "express_delete" => Stage::ExpressDelete,

            _ => Stage::Other(OtherName::new(s.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_wire_str_maps_collscan() {
        assert_eq!(Stage::from_wire_str("COLLSCAN"), Stage::Collscan);
    }

    #[test]
    fn from_wire_str_maps_ixscan() {
        assert_eq!(Stage::from_wire_str("IXSCAN"), Stage::Ixscan);
    }

    #[test]
    fn from_wire_str_maps_projection_variants() {
        assert_eq!(
            Stage::from_wire_str("PROJECTION_DEFAULT"),
            Stage::Project(ProjectionKind::Default),
        );
        assert_eq!(
            Stage::from_wire_str("PROJECTION_SIMPLE"),
            Stage::Project(ProjectionKind::Simple),
        );
        assert_eq!(
            Stage::from_wire_str("PROJECTION_COVERED"),
            Stage::Project(ProjectionKind::Covered),
        );
    }

    #[test]
    fn from_wire_str_maps_and_variants() {
        assert_eq!(
            Stage::from_wire_str("AND_SORTED"),
            Stage::And(AndKind::Sorted)
        );
        assert_eq!(Stage::from_wire_str("AND_HASH"), Stage::And(AndKind::Hash));
    }

    #[test]
    fn from_wire_str_falls_back_to_other_lowercased() {
        match Stage::from_wire_str("BRAND_NEW_STAGE") {
            Stage::Other(name) => assert_eq!(name.as_ref(), "brand_new_stage"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn from_wire_str_maps_sbe_lowercase_distinctly_from_classic() {
        // Same conceptual operation, different execution engine. Folding
        // these would lie about which engine ran the query.
        assert_eq!(Stage::from_wire_str("scan"), Stage::SbeScan);
        assert_ne!(Stage::from_wire_str("scan"), Stage::Collscan);
        assert_eq!(Stage::from_wire_str("ixscan"), Stage::SbeIxscan);
        assert_ne!(Stage::from_wire_str("ixscan"), Stage::Ixscan);
    }

    #[test]
    fn from_wire_str_maps_sbe_only_stages() {
        assert_eq!(Stage::from_wire_str("ixseek"), Stage::SbeIxseek);
        assert_eq!(Stage::from_wire_str("filter"), Stage::SbeFilter);
        assert_eq!(Stage::from_wire_str("project"), Stage::SbeProject);
        assert_eq!(Stage::from_wire_str("group"), Stage::SbeGroup);
    }

    #[test]
    fn from_wire_str_maps_express_fast_paths() {
        // Server emits these in both upper and lower case across releases —
        // both forms must round-trip to the same variant.
        for s in ["EXPRESS_IXSCAN", "express_ixscan"] {
            assert_eq!(Stage::from_wire_str(s), Stage::ExpressIxscan);
        }
        for s in ["EXPRESS_CLUSTERED_IXSCAN", "express_clustered_ixscan"] {
            assert_eq!(Stage::from_wire_str(s), Stage::ExpressClusteredIxscan);
        }
        for s in ["EXPRESS_UPDATE", "express_update"] {
            assert_eq!(Stage::from_wire_str(s), Stage::ExpressUpdate);
        }
        for s in ["EXPRESS_DELETE", "express_delete"] {
            assert_eq!(Stage::from_wire_str(s), Stage::ExpressDelete);
        }
    }
}
