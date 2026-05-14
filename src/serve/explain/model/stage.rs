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
    Other(OtherName),
}

impl Stage {
    /// Single source of truth: wire-string → [`Stage`]. Used by both the
    /// custom `serde::Deserialize` impl and any internal classifier.
    #[allow(dead_code)]
    pub(crate) fn from_wire_str(s: &str) -> Self {
        match s {
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
}
