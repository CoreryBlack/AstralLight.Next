//! memory—v1: Immutable, version-local match plans; no authority or decision cache.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use super::{
    parse_version, MemoryV1Rule, MemoryV1RuleError, MemoryV1RuleHit, MemoryV1RuleSetContent,
};
use crate::memory_v1_db_rows::RuleSetVersionRow;

const LINEAR_MAX: usize = 8;
const SORTED_MAX: usize = 128;
type PairIndex = HashMap<String, HashMap<String, Range<usize>>>;

/// Hash- and grammar-checked content of one immutable version. Registry state,
/// validity, authorization dependencies and final admission are checked separately.
#[derive(Debug)]
pub struct PreparedRuleSet {
    content: MemoryV1RuleSetContent,
    plan: MatchPlan,
}

#[derive(Debug)]
enum MatchPlan {
    Linear,
    Indexed {
        positions: Box<[u16]>,
        // First occurrences in canonical order; validates even nonmatching pairs.
        registry_positions: Box<[u16]>,
        ranges: Option<Box<PairIndex>>,
    },
}

impl PreparedRuleSet {
    // memory—v1: Only checked canonical bytes can create a prepared plan.
    pub(crate) fn prepare(row: &RuleSetVersionRow) -> Result<Self, MemoryV1RuleError> {
        Ok(Self::from_content(parse_version(row)?))
    }

    // memory—v1: Store positions, not copies of rules. All equal-key positions
    // stay in canonical order so DENY evidence and future windows are unchanged.
    fn from_content(content: MemoryV1RuleSetContent) -> Self {
        let rules = &content.rules;
        let plan = if rules.len() <= LINEAR_MAX {
            MatchPlan::Linear
        } else {
            let mut groups = BTreeMap::<(&str, &str), Vec<u16>>::new();
            for (position, rule) in rules.iter().enumerate() {
                groups
                    .entry(pair(rule))
                    .or_default()
                    .push(u16::try_from(position).expect("validated rule count fits u16"));
            }
            let mut positions = Vec::with_capacity(rules.len());
            let mut registry_positions = Vec::with_capacity(groups.len());
            let mut ranges = (rules.len() > SORTED_MAX).then(PairIndex::new);
            for ((resource, action), group) in groups {
                registry_positions.push(group[0]);
                let start = positions.len();
                positions.extend(group);
                if let Some(ranges) = &mut ranges {
                    ranges
                        .entry(resource.to_owned())
                        .or_default()
                        .insert(action.to_owned(), start..positions.len());
                }
            }
            registry_positions.sort_unstable();
            MatchPlan::Indexed {
                positions: positions.into_boxed_slice(),
                registry_positions: registry_positions.into_boxed_slice(),
                ranges: ranges.map(Box::new),
            }
        };
        Self { content, plan }
    }

    /// memory—v1: Visit every type-level hit in original rule order without
    /// materializing a hit list. Scope, windows and conflict rules are unchanged.
    pub fn rule_hits<'a>(
        &'a self,
        resource: &'a str,
        action: &'a str,
    ) -> impl Iterator<Item = MemoryV1RuleHit<'a>> + 'a {
        let rules = &self.content.rules;
        let positions = match &self.plan {
            MatchPlan::Linear => None,
            MatchPlan::Indexed {
                positions, ranges, ..
            } => {
                let selected = if let Some(ranges) = ranges {
                    ranges
                        .get(resource)
                        .and_then(|actions| actions.get(action))
                        .cloned()
                } else {
                    let key = (resource, action);
                    let start = positions.partition_point(|&i| pair(&rules[usize::from(i)]) < key);
                    let end = start
                        + positions[start..]
                            .partition_point(|&i| pair(&rules[usize::from(i)]) == key);
                    Some(start..end)
                };
                Some(selected.map_or(&[][..], |range| &positions[range]))
            }
        };
        let mut linear = rules.iter();
        let mut indexed = positions.map(<[_]>::iter);
        std::iter::from_fn(move || {
            let rule = match &mut indexed {
                Some(positions) => &rules[usize::from(*positions.next()?)],
                None => linear.find(|rule| pair(rule) == (resource, action))?,
            };
            Some(MemoryV1RuleHit::from(rule))
        })
    }

    // memory—v1: Deduplication is valid because all checks in a call hold one
    // registry read guard, and only (resource, action) affects registry status.
    pub(crate) fn registry_pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        let rules = &self.content.rules;
        let mut linear = rules.iter();
        let mut indexed = match &self.plan {
            MatchPlan::Linear => None,
            MatchPlan::Indexed {
                registry_positions, ..
            } => Some(registry_positions.iter()),
        };
        std::iter::from_fn(move || {
            let rule = match &mut indexed {
                Some(positions) => &rules[usize::from(*positions.next()?)],
                None => linear.next()?,
            };
            Some(pair(rule))
        })
    }
}

// memory—v1: All three lanes match the same exact, case-sensitive key.
fn pair(rule: &MemoryV1Rule) -> (&str, &str) {
    (&rule.resource, &rule.action)
}

impl<'a> From<&'a MemoryV1Rule> for MemoryV1RuleHit<'a> {
    // memory—v1: Borrow immutable fields; keep the only field mapping here.
    fn from(rule: &'a MemoryV1Rule) -> Self {
        Self {
            rule_id: &rule.rule_id,
            effect: rule.effect,
            validity: rule.validity.as_ref(),
            owner_scope: rule.owner_scope,
            tenant_scope: rule.tenant_scope,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // memory—v1: Compare type predicates, match order and every hit field across
    // both boundaries, including sparse, dense, and missing matches.
    #[test]
    fn ordered_hits_and_registry_pairs_match_reference_at_each_boundary() {
        for count in [
            0,
            1,
            LINEAR_MAX,
            LINEAR_MAX + 1,
            SORTED_MAX,
            SORTED_MAX + 1,
            4096,
        ] {
            let rules = (0..count)
                .map(|i| {
                    serde_json::json!({
                        "ruleId": format!("rule-{i}"),
                        "resource": (["document", "report", "record"][i % 3]),
                        "action": (["read", "write"][i % 2]),
                        "effect": (["ALLOW", "DENY"][i / 3 % 2]),
                        "validity": {"from": i, "until": i + 10},
                        "ownerScope": (["self", "all"][i / 2 % 2]),
                        "tenantScope": (["self", "self+descendants"][i / 5 % 2]),
                    })
                })
                .collect::<Vec<_>>();
            let content = MemoryV1RuleSetContent::parse(
                &serde_json::to_vec(&serde_json::json!({"rules": rules})).unwrap(),
            )
            .unwrap();
            let prepared = PreparedRuleSet::from_content(content.clone());
            for resource in ["document", "report", "record", "missing"] {
                for action in ["read", "write", "missing"] {
                    assert_eq!(
                        prepared.rule_hits(resource, action).collect::<Vec<_>>(),
                        content.rule_hits(resource, action),
                        "rules={count}"
                    );
                }
            }
            let unique = |pairs: Vec<_>| {
                let mut seen = std::collections::BTreeSet::new();
                pairs
                    .into_iter()
                    .filter(|key| seen.insert(*key))
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                unique(prepared.registry_pairs().collect()),
                unique(content.rules.iter().map(pair).collect()),
                "rules={count}"
            );
        }
    }
}
