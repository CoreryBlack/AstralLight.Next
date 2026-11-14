// InnoDB checks foreign keys immediately, so `RESTRICT` and `NO ACTION` enforce the
// same rule. The catalog may report either spelling: an omitted `ON DELETE` clause is
// recorded as `NO ACTION` on MySQL 8.0. Only that equivalence is accepted here. Every
// other rule must match exactly, and an unknown spelling never matches anything.

/// Maps one of the five MySQL referential actions to its canonical spelling.
fn canonical_action(rule: &str) -> Option<&'static str> {
    match rule {
        "RESTRICT" | "NO ACTION" => Some("RESTRICT"),
        "CASCADE" => Some("CASCADE"),
        "SET NULL" => Some("SET NULL"),
        "SET DEFAULT" => Some("SET DEFAULT"),
        _ => None,
    }
}

/// Whether two spellings name the same referential action. An unknown spelling matches
/// nothing, not even an identical unknown spelling.
pub(super) fn referential_actions_match(actual: &str, expected: &str) -> bool {
    match (canonical_action(actual), canonical_action(expected)) {
        (Some(actual), Some(expected)) => actual == expected,
        _ => false,
    }
}

/// Compares catalog foreign keys with an exact contract, row by row and in order.
/// Constraint, column and target names must be identical. Only the delete rule goes
/// through `referential_actions_match`.
pub(super) fn foreign_keys_match(
    actual: &[(String, String, String, String, String)],
    expected: &[(String, String, String, String, String)],
) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.0 == expected.0
                && actual.1 == expected.1
                && actual.2 == expected.2
                && actual.3 == expected.3
                && referential_actions_match(&actual.4, &expected.4)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTIONS: [&str; 5] = [
        "RESTRICT",
        "NO ACTION",
        "CASCADE",
        "SET NULL",
        "SET DEFAULT",
    ];

    fn row(constraint: &str, rule: &str) -> (String, String, String, String, String) {
        (
            constraint.to_owned(),
            "parent_id".to_owned(),
            "parent".to_owned(),
            "id".to_owned(),
            rule.to_owned(),
        )
    }

    #[test]
    fn only_no_action_and_restrict_are_equivalent() {
        let restrict = |rule: &str| matches!(rule, "RESTRICT" | "NO ACTION");
        for left in ACTIONS {
            for right in ACTIONS {
                let expected = left == right || (restrict(left) && restrict(right));
                assert_eq!(
                    referential_actions_match(left, right),
                    expected,
                    "{left} against {right}"
                );
            }
        }
    }

    #[test]
    fn unknown_spellings_fail_closed() {
        for rule in [
            "",
            "restrict",
            "No Action",
            "NO_ACTION",
            " RESTRICT",
            "RESTRICT ",
            "NO  ACTION",
            "SET_NULL",
            "DROP",
        ] {
            assert!(!referential_actions_match(rule, rule), "{rule:?}");
            assert!(!referential_actions_match(rule, "RESTRICT"), "{rule:?}");
            assert!(!referential_actions_match("RESTRICT", rule), "{rule:?}");
        }
    }

    #[test]
    fn foreign_keys_match_by_exact_names_and_equivalent_rules() {
        let expected = vec![row("fk_child", "RESTRICT")];
        assert!(foreign_keys_match(
            &[row("fk_child", "NO ACTION")],
            &expected
        ));
        assert!(foreign_keys_match(
            &[row("fk_child", "RESTRICT")],
            &expected
        ));
        assert!(!foreign_keys_match(
            &[row("fk_child", "CASCADE")],
            &expected
        ));
        assert!(!foreign_keys_match(
            &[row("fk_other", "RESTRICT")],
            &expected
        ));
        assert!(!foreign_keys_match(&[], &expected));
        assert!(!foreign_keys_match(
            &[row("fk_child", "RESTRICT"), row("fk_child", "RESTRICT")],
            &expected
        ));
        assert!(foreign_keys_match(&[], &[]));
    }

    #[test]
    fn foreign_keys_never_accept_an_unknown_rule_even_when_identical() {
        let unknown = vec![row("fk_child", "SET_NULL")];
        assert!(!foreign_keys_match(&unknown, &unknown));
    }
}
