//! Shared certified separation-of-duties policy types.

/// SoD policy materialized into the same certified read snapshot as card facts.
///
/// This is a read-only policy row. Mutation-time SoD validation remains owned by
/// the durable transaction path in `sod_check`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertifiedSodPolicy {
    pub policy_name: String,
    pub conflict_type: CertifiedSodConflictType,
    pub permission_a: Option<String>,
    pub permission_b: Option<String>,
    pub condition_script: Option<String>,
    pub resource_type: Option<String>,
    pub action_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CertifiedSodConflictType {
    Static,
    Dynamic,
}

impl CertifiedSodPolicy {
    /// Validate the structural bounds and conflict-specific required fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.policy_name.trim().is_empty() || self.policy_name.len() > 256 {
            return Err("certified SoD policy name is invalid".to_owned());
        }
        for value in [
            self.permission_a.as_deref(),
            self.permission_b.as_deref(),
            self.condition_script.as_deref(),
            self.resource_type.as_deref(),
            self.action_code.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.len() > 512 || value.contains('\0') {
                return Err("certified SoD policy field exceeds its bound".to_owned());
            }
        }
        match self.conflict_type {
            CertifiedSodConflictType::Static => {
                if self.permission_a.as_deref().is_none_or(str::is_empty)
                    || self.permission_b.as_deref().is_none_or(str::is_empty)
                {
                    return Err("certified STATIC SoD policy lacks both permissions".to_owned());
                }
            }
            CertifiedSodConflictType::Dynamic => {
                if self.condition_script.as_deref().is_none_or(str::is_empty) {
                    return Err("certified DYNAMIC SoD policy lacks its condition".to_owned());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CertifiedSodConflictType, CertifiedSodPolicy};
    use serde_json::json;

    fn static_policy() -> CertifiedSodPolicy {
        CertifiedSodPolicy {
            policy_name: "segregate payments".to_owned(),
            conflict_type: CertifiedSodConflictType::Static,
            permission_a: Some("payment:create".to_owned()),
            permission_b: Some("payment:approve".to_owned()),
            condition_script: None,
            resource_type: None,
            action_code: None,
        }
    }

    #[test]
    fn serde_preserves_field_names_enum_values_and_nulls() {
        let static_value = json!({
            "policy_name": "segregate payments",
            "conflict_type": "Static",
            "permission_a": "payment:create",
            "permission_b": "payment:approve",
            "condition_script": null,
            "resource_type": null,
            "action_code": null
        });
        let policy = static_policy();
        assert_eq!(serde_json::to_value(&policy).unwrap(), static_value);
        assert_eq!(
            serde_json::from_value::<CertifiedSodPolicy>(static_value).unwrap(),
            policy
        );

        let dynamic_value = json!({
            "policy_name": "owner check",
            "conflict_type": "Dynamic",
            "permission_a": null,
            "permission_b": null,
            "condition_script": "owner",
            "resource_type": "payment",
            "action_code": "approve"
        });
        let dynamic: CertifiedSodPolicy = serde_json::from_value(dynamic_value.clone()).unwrap();
        assert_eq!(dynamic.validate(), Ok(()));
        assert_eq!(serde_json::to_value(dynamic).unwrap(), dynamic_value);
        assert!(serde_json::from_value::<CertifiedSodConflictType>(json!("STATIC")).is_err());
    }

    #[test]
    fn validation_checks_name_and_optional_field_byte_bounds() {
        let mut policy = static_policy();
        policy.policy_name = " ".to_owned();
        assert_eq!(
            policy.validate().unwrap_err(),
            "certified SoD policy name is invalid"
        );
        policy.policy_name = "é".repeat(128);
        assert_eq!(policy.validate(), Ok(()));
        policy.policy_name.push('a');
        assert_eq!(
            policy.validate().unwrap_err(),
            "certified SoD policy name is invalid"
        );

        policy.policy_name = "name".to_owned();
        policy.resource_type = Some("é".repeat(256));
        assert_eq!(policy.validate(), Ok(()));
        policy.resource_type.as_mut().unwrap().push('a');
        assert_eq!(
            policy.validate().unwrap_err(),
            "certified SoD policy field exceeds its bound"
        );
        policy.resource_type = Some("bad\0value".to_owned());
        assert_eq!(
            policy.validate().unwrap_err(),
            "certified SoD policy field exceeds its bound"
        );
    }

    #[test]
    fn validation_enforces_type_specific_fields_without_trimming_them() {
        let mut policy = static_policy();
        policy.permission_a = None;
        assert_eq!(
            policy.validate().unwrap_err(),
            "certified STATIC SoD policy lacks both permissions"
        );
        policy.permission_a = Some(" ".to_owned());
        policy.permission_b = Some(String::new());
        assert_eq!(
            policy.validate().unwrap_err(),
            "certified STATIC SoD policy lacks both permissions"
        );
        policy.permission_b = Some(" ".to_owned());
        assert_eq!(policy.validate(), Ok(()));

        policy.conflict_type = CertifiedSodConflictType::Dynamic;
        policy.permission_a = None;
        policy.permission_b = None;
        assert_eq!(
            policy.validate().unwrap_err(),
            "certified DYNAMIC SoD policy lacks its condition"
        );
        policy.condition_script = Some(String::new());
        assert_eq!(
            policy.validate().unwrap_err(),
            "certified DYNAMIC SoD policy lacks its condition"
        );
        policy.condition_script = Some(" ".to_owned());
        assert_eq!(policy.validate(), Ok(()));
    }
}
