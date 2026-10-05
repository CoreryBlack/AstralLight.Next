//! Startup-frozen application registration; SDK requests cannot self-register.

use std::collections::BTreeSet;
use std::sync::Arc;

use astral_sdk_contracts::{ApplicationManifest, ExternalSubject};
use astral_types::ResourceRegistry;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;

const MAX_CONFIG_BYTES: usize = 256 * 1024;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TenantBinding {
    pub external_tenant_id: String,
    pub external_domain_id: String,
    pub tenant_id: i64,
    pub domain_id: i64,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ApplicationRegistration {
    pub app_id: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub issuer: String,
    pub manifest: ApplicationManifest,
    pub tenant_bindings: Vec<TenantBinding>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Registrations {
    applications: Vec<ApplicationRegistration>,
}

pub(crate) struct IntegrationConfig {
    pub applications: Vec<ApplicationRegistration>,
    pub decision_key_id: String,
    pub decision_key: SigningKey,
}

fn enabled(value: Option<&str>) -> Result<bool, &'static str> {
    match value {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err("invalid SDK integration enablement"),
    }
}

impl IntegrationConfig {
    pub fn from_env() -> Result<Option<Arc<Self>>, &'static str> {
        let flag = std::env::var("ASTRAL_SDK_INTEGRATION_ENABLED");
        let enabled = match flag {
            Ok(value) => enabled(Some(&value))?,
            Err(std::env::VarError::NotPresent) => enabled(None)?,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err("invalid SDK integration enablement")
            }
        };
        if !enabled {
            return Ok(None);
        }
        let registrations = std::env::var("ASTRAL_SDK_APPLICATIONS_JSON")
            .map_err(|_| "SDK application registration missing")?;
        let decision_key_id = std::env::var("ASTRAL_SDK_DECISION_KEY_ID")
            .map_err(|_| "SDK decision key ID missing")?;
        let seed = std::env::var("ASTRAL_SDK_DECISION_SEED_HEX")
            .map_err(|_| "SDK decision key missing")?;
        Self::parse(&registrations, decision_key_id, &seed).map(|config| Some(Arc::new(config)))
    }

    fn parse(json: &str, decision_key_id: String, seed: &str) -> Result<Self, &'static str> {
        if json.len() > MAX_CONFIG_BYTES
            || decision_key_id.len() > 64
            || astral_sdk_contracts::identifier(&decision_key_id).is_err()
        {
            return Err("SDK registration bounds invalid");
        }
        let registrations: Registrations =
            serde_json::from_str(json).map_err(|_| "SDK registration JSON invalid")?;
        if registrations.applications.is_empty() || registrations.applications.len() > 64 {
            return Err("SDK application bounds invalid");
        }
        let seed: [u8; 32] = hex::decode(seed)
            .map_err(|_| "SDK decision key invalid")?
            .try_into()
            .map_err(|_| "SDK decision key invalid")?;
        let mut apps = BTreeSet::new();
        let mut resource_owners = std::collections::BTreeMap::new();
        for app in &registrations.applications {
            if astral_sdk_contracts::identifier(&app.app_id).is_err()
                || app.app_id.len() > 64
                || astral_sdk_contracts::identifier(&app.key_id).is_err()
                || app.key_id.len() > 64
                || app.app_id != app.manifest.app_id
                || !apps.insert(&app.app_id)
                || app.tenant_bindings.is_empty()
                || app.tenant_bindings.len() > 256
            {
                return Err("SDK application registration invalid");
            }
            ExternalSubject {
                issuer: app.issuer.clone(),
                subject: "registration".into(),
            }
            .validate()
            .map_err(|_| "SDK issuer invalid")?;
            app.manifest
                .validate()
                .map_err(|_| "SDK manifest invalid")?;
            app.verifying_key()?;
            let mut scopes = BTreeSet::new();
            for binding in &app.tenant_bindings {
                if binding.tenant_id <= 0
                    || binding.domain_id <= 0
                    || astral_sdk_contracts::opaque_identifier(&binding.external_tenant_id).is_err()
                    || astral_sdk_contracts::opaque_identifier(&binding.external_domain_id).is_err()
                    || !scopes.insert((&binding.external_tenant_id, &binding.external_domain_id))
                {
                    return Err("SDK tenant binding invalid");
                }
            }
            for route in &app.manifest.routes {
                let registry = ResourceRegistry::global();
                if registry.is_builtin_resource(&route.resource_type)
                    && !route.resource_type.starts_with("chat_")
                    && !route.resource_type.starts_with("learn_")
                {
                    return Err("SDK may own business resources only");
                }
                if let Some(owner) = resource_owners.insert(&route.resource_type, &app.app_id) {
                    if owner != &app.app_id {
                        return Err("SDK resource has multiple application owners");
                    }
                }
                registry
                    .validate(&route.resource_type, &route.action)
                    .map_err(|_| "SDK resource/action not registered")?;
            }
        }
        Ok(Self {
            applications: registrations.applications,
            decision_key_id,
            decision_key: SigningKey::from_bytes(&seed),
        })
    }

    #[cfg(test)]
    pub(crate) fn test_config() -> Arc<Self> {
        tests::test_config()
    }

    pub fn application(&self, app_id: &str) -> Option<&ApplicationRegistration> {
        self.applications.iter().find(|app| app.app_id == app_id)
    }
}

impl ApplicationRegistration {
    pub fn verifying_key(&self) -> Result<VerifyingKey, &'static str> {
        let bytes: [u8; 32] = hex::decode(&self.public_key_hex)
            .map_err(|_| "SDK application key invalid")?
            .try_into()
            .map_err(|_| "SDK application key invalid")?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| "SDK application key invalid")
    }

    pub fn tenant_binding(&self, tenant: &str, domain: &str) -> Option<&TenantBinding> {
        self.tenant_bindings.iter().find(|binding| {
            binding.external_tenant_id == tenant && binding.external_domain_id == domain
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn application(app_id: &str, resource: &str) -> Value {
        json!({
            "appId": app_id, "keyId": "test-app", "issuer": "learn-local",
            "publicKeyHex": hex::encode(SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes()),
            "manifest": {
                "app_id": app_id, "revision": "1", "routes": [{
                    "method": "POST", "path": "/courses/{id}/publish", "resource_type": resource,
                    "action": "update", "operation": "object",
                    "resolver": {"kind": "object", "target_id_path": "/{id}"},
                }],
            },
            "tenantBindings": [{"externalTenantId": "school-a", "externalDomainId": "courses",
                "tenantId": 3, "domainId": 4}],
        })
    }

    pub(super) fn test_config() -> Arc<IntegrationConfig> {
        Arc::new(
            IntegrationConfig::parse(
                &json!({"applications": [application("astral-learn", "learn_course")]}).to_string(),
                "test-decision".into(),
                &hex::encode([32; 32]),
            )
            .unwrap(),
        )
    }

    #[test]
    fn enablement_is_strict_and_default_off() {
        assert_eq!(enabled(None), Ok(false));
        assert_eq!(enabled(Some("false")), Ok(false));
        assert_eq!(enabled(Some("true")), Ok(true));
        for invalid in ["", "1", "TRUE", " true", "true "] {
            assert!(enabled(Some(invalid)).is_err());
        }
    }

    #[test]
    fn explicit_app_and_scope_are_byte_exact() {
        let config = test_config();
        let app = config.application("astral-learn").unwrap();
        assert!(config.application("ASTRAL-LEARN").is_none());
        assert!(app.tenant_binding("school-a", "courses").is_some());
        assert!(app.tenant_binding("School-a", "courses").is_none());
    }

    #[test]
    fn platform_resources_and_duplicate_business_owners_are_refused() {
        for apps in [
            vec![application("third-party", "authorization")],
            vec![
                application("first", "learn_course"),
                application("second", "learn_course"),
            ],
        ] {
            assert!(IntegrationConfig::parse(
                &json!({"applications": apps}).to_string(),
                "test-decision".into(),
                &hex::encode([32; 32])
            )
            .is_err());
        }
    }

    #[test]
    fn duplicate_scope_or_unregistered_action_refuses_startup() {
        let mut app = application("astral-learn", "learn_course");
        let duplicate = app["tenantBindings"][0].clone();
        app["tenantBindings"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(IntegrationConfig::parse(
            &json!({"applications": [app]}).to_string(),
            "test-decision".into(),
            &hex::encode([32; 32])
        )
        .is_err());
        let mut app = application("astral-learn", "learn_course");
        app["manifest"]["routes"][0]["action"] = json!("super-allow");
        assert!(IntegrationConfig::parse(
            &json!({"applications": [app]}).to_string(),
            "test-decision".into(),
            &hex::encode([32; 32])
        )
        .is_err());
    }
}
