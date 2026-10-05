use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::types::{invalid, validate_method, ContractError, ResourceOperation};
use crate::validation::{identifier, validate_path, validate_revision};
use crate::{MAX_MANIFEST_BYTES, MAX_MANIFEST_ROUTES};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceResolver {
    /// Bind a positive integer target ID from this named business path parameter.
    Object { target_id_path: String },
    /// Bind a positive scope-local ID from this named business path parameter.
    ScopedCollection { target_id_path: String },
}

impl ResourceResolver {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Object { target_id_path } => {
                let Some(parameter) = target_id_path
                    .strip_prefix("/{")
                    .and_then(|value| value.strip_suffix('}'))
                else {
                    return Err(invalid(
                        "manifest.resolver",
                        "object target resolver must name a route path parameter",
                    ));
                };
                if target_id_path.len() > 128
                    || parameter.is_empty()
                    || !parameter.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                    })
                {
                    return Err(invalid(
                        "manifest.resolver",
                        "invalid object target resolver",
                    ));
                }
                Ok(())
            }
            Self::ScopedCollection { target_id_path } => {
                let Some(parameter) = target_id_path
                    .strip_prefix("/{")
                    .and_then(|value| value.strip_suffix('}'))
                else {
                    return Err(invalid(
                        "manifest.resolver",
                        "collection resolver must name a scope path parameter",
                    ));
                };
                if target_id_path.len() > 128
                    || parameter.is_empty()
                    || !parameter.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                    })
                {
                    return Err(invalid(
                        "manifest.resolver",
                        "invalid collection target resolver",
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRoute {
    /// Uppercase HTTP method.
    pub method: String,
    /// Axum-style bounded route template, for example `/objects/{object_id}`.
    pub path: String,
    pub resource_type: String,
    pub action: String,
    pub operation: ResourceOperation,
    pub resolver: ResourceResolver,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationManifest {
    pub app_id: String,
    pub revision: String,
    pub routes: Vec<ManifestRoute>,
}

impl ApplicationManifest {
    pub fn validate(&self) -> Result<(), ContractError> {
        identifier(&self.app_id).map_err(|_| invalid("manifest.app_id", "invalid identifier"))?;
        if self.app_id.len() > 64 {
            return Err(invalid(
                "manifest.app_id",
                "exceeds application storage width",
            ));
        }
        validate_revision(&self.revision, "manifest.revision")?;
        if self.routes.is_empty() || self.routes.len() > MAX_MANIFEST_ROUTES {
            return Err(invalid(
                "manifest.routes",
                "must contain 1..=128 declared routes",
            ));
        }
        let mut seen_routes = BTreeSet::new();
        let mut unique_method_paths = BTreeSet::new();
        for route in &self.routes {
            validate_method(&route.method)?;
            validate_path(&route.path, false)?;
            identifier(&route.resource_type)
                .map_err(|_| invalid("manifest.resource_type", "invalid identifier"))?;
            if route.resource_type.len() > 64 || route.action.len() > 64 {
                return Err(invalid(
                    "manifest.route",
                    "resource/action exceeds registry width",
                ));
            }
            identifier(&route.action)
                .map_err(|_| invalid("manifest.action", "invalid identifier"))?;
            route.resolver.validate()?;
            if !seen_routes.insert((
                route.method.as_str(),
                route.path.as_str(),
                route.resource_type.as_str(),
                route.action.as_str(),
                route.operation,
            )) {
                return Err(invalid("manifest.routes", "duplicate route binding"));
            }
            // A single handler/template must not be declared with competing
            // resource/action/operation/resolver bindings; routing is ambiguous otherwise.
            if !unique_method_paths.insert((route.method.as_str(), route.path.as_str())) {
                return Err(invalid(
                    "manifest.routes",
                    "method and path must map unambiguously",
                ));
            }
            if matches!(route.operation, ResourceOperation::Object)
                != matches!(route.resolver, ResourceResolver::Object { .. })
            {
                return Err(invalid(
                    "manifest.resolver",
                    "resolver does not match resource operation",
                ));
            }
            let resolver = match &route.resolver {
                ResourceResolver::Object { target_id_path }
                | ResourceResolver::ScopedCollection { target_id_path } => target_id_path,
            };
            let parameter = resolver.trim_start_matches("/{").trim_end_matches('}');
            let segment = format!("{{{parameter}}}");
            if route
                .path
                .split('/')
                .filter(|path_segment| *path_segment == segment)
                .count()
                != 1
            {
                return Err(invalid(
                    "manifest.resolver",
                    "resolver path parameter must appear exactly once in route",
                ));
            }
        }
        for (index, route) in self.routes.iter().enumerate() {
            if self.routes[..index].iter().any(|other| {
                other.method == route.method && route_templates_overlap(&other.path, &route.path)
            }) {
                return Err(invalid(
                    "manifest.routes",
                    "overlapping route bindings are ambiguous",
                ));
            }
        }
        let bytes = serde_json::to_vec(&self.canonicalized()).map_err(serialize_error)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ContractError::PayloadTooLarge);
        }
        Ok(())
    }

    /// Stable lowercase SHA-256 digest; declaration order does not affect it.
    pub fn digest(&self) -> Result<String, ContractError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&self.canonicalized()).map_err(serialize_error)?;
        Ok(crate::signing::digest_hex(&bytes))
    }

    /// Validate and authorize a complete signed request against one exact route
    /// declaration, including resolver-to-target equality.
    pub fn permits_request(&self, request: &crate::AuthorizationRequest) -> bool {
        if request.validate().is_err()
            || !self.permits(
                &request.facts.resource_type,
                &request.action,
                &request.method,
                &request.path,
                request.facts.operation,
            )
        {
            return false;
        }
        let Some(route) = self.routes.iter().find(|route| {
            route.resource_type == request.facts.resource_type
                && route.action == request.action
                && route.method == request.method
                && route.operation == request.facts.operation
                && route_path_matches(
                    &route.path,
                    request
                        .path
                        .split_once('?')
                        .map_or(request.path.as_str(), |(path, _)| path),
                )
        }) else {
            return false;
        };
        let resolver = match &route.resolver {
            ResourceResolver::Object { target_id_path }
            | ResourceResolver::ScopedCollection { target_id_path } => target_id_path,
        };
        let parameter = resolver.trim_start_matches("/{").trim_end_matches('}');
        let template_segments: Vec<_> = route.path.split('/').collect();
        let request_path = request
            .path
            .split_once('?')
            .map_or(request.path.as_str(), |(path, _)| path);
        let path_segments: Vec<_> = request_path.split('/').collect();
        template_segments
            .iter()
            .zip(path_segments.iter())
            .find_map(|(template, actual)| {
                (*template == format!("{{{parameter}}}")).then_some(*actual)
            })
            == Some(request.facts.target_id.as_str())
    }

    /// Deny by default. Resource, action, method, template and operation must
    /// all match one unambiguous, explicit declaration.
    pub fn permits(
        &self,
        resource_type: &str,
        action: &str,
        method: &str,
        path: &str,
        operation: ResourceOperation,
    ) -> bool {
        if self.validate().is_err()
            || validate_method(method).is_err()
            || validate_path(path, true).is_err()
            || identifier(resource_type).is_err()
            || identifier(action).is_err()
        {
            return false;
        }
        let request_path = path.split_once('?').map_or(path, |(pathname, _)| pathname);
        self.routes.iter().any(|route| {
            route.resource_type == resource_type
                && route.action == action
                && route.method == method
                && route.operation == operation
                && route_path_matches(&route.path, request_path)
        })
    }

    fn canonicalized(&self) -> Self {
        let mut canonical = self.clone();
        canonical.routes.sort_by(|a, b| {
            (
                &a.method,
                &a.path,
                &a.resource_type,
                &a.action,
                a.operation,
                serde_json::to_string(&a.resolver).unwrap_or_default(),
            )
                .cmp(&(
                    &b.method,
                    &b.path,
                    &b.resource_type,
                    &b.action,
                    b.operation,
                    serde_json::to_string(&b.resolver).unwrap_or_default(),
                ))
        });
        canonical
    }
}

fn route_templates_overlap(left: &str, right: &str) -> bool {
    let left: Vec<_> = left.split('/').collect();
    let right: Vec<_> = right.split('/').collect();
    left.len() == right.len()
        && left
            .iter()
            .zip(&right)
            .all(|(left, right)| left == right || left.starts_with('{') || right.starts_with('{'))
}

fn route_path_matches(template: &str, path: &str) -> bool {
    let template_segments: Vec<_> = template.split('/').collect();
    let path_segments: Vec<_> = path.split('/').collect();
    template_segments.len() == path_segments.len()
        && template_segments
            .iter()
            .zip(path_segments.iter())
            .all(|(pattern, value)| {
                if pattern.starts_with('{') && pattern.ends_with('}') {
                    !value.is_empty()
                } else {
                    pattern == value
                }
            })
}

fn serialize_error(error: serde_json::Error) -> ContractError {
    ContractError::Serialization(error.to_string())
}
