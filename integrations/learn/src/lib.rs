//! Learn-owned optimistic fact checks. No business lock is held across authorization.

use std::collections::BTreeMap;

use astral_sdk_contracts::{
    ApplicationManifest, AuthorizationRequest, ExternalSubject, ManifestRoute, ResourceFacts,
    ResourceOperation, ResourceResolver, VerifiedAuthorizationDecision,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CourseScope {
    pub id: i64,
    pub tenant: String,
    pub domain: String,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Course {
    pub id: i64,
    pub scope_id: i64,
    pub owner: ExternalSubject,
    pub revision: u64,
    pub published: bool,
}

#[derive(Clone, Debug)]
pub struct PublishReceipt {
    pub operation_id: String,
    pub request_digest: String,
    pub facts_digest: String,
}

#[derive(Default)]
pub struct LearnStore {
    scopes: BTreeMap<i64, CourseScope>,
    courses: BTreeMap<i64, Course>,
    operations: BTreeMap<(String, String), ([u8; 32], PublishReceipt)>,
}

impl LearnStore {
    pub fn insert_scope(&mut self, scope: CourseScope) -> Result<(), &'static str> {
        if scope.id <= 0
            || scope.revision == 0
            || self.scopes.len() >= 256
            || self.scopes.contains_key(&scope.id)
        {
            return Err("INVALID_SCOPE");
        }
        self.scopes.insert(scope.id, scope);
        Ok(())
    }

    pub fn insert(&mut self, course: Course) -> Result<(), &'static str> {
        if course.id <= 0
            || course.revision == 0
            || course.owner.validate().is_err()
            || self.courses.len() >= 1024
            || self.courses.contains_key(&course.id)
        {
            return Err("INVALID_COURSE");
        }
        let scope = self
            .scopes
            .get_mut(&course.scope_id)
            .ok_or("INVALID_SCOPE")?;
        scope.revision = scope.revision.checked_add(1).ok_or("REVISION_EXHAUSTED")?;
        self.courses.insert(course.id, course);
        Ok(())
    }

    pub fn receipt(&self, subject: &str, operation_id: &str) -> Option<&PublishReceipt> {
        self.operations
            .get(&(subject.into(), operation_id.into()))
            .map(|(_, receipt)| receipt)
    }

    pub fn course(&self, id: i64) -> Option<&Course> {
        self.courses.get(&id)
    }

    pub fn facts(&self, id: i64) -> Result<ResourceFacts, &'static str> {
        let course = self.courses.get(&id).ok_or("NOT_FOUND")?;
        let scope = self.scopes.get(&course.scope_id).ok_or("INVALID_SCOPE")?;
        Ok(ResourceFacts {
            resource_type: "learn_course".into(),
            target_id: id.to_string(),
            external_tenant_id: scope.tenant.clone(),
            external_domain_id: scope.domain.clone(),
            owner: Some(course.owner.clone()),
            revision: format!("{}-{}-{}", course.scope_id, scope.revision, course.revision),
            operation: ResourceOperation::Object,
        })
    }

    pub fn collection_facts(&self, scope_id: i64) -> Result<ResourceFacts, &'static str> {
        let scope = self.scopes.get(&scope_id).ok_or("NOT_FOUND")?;
        Ok(ResourceFacts {
            resource_type: "learn_course".into(),
            target_id: scope.id.to_string(),
            external_tenant_id: scope.tenant.clone(),
            external_domain_id: scope.domain.clone(),
            owner: None,
            revision: scope.revision.to_string(),
            operation: ResourceOperation::ScopedCollection,
        })
    }

    pub fn publish(
        &mut self,
        request: &AuthorizationRequest,
        decision: VerifiedAuthorizationDecision,
    ) -> Result<(), &'static str> {
        decision
            .require_allow_current(request)
            .map_err(|_| "DENIED")?;
        if !manifest().permits(
            "learn_course",
            "update",
            &request.method,
            &request.path,
            request.facts.operation,
        ) || request.app_id != "astral-learn"
            || request.action != "update"
            || request.facts.resource_type != "learn_course"
            || request.subject.issuer != "learn-local"
            || request.path != format!("/courses/{}/publish", request.facts.target_id)
        {
            return Err("DENIED");
        }
        let id = request
            .facts
            .target_id
            .parse::<i64>()
            .map_err(|_| "INVALID_TARGET")?;
        let payload = serde_json::to_vec(&(
            &request.app_id,
            &request.subject,
            id,
            &request.facts.external_tenant_id,
            &request.facts.external_domain_id,
            "publish",
        ))
        .map_err(|_| "INVALID_REQUEST")?;
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let operation = (
            request.subject.subject.clone(),
            request.operation_id.clone(),
        );
        if let Some(previous) = self.operations.get(&operation) {
            return if previous.0 == digest {
                Ok(())
            } else {
                Err("OPERATION_CONFLICT")
            };
        }
        if self.operations.len() >= 4096 {
            return Err("CAPACITY");
        }
        if self.facts(id)? != request.facts {
            return Err("FACTS_CHANGED");
        }
        let receipt = PublishReceipt {
            operation_id: request.operation_id.clone(),
            request_digest: request.digest().map_err(|_| "INVALID_REQUEST")?,
            facts_digest: request.facts_digest().map_err(|_| "INVALID_REQUEST")?,
        };
        let course = self.courses.get(&id).ok_or("NOT_FOUND")?;
        let scope = self.scopes.get(&course.scope_id).ok_or("INVALID_SCOPE")?;
        let next_course = course.revision.checked_add(1).ok_or("REVISION_EXHAUSTED")?;
        let next_scope = scope.revision.checked_add(1).ok_or("REVISION_EXHAUSTED")?;
        let scope_id = course.scope_id;
        let course = self.courses.get_mut(&id).ok_or("NOT_FOUND")?;
        course.revision = next_course;
        course.published = true;
        self.scopes
            .get_mut(&scope_id)
            .ok_or("INVALID_SCOPE")?
            .revision = next_scope;
        self.operations.insert(operation, (digest, receipt));
        Ok(())
    }

    pub fn move_course(&mut self, id: i64, new_scope: i64) -> Result<(), &'static str> {
        let course = self.courses.get(&id).ok_or("NOT_FOUND")?;
        let old_scope = course.scope_id;
        if old_scope == new_scope {
            return Ok(());
        }
        let next_course = course.revision.checked_add(1).ok_or("REVISION_EXHAUSTED")?;
        let next_old = self
            .scopes
            .get(&old_scope)
            .ok_or("INVALID_SCOPE")?
            .revision
            .checked_add(1)
            .ok_or("REVISION_EXHAUSTED")?;
        let next_new = self
            .scopes
            .get(&new_scope)
            .ok_or("INVALID_SCOPE")?
            .revision
            .checked_add(1)
            .ok_or("REVISION_EXHAUSTED")?;
        self.scopes
            .get_mut(&old_scope)
            .ok_or("INVALID_SCOPE")?
            .revision = next_old;
        self.scopes
            .get_mut(&new_scope)
            .ok_or("INVALID_SCOPE")?
            .revision = next_new;
        let course = self.courses.get_mut(&id).ok_or("NOT_FOUND")?;
        course.scope_id = new_scope;
        course.revision = next_course;
        Ok(())
    }

    pub fn list_scope(
        &self,
        request: &AuthorizationRequest,
        decision: VerifiedAuthorizationDecision,
    ) -> Result<Vec<Course>, &'static str> {
        decision
            .require_allow_current(request)
            .map_err(|_| "DENIED")?;
        let id = request
            .facts
            .target_id
            .parse::<i64>()
            .map_err(|_| "INVALID_TARGET")?;
        if request.app_id != "astral-learn"
            || request.subject.issuer != "learn-local"
            || request.action != "read"
            || request.method != "GET"
            || request.path != format!("/course-scopes/{id}/courses")
            || request.facts.operation != ResourceOperation::ScopedCollection
            || self.collection_facts(id)? != request.facts
        {
            return Err("FACTS_CHANGED");
        }
        Ok(self
            .courses
            .values()
            .filter(|course| course.scope_id == id)
            .cloned()
            .collect())
    }
}

pub fn manifest() -> ApplicationManifest {
    ApplicationManifest {
        app_id: "astral-learn".into(),
        revision: "1".into(),
        routes: vec![
            ManifestRoute {
                method: "POST".into(),
                path: "/courses/{id}/publish".into(),
                resource_type: "learn_course".into(),
                action: "update".into(),
                operation: ResourceOperation::Object,
                resolver: ResourceResolver::Object {
                    target_id_path: "/{id}".into(),
                },
            },
            ManifestRoute {
                method: "GET".into(),
                path: "/course-scopes/{id}/courses".into(),
                resource_type: "learn_course".into(),
                action: "read".into(),
                operation: ResourceOperation::ScopedCollection,
                resolver: ResourceResolver::ScopedCollection {
                    target_id_path: "/{id}".into(),
                },
            },
        ],
    }
}

pub fn actor(subject: &str) -> ExternalSubject {
    ExternalSubject {
        issuer: "learn-local".into(),
        subject: subject.into(),
    }
}
