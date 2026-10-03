//! 学科编排 — SubjectService
//!
//! Subject deletion is a transactional durable intent followed by idempotent
//! cascade work. The intent and soft-delete state commit together; no broker
//! publish is treated as durable completion.
//!
//! Data access lives in `repository::subject_repository`.

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::subject_repository::{SubjectRecord, SubjectRepository};

/// 学科树节点（get_subject_tree 用）
#[derive(Debug, Clone, serde::Serialize)]
pub struct SubjectTreeNode {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub children: Vec<SubjectTreeNode>,
}

/// 学科删除结果（MQ Consumer 用）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectDeleteOutcome {
    /// 学科不存在或非 DISABLED，跳过（幂等）
    Skipped,
    /// 级联删除完成
    CascadeDeleted,
    /// 单条硬删完成
    HardDeleted,
}

/// SubjectService keeps cascade intent creation in the repository transaction;
/// delivery is owned by the Learn outbox worker, never by a pre-commit publisher.
pub struct SubjectService {
    repo: Arc<dyn SubjectRepository>,
    origin_region: String,
}

impl SubjectService {
    pub fn new(repo: Arc<dyn SubjectRepository>) -> Self {
        Self::with_origin_region(repo, "local")
    }

    pub fn with_origin_region(
        repo: Arc<dyn SubjectRepository>,
        origin_region: impl Into<String>,
    ) -> Self {
        Self {
            repo,
            origin_region: origin_region.into(),
        }
    }

    /// 全量活跃学科（前端下拉）
    pub async fn list_active(&self) -> Result<Vec<SubjectRecord>, AstralError> {
        self.repo.list_active().await
    }

    /// 学科树（递归构建）
    pub async fn get_subject_tree(&self) -> Result<Vec<SubjectTreeNode>, AstralError> {
        let subjects = self.repo.list_active().await?;
        Ok(build_tree(&subjects, None))
    }

    /// Persist a durable cascade intent atomically with the soft-delete source
    /// state. RabbitMQ availability is not part of the source commit contract.
    pub async fn delete_subject(
        &self,
        subject_id: i64,
        operator_id: i64,
    ) -> Result<(), AstralError> {
        self.repo
            .request_cascade_delete(subject_id, operator_id, &self.origin_region)
            .await
    }

    /// MQ Consumer 入口：幂等检查（不存在/非 DISABLED → 跳过）→ 级联或单删
    pub async fn process_delete_message(
        &self,
        subject_id: i64,
        cascade: bool,
    ) -> Result<SubjectDeleteOutcome, AstralError> {
        let status = self.repo.get_status(subject_id).await?;
        match status.as_deref() {
            None if cascade => {
                // A previous source transaction or external delete may already
                // have removed the subject row. Still execute the idempotent
                // Learn-owned dependent cleanup before the outbox can complete.
                self.repo.cascade_delete_subject(subject_id).await?;
                return Ok(SubjectDeleteOutcome::CascadeDeleted);
            }
            None => {
                tracing::info!(subject_id, "subject already deleted, skipping");
                return Ok(SubjectDeleteOutcome::Skipped);
            }
            Some("DISABLED") => {}
            Some(s) => {
                return Err(AstralError::Database(format!(
                    "Subject {subject_id} is {s}, cascade intent is not complete"
                )));
            }
        }

        if cascade {
            self.repo.cascade_delete_subject(subject_id).await?;
            Ok(SubjectDeleteOutcome::CascadeDeleted)
        } else {
            self.repo.hard_delete(subject_id).await?;
            Ok(SubjectDeleteOutcome::HardDeleted)
        }
    }
}

/// 递归构建学科树（对齐 handler 原 build_tree）
fn build_tree(subjects: &[SubjectRecord], parent_id: Option<i64>) -> Vec<SubjectTreeNode> {
    subjects
        .iter()
        .filter(|s| s.parent_id == parent_id)
        .map(|s| SubjectTreeNode {
            id: s.id,
            name: s.name.clone(),
            code: s.code.clone(),
            children: build_tree(subjects, Some(s.id)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::subject_repository::SubjectInput;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Fake SubjectRepository（记录调用顺序，断言级联删除步骤）
    struct FakeSubjectRepository {
        calls: Mutex<Vec<String>>,
        status: Mutex<Option<String>>,
        soft_deletes: Mutex<Vec<i64>>,
    }

    impl FakeSubjectRepository {
        fn new(status: Option<String>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                status: Mutex::new(status),
                soft_deletes: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl SubjectRepository for FakeSubjectRepository {
        async fn count_all(&self) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_all(
            &self,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<SubjectRecord>, AstralError> {
            Ok(vec![])
        }

        async fn list_active(&self) -> Result<Vec<SubjectRecord>, AstralError> {
            Ok(vec![])
        }

        async fn get(&self, _id: i64) -> Result<Option<SubjectRecord>, AstralError> {
            Ok(None)
        }

        async fn create(&self, _input: &SubjectInput) -> Result<i64, AstralError> {
            Ok(1)
        }

        async fn update(&self, _id: i64, _input: &SubjectInput) -> Result<(), AstralError> {
            Ok(())
        }

        async fn request_cascade_delete(
            &self,
            subject_id: i64,
            _operator_id: i64,
            _origin_region: &str,
        ) -> Result<(), AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("intent:{subject_id}"));
            Ok(())
        }

        async fn soft_delete(&self, id: i64) -> Result<(), AstralError> {
            self.calls.lock().unwrap().push("soft_delete".into());
            self.soft_deletes.lock().unwrap().push(id);
            Ok(())
        }

        async fn get_status(&self, _id: i64) -> Result<Option<String>, AstralError> {
            Ok(self.status.lock().unwrap().clone())
        }

        async fn hard_delete(&self, _id: i64) -> Result<(), AstralError> {
            self.calls.lock().unwrap().push("hard_delete".into());
            Ok(())
        }

        async fn cascade_delete_subject(&self, _subject_id: i64) -> Result<(), AstralError> {
            self.calls.lock().unwrap().push("cascade".into());
            Ok(())
        }
    }

    #[tokio::test]
    async fn delete_subject_records_transactional_outbox_intent() {
        let repo = Arc::new(FakeSubjectRepository::new(None));
        let svc = SubjectService::with_origin_region(repo.clone(), "test-region");
        svc.delete_subject(5, 1).await.unwrap();
        assert_eq!(repo.calls.lock().unwrap().clone(), vec!["intent:5"]);
        assert!(repo.soft_deletes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_delete_message_cascades_even_when_subject_is_missing() {
        // Missing parent does not prove dependent cleanup completed.
        let repo = Arc::new(FakeSubjectRepository::new(None));
        let svc = SubjectService::new(repo.clone());
        let outcome = svc.process_delete_message(5, true).await.unwrap();
        assert_eq!(outcome, SubjectDeleteOutcome::CascadeDeleted);
        assert_eq!(repo.calls.lock().unwrap().clone(), vec!["cascade"]);
    }

    #[tokio::test]
    async fn process_delete_message_retries_when_source_state_not_disabled() {
        // An active row with a pending cascade intent is not complete and must not ACK.
        let repo = Arc::new(FakeSubjectRepository::new(Some("ACTIVE".into())));
        let svc = SubjectService::new(repo.clone());
        let result = svc.process_delete_message(5, true).await;
        assert!(matches!(result, Err(AstralError::Database(_))));
        assert!(repo.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_delete_message_cascade_when_disabled() {
        // DISABLED + cascade=true → 级联删除
        let repo = Arc::new(FakeSubjectRepository::new(Some("DISABLED".into())));
        let svc = SubjectService::new(repo.clone());
        let outcome = svc.process_delete_message(5, true).await.unwrap();
        assert_eq!(outcome, SubjectDeleteOutcome::CascadeDeleted);
        assert_eq!(repo.calls.lock().unwrap().clone(), vec!["cascade"]);
    }

    #[tokio::test]
    async fn process_delete_message_hard_delete_when_not_cascade() {
        // DISABLED + cascade=false → 单条硬删
        let repo = Arc::new(FakeSubjectRepository::new(Some("DISABLED".into())));
        let svc = SubjectService::new(repo.clone());
        let outcome = svc.process_delete_message(5, false).await.unwrap();
        assert_eq!(outcome, SubjectDeleteOutcome::HardDeleted);
        assert_eq!(repo.calls.lock().unwrap().clone(), vec!["hard_delete"]);
    }

    #[tokio::test]
    async fn build_tree_groups_children_by_parent() {
        // 纯函数：根节点 + 子节点嵌套
        let subjects = vec![
            SubjectRecord {
                id: 1,
                name: "root".into(),
                code: "R".into(),
                parent_id: None,
                description: None,
                sort_order: 0,
                status: "ACTIVE".into(),
            },
            SubjectRecord {
                id: 2,
                name: "child".into(),
                code: "C".into(),
                parent_id: Some(1),
                description: None,
                sort_order: 0,
                status: "ACTIVE".into(),
            },
        ];
        let tree = build_tree(&subjects, None);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].id, 1);
        assert_eq!(tree[0].children.len(), 1);
        assert_eq!(tree[0].children[0].id, 2);
    }
}
