//! 学科编排 — SubjectService
//!
//! 对齐 Java `SubjectServiceImpl` + `SubjectDeleteConsumer` 编排边界：
//! - 删除学科：先发 MQ（成功才软删，避免僵尸数据）→ 软删；MQ 不可用降级为仅软删 + 告警
//! - MQ 消费：幂等检查（DISABLED 才继续）→ 级联删除 / 单条硬删
//!
//! 数据访问在 `repository::subject_repository`（级联 9 步单事务在此层之下）。

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

/// 学科删除副作用端口（MQ 发布；测试注入 no-op 记录器）
#[async_trait::async_trait]
pub trait SubjectDeleteSideEffects: Send + Sync {
    /// 发布学科删除消息。
    /// Ok(true) = 已发布；Ok(false) = producer 不可用（降级为仅软删）；
    /// Err = MQ 可用但发布失败（中断软删，避免僵尸数据，对齐原 handler 语义）。
    async fn publish_subject_delete(
        &self,
        payload: astral_mq::producer::SubjectDeletePayload,
    ) -> Result<bool, AstralError>;
}

/// 生产实现：RabbitMQ Producer（None = 连接失败降级）
pub struct MqSubjectDeleteSideEffects {
    producer: Option<astral_mq::producer::Producer>,
}

impl MqSubjectDeleteSideEffects {
    pub fn new(producer: Option<astral_mq::producer::Producer>) -> Self {
        Self { producer }
    }
}

#[async_trait::async_trait]
impl SubjectDeleteSideEffects for MqSubjectDeleteSideEffects {
    async fn publish_subject_delete(
        &self,
        payload: astral_mq::producer::SubjectDeletePayload,
    ) -> Result<bool, AstralError> {
        match &self.producer {
            Some(producer) => producer
                .publish_subject_delete(payload)
                .await
                .map(|_| true)
                .map_err(|e| AstralError::Database(format!("MQ publish failed: {e}"))),
            None => Ok(false),
        }
    }
}

/// SubjectService（依赖注入 repository + MQ 副作用）
pub struct SubjectService {
    repo: Arc<dyn SubjectRepository>,
    side_effects: Arc<dyn SubjectDeleteSideEffects>,
}

impl SubjectService {
    pub fn new(
        repo: Arc<dyn SubjectRepository>,
        side_effects: Arc<dyn SubjectDeleteSideEffects>,
    ) -> Self {
        Self { repo, side_effects }
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

    /// 删除学科（对齐原 handler 语义）：
    /// - MQ 可用且发布成功 → 软删
    /// - MQ 可用但发布失败 → 中断软删并返回错误（避免僵尸数据）
    /// - MQ 不可用 → 仅软删 + 告警（后续需人工补发或补偿任务处理）
    pub async fn delete_subject(
        &self,
        subject_id: i64,
        operator_id: i64,
    ) -> Result<(), AstralError> {
        match self
            .side_effects
            .publish_subject_delete(astral_mq::producer::SubjectDeletePayload {
                subject_id,
                subject_ids: None,
                operator_id,
                cascade_delete: true,
                domain_id: None,
                tenant_id: None,
                subject_name: None,
            })
            .await
        {
            // Ok(true) = 已发布：软删
            Ok(true) => {
                self.repo.soft_delete(subject_id).await?;
                tracing::info!(subject_id, "subject soft deleted");
                Ok(())
            }
            // Ok(false) = producer 不可用：仅软删 + 告警（后续需人工补发或补偿任务处理）
            Ok(false) => {
                tracing::warn!(
                    subject_id,
                    "MQ producer unavailable, soft delete without cascade trigger"
                );
                self.repo.soft_delete(subject_id).await?;
                tracing::info!(subject_id, "subject soft deleted");
                Ok(())
            }
            // Err = MQ 发布失败：中断软删，返回错误
            Err(e) => {
                tracing::error!(subject_id, error = %e, "failed to publish subject delete, aborting soft delete");
                Err(e)
            }
        }
    }

    /// MQ Consumer 入口：幂等检查（不存在/非 DISABLED → 跳过）→ 级联或单删
    pub async fn process_delete_message(
        &self,
        subject_id: i64,
        cascade: bool,
    ) -> Result<SubjectDeleteOutcome, AstralError> {
        let status = self.repo.get_status(subject_id).await?;
        match status.as_deref() {
            None => {
                tracing::info!(subject_id, "subject already deleted, skipping");
                return Ok(SubjectDeleteOutcome::Skipped);
            }
            Some("DISABLED") => {}
            Some(s) => {
                tracing::warn!(
                    subject_id,
                    status = s,
                    "subject not in DISABLED state, skipping cascade"
                );
                return Ok(SubjectDeleteOutcome::Skipped);
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

    /// Fake MQ 副作用（发布结果可配置）
    /// Fake MQ 副作用（发布结果可配置；AstralError 非 Clone，用标志位区分）
    struct FakeSideEffects {
        publish_fail: bool,
        publish_ok: bool,
        publish_count: Mutex<i64>,
    }

    impl FakeSideEffects {
        fn new(ok: bool, fail: bool) -> Self {
            Self {
                publish_fail: fail,
                publish_ok: ok,
                publish_count: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl SubjectDeleteSideEffects for FakeSideEffects {
        async fn publish_subject_delete(
            &self,
            _payload: astral_mq::producer::SubjectDeletePayload,
        ) -> Result<bool, AstralError> {
            *self.publish_count.lock().unwrap() += 1;
            if self.publish_fail {
                Err(AstralError::Database("mq down".into()))
            } else {
                Ok(self.publish_ok)
            }
        }
    }

    #[tokio::test]
    async fn delete_subject_publishes_then_soft_deletes() {
        // MQ 可用：先发布 → 软删
        let repo = Arc::new(FakeSubjectRepository::new(None));
        let se = Arc::new(FakeSideEffects::new(true, false));
        let svc = SubjectService::new(repo.clone(), se.clone());

        svc.delete_subject(5, 1).await.unwrap();
        assert_eq!(*se.publish_count.lock().unwrap(), 1);
        assert_eq!(repo.soft_deletes.lock().unwrap().clone(), vec![5]);
    }

    #[tokio::test]
    async fn delete_subject_degrades_when_mq_unavailable() {
        // MQ 不可用（Ok(false)）：仅软删 + 告警，不报错
        let repo = Arc::new(FakeSubjectRepository::new(None));
        let svc = SubjectService::new(repo.clone(), Arc::new(FakeSideEffects::new(false, false)));
        svc.delete_subject(5, 1).await.unwrap();
        assert_eq!(repo.soft_deletes.lock().unwrap().clone(), vec![5]);
    }

    #[tokio::test]
    async fn delete_subject_aborts_when_publish_fails() {
        // MQ 可用但发布失败：中断软删并返回错误（避免僵尸数据）
        let repo = Arc::new(FakeSubjectRepository::new(None));
        let svc = SubjectService::new(repo.clone(), Arc::new(FakeSideEffects::new(true, true)));
        let result = svc.delete_subject(5, 1).await.unwrap_err();
        assert!(matches!(result, AstralError::Database(_)));
        assert!(repo.soft_deletes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_delete_message_idempotent_skips_when_missing() {
        // 学科不存在 → Skipped（幂等）
        let repo = Arc::new(FakeSubjectRepository::new(None));
        let svc = SubjectService::new(repo.clone(), Arc::new(FakeSideEffects::new(true, false)));
        let outcome = svc.process_delete_message(5, true).await.unwrap();
        assert_eq!(outcome, SubjectDeleteOutcome::Skipped);
        assert!(repo.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_delete_message_skips_when_not_disabled() {
        // 非 DISABLED 状态 → Skipped
        let repo = Arc::new(FakeSubjectRepository::new(Some("ACTIVE".into())));
        let svc = SubjectService::new(repo.clone(), Arc::new(FakeSideEffects::new(true, false)));
        let outcome = svc.process_delete_message(5, true).await.unwrap();
        assert_eq!(outcome, SubjectDeleteOutcome::Skipped);
        assert!(repo.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_delete_message_cascade_when_disabled() {
        // DISABLED + cascade=true → 级联删除
        let repo = Arc::new(FakeSubjectRepository::new(Some("DISABLED".into())));
        let svc = SubjectService::new(repo.clone(), Arc::new(FakeSideEffects::new(true, false)));
        let outcome = svc.process_delete_message(5, true).await.unwrap();
        assert_eq!(outcome, SubjectDeleteOutcome::CascadeDeleted);
        assert_eq!(repo.calls.lock().unwrap().clone(), vec!["cascade"]);
    }

    #[tokio::test]
    async fn process_delete_message_hard_delete_when_not_cascade() {
        // DISABLED + cascade=false → 单条硬删
        let repo = Arc::new(FakeSubjectRepository::new(Some("DISABLED".into())));
        let svc = SubjectService::new(repo.clone(), Arc::new(FakeSideEffects::new(true, false)));
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
