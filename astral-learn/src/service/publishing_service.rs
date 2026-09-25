//! 课程发布工作流编排 — PublishingService
//!
//! 对齐 Java `CoursePublishingServiceImpl`：状态机守卫式流转
//! DRAFT→REVIEW→APPROVED→PUBLISHED/ARCHIVED。非法流转按原 handler 语义
//! 静默忽略（返回当前 DB 状态，不报错）。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::publishing_repository::{PublishingRepository, WorkflowRecord};
use crate::srv::publishing::{CourseStats, PublishWorkflow, StudentProgress};

/// PublishingService（依赖注入 repository）
pub struct PublishingService {
    repo: Arc<dyn PublishingRepository>,
}

impl PublishingService {
    pub fn new(repo: Arc<dyn PublishingRepository>) -> Self {
        Self { repo }
    }

    /// 发布课程（DRAFT 或 APPROVED → PUBLISHED；side effect: workflow.published_at）
    pub async fn publish_course(&self, course_id: i64) -> Result<PublishWorkflow, AstralError> {
        let hit = self.repo.publish_course(course_id).await?;
        if hit {
            self.repo.upsert_published_at(course_id).await?;
        }
        tracing::info!(course_id, "course published");
        self.build_workflow(course_id, "PUBLISHED").await
    }

    /// 归档课程（任意状态 → ARCHIVED，无守卫）
    pub async fn archive_course(&self, course_id: i64) -> Result<PublishWorkflow, AstralError> {
        self.repo.archive_course(course_id).await?;
        tracing::info!(course_id, "course archived");
        self.build_workflow(course_id, "ARCHIVED").await
    }

    /// 提交审核（DRAFT → REVIEW）
    pub async fn submit_for_review(&self, course_id: i64) -> Result<PublishWorkflow, AstralError> {
        let hit = self.repo.submit_for_review(course_id).await?;
        if hit {
            tracing::info!(course_id, "course submitted for review");
        }
        self.build_workflow(course_id, "REVIEW").await
    }

    /// 审批通过（REVIEW → APPROVED；side effect: workflow reviewer/comment）
    pub async fn approve_course(&self, course_id: i64) -> Result<PublishWorkflow, AstralError> {
        let hit = self.repo.approve_course(course_id).await?;
        if hit {
            self.repo.upsert_approval(course_id).await?;
        }
        tracing::info!(course_id, "course approved");
        self.build_workflow(course_id, "APPROVED").await
    }

    /// 课程统计
    pub async fn course_stats(&self, course_id: i64) -> Result<CourseStats, AstralError> {
        let s = self.repo.course_stats(course_id).await?;
        Ok(CourseStats {
            course_id,
            total_students: s.total_students,
            avg_progress: s.avg_progress,
            completion_rate: s.completion_rate,
            avg_score: s.avg_score,
        })
    }

    /// 学生进度（选课进度优先；否则按已作答章节占比推算）
    pub async fn student_progress(
        &self,
        course_id: i64,
        user_id: i64,
    ) -> Result<StudentProgress, AstralError> {
        let total_lessons = self.repo.count_lessons(course_id).await?;
        let answered_lessons = self.repo.count_answered_lessons(course_id, user_id).await?;
        let progress_pct = match self
            .repo
            .get_enrollment_progress(course_id, user_id)
            .await?
        {
            Some(p) => p,
            None => {
                if total_lessons > 0 {
                    (answered_lessons as f64 / total_lessons as f64) * 100.0
                } else {
                    0.0
                }
            }
        };
        Ok(StudentProgress {
            user_id,
            course_id,
            completed_lessons: answered_lessons,
            total_lessons,
            progress_pct,
            last_activity: time::OffsetDateTime::now_utc().to_string(),
        })
    }

    /// 组装工作流响应（无关联行 → 默认状态占位，对齐 build_workflow 语义）
    async fn build_workflow(
        &self,
        course_id: i64,
        default_status: &str,
    ) -> Result<PublishWorkflow, AstralError> {
        let row = self.repo.get_workflow(course_id).await?;
        let wf: WorkflowRecord = row.unwrap_or_else(|| WorkflowRecord {
            current_status: default_status.to_string(),
            reviewer_id: None,
            review_comment: None,
            published_at: None,
        });
        Ok(PublishWorkflow {
            course_id,
            current_status: wf.current_status,
            reviewer_id: wf.reviewer_id,
            review_comment: wf.review_comment,
            published_at: wf.published_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::publishing_repository::CourseStatsRecord;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Fake PublishingRepository（记录守卫式 UPDATE 命中与 workflow 副作用）
    struct FakePublishingRepository {
        calls: Mutex<Vec<String>>,
        publish_hit: bool,
        review_hit: bool,
        approve_hit: bool,
        workflow: Mutex<Option<WorkflowRecord>>,
    }

    impl FakePublishingRepository {
        fn new(
            publish_hit: bool,
            review_hit: bool,
            approve_hit: bool,
            workflow: Option<WorkflowRecord>,
        ) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                publish_hit,
                review_hit,
                approve_hit,
                workflow: Mutex::new(workflow),
            }
        }
    }

    #[async_trait]
    impl PublishingRepository for FakePublishingRepository {
        async fn publish_course(&self, course_id: i64) -> Result<bool, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("publish:{course_id}"));
            Ok(self.publish_hit)
        }

        async fn archive_course(&self, course_id: i64) -> Result<bool, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("archive:{course_id}"));
            Ok(true)
        }

        async fn submit_for_review(&self, course_id: i64) -> Result<bool, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("review:{course_id}"));
            Ok(self.review_hit)
        }

        async fn approve_course(&self, course_id: i64) -> Result<bool, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("approve:{course_id}"));
            Ok(self.approve_hit)
        }

        async fn upsert_published_at(&self, course_id: i64) -> Result<(), AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("upsert_published:{course_id}"));
            Ok(())
        }

        async fn upsert_approval(&self, course_id: i64) -> Result<(), AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("upsert_approval:{course_id}"));
            Ok(())
        }

        async fn get_workflow(
            &self,
            course_id: i64,
        ) -> Result<Option<WorkflowRecord>, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("get_workflow:{course_id}"));
            Ok(self.workflow.lock().unwrap().clone())
        }

        async fn course_stats(&self, _course_id: i64) -> Result<CourseStatsRecord, AstralError> {
            Ok(CourseStatsRecord {
                total_students: 0,
                avg_progress: 0.0,
                completion_rate: 0.0,
                avg_score: 0.0,
            })
        }

        async fn count_lessons(&self, _course_id: i64) -> Result<i32, AstralError> {
            Ok(0)
        }

        async fn count_answered_lessons(
            &self,
            _course_id: i64,
            _user_id: i64,
        ) -> Result<i32, AstralError> {
            Ok(0)
        }

        async fn get_enrollment_progress(
            &self,
            _course_id: i64,
            _user_id: i64,
        ) -> Result<Option<f64>, AstralError> {
            Ok(None)
        }
    }

    fn workflow(status: &str) -> WorkflowRecord {
        WorkflowRecord {
            current_status: status.to_string(),
            reviewer_id: None,
            review_comment: None,
            published_at: None,
        }
    }

    #[tokio::test]
    async fn publish_hits_upsert_published_at() {
        // DRAFT/APPROVED → PUBLISHED 命中时写 workflow.published_at
        let repo = Arc::new(FakePublishingRepository::new(
            true,
            false,
            false,
            Some(workflow("PUBLISHED")),
        ));
        let svc = PublishingService::new(repo.clone());
        let wf = svc.publish_course(10).await.unwrap();
        assert_eq!(wf.current_status, "PUBLISHED");
        assert_eq!(
            repo.calls.lock().unwrap().clone(),
            vec!["publish:10", "upsert_published:10", "get_workflow:10"]
        );
    }

    #[tokio::test]
    async fn publish_miss_skips_workflow_upsert() {
        // 非法流转（如 REVIEW 直接 publish）未命中：不写 workflow，静默返回当前状态
        let repo = Arc::new(FakePublishingRepository::new(
            false,
            false,
            false,
            Some(workflow("REVIEW")),
        ));
        let svc = PublishingService::new(repo.clone());
        let wf = svc.publish_course(10).await.unwrap();
        assert_eq!(wf.current_status, "REVIEW");
        assert_eq!(
            repo.calls.lock().unwrap().clone(),
            vec!["publish:10", "get_workflow:10"]
        );
    }

    #[tokio::test]
    async fn approve_hits_upsert_approval() {
        // REVIEW → APPROVED 命中时写 reviewer/comment
        let repo = Arc::new(FakePublishingRepository::new(
            false,
            false,
            true,
            Some(workflow("APPROVED")),
        ));
        let svc = PublishingService::new(repo.clone());
        let wf = svc.approve_course(10).await.unwrap();
        assert_eq!(wf.current_status, "APPROVED");
        assert_eq!(
            repo.calls.lock().unwrap().clone(),
            vec!["approve:10", "upsert_approval:10", "get_workflow:10"]
        );
    }

    #[tokio::test]
    async fn submit_review_miss_is_silent() {
        // 非 DRAFT 提交审核未命中：静默忽略（对齐原 handler 语义）
        let repo = Arc::new(FakePublishingRepository::new(
            false,
            false,
            false,
            Some(workflow("APPROVED")),
        ));
        let svc = PublishingService::new(repo.clone());
        let wf = svc.submit_for_review(10).await.unwrap();
        assert_eq!(wf.current_status, "APPROVED");
    }

    #[tokio::test]
    async fn archive_has_no_guard() {
        // 任意状态 → ARCHIVED（无守卫）
        let repo = Arc::new(FakePublishingRepository::new(
            false,
            false,
            false,
            Some(workflow("ARCHIVED")),
        ));
        let svc = PublishingService::new(repo.clone());
        let wf = svc.archive_course(10).await.unwrap();
        assert_eq!(wf.current_status, "ARCHIVED");
        assert_eq!(
            repo.calls.lock().unwrap().clone(),
            vec!["archive:10", "get_workflow:10"]
        );
    }
}
