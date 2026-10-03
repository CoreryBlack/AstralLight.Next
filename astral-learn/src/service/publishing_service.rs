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
            tracing::info!(course_id, "course published");
        }
        self.build_workflow(course_id).await
    }

    /// 归档课程（任意状态 → ARCHIVED，无守卫）
    pub async fn archive_course(&self, course_id: i64) -> Result<PublishWorkflow, AstralError> {
        let hit = self.repo.archive_course(course_id).await?;
        if hit {
            tracing::info!(course_id, "course archived");
        }
        self.build_workflow(course_id).await
    }

    /// 提交审核（DRAFT → REVIEW）
    pub async fn submit_for_review(&self, course_id: i64) -> Result<PublishWorkflow, AstralError> {
        let hit = self.repo.submit_for_review(course_id).await?;
        if hit {
            tracing::info!(course_id, "course submitted for review");
        }
        self.build_workflow(course_id).await
    }

    /// 审批通过（REVIEW → APPROVED；side effect: workflow reviewer/comment）
    pub async fn approve_course(
        &self,
        course_id: i64,
        reviewer_id: i64,
    ) -> Result<PublishWorkflow, AstralError> {
        let hit = self.repo.approve_course(course_id, reviewer_id).await?;
        if hit {
            tracing::info!(course_id, reviewer_id, "course approved");
        }
        self.build_workflow(course_id).await
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

    /// Detailed course progress remains fail-closed until Learn has an
    /// authoritative per-course lesson/completion projection.
    pub async fn student_progress(
        &self,
        _course_id: i64,
        _user_id: i64,
    ) -> Result<StudentProgress, AstralError> {
        Err(AstralError::NotImplemented(
            "Course lesson progress requires an authoritative server-side projection".into(),
        ))
    }

    /// 组装工作流响应。Missing course/workflow never becomes a default success.
    async fn build_workflow(&self, course_id: i64) -> Result<PublishWorkflow, AstralError> {
        let wf: WorkflowRecord = self
            .repo
            .get_workflow(course_id)
            .await?
            .ok_or_else(|| AstralError::NotFound(format!("Course {course_id} not found")))?;
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

    /// Fake PublishingRepository（记录守卫式 UPDATE 命中）
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

        async fn approve_course(
            &self,
            course_id: i64,
            reviewer_id: i64,
        ) -> Result<bool, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("approve:{course_id}:{reviewer_id}"));
            Ok(self.approve_hit)
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
    async fn publish_hit_returns_atomic_repository_workflow() {
        // Repository owns status and published_at in one transaction; service reads the committed result.
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
            vec!["publish:10", "get_workflow:10"]
        );
    }

    #[tokio::test]
    async fn publish_miss_returns_current_workflow() {
        // Illegal transition does not change workflow metadata; return current status.
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
    async fn approve_hit_returns_atomic_repository_workflow() {
        // Repository owns approval and reviewer/comment in one transaction.
        let repo = Arc::new(FakePublishingRepository::new(
            false,
            false,
            true,
            Some(workflow("APPROVED")),
        ));
        let svc = PublishingService::new(repo.clone());
        let wf = svc.approve_course(10, 7).await.unwrap();
        assert_eq!(wf.current_status, "APPROVED");
        assert_eq!(
            repo.calls.lock().unwrap().clone(),
            vec!["approve:10:7", "get_workflow:10"]
        );
    }

    #[tokio::test]
    async fn missing_course_after_guarded_miss_is_not_reported_as_success() {
        let repo = Arc::new(FakePublishingRepository::new(false, false, false, None));
        let svc = PublishingService::new(repo.clone());
        assert!(matches!(
            svc.submit_for_review(10).await,
            Err(AstralError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn course_progress_requires_authoritative_repository_support() {
        let repo = Arc::new(FakePublishingRepository::new(
            false,
            false,
            false,
            Some(workflow("PUBLISHED")),
        ));
        let svc = PublishingService::new(repo);
        assert!(matches!(
            svc.student_progress(10, 7).await,
            Err(AstralError::NotImplemented(_))
        ));
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
