//! 成绩编排 — GradeService
//!
//! 对齐 Java `GradeServiceImpl`：find-or-create 默认作业（"默认评分"/PUBLISHED）
//! → 成绩 upsert（ON DUPLICATE KEY UPDATE 幂等）→ 重读提交 id。
//! 无成绩时降级为零分（非 404，对齐原 handler）。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::assignment_repository::AssignmentRepository;
use crate::srv::grades::Grade;

/// GradeService（依赖注入 repository）
pub struct GradeService {
    repo: Arc<dyn AssignmentRepository>,
}

impl GradeService {
    pub fn new(repo: Arc<dyn AssignmentRepository>) -> Self {
        Self { repo }
    }

    /// 单用户成绩（无记录 → 零分降级）
    pub async fn get_grade(&self, course_id: i64, user_id: i64) -> Result<Grade, AstralError> {
        match self.repo.get_grade(course_id, user_id).await? {
            Some(r) => Ok(Grade {
                id: r.id,
                course_id,
                user_id: r.user_id,
                score: r.score,
                comment: r.comment,
            }),
            None => Ok(Grade {
                id: 0,
                course_id,
                user_id,
                score: 0.0,
                comment: None,
            }),
        }
    }

    /// 课程成绩列表
    pub async fn list_course_grades(&self, course_id: i64) -> Result<Vec<Grade>, AstralError> {
        let rows = self.repo.list_course_grades(course_id).await?;
        Ok(rows
            .into_iter()
            .map(|r| Grade {
                id: r.id,
                course_id,
                user_id: r.user_id,
                score: r.score,
                comment: r.comment,
            })
            .collect())
    }

    /// 提交成绩：find-or-create 作业 → upsert → 重读提交 id
    pub async fn submit_grade(
        &self,
        course_id: i64,
        user_id: i64,
        score: f64,
        comment: Option<String>,
    ) -> Result<Grade, AstralError> {
        let assignment_id = self.repo.get_or_create_assignment(course_id).await?;
        self.repo
            .upsert_submission(assignment_id, user_id, score, comment.as_deref())
            .await?;
        let submission_id = self.repo.get_submission_id(assignment_id, user_id).await?;
        Ok(Grade {
            id: submission_id,
            course_id,
            user_id,
            score,
            comment,
        })
    }

    /// 更新成绩（仅 body 含 score 时调用）
    pub async fn update_grade(&self, id: i64, score: Option<f64>) -> Result<(), AstralError> {
        if let Some(score) = score {
            self.repo.update_grade_score(id, score).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::assignment_repository::{
        AssignmentInput, AssignmentRecord, AssignmentSubmissionRecord, GradeRecord,
        SubmissionRowRecord, TranscriptRow,
    };
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Fake AssignmentRepository（记录 submit_grade 编排顺序）
    struct FakeAssignmentRepository {
        calls: Mutex<Vec<String>>,
        assignment_id: Mutex<i64>,
    }

    impl FakeAssignmentRepository {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                assignment_id: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl AssignmentRepository for FakeAssignmentRepository {
        async fn count_assignments(&self) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_assignments(
            &self,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<AssignmentRecord>, AstralError> {
            Ok(vec![])
        }

        async fn get_assignment(&self, _id: i64) -> Result<Option<AssignmentRecord>, AstralError> {
            Ok(None)
        }

        async fn create_assignment(&self, _input: &AssignmentInput) -> Result<i64, AstralError> {
            Ok(1)
        }

        async fn update_assignment(
            &self,
            _id: i64,
            _input: &AssignmentInput,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn archive_assignment(&self, _id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn list_submissions_by_assignment(
            &self,
            _assignment_id: i64,
        ) -> Result<Vec<AssignmentSubmissionRecord>, AstralError> {
            Ok(vec![])
        }

        async fn submit_assignment(
            &self,
            _assignment_id: i64,
            _user_id: i64,
            _content: &str,
        ) -> Result<i64, AstralError> {
            Ok(1)
        }

        async fn grade_submission(
            &self,
            _assignment_id: i64,
            _user_id: i64,
            _score: f64,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn course_stats(&self, _course_id: i64) -> Result<(i64, i64), AstralError> {
            Ok((0, 0))
        }

        async fn count_submissions(&self) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_submissions_page(
            &self,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<SubmissionRowRecord>, AstralError> {
            Ok(vec![])
        }

        async fn create_submission(
            &self,
            _assignment_id: i64,
            _user_id: i64,
            _content: Option<&str>,
            _file_url: Option<&str>,
        ) -> Result<i64, AstralError> {
            Ok(1)
        }

        async fn get_submission(
            &self,
            _id: i64,
        ) -> Result<Option<SubmissionRowRecord>, AstralError> {
            Ok(None)
        }

        async fn update_submission(
            &self,
            _id: i64,
            _user_id: i64,
            _content: Option<&str>,
            _file_url: Option<&str>,
        ) -> Result<u64, AstralError> {
            Ok(0)
        }

        async fn delete_submission(&self, _id: i64) -> Result<u64, AstralError> {
            Ok(0)
        }

        async fn grade_submission_by_id(
            &self,
            _id: i64,
            _score: f64,
            _feedback: Option<&str>,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn get_or_create_assignment(&self, course_id: i64) -> Result<i64, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("get_or_create:{course_id}"));
            let mut id = self.assignment_id.lock().unwrap();
            if *id == 0 {
                *id = 500;
            }
            Ok(*id)
        }

        async fn upsert_submission(
            &self,
            assignment_id: i64,
            user_id: i64,
            _score: f64,
            _comment: Option<&str>,
        ) -> Result<(), AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("upsert:{assignment_id}:{user_id}"));
            Ok(())
        }

        async fn get_submission_id(
            &self,
            assignment_id: i64,
            user_id: i64,
        ) -> Result<i64, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("get_id:{assignment_id}:{user_id}"));
            Ok(888)
        }

        async fn get_grade(
            &self,
            _course_id: i64,
            _user_id: i64,
        ) -> Result<Option<GradeRecord>, AstralError> {
            Ok(None)
        }

        async fn list_course_grades(
            &self,
            _course_id: i64,
        ) -> Result<Vec<GradeRecord>, AstralError> {
            Ok(vec![])
        }

        async fn update_grade_score(&self, _id: i64, _score: f64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn transcript(&self, _user_id: i64) -> Result<Vec<TranscriptRow>, AstralError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn submit_grade_runs_find_or_create_then_upsert_then_rereread() {
        // find-or-create 作业 → upsert → 重读提交 id（对齐 Java GradeServiceImpl）
        let repo = Arc::new(FakeAssignmentRepository::new());
        let svc = GradeService::new(repo.clone());

        let grade = svc
            .submit_grade(10, 7, 85.5, Some("good".into()))
            .await
            .unwrap();
        assert_eq!(grade.id, 888);
        assert_eq!(grade.course_id, 10);
        assert_eq!(grade.user_id, 7);
        assert_eq!(grade.score, 85.5);
        assert_eq!(
            repo.calls.lock().unwrap().clone(),
            vec!["get_or_create:10", "upsert:500:7", "get_id:500:7"]
        );
    }

    #[tokio::test]
    async fn get_grade_degrades_to_zero_when_missing() {
        // 无成绩记录 → 零分降级（非 404）
        let repo = Arc::new(FakeAssignmentRepository::new());
        let svc = GradeService::new(repo.clone());
        let grade = svc.get_grade(10, 7).await.unwrap();
        assert_eq!(grade.id, 0);
        assert_eq!(grade.score, 0.0);
        assert_eq!(grade.course_id, 10);
        assert_eq!(grade.user_id, 7);
    }
}
