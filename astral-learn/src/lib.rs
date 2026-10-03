//! AstralLight 教育域业务服务

pub mod access;
pub mod ownership;
pub mod repository;
pub mod service;
pub mod srv;

use astral_common::config::AppConfig;
use axum::extract::FromRef;
use policy_engine::PolicyEngine;
use sqlx::MySqlPool;
use std::sync::Arc;

use crate::repository::app_user_repository::AppUserRepository;
use crate::repository::assignment_repository::AssignmentRepository;
use crate::repository::checkin_repository::CheckinRepository;
use crate::repository::class_repository::ClassRepository;
use crate::repository::course_repository::CourseRepository;
use crate::repository::device_repository::DeviceRepository;
use crate::repository::discussion_repository::DiscussionRepository;
use crate::repository::document_repository::DocumentRepository;
use crate::repository::enrollment_repository::EnrollmentRepository;
use crate::repository::exam_repository::ExamRepository;
use crate::repository::level_repository::LevelRepository;
use crate::repository::progress_repository::ProgressRepository;
use crate::repository::publishing_repository::PublishingRepository;
use crate::repository::question_repository::QuestionRepository;
use crate::repository::solution_repository::SolutionRepository;
use crate::repository::statistics_repository::StatisticsRepository;
use crate::repository::subject_repository::SubjectRepository;
use crate::repository::system_setting_repository::SystemSettingRepository;
use crate::repository::user_answer_repository::UserAnswerRepository;
use crate::repository::user_subject_repository::UserSubjectRepository;
use crate::repository::webhook_config_repository::WebhookConfigRepository;
use crate::repository::wrong_question_repository::WrongQuestionRepository;
use crate::service::app_user_service::AppUserService;
use crate::service::assignment_service::AssignmentService;
use crate::service::checkin_service::CheckinService;
use crate::service::exam_service::ExamService;
use crate::service::grade_service::GradeService;
use crate::service::level_service::LevelService;
use crate::service::progress_service::ProgressService;
use crate::service::publishing_service::PublishingService;
use crate::service::subject_service::SubjectService;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: MySqlPool,
    pub engine: Arc<PolicyEngine>,
    pub mq_producer: Option<astral_mq::producer::Producer>,
    /// 学科数据访问（含级联删除单事务）
    pub subject_repository: Arc<dyn SubjectRepository>,
    /// 题目数据访问（含批量导入单事务）
    pub question_repository: Arc<dyn QuestionRepository>,
    /// 课程/章节/课时数据访问（含章节删除级联单事务）
    pub course_repository: Arc<dyn CourseRepository>,
    /// 统计聚合数据访问
    pub statistics_repository: Arc<dyn StatisticsRepository>,
    /// 学科编排（MQ 发布 + 软删 + 级联消费）
    pub subject_service: Arc<SubjectService>,
    /// 关卡数据访问
    pub level_repository: Arc<dyn LevelRepository>,
    /// 考试数据访问
    pub exam_repository: Arc<dyn ExamRepository>,
    /// 作业/提交数据访问（assignments/submissions/grades 复用）
    pub assignment_repository: Arc<dyn AssignmentRepository>,
    /// 学习进度数据访问
    pub progress_repository: Arc<dyn ProgressRepository>,
    /// 题目解析数据访问
    pub solution_repository: Arc<dyn SolutionRepository>,
    /// 错题数据访问
    pub wrong_question_repository: Arc<dyn WrongQuestionRepository>,
    /// 用户作答数据访问
    pub user_answer_repository: Arc<dyn UserAnswerRepository>,
    /// 打卡数据访问
    pub checkin_repository: Arc<dyn CheckinRepository>,
    /// 关卡编排（状态机）
    pub level_service: Arc<LevelService>,
    /// 考试编排（计分）
    pub exam_service: Arc<ExamService>,
    /// 成绩编排（find-or-create + upsert）
    pub grade_service: Arc<GradeService>,
    /// 作业编排（提交幂等 + 批改）
    pub assignment_service: Arc<AssignmentService>,
    /// 学习进度编排（准确率 + 连续天数）
    pub progress_service: Arc<ProgressService>,
    /// 打卡编排（今日幂等 + 奖励积分）
    pub checkin_service: Arc<CheckinService>,
    /// 课程发布工作流数据访问
    pub publishing_repository: Arc<dyn PublishingRepository>,
    /// 选课数据访问
    pub enrollment_repository: Arc<dyn EnrollmentRepository>,
    /// 讨论区数据访问
    pub discussion_repository: Arc<dyn DiscussionRepository>,
    /// 文档数据访问
    pub document_repository: Arc<dyn DocumentRepository>,
    /// 设备数据访问
    pub device_repository: Arc<dyn DeviceRepository>,
    /// 系统设置数据访问
    pub system_setting_repository: Arc<dyn SystemSettingRepository>,
    /// Webhook 配置数据访问
    pub webhook_config_repository: Arc<dyn WebhookConfigRepository>,
    /// 班级数据访问
    pub class_repository: Arc<dyn ClassRepository>,
    /// 用户学科数据访问
    pub user_subject_repository: Arc<dyn UserSubjectRepository>,
    /// App 用户数据访问（验证码原子消费）
    pub app_user_repository: Arc<dyn AppUserRepository>,
    /// 课程发布工作流编排（状态机）
    pub publishing_service: Arc<PublishingService>,
    /// App 用户登录编排（外部会话签发 + 补偿）
    pub app_user_service: Arc<AppUserService>,
}

impl FromRef<AppState> for MySqlPool {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl FromRef<AppState> for astral_common::config::AppConfig {
    fn from_ref(state: &AppState) -> Self {
        (*state.config).clone()
    }
}
