//! AstralLearn 启动入口
//!
//! ```bash
//! cargo run -p astral-learn
//! # LISTEN_ADDR=0.0.0.0:9002 cargo run -p astral-learn
//! ```

use std::sync::Arc;

use axum::Router;
use lapin::Connection;
use policy_engine::PolicyEngine;
use sqlx::MySqlPool;

use astral_common::audit::{register_audit_db_writer, AuditDbWriter, AuditEntry};
use astral_common::config::AppConfig;
use astral_common::error::global_exception_handler;
use astral_common::middleware::gateway_signature::gateway_signature_middleware;
use astral_common::service::{register_mq_producer, AuditLogEvent, MqProducerRef};
use astral_common::tracing::init_tracing;
use astral_db::connect_and_validate_schema;
use astral_mq::consumer::Consumer;
use astral_mq::producer::SubjectDeletePayload;

use astral_learn::repository::app_user_repository::SqlxAppUserRepository;
use astral_learn::repository::assignment_repository::SqlxAssignmentRepository;
use astral_learn::repository::checkin_repository::SqlxCheckinRepository;
use astral_learn::repository::class_repository::SqlxClassRepository;
use astral_learn::repository::course_repository::SqlxCourseRepository;
use astral_learn::repository::device_repository::SqlxDeviceRepository;
use astral_learn::repository::discussion_repository::SqlxDiscussionRepository;
use astral_learn::repository::document_repository::SqlxDocumentRepository;
use astral_learn::repository::enrollment_repository::SqlxEnrollmentRepository;
use astral_learn::repository::exam_repository::SqlxExamRepository;
use astral_learn::repository::level_repository::SqlxLevelRepository;
use astral_learn::repository::progress_repository::SqlxProgressRepository;
use astral_learn::repository::publishing_repository::SqlxPublishingRepository;
use astral_learn::repository::question_repository::SqlxQuestionRepository;
use astral_learn::repository::solution_repository::SqlxSolutionRepository;
use astral_learn::repository::statistics_repository::SqlxStatisticsRepository;
use astral_learn::repository::subject_repository::SqlxSubjectRepository;
use astral_learn::repository::system_setting_repository::SqlxSystemSettingRepository;
use astral_learn::repository::user_answer_repository::SqlxUserAnswerRepository;
use astral_learn::repository::user_subject_repository::SqlxUserSubjectRepository;
use astral_learn::repository::webhook_config_repository::SqlxWebhookConfigRepository;
use astral_learn::repository::wrong_question_repository::SqlxWrongQuestionRepository;
use astral_learn::service::app_user_service::AppUserService;
use astral_learn::service::assignment_service::AssignmentService;
use astral_learn::service::checkin_service::CheckinService;
use astral_learn::service::exam_service::ExamService;
use astral_learn::service::grade_service::GradeService;
use astral_learn::service::level_service::LevelService;
use astral_learn::service::progress_service::ProgressService;
use astral_learn::service::publishing_service::PublishingService;
use astral_learn::service::subject_service::{
    MqSubjectDeleteSideEffects, SubjectDeleteSideEffects, SubjectService,
};
use astral_learn::srv;
use astral_learn::AppState;

mod middleware;

struct LearnAuditDbWriter {
    pool: MySqlPool,
}

#[async_trait::async_trait]
impl AuditDbWriter for LearnAuditDbWriter {
    async fn insert_audit(&self, entry: &AuditEntry) -> Result<(), String> {
        astral_db::insert_audit_log(&self.pool, entry)
            .await
            .map_err(|e| e.to_string())
    }
}

struct LearnMqProducer {
    inner: astral_mq::producer::Producer,
}

#[async_trait::async_trait]
impl MqProducerRef for LearnMqProducer {
    async fn publish_audit_log(&self, event: AuditLogEvent) -> Result<(), String> {
        self.inner
            .publish_audit_log(astral_mq::producer::AuditLogPayload {
                // message_id 必须唯一：audit consumer 以它为 mq_idempotent_log 幂等键，
                // 恒 None 会回退到派生键，permission 审计 request_id 恒 None，
                // 相同 user+resource+action 的重复判定会被 INSERT IGNORE 静默丢弃。
                message_id: Some(uuid::Uuid::new_v4().to_string()),
                user_id: event.user_id,
                card_id: event.card_id,
                action: event.action,
                resource: event.resource,
                decision: event.decision,
                reason: event.reason,
                event_type: event.event_type,
                source_ip: event.source_ip,
                request_id: event.request_id,
                domain_id: event.domain_id,
                tenant_id: event.tenant_id,
                // producer detail 随消息透传；consumer 仅在非空白时落库。
                detail: event.detail,
            })
            .await
            .map_err(|e| e.to_string())
    }

    async fn publish_login_event(
        &self,
        user_id: i64,
        login_type: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        success: bool,
    ) -> Result<(), String> {
        self.inner
            .publish_login_event(astral_mq::producer::LoginEventPayload {
                message_id: Some(uuid::Uuid::new_v4().to_string()),
                user_id,
                card_id: None,
                login_type: login_type.to_string(),
                ip_address: ip_address.map(str::to_string),
                user_agent: user_agent.map(str::to_string),
                success,
            })
            .await
            .map_err(|e| e.to_string())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = Arc::new(AppConfig::from_files("application")?);
    let db = connect_and_validate_schema(&config.database_url).await?;
    let engine = Arc::new(PolicyEngine::new());
    register_audit_db_writer(Arc::new(LearnAuditDbWriter { pool: db.clone() }));
    let rabbitmq_url = config.rabbitmq_url.clone();
    let redis_url = config.redis_url.clone();

    // 初始化 MQ Producer
    let mq_producer = init_mq_producer(&rabbitmq_url, &redis_url).await;

    // 数据访问层（对齐 Java Learn*Mapper 边界）
    let subject_repository: Arc<
        dyn astral_learn::repository::subject_repository::SubjectRepository,
    > = Arc::new(SqlxSubjectRepository::new(db.clone()));
    let question_repository: Arc<
        dyn astral_learn::repository::question_repository::QuestionRepository,
    > = Arc::new(SqlxQuestionRepository::new(db.clone()));
    let course_repository: Arc<dyn astral_learn::repository::course_repository::CourseRepository> =
        Arc::new(SqlxCourseRepository::new(db.clone()));
    let statistics_repository: Arc<
        dyn astral_learn::repository::statistics_repository::StatisticsRepository,
    > = Arc::new(SqlxStatisticsRepository::new(db.clone()));
    let level_repository: Arc<dyn astral_learn::repository::level_repository::LevelRepository> =
        Arc::new(SqlxLevelRepository::new(db.clone()));
    let exam_repository: Arc<dyn astral_learn::repository::exam_repository::ExamRepository> =
        Arc::new(SqlxExamRepository::new(db.clone()));
    let assignment_repository: Arc<
        dyn astral_learn::repository::assignment_repository::AssignmentRepository,
    > = Arc::new(SqlxAssignmentRepository::new(db.clone()));
    let progress_repository: Arc<
        dyn astral_learn::repository::progress_repository::ProgressRepository,
    > = Arc::new(SqlxProgressRepository::new(db.clone()));
    let solution_repository: Arc<
        dyn astral_learn::repository::solution_repository::SolutionRepository,
    > = Arc::new(SqlxSolutionRepository::new(db.clone()));
    let wrong_question_repository: Arc<
        dyn astral_learn::repository::wrong_question_repository::WrongQuestionRepository,
    > = Arc::new(SqlxWrongQuestionRepository::new(db.clone()));
    let user_answer_repository: Arc<
        dyn astral_learn::repository::user_answer_repository::UserAnswerRepository,
    > = Arc::new(SqlxUserAnswerRepository::new(db.clone()));
    let checkin_repository: Arc<
        dyn astral_learn::repository::checkin_repository::CheckinRepository,
    > = Arc::new(SqlxCheckinRepository::new(db.clone()));
    let publishing_repository: Arc<
        dyn astral_learn::repository::publishing_repository::PublishingRepository,
    > = Arc::new(SqlxPublishingRepository::new(db.clone()));
    let enrollment_repository: Arc<
        dyn astral_learn::repository::enrollment_repository::EnrollmentRepository,
    > = Arc::new(SqlxEnrollmentRepository::new(db.clone()));
    let discussion_repository: Arc<
        dyn astral_learn::repository::discussion_repository::DiscussionRepository,
    > = Arc::new(SqlxDiscussionRepository::new(db.clone()));
    let document_repository: Arc<
        dyn astral_learn::repository::document_repository::DocumentRepository,
    > = Arc::new(SqlxDocumentRepository::new(db.clone()));
    let device_repository: Arc<dyn astral_learn::repository::device_repository::DeviceRepository> =
        Arc::new(SqlxDeviceRepository::new(db.clone()));
    let system_setting_repository: Arc<
        dyn astral_learn::repository::system_setting_repository::SystemSettingRepository,
    > = Arc::new(SqlxSystemSettingRepository::new(db.clone()));
    let webhook_config_repository: Arc<
        dyn astral_learn::repository::webhook_config_repository::WebhookConfigRepository,
    > = Arc::new(SqlxWebhookConfigRepository::new(db.clone()));
    let class_repository: Arc<dyn astral_learn::repository::class_repository::ClassRepository> =
        Arc::new(SqlxClassRepository::new(db.clone()));
    let user_subject_repository: Arc<
        dyn astral_learn::repository::user_subject_repository::UserSubjectRepository,
    > = Arc::new(SqlxUserSubjectRepository::new(db.clone()));
    let app_user_repository: Arc<
        dyn astral_learn::repository::app_user_repository::AppUserRepository,
    > = Arc::new(SqlxAppUserRepository::new(db.clone()));

    // 学科编排（MQ 副作用注入；测试可替换 no-op）
    let subject_delete_side_effects: Arc<dyn SubjectDeleteSideEffects> =
        Arc::new(MqSubjectDeleteSideEffects::new(mq_producer.clone()));
    let subject_service = Arc::new(SubjectService::new(
        subject_repository.clone(),
        subject_delete_side_effects,
    ));

    // 学习流程编排（状态机/计分/find-or-create）
    let level_service = Arc::new(LevelService::new(level_repository.clone()));
    let exam_service = Arc::new(ExamService::new(exam_repository.clone()));
    let grade_service = Arc::new(GradeService::new(assignment_repository.clone()));
    let assignment_service = Arc::new(AssignmentService::new(assignment_repository.clone()));
    let progress_service = Arc::new(ProgressService::new(progress_repository.clone()));
    let checkin_service = Arc::new(CheckinService::new(checkin_repository.clone()));
    let publishing_service = Arc::new(PublishingService::new(publishing_repository.clone()));
    let app_user_service = Arc::new(AppUserService::new(
        app_user_repository.clone(),
        Arc::new(astral_learn::service::app_user_service::HmacAppSessionIssuer),
    ));

    let state = AppState {
        config,
        db,
        engine,
        mq_producer,
        subject_repository,
        question_repository,
        course_repository,
        statistics_repository,
        subject_service,
        level_repository,
        exam_repository,
        assignment_repository,
        progress_repository,
        solution_repository,
        wrong_question_repository,
        user_answer_repository,
        checkin_repository,
        level_service,
        exam_service,
        grade_service,
        assignment_service,
        progress_service,
        checkin_service,
        publishing_repository,
        enrollment_repository,
        discussion_repository,
        document_repository,
        device_repository,
        system_setting_repository,
        webhook_config_repository,
        class_repository,
        user_subject_repository,
        app_user_repository,
        publishing_service,
        app_user_service,
    };

    // MQ 消费者后台启动（subject delete 消费编排在 SubjectService）。
    // RabbitMQ 暂不可用时按指数退避重试，避免消费者永久缺失。
    let pool = state.db.clone();
    let mq_url = state.config.rabbitmq_url.clone();
    let redis_url = state.config.redis_url.clone();
    let subject_service_for_consumer = state.subject_service.clone();
    tokio::spawn(async move {
        let mut attempt: u32 = 0;
        loop {
            let started =
                init_mq_consumers(
                    &mq_url,
                    &redis_url,
                    pool.clone(),
                    subject_service_for_consumer.clone(),
                )
                    .await
                    .ok();
            if let Some(started) = started {
                tracing::info!(service = "learn", "MQ consumers started: {:?}", started);
                break;
            }
            attempt = attempt.saturating_add(1);
            let backoff_secs = 2u64.pow(attempt.min(5));
            tracing::warn!(
                service = "learn",
                attempt,
                backoff_secs,
                "MQ consumers startup failed, retrying with backoff"
            );
            tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        }
    });

    // 启动期注册校验
    astral_common::middleware::permission_check_shared::validate_path_map(
        middleware::LEARN_PATH_MAP,
        "learn",
    );
    astral_common::middleware::permission_check_shared::validate_path_map(
        middleware::LEARN_APP_PATH_MAP,
        "learn-app",
    );
    astral_common::middleware::permission_check_shared::validate_path_map(
        middleware::LEARN_APP_USER_PATH_MAP,
        "learn-app-users",
    );

    // 管理端路由 + 权限中间件
    let admin_routes = Router::new()
        .merge(srv::subjects::subject_routes())
        .merge(srv::questions::question_routes())
        .merge(srv::exams::exam_routes())
        .merge(srv::courses::course_routes())
        .merge(srv::enrollments::enrollment_routes())
        .merge(srv::grades::grade_routes())
        .merge(srv::publishing::publishing_routes())
        .merge(srv::assignments::assignment_routes())
        .merge(srv::discussions::discussion_routes())
        .merge(srv::classes::class_routes())
        .merge(srv::submissions::submission_routes())
        .merge(srv::chapters::chapter_routes())
        .merge(srv::levels::level_routes())
        .merge(srv::statistics::statistics_routes())
        .merge(srv::checkins::checkin_admin_routes())
        .merge(srv::documents::document_routes())
        .merge(srv::devices::device_admin_routes())
        .merge(srv::system_settings::system_setting_routes())
        .merge(srv::webhook_configs::webhook_config_routes())
        .merge(srv::wrong_questions::wrong_question_routes())
        .merge(srv::solutions::solution_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::learn_permission_middleware,
        ));

    // App端路由（不走权限中间件，由 Gateway 鉴权）
    let app_learn_routes = Router::new()
        .merge(srv::progress::progress_routes())
        .merge(srv::levels::level_app_routes())
        .merge(srv::checkins::checkin_app_routes())
        .merge(srv::solutions::solution_routes())
        .merge(srv::wrong_questions::wrong_question_routes())
        .merge(srv::user_answers::user_answer_routes())
        .merge(srv::user_subjects::user_subject_routes())
        .merge(srv::first_attempts::first_attempt_routes())
        .merge(srv::exams_app::exam_app_routes())
        .merge(srv::devices::device_app_routes())
        .merge(srv::subjects::subject_routes())
        .merge(srv::courses::course_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::learn_app_permission_middleware,
        ));

    let app_user_routes = Router::new()
        .merge(srv::app_users::app_user_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::learn_app_user_permission_middleware,
        ));

    let app = Router::new()
        .nest("/v1/admin/learn", admin_routes)
        .nest("/v1/app/learn", app_learn_routes)
        .nest("/v1/app/users", app_user_routes)
        .nest("/api", srv::health::health_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            gateway_signature_middleware,
        ))
        .layer(axum::middleware::from_fn(global_exception_handler))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9002".into());
    tracing::info!(addr = %addr, "learn service starting");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// 初始化 MQ Producer
async fn init_mq_producer(
    rabbitmq_url: &str,
    redis_url: &str,
) -> Option<astral_mq::producer::Producer> {
    if astral_mq::consumer::init_idempotency_redis(redis_url)
        .await
        .is_err()
    {
        tracing::warn!(service = "learn", "MQ Redis idempotency initialization failed");
        return None;
    }
    match Connection::connect(
        rabbitmq_url,
        lapin::ConnectionProperties::default().enable_auto_recover(),
    )
    .await
    {
        Ok(conn) => match conn.create_channel().await {
            Ok(channel) => {
                if astral_mq::producer::Producer::enable_confirms(&channel)
                    .await
                    .is_err()
                {
                    tracing::warn!(service = "learn", "MQ publisher confirms unavailable");
                    return None;
                }
                tracing::info!(service = "learn", "MQ producer initialized");
                let producer = astral_mq::producer::Producer::new(channel);
                register_mq_producer(Arc::new(LearnMqProducer {
                    inner: producer.clone(),
                }));
                Some(producer)
            }
            Err(_) => {
                tracing::warn!(service = "learn", "MQ producer channel failed");
                None
            }
        },
        Err(_) => {
            tracing::warn!(service = "learn", "MQ producer connection failed");
            None
        }
    }
}

/// 初始化 MQ 消费者
async fn init_mq_consumers(
    rabbitmq_url: &str,
    redis_url: &str,
    _pool: MySqlPool,
    subject_service: Arc<SubjectService>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    astral_mq::consumer::init_idempotency_redis(redis_url).await?;
    let conn = Connection::connect(
        rabbitmq_url,
        lapin::ConnectionProperties::default().enable_auto_recover(),
    )
    .await?;
    let channel = conn.create_channel().await?;
    astral_mq::config::declare_all(&channel).await?;

    // 通用消费者（audit, login, permission-refresh）
    let mut started = astral_mq::consumers::start_all_consumers(&channel).await?;

    // 学科删除消费者（learn 特有，独立 tokio 任务；幂等检查 + 级联编排在 SubjectService）
    let consumer = Consumer::new(
        channel.clone(),
        move |msg: &SubjectDeletePayload| {
            let svc = subject_service.clone();
            let subject_id = msg.subject_id;
            let cascade = msg.cascade_delete;
            async move {
                svc.process_delete_message(subject_id, cascade)
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
                Ok(())
            }
        },
        "astral.subject.delete",
    );
    tokio::spawn(async move {
        if consumer.start().await.is_err() {
            tracing::error!(
                queue = "astral.subject.delete",
                "subject delete consumer failed"
            );
        }
    });
    started.push("SubjectDeleteConsumer[astral.subject.delete]".into());

    // 保持连接存活
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    });
    Ok(started)
}

#[cfg(test)]
mod tests {
    #[test]
    fn mq_tracing_never_formats_credential_sources() {
        let source = include_str!("main.rs");
        let bootstrap_start = source
            .find("// MQ 消费者后台启动（subject delete")
            .expect("MQ bootstrap block must remain");
        let bootstrap_end = source[bootstrap_start..]
            .find("// 启动期注册校验")
            .map(|offset| bootstrap_start + offset)
            .expect("MQ bootstrap block must have a stable end marker");
        let init_start = source
            .find("async fn init_mq_producer(")
            .expect("MQ initializers must remain");
        let init_end = source[init_start..]
            .find("#[cfg(test)]")
            .map(|offset| init_start + offset)
            .expect("MQ initializers must have a stable end marker");
        let blocks = [
            &source[bootstrap_start..bootstrap_end],
            &source[init_start..init_end],
        ];
        let mut calls = Vec::new();
        for block in blocks {
            let mut offset = 0;
            while let Some(relative_start) = block[offset..].find("tracing::") {
                let call_start = offset + relative_start;
                let call_end = call_start
                    + block[call_start..]
                        .find(';')
                        .expect("tracing invocation must end with a semicolon")
                    + 1;
                calls.push(&block[call_start..call_end]);
                offset = call_end;
            }
        }
        assert_eq!(calls.len(), 7, "review every Learn MQ tracing call");
        for call in calls {
            for forbidden in [
                "rabbitmq_url",
                "mq_url",
                "error =",
                "%error",
                "?error",
                "%e",
                "?e",
                "{error",
                "{e",
                ".to_string()",
                "format!(",
            ] {
                assert!(
                    !call.contains(forbidden),
                    "Learn MQ tracing must not format credential sources: {call}"
                );
            }
        }
        assert!(blocks[0].contains("init_mq_consumers("));
        assert!(blocks[0].contains(".await"));
        assert!(blocks[0].contains(".ok();"));
    }
}
