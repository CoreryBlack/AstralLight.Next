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
use tokio::sync::oneshot;

use astral_common::audit::{register_audit_db_writer, AuditDbWriter, AuditEntry};
use astral_common::config::AppConfig;
use astral_common::error::global_exception_handler;
use astral_common::middleware::gateway_signature::gateway_signature_middleware;
use astral_common::service::{register_mq_producer, AuditLogEvent, MqProducerRef};
use astral_common::tracing::init_tracing;
use astral_db::connect_and_validate_schema;
use astral_db::{LocalMessageRepository, LOCAL_MESSAGE_LEASE_SECONDS};
use astral_mq::config::QUEUE_SUBJECT_DELETE;
use astral_mq::consumer::Consumer;
use astral_mq::envelope::MessageEnvelope;
use astral_mq::producer::SubjectDeletePayload;

use astral_learn::ownership;
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
use astral_learn::service::subject_service::{SubjectDeleteOutcome, SubjectService};
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

struct LearnRabbitOwner(Option<Arc<Connection>>);

impl LearnRabbitOwner {
    async fn close(&mut self) -> Result<(), String> {
        let Some(connection) = self.0.as_ref() else {
            return Ok(());
        };
        match tokio::time::timeout(
            LEARN_RABBIT_CLOSE_BOUND,
            connection.close(200, "Learn runtime cleanup".into()),
        )
        .await
        {
            Ok(Ok(())) => {
                self.0.take();
                Ok(())
            }
            _ => Err("Learn Rabbit close outcome is unproven".into()),
        }
    }
}

impl Drop for LearnRabbitOwner {
    fn drop(&mut self) {
        let Some(connection) = self.0.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if !matches!(
                    tokio::time::timeout(
                        LEARN_RABBIT_CLOSE_BOUND,
                        connection.close(200, "Learn owner dropped".into())
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    tracing::error!("Learn Rabbit drop cleanup outcome is unproven");
                }
            });
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let loaded_config = AppConfig::from_files("application")?;
    // Validate the Learn binary's own Redis adapter capability and freeze the
    // shared setting before DB connections, service assembly, or network calls.
    loaded_config.validate_redis_adapter_support(cfg!(feature = "redis-compat"))?;
    astral_common::config::install_redis_projection_compat(
        loaded_config.redis_projection_compat_enabled,
    )?;
    let config = Arc::new(loaded_config);
    let db = connect_and_validate_schema(&config.database_url).await?;
    // Grade reads/writes rely on one additive main-owned schema contract. Check
    // the live shape before any Learn repository is made available; older or
    // drifted databases fail startup rather than guessing a legacy assignment.
    validate_default_grade_schema(&db).await?;
    // Learn consumers use the durable MySQL idempotency backend by default.
    astral_mq::consumer::init_idempotency_db(db.clone()).await?;
    let engine = Arc::new(PolicyEngine::new());
    register_audit_db_writer(Arc::new(LearnAuditDbWriter { pool: db.clone() }));
    let rabbitmq_url = config.rabbitmq_url.clone();
    let redis_url = config.redis_url.clone();

    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9002".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let mut producer_owner = None;
    let initialization = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        init_mq_producer(&rabbitmq_url, &redis_url, &mut producer_owner),
    )
    .await;
    let mq_producer = match initialization {
        Ok(Ok(producer)) => Some(producer),
        _ => {
            if let Some(owner) = producer_owner.as_mut() {
                owner.close().await.map_err(anyhow::Error::msg)?;
            }
            producer_owner.take();
            None
        }
    };

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
    let subject_service = Arc::new(SubjectService::with_origin_region(
        subject_repository.clone(),
        config.region_id.clone(),
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
    // RabbitMQ 暂不可用时进行有限重启；预算耗尽即触发服务优雅关闭。
    let pool = state.db.clone();
    let mq_url = state.config.rabbitmq_url.clone();
    let redis_url = state.config.redis_url.clone();
    let subject_service_for_consumer = state.subject_service.clone();
    let relay_pool = state.db.clone();
    let relay_service = state.subject_service.clone();
    let (worker_stop_tx, worker_stop_rx) = tokio::sync::watch::channel(false);
    let relay_worker = LearnTaskHandle::spawn("subject-delete-outbox-relay", async move {
        run_subject_delete_outbox_relay(relay_pool, relay_service, worker_stop_rx).await;
        Ok::<(), String>(())
    });
    let (consumer_stop_tx, consumer_stop_rx) = tokio::sync::watch::channel(false);
    let supervisor_stop_rx = consumer_stop_rx.clone();
    let graceful_consumer_stop_rx = consumer_stop_rx.clone();
    let (consumer_failure_tx, consumer_failure_rx) = tokio::sync::watch::channel(None::<String>);
    let graceful_consumer_failure_rx = consumer_failure_rx.clone();
    let consumer_worker = LearnTaskHandle::spawn("rabbit-consumers", async move {
        let result = run_mq_consumer_supervisor(
            mq_url,
            redis_url,
            pool,
            subject_service_for_consumer,
            supervisor_stop_rx,
        )
        .await;
        if let Err(error) = &result {
            consumer_failure_tx.send_replace(Some(error.clone()));
        }
        result
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

    tracing::info!(addr = %addr, "learn service starting");
    let (http_stop_tx, http_stop_rx) = tokio::sync::oneshot::channel();
    let mut server = std::pin::pin!(std::future::IntoFuture::into_future(
        axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = http_stop_rx.await;
        })
    ));
    let mut signal_error = None;
    let server_result = tokio::select! {
        result = &mut server => result.map_err(anyhow::Error::from),
        signal = tokio::signal::ctrl_c() => {
            signal_error = signal.err().map(|error| error.to_string());
            let _ = http_stop_tx.send(());
            match tokio::time::timeout(std::time::Duration::from_secs(30), &mut server).await {
                Ok(result) => result.map_err(anyhow::Error::from),
                Err(_) => Err(anyhow::anyhow!("Learn HTTP drain timed out; outcome unknown")),
            }
        }
        _ = wait_for_task_exit(&relay_worker) => {
            let _ = http_stop_tx.send(());
            let _ = tokio::time::timeout(std::time::Duration::from_secs(30), &mut server).await;
            Err(anyhow::anyhow!("Learn subject-delete relay exited unexpectedly"))
        }
        _ = wait_for_consumer_failure(graceful_consumer_failure_rx, graceful_consumer_stop_rx) => {
            let _ = http_stop_tx.send(());
            match tokio::time::timeout(std::time::Duration::from_secs(30), &mut server).await {
                Ok(result) => result.map_err(anyhow::Error::from),
                Err(_) => Err(anyhow::anyhow!("Learn HTTP drain timed out; outcome unknown")),
            }
        }
    };
    let _ = worker_stop_tx.send(true);
    let _ = consumer_stop_tx.send(true);
    let relay_result = relay_worker
        .shutdown_join(LEARN_WORKER_SHUTDOWN_BOUND)
        .await;
    let consumer_result = consumer_worker
        .shutdown_join(LEARN_WORKER_SHUTDOWN_BOUND)
        .await;
    let audit_result =
        astral_common::audit::drain_owned_audit_tasks(std::time::Duration::from_secs(3)).await;
    let close_result = match producer_owner.as_mut() {
        Some(owner) => owner.close().await,
        None => Ok(()),
    };
    let mut failures = Vec::new();
    if let Err(error) = server_result {
        failures.push(error.to_string());
    }
    if let Some(error) = signal_error {
        failures.push(format!("Learn signal failed: {error}"));
    }
    if let Some(error) = consumer_failure_rx.borrow().clone() {
        failures.push(error);
    }
    for result in [relay_result, consumer_result] {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) | Err(error) => failures.push(error),
        }
    }
    if let Err(error) = audit_result {
        failures.push(error);
    }
    if let Err(error) = close_result {
        failures.push(error);
    }
    if !failures.is_empty() {
        anyhow::bail!(failures.join("; "));
    }
    Ok(())
}

async fn validate_default_grade_schema(pool: &MySqlPool) -> anyhow::Result<()> {
    let column: Option<(String, String, bool, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT IS NULL, \
                COALESCE(CHARACTER_SET_NAME, ''), COALESCE(COLLATION_NAME, ''), \
                CHARACTER_MAXIMUM_LENGTH \
         FROM INFORMATION_SCHEMA.COLUMNS \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'learn_assignment' \
           AND COLUMN_NAME = 'system_role'",
    )
    .fetch_optional(pool)
    .await?;
    match column {
        Some((data_type, nullable, has_null_default, charset, collation, Some(32)))
            if data_type.eq_ignore_ascii_case("varchar")
                && nullable.eq_ignore_ascii_case("YES")
                && has_null_default
                && charset.eq_ignore_ascii_case("utf8mb4")
                && collation.eq_ignore_ascii_case("utf8mb4_bin") => {}
        _ => {
            anyhow::bail!("learn_assignment.system_role schema contract is missing or incompatible")
        }
    }

    let indexes: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT INDEX_NAME, COLUMN_NAME, NON_UNIQUE, SEQ_IN_INDEX \
         FROM INFORMATION_SCHEMA.STATISTICS \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'learn_assignment' \
           AND INDEX_NAME = 'uk_learn_assignment_course_system_role' \
         ORDER BY SEQ_IN_INDEX",
    )
    .fetch_all(pool)
    .await?;
    let exact = indexes.len() == 2
        && indexes[0].0 == "uk_learn_assignment_course_system_role"
        && indexes[0].1 == "course_id"
        && indexes[0].2 == 0
        && indexes[0].3 == 1
        && indexes[1].0 == "uk_learn_assignment_course_system_role"
        && indexes[1].1 == "system_role"
        && indexes[1].2 == 0
        && indexes[1].3 == 2;
    if !exact {
        anyhow::bail!("learn_assignment DEFAULT_GRADE unique index is missing or incompatible");
    }
    Ok(())
}

const LEARN_CONSUMER_STARTUP_BOUND: std::time::Duration = std::time::Duration::from_secs(30);
const LEARN_RABBIT_CLOSE_BOUND: std::time::Duration = std::time::Duration::from_secs(5);
const LEARN_WORKER_SHUTDOWN_BOUND: std::time::Duration = std::time::Duration::from_secs(12);
const LEARN_LOCAL_DB_CALL_BOUND: std::time::Duration = std::time::Duration::from_secs(3);
const LEARN_LOCAL_DISPATCH_BOUND: std::time::Duration = std::time::Duration::from_secs(120);
const LEARN_HEARTBEAT_JOIN_BOUND: std::time::Duration = std::time::Duration::from_secs(1);

struct LearnTaskHandle<T: Send + 'static = ()> {
    name: &'static str,
    join: Option<tokio::task::JoinHandle<T>>,
}

impl<T: Send + 'static> LearnTaskHandle<T> {
    fn spawn(
        name: &'static str,
        task: impl std::future::Future<Output = T> + Send + 'static,
    ) -> Self {
        Self {
            name,
            join: Some(tokio::spawn(task)),
        }
    }

    async fn shutdown_join(mut self, timeout: std::time::Duration) -> Result<T, String> {
        let Some(join) = self.join.as_mut() else {
            return Err(format!("Learn worker {} has no join handle", self.name));
        };
        let result = match tokio::time::timeout(timeout, &mut *join).await {
            Ok(Ok(output)) => {
                self.join.take();
                Ok(output)
            }
            Ok(Err(error)) => {
                self.join.take();
                Err(format!("Learn worker {} join failed: {error}", self.name))
            }
            Err(_) => {
                join.abort();
                if tokio::time::timeout(std::time::Duration::from_secs(1), &mut *join)
                    .await
                    .is_ok()
                {
                    self.join.take();
                }
                Err(format!(
                    "Learn worker {} shutdown timed out; outcome unknown",
                    self.name
                ))
            }
        };
        result
    }
}

impl<T: Send + 'static> LearnTaskHandle<T> {
    async fn abort_join(self, timeout: std::time::Duration) -> Result<(), String> {
        if let Some(join) = self.join.as_ref() {
            join.abort();
        }
        self.shutdown_join(timeout).await.map(|_| ())
    }

    async fn stop_join(
        self,
        stop: oneshot::Sender<()>,
        timeout: std::time::Duration,
    ) -> Result<T, String> {
        let _ = stop.send(());
        self.shutdown_join(timeout).await
    }
}

impl<T: Send + 'static> Drop for LearnTaskHandle<T> {
    fn drop(&mut self) {
        if let Some(mut join) = self.join.take() {
            join.abort();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(1), &mut join).await;
                });
            }
        }
    }
}

async fn sleep_or_stopped(
    stop: &mut tokio::sync::watch::Receiver<bool>,
    duration: std::time::Duration,
) -> bool {
    if *stop.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        changed = stop.changed() => changed.is_err() || *stop.borrow(),
    }
}

async fn run_mq_consumer_supervisor(
    rabbitmq_url: String,
    redis_url: String,
    pool: MySqlPool,
    subject_service: Arc<SubjectService>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    const MAX_CONSUMER_RESTARTS: u32 = 5;
    let mut attempt: u32 = 0;
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        let mut consumers = LearnMqConsumers {
            tasks: tokio::task::JoinSet::new(),
            owner: LearnRabbitOwner(None),
        };
        let startup = {
            let startup = tokio::time::timeout(
                LEARN_CONSUMER_STARTUP_BOUND,
                init_mq_consumers(
                    &rabbitmq_url,
                    &redis_url,
                    pool.clone(),
                    subject_service.clone(),
                    &mut consumers,
                ),
            );
            tokio::pin!(startup);
            tokio::select! {
                result = &mut startup => Some(result),
                _ = wait_for_stop(stop.clone()) => None,
            }
        };
        match startup {
            Some(Ok(Ok(()))) if !*stop.borrow() => {
                tracing::info!(service = "learn", "Learn-owned Rabbit consumers registered");
                tokio::select! {
                    _ = wait_for_stop(stop.clone()) => {
                        consumers.shutdown().await?;
                        return Ok(());
                    }
                    result = consumers.tasks.join_next() => {
                        match result {
                            Some(Ok(Err(_))) | Some(Err(_)) | Some(Ok(Ok(()))) | None => {
                                consumers.shutdown().await?;
                                attempt = attempt.saturating_add(1);
                                if attempt >= MAX_CONSUMER_RESTARTS {
                                    return Err("Learn Rabbit consumer stream restart budget exhausted".into());
                                }
                                tracing::warn!(service = "learn", attempt, "Learn Rabbit consumer stream ended; bounded restart follows");
                            }
                        }
                    }
                }
            }
            other => {
                consumers.shutdown().await?;
                if *stop.borrow() {
                    return if matches!(other, Some(Ok(Ok(())))) {
                        Ok(())
                    } else {
                        Err(
                            "Learn consumer startup interrupted; connection outcome unproven"
                                .into(),
                        )
                    };
                }
                if matches!(other, Some(Err(_)) | None) {
                    return Err(
                        "Learn consumer startup timed out or was cancelled; outcome unknown".into(),
                    );
                }
                attempt = attempt.saturating_add(1);
                if attempt >= MAX_CONSUMER_RESTARTS {
                    return Err("Learn Rabbit consumer startup restart budget exhausted".into());
                }
                tracing::warn!(
                    service = "learn",
                    attempt,
                    "Learn Rabbit consumer startup failed; bounded restart follows"
                );
            }
        }
        let backoff_secs = 2u64.pow(attempt.min(5));
        if sleep_or_stopped(&mut stop, std::time::Duration::from_secs(backoff_secs)).await {
            return Ok(());
        }
    }
}

async fn wait_for_task_exit<T: Send + 'static>(task: &LearnTaskHandle<T>) {
    loop {
        if task.join.as_ref().is_none_or(|join| join.is_finished()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn wait_for_stop(mut stop: tokio::sync::watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            return;
        }
        if stop.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_for_consumer_failure(
    mut failure: tokio::sync::watch::Receiver<Option<String>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        if failure.borrow().is_some() || *stop.borrow() {
            return;
        }
        tokio::select! {
            changed = failure.changed() => if changed.is_err() { return; },
            changed = stop.changed() => if changed.is_err() || *stop.borrow() { return; },
        }
    }
}

async fn run_subject_delete_outbox_relay(
    pool: MySqlPool,
    service: Arc<SubjectService>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let repository = LocalMessageRepository::new(pool);
    let worker_id = format!("learn-subject-delete-{}", uuid::Uuid::new_v4());
    loop {
        if *stop.borrow() {
            return;
        }
        let claimed = tokio::time::timeout(
            LEARN_LOCAL_DB_CALL_BOUND,
            repository.claim_batch(&worker_id, QUEUE_SUBJECT_DELETE, 1),
        )
        .await;
        match claimed {
            Ok(Ok(rows)) if rows.is_empty() => {
                if sleep_or_stopped(&mut stop, std::time::Duration::from_millis(500)).await {
                    return;
                }
            }
            Ok(Ok(rows)) => {
                for row in rows {
                    if *stop.borrow() {
                        return; // Leave the lease for expiry/recovery, never ACK early.
                    }
                    let lease_token = row.lease_owner.clone().unwrap_or_default();
                    if !matches!(
                        tokio::time::timeout(
                            LEARN_LOCAL_DB_CALL_BOUND,
                            repository.heartbeat(&row.message_id, &lease_token),
                        )
                        .await,
                        Ok(Ok(()))
                    ) {
                        tracing::error!(message_id = %row.message_id, "subject delete lease proof unavailable before dispatch; no cleanup attempted");
                        return;
                    }
                    let (heartbeat_stop_tx, heartbeat_stop_rx) = tokio::sync::oneshot::channel();
                    let (heartbeat_failure_tx, mut heartbeat_failure_rx) =
                        tokio::sync::watch::channel(None::<String>);
                    let heartbeat_repo = repository.clone();
                    let heartbeat_id = row.message_id.clone();
                    let heartbeat_token = lease_token.clone();
                    let mut heartbeat = Some(LearnTaskHandle::spawn(
                        "subject-delete-lease-heartbeat",
                        async move {
                            let mut heartbeat_stop_rx = heartbeat_stop_rx;
                            let interval = std::time::Duration::from_secs(
                                (LOCAL_MESSAGE_LEASE_SECONDS / 3).max(1),
                            );
                            loop {
                                tokio::select! {
                                    _ = tokio::time::sleep(interval) => {
                                        let heartbeat_ok = matches!(
                                            tokio::time::timeout(
                                                LEARN_LOCAL_DB_CALL_BOUND,
                                                heartbeat_repo.heartbeat(&heartbeat_id, &heartbeat_token),
                                            ).await,
                                            Ok(Ok(()))
                                        );
                                        if !heartbeat_ok {
                                            let reason = "subject delete lease heartbeat failed or timed out".to_owned();
                                            heartbeat_failure_tx.send_replace(Some(reason.clone()));
                                            return Err(reason);
                                        }
                                    }
                                    _ = &mut heartbeat_stop_rx => return Ok(()),
                                }
                            }
                        },
                    ));
                    let mut dispatch = Box::pin(tokio::time::timeout(
                        LEARN_LOCAL_DISPATCH_BOUND,
                        dispatch_subject_delete_outbox_row(&service, &row),
                    ));
                    let mut lease_lost = false;
                    let result = tokio::select! {
                        result = &mut dispatch => result
                            .unwrap_or_else(|_| Err("subject delete dispatch timed out; cleanup outcome unknown".into())),
                        changed = heartbeat_failure_rx.changed() => {
                            lease_lost = true;
                            let reason = heartbeat_failure_rx.borrow().clone()
                                .unwrap_or_else(|| "subject delete heartbeat stopped unexpectedly".into());
                            let _ = changed;
                            Err(format!("{reason}; cascade outcome remains unknown"))
                        }
                    };
                    if lease_lost {
                        if let Some(heartbeat) = heartbeat.take() {
                            let _ = heartbeat.abort_join(LEARN_HEARTBEAT_JOIN_BOUND).await;
                        }
                        tracing::error!(message_id = %row.message_id, error = ?result.as_ref().err(), "subject delete heartbeat failed; preserving leased row for unknown-outcome reconciliation");
                    }
                    let heartbeat_result = if lease_lost {
                        Err("lease heartbeat failed; no settlement allowed".into())
                    } else if let Some(heartbeat) = heartbeat.take() {
                        heartbeat
                            .stop_join(heartbeat_stop_tx, LEARN_HEARTBEAT_JOIN_BOUND)
                            .await
                    } else {
                        Err("lease heartbeat task handle missing".into())
                    };
                    let result = match heartbeat_result {
                        Ok(Ok(())) => result,
                        Ok(Err(error)) | Err(error) => Err(format!(
                            "{error}; subject delete cleanup outcome requires idempotent reconciliation"
                        )),
                    };
                    let settlement: Result<(), String> = if lease_lost {
                        Err("lease lost; durable outbox state left untouched".into())
                    } else {
                        match result {
                            Ok(()) => match tokio::time::timeout(
                                LEARN_LOCAL_DB_CALL_BOUND,
                                repository.complete(&row.message_id, &lease_token),
                            )
                            .await
                            {
                                Ok(Ok(())) => Ok(()),
                                Ok(Err(error)) => Err(error.to_string()),
                                Err(_) => Err("complete timed out".into()),
                            },
                            Err(error) => match tokio::time::timeout(
                                LEARN_LOCAL_DB_CALL_BOUND,
                                repository.mark_in_doubt(&row.message_id, &lease_token, &error),
                            )
                            .await
                            {
                                Ok(Ok(())) => Ok(()),
                                Ok(Err(error)) => Err(error.to_string()),
                                Err(_) => Err("IN_DOUBT settlement timed out".into()),
                            },
                        }
                    };
                    if let Err(error) = settlement {
                        tracing::error!(message_id = %row.message_id, %error, "subject delete intent settlement unproven; lease expiry remains the recovery path");
                    }
                }
            }
            _ => {
                tracing::error!(
                    "subject delete outbox claim failed or timed out; worker remains fail-closed"
                );
                if sleep_or_stopped(&mut stop, std::time::Duration::from_secs(1)).await {
                    return;
                }
            }
        }
    }
}

async fn dispatch_subject_delete_outbox_row(
    service: &SubjectService,
    row: &astral_db::LocalMessageRow,
) -> Result<(), String> {
    if row.queue_name != QUEUE_SUBJECT_DELETE
        || row.message_type != "SUBJECT_DELETE"
        || row.headers_json.is_some()
    {
        return Err(
            "subject delete intent metadata does not match the Learn relay contract".into(),
        );
    }
    let envelope: MessageEnvelope = serde_json::from_str(&row.payload_json)
        .map_err(|error| format!("subject delete intent JSON invalid: {error}"))?;
    envelope.validate()?;
    if envelope.envelope_json()? != row.payload_json
        || envelope.message_id != row.message_id
        || envelope.operation_id != row.operation_id
        || envelope.message_type != row.message_type
        || envelope.tenant_id != row.tenant_id
        || envelope.origin_region != row.origin_region
        || envelope.target_region.as_deref() != row.target_region.as_deref()
        || envelope.schema_version != row.schema_version
        || envelope.ordering_key.as_deref() != row.ordering_key.as_deref()
        || envelope.payload_sha256 != row.payload_sha256
    {
        return Err("subject delete intent envelope differs from durable row".into());
    }
    let payload: SubjectDeletePayload = serde_json::from_value(envelope.payload)
        .map_err(|error| format!("subject delete payload invalid: {error}"))?;
    if !payload.cascade_delete {
        return Err("subject delete outbox currently handles cascade intents only".into());
    }
    match service
        .process_delete_message(payload.subject_id, payload.cascade_delete)
        .await
    {
        Ok(SubjectDeleteOutcome::CascadeDeleted | SubjectDeleteOutcome::Skipped) => Ok(()),
        Ok(SubjectDeleteOutcome::HardDeleted) => {
            Err("cascade intent unexpectedly completed a hard delete".into())
        }
        Err(error) => Err(error.to_string()),
    }
}

async fn confirm_subject_delete_receipt(
    pool: &MySqlPool,
    message_id: &str,
    payload: &SubjectDeletePayload,
) -> Result<(), String> {
    let row: Option<(String, String)> = tokio::time::timeout(
        LEARN_LOCAL_DB_CALL_BOUND,
        sqlx::query_as(
            "SELECT status, payload_json FROM al_message_outbox \
            WHERE queue_name = ? AND message_id = ? AND message_type = 'SUBJECT_DELETE'",
        )
        .bind(QUEUE_SUBJECT_DELETE)
        .bind(message_id)
        .fetch_optional(pool),
    )
    .await
    .map_err(|_| "subject delete receipt lookup timed out".to_owned())?
    .map_err(|_| "subject delete receipt lookup unavailable".to_owned())?;
    let Some((status, serialized)) = row else {
        return Err("subject delete notification has no committed local intent".into());
    };
    let envelope: MessageEnvelope = serde_json::from_str(&serialized)
        .map_err(|_| "subject delete receipt envelope is invalid".to_owned())?;
    envelope.validate()?;
    if status != "PROCESSED"
        || envelope.message_id != message_id
        || envelope.message_type != "SUBJECT_DELETE"
        || envelope.envelope_json()? != serialized
        || envelope.payload
            != serde_json::to_value(payload)
                .map_err(|_| "invalid subject deletion payload".to_owned())?
    {
        return Err("subject delete notification lacks exact durable completion proof".into());
    }
    Ok(())
}

async fn init_mq_producer(
    rabbitmq_url: &str,
    redis_url: &str,
    owner: &mut Option<LearnRabbitOwner>,
) -> Result<astral_mq::producer::Producer, String> {
    if astral_common::config::redis_projection_compat_frozen() {
        #[cfg(feature = "redis-compat")]
        astral_mq::consumer::init_idempotency_redis(redis_url)
            .await
            .map_err(|_| "Learn Redis idempotency initialization failed".to_owned())?;
        #[cfg(not(feature = "redis-compat"))]
        return Err("Learn Redis compatibility adapter is unavailable".into());
    }
    let _ = redis_url;
    let connection = Arc::new(
        Connection::connect(
            rabbitmq_url,
            lapin::ConnectionProperties::default().enable_auto_recover(),
        )
        .await
        .map_err(|_| "Learn Rabbit connection failed".to_owned())?,
    );
    *owner = Some(LearnRabbitOwner(Some(connection.clone())));
    let channel = connection
        .create_channel()
        .await
        .map_err(|_| "Learn Rabbit producer channel failed".to_owned())?;
    astral_mq::producer::Producer::enable_confirms(&channel)
        .await
        .map_err(|_| "Learn publisher confirmation setup failed".to_owned())?;
    let producer = astral_mq::producer::Producer::new(channel);
    register_mq_producer(Arc::new(LearnMqProducer {
        inner: producer.clone(),
    }));
    Ok(producer)
}

struct LearnMqConsumers {
    tasks: tokio::task::JoinSet<Result<(), String>>,
    owner: LearnRabbitOwner,
}

impl LearnMqConsumers {
    async fn shutdown(&mut self) -> Result<(), String> {
        self.tasks.abort_all();
        let drain = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while self.tasks.join_next().await.is_some() {}
        })
        .await;
        let close = self.owner.close().await;
        if drain.is_err() {
            return Err("Learn consumer drain outcome unknown".into());
        }
        close
    }
}

/// Register the required Rabbit consumer set on a private channel. General audit
/// and login queues are owned by TrustGraph and Identity respectively; Learn only
/// registers its subject-delete relay alongside its local durable dispatcher.
async fn init_mq_consumers(
    rabbitmq_url: &str,
    redis_url: &str,
    pool: MySqlPool,
    _subject_service: Arc<SubjectService>,
    consumers: &mut LearnMqConsumers,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if astral_common::config::redis_projection_compat_frozen() {
        #[cfg(feature = "redis-compat")]
        astral_mq::consumer::init_idempotency_redis(redis_url).await?;
        #[cfg(not(feature = "redis-compat"))]
        return Err("Redis idempotency compat requested without Learn redis-compat feature".into());
    }
    let _ = redis_url;
    let connection = Arc::new(
        Connection::connect(
            rabbitmq_url,
            lapin::ConnectionProperties::default().enable_auto_recover(),
        )
        .await?,
    );
    consumers.owner = LearnRabbitOwner(Some(connection.clone()));
    let channel = connection.create_channel().await?;
    astral_mq::config::declare_all(&channel)
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    // Rabbit deliveries are notifications of committed work, never deletion authority.
    let consumer = Consumer::new_with_message_id(
        channel,
        move |message_id: &str, payload: &SubjectDeletePayload| {
            let pool = pool.clone();
            let message_id = message_id.to_owned();
            let payload = payload.clone();
            async move {
                confirm_subject_delete_receipt(&pool, &message_id, &payload)
                    .await
                    .map_err(|error| {
                        Box::new(std::io::Error::other(error)) as Box<dyn std::error::Error + Send>
                    })
            }
        },
        QUEUE_SUBJECT_DELETE,
    );
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    consumers.tasks.spawn(async move {
        consumer
            .start_with_readiness(Some(ready_tx))
            .await
            .map_err(|error| error.to_string())
    });
    ready_rx
        .await
        .map_err(|_| "subject delete consumer task ended before registration".to_owned())?
        .map_err(|_| "subject delete consumer registration failed".to_owned())?;

    // Notification and learning-progress queues have no authoritative Learn
    // handler; leave them unregistered rather than ACK/drop. Audit and login stay
    // owned by TrustGraph and Identity, so Learn registers only subject deletion.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn owned_task_terminal_result_is_consumed_once() {
        let task = LearnTaskHandle::spawn("terminal", async { 7 });
        assert_eq!(
            task.shutdown_join(std::time::Duration::from_secs(1))
                .await
                .unwrap(),
            7
        );
    }

    #[tokio::test]
    async fn cancelled_join_keeps_owned_task_until_abort() {
        struct DropSignal(Option<oneshot::Sender<()>>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }
        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let task = LearnTaskHandle::spawn("cancel", async move {
            let _drop = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        {
            let mut shutdown =
                std::pin::pin!(task.shutdown_join(std::time::Duration::from_secs(5)));
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), &mut shutdown)
                    .await
                    .is_err()
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn consumer_startup_keeps_partial_owner_for_awaited_cleanup() {
        let source = include_str!("main.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let supervisor = source
            .split("async fn run_mq_consumer_supervisor(")
            .nth(1)
            .unwrap()
            .split("async fn wait_for_task_exit")
            .next()
            .unwrap();
        assert!(
            supervisor
                .find("let mut consumers = LearnMqConsumers")
                .unwrap()
                < supervisor.find("init_mq_consumers(").unwrap()
        );
        assert!(supervisor.contains("_ = wait_for_stop(stop.clone()) => None"));
        assert!(supervisor.contains("consumers.shutdown().await?"));
        assert!(supervisor.contains("connection outcome unproven"));
        let initializer = source.split("async fn init_mq_consumers(").nth(1).unwrap();
        assert!(
            initializer
                .find("consumers.owner = LearnRabbitOwner")
                .unwrap()
                < initializer.find("create_channel()").unwrap()
        );
        assert!(initializer.contains("consumers.tasks.spawn("));
        const {
            assert!(LEARN_WORKER_SHUTDOWN_BOUND.as_secs() > 2 + LEARN_RABBIT_CLOSE_BOUND.as_secs());
        }
        let schema = source
            .split("async fn validate_default_grade_schema(")
            .nth(1)
            .unwrap()
            .split("const LEARN_CONSUMER_STARTUP_BOUND")
            .next()
            .unwrap();
        assert!(schema.contains("CHARACTER_MAXIMUM_LENGTH"));
        assert!(schema.contains("Some(32)"));
    }

    #[test]
    fn relay_errors_never_replay_and_broker_payload_is_not_source_authority() {
        let source = include_str!("main.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let relay = source
            .split("async fn run_subject_delete_outbox_relay(")
            .nth(1)
            .unwrap()
            .split("async fn dispatch_subject_delete_outbox_row(")
            .next()
            .unwrap();
        assert!(relay.contains("mark_in_doubt("));
        assert!(!relay.contains("schedule_retry("));
        assert!(!relay.contains("quarantine("));
        let consumer = source.split("async fn init_mq_consumers(").nth(1).unwrap();
        assert!(consumer.contains("confirm_subject_delete_receipt("));
        assert!(!consumer.contains("process_delete_message("));
        assert!(source.contains("LearnRabbitOwner"));
        assert!(source.contains("Learn HTTP drain timed out; outcome unknown"));
    }

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
        let supervisor_start = source.find("async fn run_mq_consumer_supervisor(").unwrap();
        let supervisor_end = source[supervisor_start..]
            .find("async fn wait_for_task_exit")
            .map(|offset| supervisor_start + offset)
            .unwrap();
        let blocks = [
            &source[bootstrap_start..bootstrap_end],
            &source[init_start..init_end],
            &source[supervisor_start..supervisor_end],
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
        assert!(!calls.is_empty(), "review every Learn MQ tracing call");
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
        assert!(source.contains("init_mq_consumers("));
        assert!(blocks[0].contains("run_subject_delete_outbox_relay"));
        assert!(blocks[0].contains("LearnTaskHandle::spawn"));
        assert!(blocks[0].contains("consumer_failure_tx"));
        assert!(!blocks[0].contains(".ok();"));
        assert!(blocks[1].contains("QUEUE_SUBJECT_DELETE"));
        assert!(source.contains("init_idempotency_db"));
        assert!(source.contains("wait_for_consumer_failure"));
        assert!(source.contains("MAX_CONSUMER_RESTARTS"));
        assert!(source.contains("stop_join"));
        assert!(!source.contains("tokio::spawn(async move {\n                        let interval"));
        assert!(source.contains("LEARN_LOCAL_DISPATCH_BOUND"));
        assert!(source.contains("wait_for_consumer_failure"));
        assert!(source.contains("MAX_CONSUMER_RESTARTS"));
        assert!(source.contains("LEARN_LOCAL_DISPATCH_BOUND"));
        assert!(!blocks[1].contains("start_all_consumers"));
    }
}
