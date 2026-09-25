//! 教育域数据访问层（对齐 Java `Learn*Mapper` 边界）
//!
//! Repository 返回领域 record + `AstralError`，不返回 Axum/HTTP 类型；
//! 多表事务（学科级联删除、章节级联删除、批量导入）收敛为 repository 聚合方法；
//! MQ 发布等副作用由 service 编排。

pub mod app_user_repository;
pub mod assignment_repository;
pub mod checkin_repository;
pub mod class_repository;
pub mod course_repository;
pub mod device_repository;
pub mod discussion_repository;
pub mod document_repository;
pub mod enrollment_repository;
pub mod exam_repository;
pub mod level_repository;
pub mod progress_repository;
pub mod publishing_repository;
pub mod question_repository;
pub mod solution_repository;
pub mod statistics_repository;
pub mod subject_repository;
pub mod system_setting_repository;
pub mod user_answer_repository;
pub mod user_subject_repository;
pub mod webhook_config_repository;
pub mod wrong_question_repository;
