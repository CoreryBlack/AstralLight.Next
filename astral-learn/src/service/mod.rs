//! 教育域应用服务层（对齐 Java `Learn*ServiceImpl` 编排边界）
//!
//! Service 为具体 struct（非 trait），注入 `Arc<dyn Repository>`；
//! MQ 副作用经 `SubjectDeleteSideEffects` 注入。

pub mod app_user_service;
pub mod assignment_service;
pub mod checkin_service;
pub mod exam_service;
pub mod grade_service;
pub mod level_service;
pub mod progress_service;
pub mod publishing_service;
pub mod subject_service;
