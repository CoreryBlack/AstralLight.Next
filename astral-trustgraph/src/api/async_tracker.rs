//! 统一异步操作追踪器
//!
//! 所有 async 端点（scan/async, apply/async, bind/async）共享同一个任务注册表。
//! 内存存储 + TTL 自动过期，可选持久化到 async_operation 表。
//!
//! 对齐 Java AsyncOperationTrackerService：
//! - 任务创建时状态 PENDING
//! - 后台任务执行时状态 RUNNING → COMPLETED/FAILED
//! - 查询时返回当前状态 + 进度

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// 异步操作状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

/// 异步操作记录
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsyncTask {
    pub task_id: String,
    pub task_type: String,
    pub status: TaskStatus,
    pub total: Option<usize>,
    pub completed: Option<usize>,
    pub error_message: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// 内存任务注册表（带 TTL 自动过期）
pub struct AsyncOperationTracker {
    tasks: RwLock<HashMap<String, AsyncTask>>,
    ttl: Duration,
}

impl Default for AsyncOperationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncOperationTracker {
    pub fn new() -> Self {
        Self {
            tasks: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(3600), // 默认 1 小时过期
        }
    }

    /// 注册新任务
    pub async fn register(
        &self,
        task_id: &str,
        task_type: &str,
        total: Option<usize>,
    ) -> AsyncTask {
        let now = epoch_millis();
        let task = AsyncTask {
            task_id: task_id.to_string(),
            task_type: task_type.to_string(),
            status: TaskStatus::Pending,
            total,
            completed: Some(0),
            error_message: None,
            created_at: now,
            updated_at: now,
        };
        self.tasks
            .write()
            .await
            .insert(task_id.to_string(), task.clone());
        task
    }

    /// 查询任务状态
    pub async fn get(&self, task_id: &str) -> Option<AsyncTask> {
        // 惰性清理过期任务
        self.evict_expired().await;
        self.tasks.read().await.get(task_id).cloned()
    }

    /// 更新任务状态为 RUNNING
    pub async fn start(&self, task_id: &str) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.status = TaskStatus::Running;
            task.updated_at = epoch_millis();
        }
    }

    /// 更新任务进度
    pub async fn update_progress(&self, task_id: &str, completed: usize) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.completed = Some(completed);
            task.updated_at = epoch_millis();
        }
    }

    /// 标记任务完成
    pub async fn complete(&self, task_id: &str) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.status = TaskStatus::Completed;
            task.completed = task.total;
            task.updated_at = epoch_millis();
        }
    }

    /// 标记任务失败
    pub async fn fail(&self, task_id: &str, error: &str) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.get_mut(task_id) {
            task.status = TaskStatus::Failed;
            task.error_message = Some(error.to_string());
            task.updated_at = epoch_millis();
        }
    }

    /// 惰性清理过期任务
    async fn evict_expired(&self) {
        let cutoff = epoch_millis() - self.ttl.as_millis() as i64;
        let mut tasks = self.tasks.write().await;
        tasks.retain(|_, t| t.created_at > cutoff);
    }
}

/// 全局单例
static TRACKER: once_cell::sync::Lazy<AsyncOperationTracker> =
    once_cell::sync::Lazy::new(AsyncOperationTracker::new);

/// 获取全局 tracker 实例
pub fn tracker() -> &'static AsyncOperationTracker {
    &TRACKER
}

/// 生成 task_id（类型前缀 + 时间戳）
pub fn generate_task_id(prefix: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}_{:016x}", prefix, ts)
}

fn epoch_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
