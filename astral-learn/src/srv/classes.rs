//! 班级管理 API — HTTP adapter
//!
//! 对应 Java `ClassController`。数据访问在 `repository::class_repository`。
//! 表: `class`

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::repository::class_repository::ClassInput;
use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct ClassRow {
    pub id: i64,
    pub name: String,
    pub code: Option<String>,
    pub subject_id: Option<i64>,
    pub teacher_id: Option<i64>,
    pub description: Option<String>,
}

impl From<crate::repository::class_repository::ClassRecord> for ClassRow {
    fn from(r: crate::repository::class_repository::ClassRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            code: r.code,
            subject_id: r.subject_id,
            teacher_id: r.teacher_id,
            description: r.description,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassDto {
    pub id: Option<i64>,
    pub name: String,
    pub code: Option<String>,
    pub subject_id: Option<i64>,
    pub teacher_id: Option<i64>,
    pub description: Option<String>,
}

impl From<ClassRow> for ClassDto {
    fn from(r: ClassRow) -> Self {
        ClassDto {
            id: Some(r.id),
            name: r.name,
            code: r.code,
            subject_id: r.subject_id,
            teacher_id: r.teacher_id,
            description: r.description,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListClassesQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn class_routes() -> Router<AppState> {
    Router::new()
        .route("/classes", get(list_classes))
        .route("/classes", post(create_class))
        .route("/classes/{id}", get(get_class))
        .route("/classes/{id}", put(update_class))
        .route("/classes/{id}", delete(delete_class))
        .route("/classes/{id}/students", get(list_class_students))
}

fn to_input(req: &ClassDto) -> ClassInput {
    ClassInput {
        name: req.name.clone(),
        code: req.code.clone(),
        subject_id: req.subject_id,
        teacher_id: req.teacher_id,
        description: req.description.clone(),
    }
}

async fn list_classes(
    State(state): State<AppState>,
    Query(query): Query<ListClassesQuery>,
) -> Result<Json<ApiResponse<PageResponse<ClassDto>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.class_repository.count_all().await?;
    let items = state
        .class_repository
        .list_all(size, offset)
        .await?
        .into_iter()
        .map(ClassRow::from)
        .map(ClassDto::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn create_class(
    State(state): State<AppState>,
    Json(req): Json<ClassDto>,
) -> Result<Json<ApiResponse<ClassDto>>, AppError> {
    let id = state.class_repository.create(&to_input(&req)).await?;
    Ok(Json(ApiResponse::success(ClassDto {
        id: Some(id),
        ..req
    })))
}

async fn get_class(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<ClassDto>>, AppError> {
    let row = state
        .class_repository
        .get(id)
        .await?
        .map(ClassRow::from)
        .ok_or_else(|| {
            AppError(astral_types::AstralError::Internal(
                "Class not found".into(),
            ))
        })?;
    Ok(Json(ApiResponse::success(ClassDto::from(row))))
}

async fn update_class(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<ClassDto>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.class_repository.update(id, &to_input(&req)).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_class(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.class_repository.delete(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_class_students(
    State(_state): State<AppState>,
    Path(_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<i64>>>, AppError> {
    // 保留原 stub 语义（无 DB）
    Ok(Json(ApiResponse::success(vec![42, 43, 44, 45, 46])))
}
