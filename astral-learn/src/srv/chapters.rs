//! 章节管理 API（独立于课程）
//!
//! 对应 Java `ChaptersController`。表: `learn_chapter`（platform_v4）。
//! 数据访问在 `repository::course_repository`（章节删除级联单事务在此层）。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

use crate::repository::course_repository::ChapterInput;
use crate::AppState;

#[derive(Debug, sqlx::FromRow)]
pub struct ChapterRow {
    pub id: i64,
    pub course_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub sort_order: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChapterDto {
    pub id: Option<i64>,
    pub course_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub sort_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListChaptersQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn chapter_routes() -> Router<AppState> {
    Router::new()
        .route("/chapters", get(list_chapters))
        .route("/chapters", post(create_chapter))
        .route("/chapters/{id}", get(get_chapter))
        .route("/chapters/{id}", put(update_chapter))
        .route("/chapters/{id}", delete(delete_chapter))
}

async fn list_chapters(
    State(state): State<AppState>,
    Query(query): Query<ListChaptersQuery>,
) -> Result<Json<ApiResponse<PageResponse<ChapterDto>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.course_repository.count_chapters().await?;
    let rows = state
        .course_repository
        .list_chapters_page(size, offset)
        .await?;
    let items = rows
        .into_iter()
        .map(|r| ChapterDto {
            id: Some(r.id),
            course_id: r.course_id,
            title: r.title,
            description: r.description,
            sort_order: Some(r.sort_order),
        })
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn create_chapter(
    State(state): State<AppState>,
    Json(req): Json<ChapterDto>,
) -> Result<Json<ApiResponse<ChapterDto>>, AppError> {
    let input = ChapterInput {
        title: req.title.clone(),
        description: req.description.clone(),
        sort_order: req.sort_order.unwrap_or(0),
    };
    let new_id = state
        .course_repository
        .create_chapter(req.course_id, &input)
        .await?;
    Ok(Json(ApiResponse::success(ChapterDto {
        id: Some(new_id),
        ..req
    })))
}

async fn get_chapter(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<ChapterDto>>, AppError> {
    let r = state
        .course_repository
        .get_chapter(id)
        .await?
        .ok_or_else(|| {
            AppError(astral_types::AstralError::Internal(
                "Chapter not found".into(),
            ))
        })?;
    Ok(Json(ApiResponse::success(ChapterDto {
        id: Some(r.id),
        course_id: r.course_id,
        title: r.title,
        description: r.description,
        sort_order: Some(r.sort_order),
    })))
}

async fn update_chapter(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<ChapterDto>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state
        .course_repository
        .update_chapter(
            id,
            &ChapterInput {
                title: req.title,
                description: req.description,
                sort_order: req.sort_order.unwrap_or(0),
            },
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_chapter(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // 级联单事务（先删课时再删章节）在 course_repository
    state.course_repository.delete_chapter(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
