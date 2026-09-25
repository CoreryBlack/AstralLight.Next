//! 公告与讨论区 — HTTP adapter
//!
//! 课程公告、学生讨论帖。数据访问在 `repository::discussion_repository`。
//! 基于 `learn_announcement` + `learn_discussion_post` 表实现真实 DB CRUD。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Announcement {
    pub id: Option<i64>,
    pub course_id: i64,
    pub title: String,
    pub content: String,
    pub author_id: i64,
    pub pinned: bool,
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscussionPost {
    pub id: Option<i64>,
    pub course_id: i64,
    pub title: String,
    pub content: String,
    pub author_id: i64,
    pub reply_count: i32,
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAnnouncementsQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDiscussionsQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn discussion_routes() -> Router<AppState> {
    Router::new()
        .route("/announcements", get(list_announcements))
        .route("/announcements", post(create_announcement))
        .route("/announcements/{id}", get(get_announcement))
        .route("/announcements/{id}", put(update_announcement))
        .route("/announcements/{id}", delete(delete_announcement))
        .route("/discussions", get(list_discussions))
        .route("/discussions", post(create_discussion))
        .route("/discussions/{id}", get(get_discussion))
        .route("/discussions/{id}", delete(delete_discussion))
}

async fn list_announcements(
    State(state): State<AppState>,
    Query(query): Query<ListAnnouncementsQuery>,
) -> Result<Json<ApiResponse<PageResponse<Announcement>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.discussion_repository.count_announcements().await?;
    let items = state
        .discussion_repository
        .list_announcements(size, offset)
        .await?
        .into_iter()
        .map(|r| Announcement {
            id: Some(r.id),
            course_id: r.course_id,
            title: r.title,
            content: r.content,
            author_id: r.author_id,
            pinned: r.pinned,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn create_announcement(
    State(state): State<AppState>,
    Json(req): Json<Announcement>,
) -> Result<Json<ApiResponse<Announcement>>, AppError> {
    let id = state
        .discussion_repository
        .create_announcement(
            req.course_id,
            &req.title,
            &req.content,
            req.author_id,
            req.pinned,
        )
        .await?;
    Ok(Json(ApiResponse::success(Announcement {
        id: Some(id),
        course_id: req.course_id,
        title: req.title,
        content: req.content,
        author_id: req.author_id,
        pinned: req.pinned,
        created_at: None,
    })))
}

async fn get_announcement(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Announcement>>, AppError> {
    let r = state
        .discussion_repository
        .get_announcement(id)
        .await?
        .ok_or_else(|| {
            astral_types::AstralError::Validation(format!("Announcement {id} not found"))
        })?;
    Ok(Json(ApiResponse::success(Announcement {
        id: Some(r.id),
        course_id: r.course_id,
        title: r.title,
        content: r.content,
        author_id: r.author_id,
        pinned: r.pinned,
        created_at: r.created_at,
    })))
}

async fn update_announcement(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<Announcement>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state
        .discussion_repository
        .update_announcement(id, &req.title, &req.content, req.pinned)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_announcement(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.discussion_repository.delete_announcement(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_discussions(
    State(state): State<AppState>,
    Query(query): Query<ListDiscussionsQuery>,
) -> Result<Json<ApiResponse<PageResponse<DiscussionPost>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.discussion_repository.count_discussions().await?;
    let items = state
        .discussion_repository
        .list_discussions(size, offset)
        .await?
        .into_iter()
        .map(|r| DiscussionPost {
            id: Some(r.id),
            course_id: r.course_id,
            title: r.title,
            content: r.content,
            author_id: r.author_id,
            reply_count: 0,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn create_discussion(
    State(state): State<AppState>,
    Json(req): Json<DiscussionPost>,
) -> Result<Json<ApiResponse<DiscussionPost>>, AppError> {
    let id = state
        .discussion_repository
        .create_discussion(req.course_id, &req.title, &req.content, req.author_id)
        .await?;
    Ok(Json(ApiResponse::success(DiscussionPost {
        id: Some(id),
        course_id: req.course_id,
        title: req.title,
        content: req.content,
        author_id: req.author_id,
        reply_count: 0,
        created_at: None,
    })))
}

async fn get_discussion(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<DiscussionPost>>, AppError> {
    let r = state
        .discussion_repository
        .get_discussion(id)
        .await?
        .ok_or_else(|| {
            astral_types::AstralError::Validation(format!("Discussion {id} not found"))
        })?;
    Ok(Json(ApiResponse::success(DiscussionPost {
        id: Some(r.id),
        course_id: r.course_id,
        title: r.title,
        content: r.content,
        author_id: r.author_id,
        reply_count: 0,
        created_at: r.created_at,
    })))
}

async fn delete_discussion(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.discussion_repository.delete_discussion(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
