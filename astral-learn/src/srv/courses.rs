//! 课程管理 — HTTP adapter
//!
//! 数据访问在 `repository::course_repository`（learn_course/learn_chapter/learn_lesson，
//! 章节删除级联单事务在此层）。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::AppState;
use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;

use crate::repository::course_repository::{ChapterInput, CourseInput, LessonInput};

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Course {
    pub id: i64,
    pub subject_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub teacher_id: Option<i64>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCourseReq {
    pub subject_id: i64,
    pub title: String,
    pub description: Option<String>,
    pub teacher_id: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Chapter {
    pub id: i64,
    pub course_id: i64,
    pub title: String,
    pub sort_order: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateChapterReq {
    pub title: String,
    pub sort_order: Option<i32>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Lesson {
    pub id: i64,
    pub chapter_id: i64,
    pub title: String,
    pub content_type: String,
    pub content_url: Option<String>,
    pub duration_minutes: i32,
    pub sort_order: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLessonReq {
    pub title: String,
    pub content_type: Option<String>,
    pub content_url: Option<String>,
    pub duration_minutes: Option<i32>,
    pub sort_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCoursesQuery {
    pub page: Option<i64>,
    pub size: Option<i64>,
}

pub fn course_routes() -> Router<AppState> {
    Router::new()
        .route("/courses", get(list_courses))
        .route("/courses", post(create_course))
        .route("/courses/{id}", get(get_course))
        .route("/courses/{id}", put(update_course))
        .route("/courses/{id}", delete(delete_course))
        .route("/courses/{id}/chapters", get(list_chapters))
        .route("/courses/{id}/chapters", post(create_chapter))
        .route("/courses/{id}/chapters/{ch_id}", put(update_chapter))
        .route("/courses/{id}/chapters/{ch_id}/lessons", get(list_lessons))
        .route(
            "/courses/{id}/chapters/{ch_id}/lessons",
            post(create_lesson),
        )
}

async fn list_courses(
    State(state): State<AppState>,
    Query(query): Query<ListCoursesQuery>,
) -> Result<Json<ApiResponse<PageResponse<Course>>>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let size = query.size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * size;

    let total = state.course_repository.count_courses().await?;
    let items = state
        .course_repository
        .list_courses(size, offset)
        .await?
        .into_iter()
        .map(|r| Course {
            id: r.id,
            subject_id: r.subject_id,
            title: r.title,
            description: r.description,
            teacher_id: r.teacher_id,
            status: r.status,
        })
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        items, total, page, size,
    ))))
}

async fn create_course(
    State(state): State<AppState>,
    Json(req): Json<CreateCourseReq>,
) -> Result<Json<ApiResponse<Course>>, AppError> {
    let input = CourseInput {
        subject_id: req.subject_id,
        title: req.title,
        description: req.description,
        teacher_id: req.teacher_id,
    };
    let id = state.course_repository.create_course(&input).await?;
    Ok(Json(ApiResponse::success(Course {
        id,
        subject_id: input.subject_id,
        title: input.title,
        description: input.description,
        teacher_id: input.teacher_id,
        status: "DRAFT".into(),
    })))
}

async fn get_course(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Course>>, AppError> {
    let course = state
        .course_repository
        .get_course(id)
        .await?
        .map(|r| Course {
            id: r.id,
            subject_id: r.subject_id,
            title: r.title,
            description: r.description,
            teacher_id: r.teacher_id,
            status: r.status,
        })
        .ok_or_else(|| astral_types::AstralError::Validation("Not found".into()))?;
    Ok(Json(ApiResponse::success(course)))
}

async fn update_course(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<CreateCourseReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state
        .course_repository
        .update_course(
            id,
            &CourseInput {
                subject_id: req.subject_id,
                title: req.title,
                description: req.description,
                teacher_id: req.teacher_id,
            },
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_course(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.course_repository.archive_course(id).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_chapters(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<Chapter>>>, AppError> {
    // platform_v4 learn_chapter 直接用 subject_id 关联（无 course_id 列）
    let items = state
        .course_repository
        .list_chapters_by_subject(id)
        .await?
        .into_iter()
        .map(|r| Chapter {
            id: r.id,
            course_id: r.course_id,
            title: r.title,
            sort_order: r.sort_order,
        })
        .collect();
    Ok(Json(ApiResponse::success(items)))
}

async fn create_chapter(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<CreateChapterReq>,
) -> Result<Json<ApiResponse<Chapter>>, AppError> {
    // id 实际是 subject_id（learn_chapter.subject_id）
    let sort_order = req.sort_order.unwrap_or(0);
    let new_id = state
        .course_repository
        .create_chapter(
            id,
            &ChapterInput {
                title: req.title.clone(),
                description: None,
                sort_order,
            },
        )
        .await?;
    Ok(Json(ApiResponse::success(Chapter {
        id: new_id,
        course_id: id,
        title: req.title,
        sort_order,
    })))
}

async fn update_chapter(
    State(state): State<AppState>,
    Path((id, ch_id)): Path<(i64, i64)>,
    Json(req): Json<CreateChapterReq>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // id 实际是 subject_id（learn_chapter.subject_id）
    state
        .course_repository
        .update_chapter_by_subject(
            ch_id,
            id,
            &ChapterInput {
                title: req.title,
                description: None,
                sort_order: req.sort_order.unwrap_or(0),
            },
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_lessons(
    State(state): State<AppState>,
    Path((_id, ch_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<Vec<Lesson>>>, AppError> {
    let items = state
        .course_repository
        .list_lessons(ch_id)
        .await?
        .into_iter()
        .map(|r| Lesson {
            id: r.id,
            chapter_id: r.chapter_id,
            title: r.title,
            content_type: r.content_type,
            content_url: r.content_url,
            duration_minutes: r.duration_minutes,
            sort_order: r.sort_order,
        })
        .collect();
    Ok(Json(ApiResponse::success(items)))
}

async fn create_lesson(
    State(state): State<AppState>,
    Path((_id, ch_id)): Path<(i64, i64)>,
    Json(req): Json<CreateLessonReq>,
) -> Result<Json<ApiResponse<Lesson>>, AppError> {
    let input = LessonInput {
        title: req.title,
        content_type: req.content_type.unwrap_or_else(|| "VIDEO".into()),
        content_url: req.content_url,
        duration_minutes: req.duration_minutes.unwrap_or(0),
        sort_order: req.sort_order.unwrap_or(0),
    };
    let new_id = state.course_repository.create_lesson(ch_id, &input).await?;
    Ok(Json(ApiResponse::success(Lesson {
        id: new_id,
        chapter_id: ch_id,
        title: input.title,
        content_type: input.content_type,
        content_url: input.content_url,
        duration_minutes: input.duration_minutes,
        sort_order: input.sort_order,
    })))
}
