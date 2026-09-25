//! 身份认证业务服务
//!
//! 用户管理、卡片管理、会话管理、密码重置、管理员端点等。

pub mod admin;
pub(crate) mod app_user_repository;
pub(crate) mod auth_repository;
pub(crate) mod auth_service;
pub(crate) mod card_repository;
pub mod cards;
pub mod internal;
pub mod me;
pub(crate) mod me_repository;
pub(crate) mod me_service;
pub mod mfa;
pub(crate) mod org_repository;
pub(crate) mod org_service;
pub mod orgs;
pub mod password;
pub mod session;
pub(crate) mod session_projection_worker;
pub(crate) mod session_repository;
pub(crate) mod user_repository;
pub(crate) mod user_service;
pub mod users;
pub mod verification;
