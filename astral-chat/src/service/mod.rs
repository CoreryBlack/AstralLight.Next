//! 聊天域应用服务层（对齐 Java `Chat*ServiceImpl` 编排边界）
//!
//! Service 为具体 struct（非 trait），注入 `Arc<dyn Repository>`；
//! 消息通过 durable send intent 接收，再由有界 relay 发布和推送；
//! 授权/成员资格校验集中在 service。

pub mod group_service;
pub mod message_service;
pub mod receipt_service;
pub mod send_intent_relay;
pub mod session_service;
