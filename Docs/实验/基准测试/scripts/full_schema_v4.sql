-- MySQL dump 10.13  Distrib 8.0.46, for Linux (x86_64)
--
-- Host: localhost    Database: platform_v4
-- ------------------------------------------------------
-- Server version	8.0.46

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `auth_audit_log`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_audit_log` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint DEFAULT NULL COMMENT '操作用户 ID',
  `card_id` bigint DEFAULT NULL COMMENT '当前激活卡片 ID',
  `domain_id` bigint DEFAULT NULL COMMENT '操作所属域 ID',
  `identity_id` bigint DEFAULT NULL COMMENT '关联的 user_identity ID',
  `session_id` bigint DEFAULT NULL COMMENT '关联的 Session ID',
  `event_type` varchar(64) NOT NULL COMMENT '事件类型',
  `resource` varchar(128) DEFAULT NULL COMMENT '操作资源',
  `action` varchar(64) DEFAULT NULL COMMENT '操作动作',
  `target_id` bigint DEFAULT NULL COMMENT '目标实体 ID',
  `result` varchar(16) NOT NULL DEFAULT 'UNKNOWN' COMMENT 'ALLOW / DENY / ERROR',
  `reason` varchar(256) DEFAULT NULL COMMENT '判定原因',
  `provider` varchar(64) DEFAULT NULL COMMENT '第三方提供商',
  `severity` varchar(16) NOT NULL DEFAULT 'INFO' COMMENT 'INFO / WARN / CRITICAL',
  `ip` varchar(64) DEFAULT NULL COMMENT '操作 IP',
  `user_agent` varchar(512) DEFAULT NULL COMMENT 'User-Agent',
  `detail` text COMMENT '结构化事件数据',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_audit_card` (`card_id`),
  KEY `idx_audit_event` (`event_type`),
  KEY `idx_audit_result` (`result`),
  KEY `idx_audit_time` (`created_at`),
  KEY `idx_audit_user` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=855 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='统一审计日志';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_device_session`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_device_session` (
  `session_id` bigint NOT NULL AUTO_INCREMENT,
  `family_id` bigint NOT NULL,
  `user_id` bigint NOT NULL,
  `device_id` varchar(255) NOT NULL,
  `device_type` varchar(64) DEFAULT NULL,
  `client_app_id` varchar(128) DEFAULT NULL,
  `channel_code` varchar(64) DEFAULT NULL,
  `current_user_card_id` bigint DEFAULT NULL COMMENT '当前激活的用户卡ID（user_card.card_id）',
  `refresh_token_hash` varchar(255) NOT NULL,
  `refresh_expires_at` datetime DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `ip_address` varchar(64) DEFAULT NULL,
  `user_agent` varchar(512) DEFAULT NULL,
  `last_seen_at` datetime DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `revoked_reason` varchar(512) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`session_id`),
  UNIQUE KEY `uk_ads_refresh_token` (`refresh_token_hash`),
  KEY `idx_ads_user_device` (`user_id`,`device_id`),
  KEY `idx_ads_family` (`family_id`),
  KEY `idx_ads_card` (`current_user_card_id`),
  CONSTRAINT `fk_ads_card` FOREIGN KEY (`current_user_card_id`) REFERENCES `user_card` (`card_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_ads_family` FOREIGN KEY (`family_id`) REFERENCES `auth_token_family` (`family_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ads_user` FOREIGN KEY (`user_id`) REFERENCES `platform_user` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='认证设备会话';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_token_family`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_token_family` (
  `family_id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `family_key` varchar(255) NOT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `issued_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` datetime DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `revoked_reason` varchar(512) DEFAULT NULL,
  `metadata_json` json DEFAULT NULL,
  PRIMARY KEY (`family_id`),
  UNIQUE KEY `uk_atf_family_key` (`family_key`),
  KEY `idx_atf_status` (`status`),
  KEY `idx_atf_user` (`user_id`),
  CONSTRAINT `fk_atf_user` FOREIGN KEY (`user_id`) REFERENCES `platform_user` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Token 家族';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `badge_definitions`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `badge_definitions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `code` varchar(64) NOT NULL,
  `name` varchar(128) NOT NULL,
  `category` varchar(64) DEFAULT NULL,
  `description` text,
  `rarity` varchar(32) DEFAULT NULL,
  `icon_url` varchar(512) DEFAULT NULL,
  `points_reward` int DEFAULT NULL,
  `unlock_condition` json DEFAULT NULL,
  `color` varchar(32) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_badge_definitions_code` (`code`)
) ENGINE=InnoDB AUTO_INCREMENT=29 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='徽章定义表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `card_rule_set_ref`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `card_rule_set_ref` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `card_id` bigint NOT NULL COMMENT '用户卡ID',
  `rule_set_id` bigint NOT NULL COMMENT '规则集ID',
  `ref_type` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'BASE' COMMENT 'BASE / OVERLAY',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_card_rule_set` (`card_id`,`rule_set_id`),
  KEY `idx_crsr_card` (`card_id`),
  KEY `idx_crsr_rule_set` (`rule_set_id`),
  CONSTRAINT `fk_crsr_card` FOREIGN KEY (`card_id`) REFERENCES `user_card` (`card_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_crsr_rule_set` FOREIGN KEY (`rule_set_id`) REFERENCES `rule_set` (`rule_set_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=97 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='卡片规则集绑定';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `chapter_progress`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `chapter_progress` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `chapter_id` bigint NOT NULL,
  `completed_levels` int DEFAULT NULL,
  `total_levels` int DEFAULT NULL,
  `completion_percentage` decimal(8,2) DEFAULT NULL,
  `average_score` decimal(8,2) DEFAULT NULL,
  `study_minutes` int DEFAULT NULL,
  `total_points` int DEFAULT NULL,
  `last_activity_at` datetime DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_chapter_progress_user` (`user_id`),
  KEY `idx_chapter_progress_chapter` (`chapter_id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='章节进度表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `chat_client_session`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `chat_client_session` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '会话ID',
  `user_id` bigint NOT NULL COMMENT '用户ID',
  `client_type` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '客户端类型',
  `device_id` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '设备唯一标识',
  `device_name` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '设备名称',
  `connection_id` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT 'WebSocket连接ID',
  `status` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'ONLINE' COMMENT '状态',
  `last_active_at` datetime DEFAULT NULL COMMENT '最后活跃时间',
  `push_token` varchar(200) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '推送Token',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_client_device` (`user_id`,`client_type`,`device_id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='客户端会话表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `chat_conversation`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `chat_conversation` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '会话ID',
  `conversation_type` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '会话类型: SINGLE/GROUP/BUSINESS',
  `business_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '业务类型',
  `business_id` bigint DEFAULT NULL COMMENT '关联业务ID',
  `name` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '会话名称',
  `avatar` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '会话头像URL',
  `owner_id` bigint DEFAULT NULL COMMENT '群主ID',
  `domain_id` bigint NOT NULL COMMENT '域ID',
  `last_message_id` bigint DEFAULT NULL COMMENT '最后一条消息ID',
  `last_message_time` datetime DEFAULT NULL COMMENT '最后消息时间',
  `last_message_summary` varchar(200) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '最后消息摘要',
  `member_count` int DEFAULT '0' COMMENT '成员数量',
  `max_members` int DEFAULT '500' COMMENT '最大成员数',
  `status` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'ACTIVE' COMMENT '状态: ACTIVE/ARCHIVED/DISBANDED',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `is_deleted` tinyint DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `idx_domain_org` (`domain_id`),
  KEY `idx_owner` (`owner_id`),
  KEY `idx_business` (`business_type`,`business_id`),
  KEY `idx_type_status` (`conversation_type`,`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='聊天会话表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `chat_conversation_member`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `chat_conversation_member` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '成员记录ID',
  `conversation_id` bigint NOT NULL COMMENT '会话ID',
  `user_id` bigint NOT NULL COMMENT '用户ID',
  `nickname` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '群内昵称',
  `role` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'MEMBER' COMMENT '角色: OWNER/ADMIN/MEMBER',
  `last_read_message_id` bigint DEFAULT NULL COMMENT '最后已读消息ID',
  `last_read_time` datetime DEFAULT NULL COMMENT '最后阅读时间',
  `muted` tinyint DEFAULT '0' COMMENT '是否免打扰',
  `pinned` tinyint DEFAULT '0' COMMENT '是否置顶',
  `hide_nickname` tinyint DEFAULT '0' COMMENT '是否隐藏昵称',
  `joined_at` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '加入时间',
  `left_at` datetime DEFAULT NULL COMMENT '退出时间',
  `invite_by` bigint DEFAULT NULL COMMENT '邀请人ID',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_conversation_user` (`conversation_id`,`user_id`),
  KEY `idx_user` (`user_id`),
  KEY `idx_user_pinned` (`user_id`,`pinned`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='会话成员表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `chat_message`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `chat_message` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '消息ID',
  `message_id` varchar(36) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '消息唯一标识(UUID)',
  `conversation_id` bigint NOT NULL COMMENT '会话ID',
  `sender_id` bigint NOT NULL COMMENT '发送者ID',
  `message_type` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '消息类型',
  `content` text COLLATE utf8mb4_unicode_ci COMMENT '消息内容',
  `media_url` varchar(500) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '媒体文件URL',
  `media_metadata` json DEFAULT NULL COMMENT '媒体元数据',
  `business_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '业务类型',
  `business_id` bigint DEFAULT NULL COMMENT '关联业务ID',
  `reference_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '引用类型',
  `reference_id` bigint DEFAULT NULL COMMENT '引用ID',
  `reference_data` json DEFAULT NULL COMMENT '引用数据快照',
  `reply_to_id` bigint DEFAULT NULL COMMENT '回复消息ID',
  `quote_content` text COLLATE utf8mb4_unicode_ci COMMENT '引用内容',
  `status` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'SENT' COMMENT '状态',
  `recalled_at` datetime DEFAULT NULL COMMENT '撤回时间',
  `domain_id` bigint NOT NULL COMMENT '域ID',
  `client_type` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '发送客户端类型',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `is_deleted` tinyint DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_message_id` (`message_id`),
  KEY `idx_conversation_time` (`conversation_id`,`created_at`),
  KEY `idx_sender` (`sender_id`),
  KEY `idx_domain` (`domain_id`),
  KEY `idx_business` (`business_type`,`business_id`),
  FULLTEXT KEY `ft_content` (`content`) /*!50100 WITH PARSER `ngram` */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='聊天消息表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `chat_message_delivery`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `chat_message_delivery` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `message_id` bigint NOT NULL COMMENT '消息ID',
  `recipient_id` bigint NOT NULL COMMENT '接收者ID',
  `client_type` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '目标客户端类型',
  `device_id` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '目标设备ID',
  `status` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT 'PENDING' COMMENT '状态',
  `sent_at` datetime DEFAULT NULL COMMENT '发送时间',
  `delivered_at` datetime DEFAULT NULL COMMENT '送达时间',
  `read_at` datetime DEFAULT NULL COMMENT '阅读时间',
  `failed_at` datetime DEFAULT NULL COMMENT '失败时间',
  `failure_reason` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '失败原因',
  `retry_count` int DEFAULT '0' COMMENT '重试次数',
  `last_retry_at` datetime DEFAULT NULL COMMENT '最后重试时间',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_message_recipient` (`message_id`,`recipient_id`,`client_type`),
  KEY `idx_recipient` (`recipient_id`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='消息投递记录表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `chat_read_watermark`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `chat_read_watermark` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL COMMENT '用户ID',
  `conversation_id` bigint NOT NULL COMMENT '会话ID',
  `max_read_message_id` bigint NOT NULL COMMENT '已读的最大消息ID',
  `read_at` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '阅读时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_conversation` (`user_id`,`conversation_id`),
  KEY `idx_conversation` (`conversation_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='已读水位线表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `departments`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `departments` (
  `dept_id` bigint NOT NULL AUTO_INCREMENT COMMENT '部门ID',
  `tenant_id` bigint NOT NULL COMMENT '所属根租户ID',
  `sub_tenant_id` bigint DEFAULT NULL COMMENT '所属子租户ID（NULL=直辖部门）',
  `dept_name` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '部门名称',
  `dept_code` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '部门编码（同租户下唯一）',
  `parent_dept_id` bigint DEFAULT NULL COMMENT '父部门ID（支持部门嵌套）',
  `sort_order` int NOT NULL DEFAULT '0' COMMENT '排序',
  `status` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE / SUSPENDED',
  `description` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '部门描述',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`dept_id`),
  UNIQUE KEY `uk_dept_code_tenant` (`tenant_id`,`dept_code`),
  KEY `idx_dept_tenant` (`tenant_id`),
  KEY `idx_dept_sub_tenant` (`sub_tenant_id`),
  KEY `idx_dept_parent` (`parent_dept_id`),
  CONSTRAINT `fk_dept_parent` FOREIGN KEY (`parent_dept_id`) REFERENCES `departments` (`dept_id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_dept_sub_tenant` FOREIGN KEY (`sub_tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_dept_tenant` FOREIGN KEY (`tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='部门表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `documents`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `documents` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `filename` varchar(255) DEFAULT NULL,
  `file_type` varchar(64) DEFAULT NULL,
  `file_size` bigint DEFAULT NULL,
  `checksum` varchar(128) DEFAULT NULL,
  `subject_id` bigint DEFAULT NULL,
  `chapter_id` bigint DEFAULT NULL,
  `level_id` bigint DEFAULT NULL,
  `description` text,
  `storage_url` varchar(512) DEFAULT NULL,
  `is_public` tinyint(1) DEFAULT NULL,
  `download_count` int DEFAULT NULL,
  `uploaded_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_documents_subject` (`subject_id`),
  KEY `idx_documents_chapter` (`chapter_id`),
  KEY `idx_documents_level` (`level_id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='学习资料表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `domain_resource_type`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `domain_resource_type` (
  `resource_type_id` bigint NOT NULL AUTO_INCREMENT,
  `domain_id` bigint DEFAULT NULL COMMENT '所属域（NULL=全局资源）',
  `type_code` varchar(64) NOT NULL COMMENT '资源代码（如 enterprise, user）',
  `type_name` varchar(128) NOT NULL COMMENT '资源名称',
  `type_description` text,
  `sensitivity_level` int NOT NULL DEFAULT '0' COMMENT '敏感度 0-5',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`resource_type_id`),
  UNIQUE KEY `uk_domain_type_code` (`domain_id`,`type_code`)
) ENGINE=InnoDB AUTO_INCREMENT=101 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='域资源类型';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `identity_card`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `identity_card` (
  `card_id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `domain_id` bigint DEFAULT NULL COMMENT '默认领域上下文',
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE|DISABLED|EXPIRED',
  `token_version` bigint NOT NULL DEFAULT '1' COMMENT 'Token 版本号，用于撤销',
  `expires_at` datetime DEFAULT NULL COMMENT '身份证过期时间',
  `disabled_reason` varchar(512) DEFAULT NULL COMMENT '禁用原因',
  `last_used_at` datetime DEFAULT NULL COMMENT '最后使用时间',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`card_id`),
  UNIQUE KEY `uk_ic_user` (`user_id`),
  KEY `idx_ic_domain` (`domain_id`),
  KEY `idx_ic_status` (`status`),
  CONSTRAINT `fk_ic_domain` FOREIGN KEY (`domain_id`) REFERENCES `platform_domain` (`domain_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_ic_user` FOREIGN KEY (`user_id`) REFERENCES `platform_user` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=46 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='身份卡（身份证）：每人只有一张，用于身份认证';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `identity_global_admin`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `identity_global_admin` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `granted_by` bigint DEFAULT NULL,
  `granted_reason` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_identity_global_admin_user_id` (`user_id`),
  KEY `idx_identity_global_admin_status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='全局管理员';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `identity_level_template`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `identity_level_template` (
  `template_id` bigint NOT NULL AUTO_INCREMENT,
  `template_code` varchar(64) NOT NULL,
  `template_name` varchar(128) NOT NULL,
  `domain_id` bigint NOT NULL,
  `principal_type` varchar(32) NOT NULL COMMENT 'PERSONAL|ENTERPRISE',
  `grant_type` varchar(32) NOT NULL COMMENT 'NORMAL|SPECIAL',
  `level_no` int NOT NULL,
  `user_card_template_id` bigint DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `version_no` int NOT NULL DEFAULT '1',
  `force_cover` tinyint(1) NOT NULL DEFAULT '1',
  `description` varchar(512) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`template_id`),
  UNIQUE KEY `uk_ilt_domain_template_code` (`domain_id`,`template_code`),
  UNIQUE KEY `uk_ilt_scope` (`domain_id`,`principal_type`,`grant_type`,`level_no`,`status`),
  KEY `fk_ilt_card_template` (`user_card_template_id`),
  KEY `idx_ilt_domain_level` (`domain_id`,`level_no`),
  KEY `idx_ilt_status` (`status`),
  CONSTRAINT `fk_ilt_card_template` FOREIGN KEY (`user_card_template_id`) REFERENCES `user_card_template` (`template_id`),
  CONSTRAINT `fk_ilt_domain` FOREIGN KEY (`domain_id`) REFERENCES `platform_domain` (`domain_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='等级模板主表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `identity_level_template_action_map`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `identity_level_template_action_map` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `template_id` bigint NOT NULL,
  `action_id` bigint NOT NULL,
  `effect` varchar(16) NOT NULL DEFAULT 'ALLOW',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ilta_template_action` (`template_id`,`action_id`),
  KEY `idx_ilta_action` (`action_id`),
  CONSTRAINT `fk_ilta_action` FOREIGN KEY (`action_id`) REFERENCES `permission_action` (`action_id`),
  CONSTRAINT `fk_ilta_template` FOREIGN KEY (`template_id`) REFERENCES `identity_level_template` (`template_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='等级模板功能映射';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `identity_level_template_resource_map`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `identity_level_template_resource_map` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `template_id` bigint NOT NULL,
  `resource_type_id` bigint NOT NULL,
  `priority` int NOT NULL DEFAULT '100',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_iltm_template_resource` (`template_id`,`resource_type_id`),
  KEY `fk_iltm_resource` (`resource_type_id`),
  KEY `idx_iltm_template` (`template_id`),
  KEY `idx_iltm_priority` (`priority`),
  CONSTRAINT `fk_iltm_resource` FOREIGN KEY (`resource_type_id`) REFERENCES `domain_resource_type` (`resource_type_id`),
  CONSTRAINT `fk_iltm_template` FOREIGN KEY (`template_id`) REFERENCES `identity_level_template` (`template_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='等级模板资源映射';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `identity_user_grading`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `identity_user_grading` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `level_no` int NOT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `source` varchar(64) DEFAULT NULL,
  `description` varchar(512) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_iug_user_level` (`user_id`,`level_no`),
  KEY `idx_iug_user` (`user_id`),
  KEY `idx_iug_status` (`status`),
  CONSTRAINT `fk_iug_user` FOREIGN KEY (`user_id`) REFERENCES `platform_user` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户等级授予';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `leaderboards`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `leaderboards` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `school_id` bigint DEFAULT NULL,
  `global_rank` int DEFAULT NULL,
  `school_rank` int DEFAULT NULL,
  `total_score` int DEFAULT NULL,
  `levels_completed` int DEFAULT NULL,
  `questions_answered` int DEFAULT NULL,
  `average_accuracy` decimal(8,2) DEFAULT NULL,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_leaderboards_user` (`user_id`),
  KEY `idx_leaderboards_school` (`school_id`)
) ENGINE=InnoDB AUTO_INCREMENT=21 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='排行榜表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_chapter`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_chapter` (
  `chapter_id` bigint NOT NULL AUTO_INCREMENT,
  `subject_id` bigint NOT NULL,
  `domain_id` bigint DEFAULT NULL,
  `chapter_no` varchar(64) DEFAULT NULL,
  `title` varchar(255) NOT NULL,
  `subtitle` varchar(255) DEFAULT NULL,
  `description` text,
  `content_md` longtext,
  `cover_image` varchar(512) DEFAULT NULL,
  `difficulty` varchar(32) DEFAULT NULL,
  `sort_order` int DEFAULT NULL,
  `parent_chapter_id` bigint DEFAULT NULL,
  `level` int DEFAULT NULL,
  `level_count` int DEFAULT NULL,
  `is_locked` tinyint(1) DEFAULT NULL,
  `video_url` varchar(512) DEFAULT NULL,
  `video_duration` int DEFAULT NULL,
  `document_urls_json` json DEFAULT NULL,
  `learning_objectives_json` json DEFAULT NULL,
  `keywords_json` json DEFAULT NULL,
  `unlock_condition_json` json DEFAULT NULL,
  `estimated_hours` decimal(8,2) DEFAULT NULL,
  `question_count` int DEFAULT NULL,
  `completion_count` int DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by_user_id` bigint DEFAULT NULL,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`chapter_id`),
  KEY `idx_learn_chapter_subject` (`subject_id`),
  KEY `idx_learn_chapter_domain` (`domain_id`),
  KEY `idx_learn_chapter_parent` (`parent_chapter_id`)
) ENGINE=InnoDB AUTO_INCREMENT=75 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='学习章节表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_class_attendance`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_class_attendance` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `course_id` bigint NOT NULL,
  `user_id` bigint NOT NULL,
  `date` date DEFAULT NULL,
  `lesson_no` varchar(64) DEFAULT NULL,
  `instructor_user_id` bigint DEFAULT NULL,
  `instructor` varchar(128) DEFAULT NULL,
  `student_number` varchar(64) DEFAULT NULL,
  `student_name` varchar(128) DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `class_group` varchar(128) DEFAULT NULL,
  `location` varchar(255) DEFAULT NULL,
  `method` varchar(64) DEFAULT NULL,
  `minutes_late` int DEFAULT NULL,
  `notes` text,
  `photo_url` varchar(512) DEFAULT NULL,
  `checkin_time` datetime DEFAULT NULL,
  `checkout_time` datetime DEFAULT NULL,
  `start_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  `verified_by_user_id` bigint DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_class_attendance_course` (`course_id`),
  KEY `idx_class_attendance_user` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=47 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='课堂考勤表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_course`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_course` (
  `course_id` bigint NOT NULL AUTO_INCREMENT,
  `subject_id` bigint DEFAULT NULL,
  `code` varchar(64) DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `description` text,
  `academic_year` varchar(32) DEFAULT NULL,
  `semester` varchar(32) DEFAULT NULL,
  `classroom` varchar(128) DEFAULT NULL,
  `class_times_json` json DEFAULT NULL,
  `content_chapters_json` json DEFAULT NULL,
  `capacity` int DEFAULT NULL,
  `enrolled_count` int DEFAULT NULL,
  `instructor_user_id` bigint DEFAULT NULL,
  `start_date` date DEFAULT NULL,
  `end_date` date DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by_user_id` bigint DEFAULT NULL,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`course_id`),
  UNIQUE KEY `uk_learn_course_code` (`code`),
  KEY `idx_learn_course_subject` (`subject_id`),
  KEY `idx_learn_course_instructor` (`instructor_user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='课程表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_course_enrollment`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_course_enrollment` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `course_id` bigint NOT NULL,
  `user_id` bigint NOT NULL,
  `status` varchar(32) DEFAULT NULL,
  `final_score` decimal(8,2) DEFAULT NULL,
  `attendance_rate` decimal(8,2) DEFAULT NULL,
  `enrolled_at` datetime DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_course_enrollment` (`course_id`,`user_id`),
  KEY `idx_course_enrollment_user` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=33 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='课程报名表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_level`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_level` (
  `level_id` bigint NOT NULL AUTO_INCREMENT,
  `subject_id` bigint DEFAULT NULL,
  `chapter_id` bigint DEFAULT NULL,
  `domain_id` bigint DEFAULT NULL,
  `code` varchar(64) DEFAULT NULL,
  `title` varchar(255) NOT NULL,
  `level_type` varchar(64) DEFAULT NULL,
  `difficulty` varchar(32) DEFAULT NULL,
  `description` text,
  `sort_order` int DEFAULT NULL,
  `points` int DEFAULT NULL,
  `question_count` int DEFAULT NULL,
  `total_attempts` int DEFAULT NULL,
  `completed_count` int DEFAULT NULL,
  `average_score` decimal(8,2) DEFAULT NULL,
  `max_attempts` int DEFAULT NULL,
  `pass_score_percentage` decimal(8,2) DEFAULT NULL,
  `time_limit_minutes` int DEFAULT NULL,
  `is_locked` tinyint(1) DEFAULT NULL,
  `badge_url` varchar(512) DEFAULT NULL,
  `prerequisite_level_ids_json` json DEFAULT NULL,
  `unlock_condition_json` json DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by_user_id` bigint DEFAULT NULL,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`level_id`),
  UNIQUE KEY `uk_learn_level_code` (`code`),
  KEY `idx_learn_level_subject` (`subject_id`),
  KEY `idx_learn_level_chapter` (`chapter_id`),
  KEY `idx_level_subject_chapter_sort` (`subject_id`,`chapter_id`,`sort_order`)
) ENGINE=InnoDB AUTO_INCREMENT=81 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='关卡表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_level_completion`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_level_completion` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `level_id` bigint NOT NULL,
  `total_score` int DEFAULT NULL,
  `percentage_score` decimal(8,2) DEFAULT NULL,
  `correct_count` int DEFAULT NULL,
  `attempt_number` int DEFAULT NULL,
  `best_score` int DEFAULT NULL,
  `is_best_attempt` tinyint(1) DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  `started_at` datetime DEFAULT NULL,
  `spent_minutes` int DEFAULT NULL,
  `total_questions` int DEFAULT NULL,
  `unlocked_next_level` tinyint(1) DEFAULT NULL,
  `feedback` text,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_level_completion_user` (`user_id`),
  KEY `idx_level_completion_level` (`level_id`),
  KEY `idx_completion_user_level` (`user_id`,`level_id`)
) ENGINE=InnoDB AUTO_INCREMENT=37 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='关卡完成记录表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_level_question`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_level_question` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `level_id` bigint NOT NULL,
  `question_id` bigint NOT NULL,
  `order_no` int DEFAULT NULL,
  `question_type` varchar(64) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_level_question` (`level_id`,`question_id`),
  KEY `idx_level_question_level` (`level_id`),
  KEY `idx_level_question_question` (`question_id`)
) ENGINE=InnoDB AUTO_INCREMENT=61 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='关卡题目关联表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_level_status`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_level_status` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `level_id` bigint NOT NULL,
  `best_score` int DEFAULT NULL,
  `attempts` int DEFAULT NULL,
  `unlocked_next` tinyint(1) DEFAULT NULL,
  `last_played` datetime DEFAULT NULL,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_level_status_user` (`user_id`),
  KEY `idx_level_status_level` (`level_id`)
) ENGINE=InnoDB AUTO_INCREMENT=39 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='关卡状态表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_question`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_question` (
  `question_id` bigint NOT NULL AUTO_INCREMENT,
  `subject_id` bigint DEFAULT NULL,
  `chapter_id` bigint DEFAULT NULL,
  `domain_id` bigint DEFAULT NULL,
  `category` varchar(64) DEFAULT NULL,
  `title` varchar(255) NOT NULL,
  `content` longtext,
  `explanation` longtext,
  `question_type` varchar(64) DEFAULT NULL,
  `difficulty` varchar(32) DEFAULT NULL,
  `options_json` json DEFAULT NULL,
  `answer_text` text,
  `answer_keys_json` json DEFAULT NULL,
  `points` int DEFAULT NULL,
  `is_public` tinyint(1) DEFAULT NULL,
  `review_status` varchar(32) DEFAULT NULL,
  `reviewed_by_user_id` bigint DEFAULT NULL,
  `reviewed_at` datetime DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `attempt_count` int DEFAULT NULL,
  `correct_count` int DEFAULT NULL,
  `wrong_count` int DEFAULT NULL,
  `accuracy_rate` decimal(8,2) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by_user_id` bigint DEFAULT NULL,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`question_id`),
  KEY `idx_learn_question_subject` (`subject_id`),
  KEY `idx_learn_question_chapter` (`chapter_id`),
  KEY `idx_learn_question_domain` (`domain_id`),
  KEY `idx_question_subject_chapter` (`subject_id`,`chapter_id`)
) ENGINE=InnoDB AUTO_INCREMENT=81 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='题目表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_question_first_attempt`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_question_first_attempt` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `question_id` bigint NOT NULL,
  `level_id` bigint DEFAULT NULL,
  `subject_id` bigint DEFAULT NULL,
  `chapter_id` bigint DEFAULT NULL,
  `first_attempt_at` datetime DEFAULT NULL,
  `first_attempt_is_correct` tinyint(1) DEFAULT NULL,
  `first_selected_option` varchar(255) DEFAULT NULL,
  `first_selected_options_json` json DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_question_first_attempt` (`user_id`,`question_id`),
  KEY `idx_question_first_attempt_level` (`level_id`)
) ENGINE=InnoDB AUTO_INCREMENT=45 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='题目首答记录表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_question_solution`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_question_solution` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `question_id` bigint NOT NULL COMMENT '题目ID',
  `user_id` bigint NOT NULL COMMENT '提交用户ID',
  `title` varchar(256) DEFAULT NULL COMMENT '题解标题',
  `content` text NOT NULL COMMENT '题解内容',
  `content_type` varchar(32) NOT NULL DEFAULT 'MARKDOWN' COMMENT '内容格式',
  `like_count` int NOT NULL DEFAULT '0' COMMENT '点赞数',
  `view_count` int NOT NULL DEFAULT '0' COMMENT '浏览数',
  `comment_count` int NOT NULL DEFAULT '0' COMMENT '评论数',
  `status` varchar(16) NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE / HIDDEN / DELETED',
  `is_official` tinyint(1) NOT NULL DEFAULT '0' COMMENT '是否官方题解',
  `is_pinned` tinyint(1) NOT NULL DEFAULT '0' COMMENT '是否置顶',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `edited_at` datetime DEFAULT NULL COMMENT '最后编辑时间',
  PRIMARY KEY (`id`),
  KEY `idx_lqs_question` (`question_id`),
  KEY `idx_lqs_user` (`user_id`),
  KEY `idx_lqs_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='题解表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_question_summary`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_question_summary` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `question_id` bigint NOT NULL,
  `title` varchar(255) DEFAULT NULL,
  `subject_id` bigint DEFAULT NULL,
  `chapter_id` bigint DEFAULT NULL,
  `level_id` bigint DEFAULT NULL,
  `course_id` bigint DEFAULT NULL,
  `teacher_user_id` bigint DEFAULT NULL,
  `stage` varchar(64) DEFAULT NULL,
  `students_done` int DEFAULT NULL,
  `students_first_wrong` int DEFAULT NULL,
  `last_aggregated_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_question_summary_question` (`question_id`),
  KEY `idx_question_summary_subject` (`subject_id`),
  KEY `idx_question_summary_chapter` (`chapter_id`)
) ENGINE=InnoDB AUTO_INCREMENT=63 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='题目汇总表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_solution_like`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_solution_like` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `solution_id` bigint NOT NULL COMMENT '题解ID',
  `user_id` bigint NOT NULL COMMENT '点赞用户ID',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_solution_like_user` (`solution_id`,`user_id`),
  KEY `idx_lsl_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='题解点赞表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_subject`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_subject` (
  `subject_id` bigint NOT NULL AUTO_INCREMENT,
  `domain_id` bigint DEFAULT NULL,
  `code` varchar(64) NOT NULL,
  `name` varchar(128) NOT NULL,
  `name_en` varchar(128) DEFAULT NULL,
  `category` varchar(64) DEFAULT NULL,
  `parent_subject_id` bigint DEFAULT NULL,
  `level` int DEFAULT NULL,
  `sort_order` int DEFAULT NULL,
  `description` text,
  `theme_color` varchar(32) DEFAULT NULL,
  `cover_image` varchar(512) DEFAULT NULL,
  `icon_url` varchar(512) DEFAULT NULL,
  `chapter_count` int DEFAULT NULL,
  `question_count` int DEFAULT NULL,
  `student_count` int DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `is_public` tinyint(1) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by_user_id` bigint DEFAULT NULL,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`subject_id`),
  UNIQUE KEY `uk_learn_subject_code` (`code`),
  KEY `idx_learn_subject_domain` (`domain_id`),
  KEY `idx_learn_subject_parent` (`parent_subject_id`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='学习学科表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_user_answer`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_user_answer` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `level_id` bigint DEFAULT NULL,
  `question_id` bigint NOT NULL,
  `is_correct` tinyint(1) DEFAULT NULL,
  `points_earned` int DEFAULT NULL,
  `time_spent_seconds` int DEFAULT NULL,
  `user_answer_text` text,
  `user_answer_json` json DEFAULT NULL,
  `answered_at` datetime DEFAULT NULL,
  `device_info` varchar(512) DEFAULT NULL,
  `ip_address` varchar(64) DEFAULT NULL,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_learn_user_answer_user` (`user_id`),
  KEY `idx_learn_user_answer_level` (`level_id`),
  KEY `idx_learn_user_answer_question` (`question_id`),
  KEY `idx_answer_user_level` (`user_id`,`level_id`)
) ENGINE=InnoDB AUTO_INCREMENT=97 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户答题记录表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_user_profile`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_user_profile` (
  `user_id` bigint NOT NULL,
  `domain_id` bigint DEFAULT NULL,
  `score` int DEFAULT NULL,
  `current_level_no` int DEFAULT NULL,
  `total_study_minutes` int DEFAULT NULL,
  `last_login_at` datetime DEFAULT NULL,
  `last_subject_id` bigint DEFAULT NULL,
  `nickname` varchar(128) DEFAULT NULL,
  `avatar_url` varchar(512) DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `completed_chapters` int DEFAULT NULL,
  `total_chapters` int DEFAULT NULL,
  `completed_percent` decimal(8,2) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`user_id`),
  KEY `idx_learn_user_profile_domain` (`domain_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='学习用户档案表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_user_subject`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_user_subject` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `subject_id` bigint NOT NULL,
  `domain_id` bigint DEFAULT NULL,
  `selected_at` datetime DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_learn_user_subject` (`user_id`,`subject_id`),
  KEY `idx_learn_user_subject_domain` (`domain_id`)
) ENGINE=InnoDB AUTO_INCREMENT=31 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户学科关联表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learn_wrong_question`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `learn_wrong_question` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL COMMENT '用户ID',
  `question_id` bigint NOT NULL COMMENT '题目ID',
  `subject_id` bigint DEFAULT NULL COMMENT '学科ID',
  `chapter_id` bigint DEFAULT NULL COMMENT '章节ID',
  `level_id` bigint DEFAULT NULL COMMENT '关卡ID',
  `wrong_answer` text COMMENT '错误答案',
  `wrong_count` int NOT NULL DEFAULT '1' COMMENT '错误次数',
  `first_wrong_at` datetime DEFAULT NULL COMMENT '首次错误时间',
  `last_wrong_at` datetime DEFAULT NULL COMMENT '最近错误时间',
  `is_reviewed` tinyint(1) NOT NULL DEFAULT '0' COMMENT '是否已复习',
  `reviewed_at` datetime DEFAULT NULL COMMENT '复习时间',
  `review_count` int NOT NULL DEFAULT '0' COMMENT '复习次数',
  `is_mastered` tinyint(1) NOT NULL DEFAULT '0' COMMENT '是否已掌握',
  `mastered_at` datetime DEFAULT NULL COMMENT '掌握时间',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_lwq_user` (`user_id`),
  KEY `idx_lwq_question` (`question_id`),
  KEY `idx_lwq_mastered` (`is_mastered`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='错题本表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `mfa_attempt_log`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `mfa_attempt_log` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `mfa_type` varchar(32) NOT NULL,
  `attempt_code` varchar(64) DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'UNKNOWN',
  `success` tinyint(1) NOT NULL DEFAULT '0',
  `failure_reason` varchar(512) DEFAULT NULL,
  `attempted_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip` varchar(64) DEFAULT NULL,
  `user_agent` varchar(512) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_mal_created` (`created_at`),
  KEY `idx_mal_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='MFA 尝试日志';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `notifications`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `notifications` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint DEFAULT NULL,
  `webhook_config_id` bigint DEFAULT NULL,
  `notification_type` varchar(64) DEFAULT NULL,
  `event_type` varchar(64) DEFAULT NULL,
  `event_data` json DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `status_code` int DEFAULT NULL,
  `response_text` text,
  `error_message` text,
  `attempt_count` int DEFAULT NULL,
  `last_attempt_at` datetime DEFAULT NULL,
  `recipient` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_notifications_user` (`user_id`),
  KEY `idx_notifications_webhook` (`webhook_config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=29 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='通知表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `permission_action`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_action` (
  `action_id` bigint NOT NULL AUTO_INCREMENT,
  `domain_id` bigint DEFAULT NULL,
  `resource_type_id` bigint NOT NULL,
  `action_code` varchar(64) NOT NULL COMMENT '动作代码（如 read, write, delete）',
  `action_name` varchar(128) NOT NULL,
  `action_description` text,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`action_id`),
  UNIQUE KEY `uk_resource_action` (`resource_type_id`,`action_code`),
  KEY `idx_action_domain` (`domain_id`)
) ENGINE=InnoDB AUTO_INCREMENT=632 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='权限动作';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `permission_delegation`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_delegation` (
  `delegation_id` bigint NOT NULL AUTO_INCREMENT,
  `delegator_card_id` bigint NOT NULL COMMENT '委托方卡片ID',
  `delegate_card_id` bigint NOT NULL COMMENT '被委托方卡片ID',
  `resource_type` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '委托的资源类型',
  `action_code` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '委托的动作',
  `effective_from` datetime NOT NULL,
  `effective_until` datetime NOT NULL,
  `max_duration_hours` int DEFAULT '24',
  `is_revokable` tinyint(1) DEFAULT '1',
  `delegated_at` datetime NOT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `status` varchar(16) COLLATE utf8mb4_unicode_ci DEFAULT 'ACTIVE',
  PRIMARY KEY (`delegation_id`),
  KEY `idx_delegator` (`delegator_card_id`),
  KEY `idx_delegate` (`delegate_card_id`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `permission_hit_stat`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_hit_stat` (
  `card_id` bigint NOT NULL,
  `resource_type` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `action_code` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `hit_count` bigint DEFAULT '0',
  `last_hit_at` datetime DEFAULT NULL,
  PRIMARY KEY (`card_id`,`resource_type`,`action_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `permission_request`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_request` (
  `request_id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL COMMENT '申请人ID',
  `request_type` varchar(32) NOT NULL COMMENT '申请类型: RULE / LEVEL_UP / TEMP_PERMISSION',
  `request_content` text COMMENT '申请内容JSON',
  `reason` varchar(512) DEFAULT NULL COMMENT '申请原因',
  `status` varchar(32) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING / APPROVED / REJECTED / CANCELLED',
  `approver_id` bigint DEFAULT NULL COMMENT '审批人ID',
  `approved_at` datetime DEFAULT NULL COMMENT '审批时间',
  `approve_comment` varchar(512) DEFAULT NULL COMMENT '审批意见',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`request_id`),
  KEY `idx_pr_user` (`user_id`),
  KEY `idx_pr_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='权限申请表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `permission_rule`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_rule` (
  `rule_id` bigint NOT NULL AUTO_INCREMENT,
  `card_id` bigint NOT NULL COMMENT '用户卡ID',
  `resource_type` varchar(64) NOT NULL COMMENT '资源类型编码',
  `resource_id` bigint DEFAULT NULL COMMENT '资源ID，可为空表示资源类型级',
  `action_code` varchar(64) NOT NULL COMMENT '动作编码',
  `effect` varchar(16) NOT NULL DEFAULT 'ALLOW' COMMENT 'ALLOW / DENY',
  `condition_json` text COMMENT '规则条件JSON',
  `priority` int NOT NULL DEFAULT '0' COMMENT '优先级，越大越先匹配',
  `source_type` varchar(32) NOT NULL DEFAULT 'MANUAL' COMMENT 'MANUAL / TEMPLATE / SYSTEM',
  `source_id` bigint DEFAULT NULL COMMENT '来源ID',
  `valid_from` datetime DEFAULT NULL COMMENT '生效时间',
  `valid_to` datetime DEFAULT NULL COMMENT '失效时间',
  `enabled` tinyint NOT NULL DEFAULT '1' COMMENT '是否启用',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`rule_id`),
  KEY `idx_permission_rule_card_scope` (`card_id`,`resource_type`,`action_code`,`enabled`,`priority`),
  KEY `idx_permission_rule_effective` (`card_id`,`enabled`,`valid_from`,`valid_to`),
  CONSTRAINT `fk_permission_rule_card` FOREIGN KEY (`card_id`) REFERENCES `user_card` (`card_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1810 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='权限规则表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `permission_rule_audit_log`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_rule_audit_log` (
  `audit_id` bigint NOT NULL AUTO_INCREMENT,
  `rule_id` bigint DEFAULT NULL,
  `card_id` bigint DEFAULT NULL,
  `changed_by` bigint DEFAULT NULL COMMENT '操作人用户ID',
  `change_type` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'CREATE/UPDATE/DELETE',
  `old_value_json` text COLLATE utf8mb4_unicode_ci COMMENT '变更前完整快照',
  `new_value_json` text COLLATE utf8mb4_unicode_ci COMMENT '变更后完整快照',
  `changed_at` datetime NOT NULL,
  `ip_address` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`audit_id`),
  KEY `idx_rule` (`rule_id`),
  KEY `idx_card` (`card_id`),
  KEY `idx_changed_at` (`changed_at`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `permission_rule_snapshot`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_rule_snapshot` (
  `snapshot_id` bigint NOT NULL AUTO_INCREMENT,
  `card_id` bigint NOT NULL,
  `resource_key` varchar(128) NOT NULL COMMENT 'resource_type:resource_id',
  `action_code` varchar(64) NOT NULL,
  `final_effect` varchar(16) NOT NULL COMMENT 'ALLOW / DENY',
  `rule_id` bigint NOT NULL,
  `version_no` bigint NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`snapshot_id`),
  UNIQUE KEY `uk_permission_rule_snapshot` (`card_id`,`resource_key`,`action_code`),
  KEY `idx_permission_rule_snapshot_card` (`card_id`,`action_code`)
) ENGINE=InnoDB AUTO_INCREMENT=1699 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='权限规则快照表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `permission_rule_template`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permission_rule_template` (
  `template_rule_id` bigint NOT NULL AUTO_INCREMENT COMMENT '规则模板条目ID',
  `template_id` bigint NOT NULL COMMENT '用户卡模板ID，引用 user_card_template.template_id',
  `resource_type` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '资源类型（如 course, question, subject）',
  `resource_id` bigint DEFAULT NULL COMMENT '资源ID，NULL 表示该类型下所有资源',
  `action_code` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '动作编码（如 read, write, delete）',
  `effect` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ALLOW' COMMENT 'ALLOW / DENY',
  `condition_json` json DEFAULT NULL COMMENT 'ABAC 条件（预留）',
  `priority` int NOT NULL DEFAULT '0' COMMENT '优先级，越大越优先',
  `enabled` tinyint NOT NULL DEFAULT '1' COMMENT '是否启用：1=启用，0=禁用',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`template_rule_id`),
  UNIQUE KEY `uk_prt_template_resource_action` (`template_id`,`resource_type`,`action_code`),
  KEY `idx_prt_template` (`template_id`),
  CONSTRAINT `fk_prt_template` FOREIGN KEY (`template_id`) REFERENCES `user_card_template` (`template_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=548 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='规则模板表：模板级规则定义，发放时实例化到 user_card';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `platform_domain`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `platform_domain` (
  `domain_id` bigint NOT NULL AUTO_INCREMENT,
  `domain_code` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `domain_name` varchar(128) NOT NULL,
  `domain_description` varchar(512) DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`domain_id`),
  UNIQUE KEY `uk_pd_domain_code` (`domain_code`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='模块域（Chat/Learn/Identity/TrustGraph 等）';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `platform_package`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `platform_package` (
  `package_id` bigint NOT NULL AUTO_INCREMENT,
  `package_name` varchar(64) NOT NULL,
  `package_code` varchar(64) NOT NULL,
  `description` varchar(512) DEFAULT NULL,
  `price` decimal(10,2) DEFAULT '0.00',
  `status` varchar(16) DEFAULT 'ACTIVE',
  `version_no` int DEFAULT '1',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`package_id`),
  UNIQUE KEY `uk_pkg_code` (`package_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='方案包定义';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `platform_package_domain_ref`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `platform_package_domain_ref` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `package_id` bigint NOT NULL,
  `domain_id` bigint NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ppdr_pkg_domain` (`package_id`,`domain_id`),
  KEY `fk_ppdr_domain` (`domain_id`),
  CONSTRAINT `fk_ppdr_domain` FOREIGN KEY (`domain_id`) REFERENCES `platform_domain` (`domain_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ppdr_package` FOREIGN KEY (`package_id`) REFERENCES `platform_package` (`package_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='方案包-域关联';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `platform_package_rule_set_ref`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `platform_package_rule_set_ref` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `package_id` bigint NOT NULL,
  `rule_set_id` bigint NOT NULL,
  `role_type` varchar(16) NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_pprsr_pkg_rule_role` (`package_id`,`rule_set_id`,`role_type`),
  KEY `fk_pprsr_rule_set` (`rule_set_id`),
  CONSTRAINT `fk_pprsr_package` FOREIGN KEY (`package_id`) REFERENCES `platform_package` (`package_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_pprsr_rule_set` FOREIGN KEY (`rule_set_id`) REFERENCES `rule_set` (`rule_set_id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='方案包-规则集关联';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `platform_user`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `platform_user` (
  `user_id` bigint NOT NULL AUTO_INCREMENT,
  `user_no` varchar(64) NOT NULL,
  `display_name` varchar(128) NOT NULL,
  `email` varchar(255) DEFAULT NULL,
  `phone` varchar(32) DEFAULT NULL,
  `avatar_url` varchar(512) DEFAULT NULL,
  `source_type` varchar(64) NOT NULL DEFAULT 'LOCAL' COMMENT '账户来源类型',
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` datetime DEFAULT NULL,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `uk_pu_user_no` (`user_no`),
  KEY `idx_pu_email` (`email`),
  KEY `idx_pu_phone` (`phone`),
  KEY `idx_pu_status` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=52 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='平台用户';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `rule_set`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `rule_set` (
  `rule_set_id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '规则集名称',
  `code` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '规则集编码',
  `description` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '描述',
  `source_type` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'TEMPLATE' COMMENT 'TEMPLATE / OVERLAY',
  `source_id` bigint DEFAULT NULL COMMENT '来源ID（如模板ID）',
  `enabled` tinyint NOT NULL DEFAULT '1' COMMENT '是否启用',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL COMMENT 'tenant_id',
  PRIMARY KEY (`rule_set_id`),
  UNIQUE KEY `uk_rule_set_code` (`code`),
  KEY `idx_rule_set_source` (`source_type`,`source_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='规则集';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `rule_set_audit_log`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `rule_set_audit_log` (
  `audit_id` bigint NOT NULL AUTO_INCREMENT,
  `rule_set_id` bigint NOT NULL COMMENT '规则集ID',
  `entry_id` bigint DEFAULT NULL COMMENT '条目ID',
  `changed_by` bigint NOT NULL COMMENT '操作人ID',
  `change_type` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'CREATE / UPDATE / DELETE / REBUILD_SNAPSHOT',
  `old_value_json` json DEFAULT NULL COMMENT '变更前值',
  `new_value_json` json DEFAULT NULL COMMENT '变更后值',
  `changed_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`audit_id`),
  KEY `idx_rsal_rule_set` (`rule_set_id`),
  KEY `idx_rsal_changed_by` (`changed_by`),
  CONSTRAINT `fk_rsal_rule_set` FOREIGN KEY (`rule_set_id`) REFERENCES `rule_set` (`rule_set_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='规则集审计日志';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `rule_set_entry`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `rule_set_entry` (
  `entry_id` bigint NOT NULL AUTO_INCREMENT,
  `rule_set_id` bigint NOT NULL COMMENT '所属规则集ID',
  `resource_type` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '资源类型',
  `resource_id` bigint DEFAULT NULL COMMENT '资源ID（NULL表示类型级）',
  `action_code` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '动作编码',
  `effect` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ALLOW' COMMENT 'ALLOW / DENY',
  `condition_json` json DEFAULT NULL COMMENT 'ABAC条件',
  `priority` int NOT NULL DEFAULT '0' COMMENT '优先级，越大越优先',
  `enabled` tinyint NOT NULL DEFAULT '1' COMMENT '是否启用',
  `valid_from` datetime DEFAULT NULL COMMENT '生效时间',
  `valid_to` datetime DEFAULT NULL COMMENT '失效时间',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`entry_id`),
  KEY `idx_rule_set_entry` (`rule_set_id`,`enabled`,`priority`),
  CONSTRAINT `fk_rse_rule_set` FOREIGN KEY (`rule_set_id`) REFERENCES `rule_set` (`rule_set_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=635 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='规则集条目';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `rule_set_snapshot`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `rule_set_snapshot` (
  `snapshot_id` bigint NOT NULL AUTO_INCREMENT,
  `rule_set_id` bigint NOT NULL COMMENT '规则集ID',
  `resource_key` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'resourceType:resourceId 或 resourceType:*',
  `action_code` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '动作编码',
  `final_effect` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'ALLOW / DENY',
  `entry_id` bigint NOT NULL COMMENT '来源条目ID',
  `version_no` bigint NOT NULL DEFAULT '0' COMMENT '版本号',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`snapshot_id`),
  UNIQUE KEY `uk_rule_set_snapshot` (`rule_set_id`,`resource_key`,`action_code`),
  KEY `idx_rss_rule_set` (`rule_set_id`,`action_code`),
  CONSTRAINT `fk_rss_rule_set` FOREIGN KEY (`rule_set_id`) REFERENCES `rule_set` (`rule_set_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=462 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='规则集快照';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `school_members`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `school_members` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `school_id` bigint NOT NULL,
  `user_id` bigint NOT NULL,
  `member_type` varchar(32) NOT NULL,
  `student_number` varchar(64) DEFAULT NULL,
  `department` varchar(128) DEFAULT NULL,
  `major` varchar(128) DEFAULT NULL,
  `grade` varchar(64) DEFAULT NULL,
  `class_name` varchar(128) DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `joined_at` datetime DEFAULT NULL,
  `left_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_school_members_school` (`school_id`),
  KEY `idx_school_members_user` (`user_id`),
  KEY `idx_school_members_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='学校成员表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `schools`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `schools` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `code` varchar(64) NOT NULL COMMENT '学校代码',
  `name` varchar(128) NOT NULL COMMENT '学校名称',
  `name_en` varchar(128) DEFAULT NULL COMMENT '英文名称',
  `type` varchar(32) DEFAULT NULL COMMENT '机构类型',
  `contact_person` varchar(64) DEFAULT NULL COMMENT '联系人',
  `contact_phone` varchar(32) DEFAULT NULL COMMENT '联系电话',
  `contact_email` varchar(128) DEFAULT NULL COMMENT '联系邮箱',
  `country` varchar(16) DEFAULT NULL COMMENT '国家代码',
  `province` varchar(64) DEFAULT NULL COMMENT '省份',
  `city` varchar(64) DEFAULT NULL COMMENT '城市',
  `district` varchar(64) DEFAULT NULL COMMENT '区县',
  `address` varchar(512) DEFAULT NULL COMMENT '详细地址',
  `postal_code` varchar(32) DEFAULT NULL COMMENT '邮编',
  `logo_url` varchar(512) DEFAULT NULL COMMENT 'Logo URL',
  `website` varchar(512) DEFAULT NULL COMMENT '官网',
  `description` text COMMENT '简介',
  `timezone` varchar(64) DEFAULT NULL COMMENT '时区',
  `locale` varchar(16) DEFAULT NULL COMMENT '语言地区',
  `settings` json DEFAULT NULL COMMENT '学校配置JSON',
  `status` varchar(16) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态',
  `verified` tinyint(1) DEFAULT '0' COMMENT '是否认证',
  `verified_at` datetime DEFAULT NULL COMMENT '认证时间',
  `student_count` int DEFAULT '0' COMMENT '学生数',
  `teacher_count` int DEFAULT '0' COMMENT '教师数',
  `course_count` int DEFAULT '0' COMMENT '课程数',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by` bigint DEFAULT NULL COMMENT '创建人ID',
  `domain_id` bigint DEFAULT NULL,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_school_code` (`code`),
  KEY `idx_schools_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='学校/机构表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sod_policy`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sod_policy` (
  `policy_id` bigint NOT NULL AUTO_INCREMENT,
  `policy_name` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `description` varchar(512) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `conflict_type` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'STATIC / DYNAMIC / BEHAVIORAL',
  `resource_type` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '资源类型（动态/行为类需要）',
  `action_code` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '动作代码（动态/行为类需要）',
  `permission_a` varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '互斥权限 A，如 question:create',
  `permission_b` varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '互斥权限 B，如 question:publish',
  `condition_script` varchar(1024) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '条件脚本',
  `limit_count` int DEFAULT '0' COMMENT '行为限制次数',
  `limit_window` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '行为时间窗口，如 1d/1h',
  `status` varchar(16) COLLATE utf8mb4_unicode_ci DEFAULT 'ACTIVE',
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`policy_id`),
  UNIQUE KEY `uk_policy_name` (`policy_name`),
  KEY `idx_conflict_type` (`conflict_type`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sod_violation`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `sod_violation` (
  `violation_id` bigint NOT NULL AUTO_INCREMENT,
  `policy_id` bigint NOT NULL,
  `policy_name` varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `card_id` bigint DEFAULT NULL,
  `user_id` bigint DEFAULT NULL,
  `operator_id` bigint DEFAULT NULL,
  `violation_type` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'GRANT / RUNTIME',
  `details_json` json DEFAULT NULL,
  `blocked` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` datetime DEFAULT NULL,
  PRIMARY KEY (`violation_id`),
  KEY `idx_policy` (`policy_id`),
  KEY `idx_card` (`card_id`),
  KEY `idx_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `subject_progress`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `subject_progress` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `subject_id` bigint NOT NULL,
  `completed_chapters` int DEFAULT NULL,
  `total_chapters` int DEFAULT NULL,
  `completed_levels` int DEFAULT NULL,
  `total_levels` int DEFAULT NULL,
  `completion_percentage` decimal(8,2) DEFAULT NULL,
  `average_score` decimal(8,2) DEFAULT NULL,
  `study_minutes` int DEFAULT NULL,
  `total_points` int DEFAULT NULL,
  `last_activity_at` datetime DEFAULT NULL,
  `completed_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_subject_progress_user` (`user_id`),
  KEY `idx_subject_progress_subject` (`subject_id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='学科进度表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `system_settings`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `system_settings` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `setting_key` varchar(128) NOT NULL,
  `setting_value` text,
  `value_type` int NOT NULL DEFAULT '0',
  `category` varchar(64) DEFAULT NULL,
  `display_name` varchar(128) DEFAULT NULL,
  `description` text,
  `is_system` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `updated_by` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_system_settings_key` (`setting_key`),
  KEY `idx_system_settings_category` (`category`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='系统配置表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tenant`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tenant` (
  `tenant_id` bigint NOT NULL AUTO_INCREMENT,
  `tenant_code` varchar(64) NOT NULL,
  `tenant_name` varchar(128) NOT NULL,
  `tenant_type` varchar(32) NOT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `parent_tenant_id` bigint DEFAULT NULL COMMENT '父租户ID（NULL=根租户）',
  `path` varchar(512) DEFAULT NULL COMMENT '物化路径，如 /1/2/5',
  `depth` int NOT NULL DEFAULT '0' COMMENT '层级深度（0=根）',
  `contact_person` varchar(64) DEFAULT NULL,
  `contact_phone` varchar(32) DEFAULT NULL,
  `contact_email` varchar(128) DEFAULT NULL,
  `max_members` int NOT NULL DEFAULT '1000' COMMENT '最大成员数',
  `max_admins` int NOT NULL DEFAULT '10',
  `current_members` int NOT NULL DEFAULT '0' COMMENT '当前成员数',
  `license_key` varchar(256) DEFAULT NULL,
  `license_expires` datetime DEFAULT NULL,
  `logo_url` varchar(512) DEFAULT NULL COMMENT 'Logo URL',
  `settings_json` json DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`tenant_id`),
  UNIQUE KEY `uk_tenant_code` (`tenant_code`),
  KEY `idx_tenant_parent` (`parent_tenant_id`),
  KEY `idx_tenant_path` (`path`),
  CONSTRAINT `fk_tenant_parent` FOREIGN KEY (`parent_tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE RESTRICT
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='租户主表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tenant_audit_log`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tenant_audit_log` (
  `log_id` bigint NOT NULL AUTO_INCREMENT COMMENT '日志ID',
  `tenant_id` bigint NOT NULL COMMENT '租户ID',
  `operator_id` bigint DEFAULT NULL COMMENT '操作人用户ID',
  `action` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '操作类型',
  `target_type` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '目标类型',
  `target_id` bigint DEFAULT NULL COMMENT '目标ID',
  `detail_json` json DEFAULT NULL COMMENT '详情JSON',
  `ip` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '操作来源IP',
  `trace_id` varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '链路追踪ID',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`log_id`),
  KEY `idx_tal_tenant` (`tenant_id`),
  KEY `idx_tal_operator` (`operator_id`),
  KEY `idx_tal_action` (`action`),
  KEY `idx_tal_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='租户操作审计日志';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tenant_domain_map`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tenant_domain_map` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint NOT NULL,
  `domain_id` bigint NOT NULL,
  `granted_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `granted_by` bigint DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_tenant_domain` (`tenant_id`,`domain_id`),
  KEY `fk_tdm_domain` (`domain_id`),
  CONSTRAINT `fk_tdm_domain` FOREIGN KEY (`domain_id`) REFERENCES `platform_domain` (`domain_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_tdm_tenant` FOREIGN KEY (`tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='租户-域映射';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tenant_invitation`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tenant_invitation` (
  `invitation_id` bigint NOT NULL AUTO_INCREMENT COMMENT '邀请ID',
  `tenant_id` bigint NOT NULL COMMENT '租户ID',
  `sub_tenant_id` bigint DEFAULT NULL COMMENT '目标子租户ID',
  `dept_id` bigint DEFAULT NULL COMMENT '目标部门ID',
  `invite_code` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '邀请码（唯一）',
  `role` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'MEMBER' COMMENT '邀请角色',
  `invited_by` bigint DEFAULT NULL COMMENT '邀请人用户ID',
  `max_uses` int DEFAULT NULL COMMENT '最大使用次数（NULL无限制）',
  `current_uses` int NOT NULL DEFAULT '0' COMMENT '已使用次数',
  `expires_at` datetime DEFAULT NULL COMMENT '过期时间',
  `status` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE / REVOKED / EXHAUSTED',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`invitation_id`),
  UNIQUE KEY `uk_invite_code` (`invite_code`),
  KEY `idx_ti_tenant` (`tenant_id`),
  KEY `idx_ti_status` (`status`),
  KEY `idx_ti_sub_tenant` (`sub_tenant_id`),
  KEY `idx_ti_dept` (`dept_id`),
  CONSTRAINT `fk_ti_dept` FOREIGN KEY (`dept_id`) REFERENCES `departments` (`dept_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_ti_sub_tenant` FOREIGN KEY (`sub_tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_ti_tenant` FOREIGN KEY (`tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='租户邀请码';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tenant_members`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tenant_members` (
  `member_id` bigint NOT NULL AUTO_INCREMENT COMMENT '成员记录ID',
  `user_id` bigint NOT NULL COMMENT '用户ID',
  `tenant_id` bigint NOT NULL COMMENT '所属根租户ID',
  `sub_tenant_id` bigint DEFAULT NULL COMMENT '所属子租户ID',
  `dept_id` bigint DEFAULT NULL COMMENT '所属部门ID',
  `admin_level` int NOT NULL DEFAULT '0' COMMENT '管理等级（0=成员, 1+=管理层级, 值越大权限越高）',
  `role_type` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'MEMBER' COMMENT 'TENANT_OWNER / ADMIN / MEMBER',
  `position` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '职位名称',
  `member_status` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE / SUSPENDED / REMOVED',
  `is_primary` tinyint(1) NOT NULL DEFAULT '1' COMMENT '是否主租户',
  `joined_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `invited_by` bigint DEFAULT NULL COMMENT '邀请人ID',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`member_id`),
  UNIQUE KEY `uk_member_user_tenant` (`user_id`,`tenant_id`),
  KEY `idx_tm_tenant` (`tenant_id`),
  KEY `idx_tm_sub_tenant` (`sub_tenant_id`),
  KEY `idx_tm_dept` (`dept_id`),
  KEY `idx_tm_role` (`tenant_id`,`role_type`),
  KEY `idx_tm_user` (`user_id`),
  CONSTRAINT `fk_tm_dept` FOREIGN KEY (`dept_id`) REFERENCES `departments` (`dept_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_tm_sub_tenant` FOREIGN KEY (`sub_tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_tm_tenant` FOREIGN KEY (`tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_tm_user` FOREIGN KEY (`user_id`) REFERENCES `platform_user` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=24 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='租户成员表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tenant_purchase`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tenant_purchase` (
  `purchase_id` bigint NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint NOT NULL,
  `sub_tenant_id` bigint DEFAULT NULL COMMENT '若为子租户单独购买',
  `package_id` bigint NOT NULL,
  `status` varchar(16) DEFAULT 'ACTIVE',
  `purchased_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `expired_at` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`purchase_id`),
  KEY `idx_tp_tenant` (`tenant_id`),
  KEY `idx_tp_package` (`package_id`),
  KEY `idx_tp_sub_tenant` (`sub_tenant_id`),
  CONSTRAINT `fk_tp_package` FOREIGN KEY (`package_id`) REFERENCES `platform_package` (`package_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_tp_sub_tenant` FOREIGN KEY (`sub_tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_tp_tenant` FOREIGN KEY (`tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='租户购买记录';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tenant_user_map`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `tenant_user_map` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `tenant_id` bigint NOT NULL,
  `user_id` bigint NOT NULL,
  `role` varchar(32) NOT NULL DEFAULT 'MEMBER',
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `joined_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `invited_by` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_tenant_user` (`tenant_id`,`user_id`),
  KEY `fk_tum_user` (`user_id`),
  CONSTRAINT `fk_tum_tenant` FOREIGN KEY (`tenant_id`) REFERENCES `tenant` (`tenant_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_tum_user` FOREIGN KEY (`user_id`) REFERENCES `platform_user` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='租户-用户绑定';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_badges`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_badges` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `badge_id` bigint NOT NULL,
  `earned_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_badges` (`user_id`,`badge_id`),
  KEY `idx_user_badges_user` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=86 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户徽章表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_card`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_card` (
  `card_id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint DEFAULT NULL COMMENT '可为空，发布后自动发放',
  `domain_id` bigint DEFAULT NULL,
  `card_type` varchar(32) NOT NULL COMMENT 'PLATFORM_CARD|ORG_CARD|STARTER_CARD',
  `card_status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `template_id` bigint DEFAULT NULL,
  `level_id` bigint DEFAULT NULL,
  `priority` int NOT NULL DEFAULT '100',
  `is_primary` tinyint(1) NOT NULL DEFAULT '0',
  `valid_from` datetime DEFAULT NULL,
  `valid_until` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `tenant_id` bigint DEFAULT NULL,
  PRIMARY KEY (`card_id`),
  KEY `fk_uc_level` (`level_id`),
  KEY `fk_uc_template` (`template_id`),
  KEY `idx_uc_card_type` (`card_type`),
  KEY `idx_uc_domain` (`domain_id`),
  KEY `idx_uc_primary` (`is_primary`),
  KEY `idx_uc_user` (`user_id`),
  CONSTRAINT `fk_uc_domain` FOREIGN KEY (`domain_id`) REFERENCES `platform_domain` (`domain_id`),
  CONSTRAINT `fk_uc_level` FOREIGN KEY (`level_id`) REFERENCES `user_card_level_definition` (`level_id`),
  CONSTRAINT `fk_uc_template` FOREIGN KEY (`template_id`) REFERENCES `user_card_template` (`template_id`),
  CONSTRAINT `fk_uc_user` FOREIGN KEY (`user_id`) REFERENCES `platform_user` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=94 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户卡片';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_card_context_cache`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_card_context_cache` (
  `card_id` bigint NOT NULL COMMENT '用户卡ID（user_card.card_id）',
  `context_hash` varchar(255) NOT NULL,
  `scope_json` json DEFAULT NULL,
  `grants_json` json DEFAULT NULL,
  `expire_at` datetime DEFAULT NULL,
  PRIMARY KEY (`card_id`),
  CONSTRAINT `fk_uccc_card` FOREIGN KEY (`card_id`) REFERENCES `user_card` (`card_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户卡上下文缓存';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_card_level_definition`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_card_level_definition` (
  `level_id` bigint NOT NULL AUTO_INCREMENT,
  `domain_id` bigint NOT NULL,
  `level_no` int NOT NULL,
  `level_code` varchar(64) NOT NULL,
  `level_name` varchar(128) NOT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `upgrade_strategy_json` text COMMENT '升级策略预留，当前为空',
  `description` varchar(512) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`level_id`),
  UNIQUE KEY `uk_iuld_domain_level_code` (`domain_id`,`level_code`),
  UNIQUE KEY `uk_iuld_domain_level_no` (`domain_id`,`level_no`),
  KEY `idx_iuld_status` (`status`),
  CONSTRAINT `fk_iuld_domain` FOREIGN KEY (`domain_id`) REFERENCES `platform_domain` (`domain_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户卡等级定义';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_card_template`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_card_template` (
  `template_id` bigint NOT NULL AUTO_INCREMENT,
  `domain_id` bigint NOT NULL,
  `tenant_id` bigint DEFAULT NULL COMMENT '租户ID',
  `parent_template_id` bigint DEFAULT NULL,
  `template_code` varchar(128) NOT NULL,
  `template_name` varchar(128) NOT NULL,
  `card_type` varchar(32) NOT NULL COMMENT 'PLATFORM_CARD|ORG_CARD|STARTER_CARD',
  `template_scope` varchar(32) NOT NULL DEFAULT 'SYSTEM' COMMENT 'SYSTEM|DOMAIN|ORG',
  `version_no` int NOT NULL DEFAULT '1',
  `default_priority` int NOT NULL DEFAULT '100',
  `default_roles_json` json DEFAULT NULL,
  `resource_scope_json` json DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`template_id`),
  UNIQUE KEY `uk_uct_domain_code` (`domain_id`,`template_code`),
  KEY `idx_parent_template` (`parent_template_id`),
  CONSTRAINT `fk_parent_template` FOREIGN KEY (`parent_template_id`) REFERENCES `user_card_template` (`template_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_uct_domain` FOREIGN KEY (`domain_id`) REFERENCES `platform_domain` (`domain_id`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户卡模板（员工证/医疗证模板）';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_identity`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_identity` (
  `identity_id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL COMMENT '冗余字段，便于快速查询',
  `identity_card_id` bigint DEFAULT NULL COMMENT '绑定的身份证ID',
  `provider_client_id` bigint DEFAULT NULL,
  `provider` varchar(64) NOT NULL COMMENT 'wechat|google|github|microsoft|local',
  `subject_key` varchar(255) NOT NULL,
  `account_key` varchar(255) DEFAULT NULL,
  `provider_user_id` varchar(255) DEFAULT NULL COMMENT '旧字段兼容',
  `provider_username` varchar(255) DEFAULT NULL,
  `provider_email` varchar(255) DEFAULT NULL,
  `provider_phone` varchar(64) DEFAULT NULL,
  `provider_data` json DEFAULT NULL,
  `verified` tinyint(1) NOT NULL DEFAULT '0',
  `provider_account_id` varchar(255) DEFAULT NULL,
  `provider_subject_id` varchar(255) DEFAULT NULL,
  `provider_subject_type` varchar(64) DEFAULT NULL,
  `provider_account_type` varchar(64) DEFAULT NULL,
  `app_id` varchar(128) DEFAULT NULL,
  `client_app_id` varchar(128) DEFAULT NULL,
  `tenant_id` varchar(128) DEFAULT NULL,
  `channel_code` varchar(64) DEFAULT NULL,
  `binding_status` varchar(32) DEFAULT NULL,
  `merged_to_identity_id` bigint DEFAULT NULL,
  `display_name` varchar(128) DEFAULT NULL,
  `avatar_url` varchar(512) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `email_verified` tinyint(1) DEFAULT '0',
  `meta_json` json DEFAULT NULL,
  `access_token_enc` blob,
  `refresh_token_enc` blob,
  `token_expires_at` datetime DEFAULT NULL,
  `last_used_at` datetime DEFAULT NULL,
  `bound_at` datetime DEFAULT NULL,
  `unbound_at` datetime DEFAULT NULL,
  `unbound_by` varchar(128) DEFAULT NULL,
  `disabled_at` datetime DEFAULT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `is_primary` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`identity_id`),
  UNIQUE KEY `uk_ui_provider_user` (`provider`,`provider_user_id`),
  KEY `fk_ui_identity_card` (`identity_card_id`),
  KEY `idx_ui_subject_key` (`provider`,`subject_key`),
  KEY `idx_ui_account_key` (`provider`,`account_key`),
  KEY `idx_ui_provider_account_id` (`provider`,`provider_account_id`),
  KEY `idx_ui_provider_subject_id` (`provider`,`provider_subject_id`),
  KEY `idx_ui_provider` (`provider`),
  KEY `idx_ui_user` (`user_id`),
  CONSTRAINT `fk_ui_identity_card` FOREIGN KEY (`identity_card_id`) REFERENCES `identity_card` (`card_id`) ON DELETE SET NULL,
  CONSTRAINT `fk_ui_user` FOREIGN KEY (`user_id`) REFERENCES `platform_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户身份（第三方身份绑定到身份证）';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_learning_profile`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_learning_profile` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL COMMENT '用户ID',
  `score` int DEFAULT NULL COMMENT '积分',
  `user_level` int DEFAULT NULL COMMENT '用户等级',
  `completed_chapters` int DEFAULT NULL COMMENT '已完成章节数',
  `total_chapters` int DEFAULT NULL COMMENT '总章节数',
  `completed_percent` decimal(5,2) DEFAULT NULL COMMENT '完成百分比',
  `last_activity_at` datetime DEFAULT NULL COMMENT '最后活动时间',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_ulp_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户学习档案（历史遗留）';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_local_credential`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_local_credential` (
  `credential_id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `login_name` varchar(128) DEFAULT NULL COMMENT '登录名（手机号/邮箱/用户名）',
  `password_hash` varchar(256) NOT NULL,
  `password_algo` varchar(32) NOT NULL DEFAULT 'ARGON2ID' COMMENT '密码算法',
  `password_set_at` datetime DEFAULT NULL COMMENT '密码设置时间',
  `password_updated_at` datetime DEFAULT NULL COMMENT '密码更新时间',
  `must_change_password` tinyint(1) NOT NULL DEFAULT '0' COMMENT '是否需要修改密码',
  `status` varchar(32) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态',
  `last_login_at` datetime DEFAULT NULL COMMENT '最后登录时间',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`credential_id`),
  UNIQUE KEY `uk_ulc_user_id` (`user_id`),
  UNIQUE KEY `uk_ulc_login_name` (`login_name`),
  KEY `idx_ulc_user` (`user_id`),
  KEY `idx_ulc_login_name` (`login_name`),
  CONSTRAINT `fk_ulc_user` FOREIGN KEY (`user_id`) REFERENCES `platform_user` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=46 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户本地凭证';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_personal_permission_binding`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_personal_permission_binding` (
  `binding_id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL COMMENT '用户ID',
  `permission_code` varchar(128) NOT NULL COMMENT '权限编码',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`binding_id`),
  KEY `idx_uppb_user` (`user_id`),
  KEY `idx_uppb_code` (`permission_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户个人权限绑定表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_profiles`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_profiles` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `school_id` bigint DEFAULT NULL,
  `total_levels_completed` int DEFAULT NULL,
  `total_questions_answered` int DEFAULT NULL,
  `overall_accuracy` decimal(8,2) DEFAULT NULL,
  `total_points` int DEFAULT NULL,
  `badge_count` int DEFAULT NULL,
  `current_level_id` bigint DEFAULT NULL,
  `last_activity_at` datetime DEFAULT NULL,
  `preferences` json DEFAULT NULL,
  `streak_days` int DEFAULT NULL,
  `total_correct_answers` int DEFAULT NULL,
  `user_rank` int DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_profiles_user` (`user_id`),
  KEY `idx_user_profiles_school` (`school_id`)
) ENGINE=InnoDB AUTO_INCREMENT=41 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户学习档案表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_sessions`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_sessions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint NOT NULL,
  `refresh_token_id` bigint DEFAULT NULL,
  `device_id` varchar(255) DEFAULT NULL,
  `device_type` varchar(64) DEFAULT NULL,
  `device_name` varchar(255) DEFAULT NULL,
  `os_name` varchar(128) DEFAULT NULL,
  `os_version` varchar(128) DEFAULT NULL,
  `browser_name` varchar(128) DEFAULT NULL,
  `browser_version` varchar(128) DEFAULT NULL,
  `ip` varchar(64) DEFAULT NULL,
  `ip_location` varchar(512) DEFAULT NULL,
  `is_current` tinyint(1) NOT NULL DEFAULT '0',
  `trusted` tinyint(1) NOT NULL DEFAULT '0',
  `last_active_at` datetime DEFAULT NULL,
  `expires_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `revoked` tinyint(1) NOT NULL DEFAULT '0',
  `revoked_at` datetime DEFAULT NULL,
  `revoked_reason` varchar(512) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_usersessions_user` (`user_id`),
  KEY `idx_usersessions_refresh` (`refresh_token_id`),
  KEY `idx_usersessions_device` (`device_id`),
  CONSTRAINT `fk_usersessions_user` FOREIGN KEY (`user_id`) REFERENCES `platform_user` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='用户会话';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `user_id` bigint NOT NULL AUTO_INCREMENT,
  `openid` varchar(128) DEFAULT NULL,
  `unionid` varchar(128) DEFAULT NULL,
  `nickname` varchar(128) DEFAULT NULL,
  `avatar_url` varchar(512) DEFAULT NULL,
  `gender` int DEFAULT NULL,
  `phone_number` varchar(64) DEFAULT NULL,
  `score` int DEFAULT NULL,
  `level` int DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` datetime DEFAULT NULL,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `uk_users_openid` (`openid`),
  UNIQUE KEY `uk_users_unionid` (`unionid`)
) ENGINE=InnoDB AUTO_INCREMENT=41 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='小程序用户表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `webhook_configs`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `webhook_configs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(128) NOT NULL,
  `webhook_url` varchar(512) NOT NULL,
  `events` json DEFAULT NULL,
  `secret_key` varchar(255) DEFAULT NULL,
  `use_hmac` tinyint(1) NOT NULL DEFAULT '0',
  `retry_times` int NOT NULL DEFAULT '3',
  `retry_delay` int NOT NULL DEFAULT '5',
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `created_by` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_webhook_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Webhook配置表';
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-06-05 20:29:21
