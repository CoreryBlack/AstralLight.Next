-- F4-Rust 分布式一致性 e2e seed（namespace e2e_f4rust_*；与 F3 同 ID 段，目标为全新 run 库）
INSERT INTO platform_domain (domain_id, domain_code, domain_name, status) VALUES
 (9011, 'e2e_f4rust_domain_9001', 'F4R domain 9001', 'ACTIVE'),
 (9012, 'e2e_f4rust_domain_9002', 'F4R domain 9002', 'ACTIVE');

INSERT INTO tenant (tenant_id, tenant_code, tenant_name, tenant_type, status, path, depth) VALUES
 (9001, 'e2e_f4rust_tenant_9001', 'F4R tenant 9001', 'ORGANIZATION', 'ACTIVE', '/9001', 0),
 (9002, 'e2e_f4rust_tenant_9002', 'F4R tenant 9002', 'ORGANIZATION', 'ACTIVE', '/9002', 0);

INSERT INTO tenant_domain_map (id, tenant_id, domain_id, status) VALUES
 (9021, 9001, 9011, 'ACTIVE'),
 (9022, 9002, 9012, 'ACTIVE');

INSERT INTO platform_user (user_id, user_no, display_name, source_type, status) VALUES
 (9031, 'e2e_f4rust_user_9031', 'F4R admin A', 'LOCAL', 'ACTIVE'),
 (9032, 'e2e_f4rust_user_9032', 'F4R admin B', 'LOCAL', 'ACTIVE'),
 (9033, 'e2e_f4rust_user_9033', 'F4R norole C', 'LOCAL', 'ACTIVE');

INSERT INTO user_local_credential (credential_id, user_id, login_name, password_hash, password_algo, password_set_at, password_updated_at, must_change_password, status, created_at, updated_at) VALUES
 (9101, 9031, 'e2e_f4rust_admin1', '$argon2id$v=19$m=102400,t=2,p=8$GdQOo/nNsxeov7g9eiZspw$+vBUrZKOFszaaXwDfrsAIw', 'ARGON2ID', NOW(), NOW(), 0, 'ACTIVE', NOW(), NOW()),
 (9102, 9032, 'e2e_f4rust_admin2', '$argon2id$v=19$m=102400,t=2,p=8$p5fMdKaK/2+L09VI+OP19A$zitNR4urA1Hj/m0AsCgRWQ', 'ARGON2ID', NOW(), NOW(), 0, 'ACTIVE', NOW(), NOW());

INSERT INTO identity_card (card_id, user_id, status, token_version) VALUES
 (9041, 9031, 'ACTIVE', 1),
 (9042, 9032, 'ACTIVE', 1),
 (9043, 9033, 'ACTIVE', 1);

INSERT INTO user_card_template (template_id, domain_id, tenant_id, template_code, template_name, card_type, template_scope, version_no, default_priority, status) VALUES
 (9051, 9011, 9001, 'e2e_f4rust_template_9001', 'F4R template 9001', 'ORG_CARD', 'DOMAIN', 1, 100, 'ACTIVE'),
 (9052, 9012, 9002, 'e2e_f4rust_template_9002', 'F4R template 9002', 'ORG_CARD', 'DOMAIN', 1, 100, 'ACTIVE'),
 (9053, 9011, 9001, 'e2e_f4rust_template_9001b', 'F4R template 9001b', 'ORG_CARD', 'DOMAIN', 1, 100, 'ACTIVE');

INSERT INTO user_card (card_id, user_id, domain_id, card_type, card_status, template_id, tenant_id) VALUES
 (9061, 9031, 9011, 'ORG_CARD', 'ACTIVE', 9051, 9001),
 (9062, 9032, 9012, 'ORG_CARD', 'ACTIVE', 9052, 9002),
 (9063, 9033, 9011, 'ORG_CARD', 'ACTIVE', 9053, 9001);

INSERT INTO rule_set (rule_set_id, name, code, description, source_type, enabled, tenant_id) VALUES
 (9071, 'F4R rule set 9001', 'e2e_f4rust_rs_9001', 'F4R e2e rule set tenant 9001', 'CUSTOM', 1, 9001),
 (9072, 'F4R rule set 9002', 'e2e_f4rust_rs_9002', 'F4R e2e rule set tenant 9002', 'CUSTOM', 1, 9002);

INSERT INTO rule_set_entry (entry_id, rule_set_id, resource_type, action_code, effect, priority, enabled, tenant_id) VALUES
 (9081, 9071, 'learn_subject', 'read', 'ALLOW', 1, 1, 9001);

INSERT INTO identity_global_admin (id, user_id, status, granted_by, granted_reason, created_at, updated_at) VALUES
 (9091, 9031, 'ACTIVE', NULL, 'e2e-f4rust bootstrap admin', NOW(), NOW()),
 (9092, 9032, 'ACTIVE', NULL, 'e2e-f4rust bootstrap admin', NOW(), NOW());
