package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.astral_identity.persistence.entity.User;
import com.coreryblack.astral_identity.persistence.mapper.PlatformUserMapper;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.*;
import com.coreryblack.astral_permission.infrastructure.persistence.mapper.*;
import com.coreryblack.astral_platform.persistence.entity.platform.PlatformDomain;
import com.coreryblack.astral_platform.persistence.mapper.PlatformDomainMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Benchmark 数据库持久化服务。
 * 从 NativeDataGenerator 中提取，负责将生成的基准测试数据批量写入数据库。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DataPersistenceService {

    private static final int DEFAULT_BATCH_SIZE = 5000;

    private final UserCardTemplateMapper templateMapper;
    private final RuleSetMapper ruleSetMapper;
    private final RuleSetEntryMapper entryMapper;
    private final RuleSetSnapshotMapper snapshotMapper;
    private final UserCardMapper userCardMapper;
    private final CardRuleSetRefMapper cardRefMapper;
    private final PermissionRuleMapper permissionRuleMapper;
    private final PermissionRuleSnapshotMapper permSnapshotMapper;
    private final SodPolicyMapper sodPolicyMapper;
    private final PlatformDomainMapper domainMapper;
    private final PlatformUserMapper platformUserMapper;
    private final JdbcTemplate jdbcTemplate;

    private Clock clock = Clock.systemUTC();

    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Transactional(rollbackFor = Exception.class)
    public void persistAll(NativeDataGenerator.NativeGeneratedDataSet dataset) {
        int batchSize = DEFAULT_BATCH_SIZE;
        ensureReferenceData(dataset);

        log.info("[Native] Persisting {} templates (batch)...", dataset.templates.size());
        templateMapper.batchInsert(dataset.templates);

        log.info("[Native] Persisting {} rule sets (batch)...", dataset.ruleSets.size());
        batchInsert(dataset.ruleSets, batchSize, ruleSetMapper::batchInsert);

        log.info("[Native] Persisting {} rule set entries (batch)...", dataset.entries.size());
        for (int i = 0; i < dataset.entries.size(); i += batchSize) {
            List<RuleSetEntry> batch = dataset.entries.subList(i, Math.min(i + batchSize, dataset.entries.size()));
            entryMapper.batchInsert(batch);
            if ((i + batchSize) % 5000 == 0 || i + batchSize >= dataset.entries.size()) {
                log.info("  persisted {}/{} entries", Math.min(i + batchSize, dataset.entries.size()), dataset.entries.size());
            }
        }

        log.info("[Native] Persisting {} rule set snapshots (batch)...", dataset.snapshots.size());
        batchInsert(dataset.snapshots, batchSize, snapshotMapper::batchInsert);

        // Collect all user_cards and card_refs from bindings for batch insert
        List<UserCard> userCards = new ArrayList<>();
        List<CardRuleSetRef> cardRefs = new ArrayList<>();
        List<PermissionRule> allPermRules = new ArrayList<>();
        for (NativeDataGenerator.NativeCardBinding b : dataset.bindings) {
            UserCard userCard = new UserCard();
            userCard.setCardId(b.cardId);
            userCard.setUserId(b.userId);
            userCard.setDomainId(b.domainId);
            userCard.setTenantId(b.tenantId);
            userCard.setCardType(b.cardType);
            userCard.setCardStatus(b.cardStatus);
            userCard.setTemplateId(b.templateId);
            userCard.setPriority(0);
            userCard.setIsPrimary(true);
            userCard.setCreatedAt(now());
            userCard.setUpdatedAt(now());
            userCards.add(userCard);

            if (b.baseRef != null) {
                cardRefs.add(b.baseRef);
            }
            cardRefs.addAll(b.overlayRefs);

            if (b.permissionRules != null) {
                allPermRules.addAll(b.permissionRules);
            }
        }

        log.info("[Native] Persisting {} user cards (batch)...", userCards.size());
        for (int i = 0; i < userCards.size(); i += batchSize) {
            List<UserCard> batch = userCards.subList(i, Math.min(i + batchSize, userCards.size()));
            userCardMapper.batchInsert(batch);
            if ((i + batchSize) % 10000 == 0 || i + batchSize >= userCards.size()) {
                log.info("  persisted {}/{} cards", Math.min(i + batchSize, userCards.size()), userCards.size());
            }
        }

        log.info("[Native] Persisting {} card refs (batch)...", cardRefs.size());
        batchInsert(cardRefs, batchSize, cardRefMapper::batchInsert);

        if (!allPermRules.isEmpty()) {
            log.info("[Native] Persisting {} permission rules (batch)...", allPermRules.size());
            batchInsert(allPermRules, batchSize, permissionRuleMapper::batchInsertWithIds);
        }

        if (!dataset.permSnapshots.isEmpty()) {
            log.info("[Native] Persisting {} permission rule snapshots (batch)...", dataset.permSnapshots.size());
            batchInsert(dataset.permSnapshots, batchSize, permSnapshotMapper::batchInsert);
        }

        if (!dataset.sodPolicies.isEmpty()) {
            log.info("[Native] Persisting {} SOD policies (batch)...", dataset.sodPolicies.size());
            batchInsert(dataset.sodPolicies, batchSize, sodPolicyMapper::batchInsert);
        }

        log.info("[Native] Persistence complete.");
    }

    /**
     * Ensures the benchmark's generated foreign-key context exists before any
     * child row is written. A missing parent is a hard precondition failure,
     * not a condition to ignore and continue with an invalid dataset.
     */
    private void ensureReferenceData(NativeDataGenerator.NativeGeneratedDataSet dataset) {
        Set<Long> domainIds = new LinkedHashSet<>();
        dataset.templates.forEach(template -> domainIds.add(template.getDomainId()));
        for (Long domainId : domainIds) {
            if (!exists("platform_domain", "domain_id", domainId)) {
                PlatformDomain domain = new PlatformDomain();
                domain.setId(domainId);
                domain.setCode("BENCH_DOMAIN_" + domainId);
                domain.setName("Benchmark Domain " + domainId);
                domain.setDescription("Dedicated benchmark domain");
                domain.setStatus("ACTIVE");
                domain.setCreatedAt(now());
                domain.setUpdatedAt(now());
                try {
                    domainMapper.insert(domain);
                } catch (DuplicateKeyException duplicate) {
                    // Another benchmark process may have created the same
                    // reference row between the read and insert. Re-read and
                    // continue only when the requested parent now exists.
                    if (!exists("platform_domain", "domain_id", domainId)) {
                        throw duplicate;
                    }
                }
            }
        }

        Set<Long> userIds = new LinkedHashSet<>();
        dataset.bindings.forEach(binding -> userIds.add(binding.userId));
        for (Long userId : userIds) {
            if (!exists("platform_user", "user_id", userId)) {
                User user = new User();
                user.setId(userId);
                user.setUserNo("BENCH_USER_" + userId);
                user.setDisplayName("Benchmark User " + userId);
                user.setEmail("benchmark-" + userId + "@test.local");
                user.setSourceType("LOCAL");
                user.setStatus("ACTIVE");
                user.setCreatedAt(now());
                user.setUpdatedAt(now());
                try {
                    platformUserMapper.insert(user);
                } catch (DuplicateKeyException duplicate) {
                    if (!exists("platform_user", "user_id", userId)) {
                        throw duplicate;
                    }
                }
            }
        }
    }

    private boolean exists(String table, String idColumn, long id) {
        Integer count = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM " + table + " WHERE " + idColumn + " = ?",
            Integer.class, id);
        return count != null && count > 0;
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }

    private <T> void batchInsert(List<T> items, int batchSize, java.util.function.Consumer<List<T>> inserter) {
        for (int i = 0; i < items.size(); i += batchSize) {
            List<T> batch = items.subList(i, Math.min(i + batchSize, items.size()));
            inserter.accept(batch);
        }
    }
}
