package com.coreryblack.benchmark.data;

import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.*;
import com.coreryblack.astral_platform.persistence.entity.platform.PlatformDomain;
import com.coreryblack.astral_identity.persistence.entity.User;
import com.coreryblack.astral_identity.persistence.mapper.PlatformUserMapper;
import com.coreryblack.astral_permission.infrastructure.persistence.mapper.*;
import com.coreryblack.astral_platform.persistence.mapper.PlatformDomainMapper;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;

import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataGenerator {

    private final RuleSetMapper ruleSetMapper;
    private final RuleSetEntryMapper entryMapper;
    private final RuleSetSnapshotMapper snapshotMapper;
    private final CardRuleSetRefMapper cardRefMapper;
    private final UserCardMapper userCardMapper;
    private final PlatformDomainMapper domainMapper;
    private final PlatformUserMapper platformUserMapper;
    private final UserCardTemplateMapper templateMapper;
    private final PermissionRuleMapper permissionRuleMapper;
    private final PermissionRuleSnapshotMapper permSnapshotMapper;
    private final StringRedisTemplate redisTemplate;

    public static final String[] RESOURCE_TYPES = {
        "learn_subject", "learn_level", "learn_question", "learn_chapter",
        "learn_course", "learn_school", "learn_exam", "learn_statistics",
        "permission_rule", "domain", "audit", "identity_users",
        "chat_message", "chat_conversation", "platform_tenant",
        "platform_package", "platform_dept", "platform_tenant_member",
        "user_profile", "learn_device"
    };

    public static final String[] ACTIONS = {
        "read", "create", "update", "delete", "write", "import", "export",
        "approve", "publish", "bind-permission", "scan"
    };

    private static final int[] HOT_RESOURCE_BUCKETS = {1, 1, 1, 2, 2, 3, 5, 8};

    private Long seed = null;

    /** Deterministic ID generator for RuleSet objects (avoids dependency on DB auto-increment) */
    private final java.util.concurrent.atomic.AtomicLong ruleSetIdSeq = new java.util.concurrent.atomic.AtomicLong(0);
    private final java.util.concurrent.atomic.AtomicLong entryIdSeq = new java.util.concurrent.atomic.AtomicLong(0);
    private final java.util.concurrent.atomic.AtomicLong snapshotIdSeq = new java.util.concurrent.atomic.AtomicLong(0);

    public void setSeed(Long seed) {
        this.seed = seed;
    }

    private Random createRng() {
        return seed != null ? new Random(seed) : new Random(42L);
    }

    public GeneratedDataSet generate(ScaleConfig config) {
        log.info("Generating data for scale: cards={}, baseRules={}, overlayRules={}, templates={}, domains={}, seed={}",
            config.getCardCount(), config.getBaseRulesPerCard(), config.getOverlayRulesPerCard(),
            config.getTemplateCount(), config.getDomainCount(), seed);

        GeneratedDataSet dataset = new GeneratedDataSet();
        dataset.config = config;

        // Reset ID sequence for reproducible data generation
        ruleSetIdSeq.set(0);
        entryIdSeq.set(0);
        snapshotIdSeq.set(0);

        // Use a single RNG instance across all generation to avoid seed reset causing data homogenization
        Random rng = createRng();

        // P7 fix: support multiple templates, distribute cards across templates
        int templateCount = Math.max(1, config.getTemplateCount());
        List<UserCardTemplate> templates = new ArrayList<>();
        for (int t = 0; t < templateCount; t++) {
            long tid = t + 1L;
            UserCardTemplate template = createTemplate(tid, "BenchmarkTemplate_" + t);
            templates.add(template);
        }
        dataset.templates = templates;
        dataset.template = templates.get(0); // backward compat

        // Create rule sets per template
        List<RuleSet> baseRuleSets = new ArrayList<>();
        List<RuleSet> overlayRuleSets = new ArrayList<>();
        List<List<RuleSetEntry>> allBaseEntries = new ArrayList<>();
        List<List<RuleSetEntry>> allOverlayEntries = new ArrayList<>();

        for (int t = 0; t < templateCount; t++) {
            long templateId = templates.get(t).getTemplateId();
            RuleSet baseRuleSet = createRuleSet("BASE_Benchmark_" + t, "TEMPLATE", templateId);
            baseRuleSets.add(baseRuleSet);

            List<RuleSetEntry> baseEntries = generateEntries(
                rng, baseRuleSet.getRuleSetId(), config.getBaseRulesPerCard(),
                config.getResourceTypes(), config.getActionsPerResource(), false, config.getDenyRatio());
            allBaseEntries.add(baseEntries);

            if (config.getOverlayRulesPerCard() > 0) {
                RuleSet overlayRuleSet = createRuleSet("OVERLAY_Benchmark_" + t, "OVERLAY", templateId);
                overlayRuleSets.add(overlayRuleSet);
                List<RuleSetEntry> overlayEntries = generateEntries(
                    rng, overlayRuleSet.getRuleSetId(), config.getOverlayRulesPerCard(),
                    config.getResourceTypes(), config.getActionsPerResource(), true, config.getDenyRatio());
                allOverlayEntries.add(overlayEntries);
            } else {
                overlayRuleSets.add(null);
                allOverlayEntries.add(Collections.emptyList());
            }
        }

        dataset.baseRuleSets = baseRuleSets;
        dataset.overlayRuleSets = overlayRuleSets;
        dataset.allBaseEntries = allBaseEntries;
        dataset.allOverlayEntries = allOverlayEntries;
        // backward compat
        dataset.baseRuleSet = baseRuleSets.get(0);
        dataset.baseEntries = allBaseEntries.get(0);
        dataset.overlayRuleSet = overlayRuleSets.get(0);
        dataset.overlayEntries = allOverlayEntries.get(0);

        List<CardBinding> bindings = new ArrayList<>();
        for (int i = 0; i < config.getCardCount(); i++) {
            long cardId = i + 1L;
            int templateIdx = i % templateCount;

            // P8 fix: distribute domainId across domains
            // Default domainId=10 matches platform_domain created by SuperAdminTemplateInitializer
            long domainId = config.getDomainCount() > 1
                ? (long) (i % config.getDomainCount() + 1)
                : 10L;

            CardBinding binding = new CardBinding();
            binding.cardId = cardId;
            binding.templateIdx = templateIdx;
            binding.domainId = domainId;

            CardRuleSetRef baseRef = new CardRuleSetRef();
            baseRef.setCardId(cardId);
            baseRef.setRuleSetId(baseRuleSets.get(templateIdx).getRuleSetId());
            baseRef.setTenantId(1L);
            baseRef.setRefType("BASE");
            baseRef.setCreatedAt(LocalDateTime.now());
            binding.baseRef = baseRef;

            RuleSet overlayRs = overlayRuleSets.get(templateIdx);
            if (overlayRs != null) {
                CardRuleSetRef overlayRef = new CardRuleSetRef();
                overlayRef.setCardId(cardId);
                overlayRef.setRuleSetId(overlayRs.getRuleSetId());
                overlayRef.setTenantId(1L);
                overlayRef.setRefType("OVERLAY");
                overlayRef.setCreatedAt(LocalDateTime.now());
                binding.overlayRef = overlayRef;
            }

            bindings.add(binding);
        }
        dataset.bindings = bindings;

        dataset.evalRequests = generateEvalRequests(rng, config);

        log.info("Data generation complete: {} cards, {} templates, {} domains, {} eval requests",
            config.getCardCount(), templateCount, config.getDomainCount(),
            dataset.evalRequests.size());

        return dataset;
    }

    public void persistToDatabase(GeneratedDataSet dataset) {
        ScaleConfig config = dataset.config;
        int batchSize = 5000;

        // Ensure all needed platform_domain entries exist (user_card.domain_id FK → platform_domain.domain_id)
        int domainCount = Math.max(1, config.getDomainCount());
        boolean isMultiDomain = config.getDomainCount() > 1;
        for (int d = 0; d < domainCount; d++) {
            long did = isMultiDomain ? (d + 1L) : 10L;
            try {
                PlatformDomain pd = new PlatformDomain();
                pd.setId(did);
                String suffix = isMultiDomain ? "_" + did : "";
                pd.setCode("BENCH_DOMAIN" + suffix);
                pd.setName("Benchmark Domain" + suffix);
                pd.setStatus("ACTIVE");
                pd.setCreatedAt(LocalDateTime.now());
                pd.setUpdatedAt(LocalDateTime.now());
                domainMapper.insert(pd);
                log.debug("platform_domain ensured: domain_id={}", did);
            } catch (Exception e) {
                log.debug("Platform domain already exists: domain_id={}", did);
            }
        }

        // Ensure default platform_user exists (user_card.user_id FK -> platform_user.user_id)
        try {
            User user = new User();
            user.setId(1L);
            user.setUserNo("BENCH_USER");
            user.setDisplayName("Benchmark User");
            user.setEmail("benchmark@test.local");
            user.setStatus("ACTIVE");
            user.setCreatedAt(LocalDateTime.now());
            user.setUpdatedAt(LocalDateTime.now());
            platformUserMapper.insert(user);
            log.info("Default platform_user created: user_id=1");
        } catch (Exception e) {
            log.debug("Platform user already exists (or error): {}", e.getMessage());
        }

        log.info("Persisting templates (batch)...");
        templateMapper.batchInsert(dataset.templates);

        int templateCount = dataset.baseRuleSets.size();

        // Batch insert rule sets
        List<RuleSet> allRuleSets = new ArrayList<>();
        for (int t = 0; t < templateCount; t++) {
            allRuleSets.add(dataset.baseRuleSets.get(t));
            if (dataset.overlayRuleSets.get(t) != null) {
                allRuleSets.add(dataset.overlayRuleSets.get(t));
            }
        }
        log.info("Persisting {} rule sets (batch)...", allRuleSets.size());
        for (int i = 0; i < allRuleSets.size(); i += batchSize) {
            List<RuleSet> batch = allRuleSets.subList(i, Math.min(i + batchSize, allRuleSets.size()));
            ruleSetMapper.batchInsert(batch);
        }

        // Batch insert entries
        List<RuleSetEntry> allEntries = new ArrayList<>();
        for (int t = 0; t < templateCount; t++) {
            allEntries.addAll(dataset.allBaseEntries.get(t));
            if (dataset.allOverlayEntries.get(t) != null) {
                allEntries.addAll(dataset.allOverlayEntries.get(t));
            }
        }
        log.info("Persisting {} rule set entries (batch)...", allEntries.size());
        for (int i = 0; i < allEntries.size(); i += batchSize) {
            List<RuleSetEntry> batch = allEntries.subList(i, Math.min(i + batchSize, allEntries.size()));
            entryMapper.batchInsert(batch);
        }

        // Batch insert snapshots
        List<RuleSetSnapshot> allSnapshots = new ArrayList<>();
        for (int t = 0; t < templateCount; t++) {
            long baseRuleSetId = dataset.baseRuleSets.get(t).getRuleSetId();
            Map<String, RuleSetEntry> dedupedBase = new LinkedHashMap<>();
            for (RuleSetEntry entry : dataset.allBaseEntries.get(t)) {
                String key = entry.getResourceType() + ":" +
                    (entry.getResourceId() != null ? entry.getResourceId() : "*") + ":" + entry.getActionCode();
                dedupedBase.putIfAbsent(key, entry);
            }
            for (RuleSetEntry entry : dedupedBase.values()) {
                RuleSetSnapshot snapshot = new RuleSetSnapshot();
                snapshot.setSnapshotId(snapshotIdSeq.incrementAndGet());
                snapshot.setRuleSetId(baseRuleSetId);
                snapshot.setTenantId(1L);
                snapshot.setResourceKey(entry.getResourceType() + ":" +
                    (entry.getResourceId() != null ? entry.getResourceId() : "*"));
                snapshot.setActionCode(entry.getActionCode());
                snapshot.setFinalEffect(entry.getEffect());
                snapshot.setEntryId(entry.getEntryId());
                snapshot.setVersionNo(1L);
                snapshot.setCreatedAt(LocalDateTime.now());
                snapshot.setUpdatedAt(LocalDateTime.now());
                allSnapshots.add(snapshot);
            }

            RuleSet overlayRs = dataset.overlayRuleSets.get(t);
            if (overlayRs != null) {
                long overlayRuleSetId = overlayRs.getRuleSetId();
                Map<String, RuleSetEntry> dedupedOverlay = new LinkedHashMap<>();
                for (RuleSetEntry entry : dataset.allOverlayEntries.get(t)) {
                    String key = entry.getResourceType() + ":" +
                        (entry.getResourceId() != null ? entry.getResourceId() : "*") + ":" + entry.getActionCode();
                    dedupedOverlay.putIfAbsent(key, entry);
                }
                for (RuleSetEntry entry : dedupedOverlay.values()) {
                    RuleSetSnapshot snapshot = new RuleSetSnapshot();
                    snapshot.setSnapshotId(snapshotIdSeq.incrementAndGet());
                    snapshot.setRuleSetId(overlayRuleSetId);
                    snapshot.setTenantId(1L);
                    snapshot.setResourceKey(entry.getResourceType() + ":" +
                        (entry.getResourceId() != null ? entry.getResourceId() : "*"));
                    snapshot.setActionCode(entry.getActionCode());
                    snapshot.setFinalEffect(entry.getEffect());
                    snapshot.setEntryId(entry.getEntryId());
                    snapshot.setVersionNo(1L);
                    snapshot.setCreatedAt(LocalDateTime.now());
                    snapshot.setUpdatedAt(LocalDateTime.now());
                    allSnapshots.add(snapshot);
                }
            }
        }
        log.info("Persisting {} rule set snapshots (batch)...", allSnapshots.size());
        for (int i = 0; i < allSnapshots.size(); i += batchSize) {
            List<RuleSetSnapshot> batch = allSnapshots.subList(i, Math.min(i + batchSize, allSnapshots.size()));
            snapshotMapper.batchInsert(batch);
        }

        // Collect all user_cards and card_refs for batch insert
        List<UserCard> userCards = new ArrayList<>();
        List<CardRuleSetRef> cardRefs = new ArrayList<>();
        for (CardBinding b : dataset.bindings) {
            UserCard userCard = new UserCard();
            userCard.setCardId(b.cardId);
            userCard.setUserId(1L);
            userCard.setDomainId(b.domainId);
            userCard.setTenantId(1L);
            userCard.setCardType("STUDENT");
            userCard.setCardStatus("ACTIVE");
            userCard.setTemplateId(dataset.templates.get(b.templateIdx).getTemplateId());
            userCard.setIsPrimary(true);
            userCard.setPriority(0);
            userCard.setCreatedAt(LocalDateTime.now());
            userCard.setUpdatedAt(LocalDateTime.now());
            userCards.add(userCard);

            cardRefs.add(b.baseRef);
            if (b.overlayRef != null) {
                cardRefs.add(b.overlayRef);
            }
        }

        log.info("Persisting {} user cards (batch)...", userCards.size());
        for (int i = 0; i < userCards.size(); i += batchSize) {
            List<UserCard> batch = userCards.subList(i, Math.min(i + batchSize, userCards.size()));
            userCardMapper.batchInsert(batch);
            if ((i + batchSize) % 5000 == 0 || i + batchSize >= userCards.size()) {
                log.info("  persisted {}/{} cards", Math.min(i + batchSize, userCards.size()), userCards.size());
            }
        }

        log.info("Persisting {} card refs (batch)...", cardRefs.size());
        for (int i = 0; i < cardRefs.size(); i += batchSize) {
            List<CardRuleSetRef> batch = cardRefs.subList(i, Math.min(i + batchSize, cardRefs.size()));
            cardRefMapper.batchInsert(batch);
        }

        log.info("Persistence complete. (with rule_set_snapshot, {} templates, batch mode)", templateCount);
    }

    public void populateRedisCache(GeneratedDataSet dataset) {
        log.info("Populating Redis cache for {} cards, {} templates (pipelined)...", dataset.bindings.size(), dataset.baseRuleSets.size());
        long tenantId = 1L;
        int templateCount = dataset.baseRuleSets.size();

        // Batch 1: RuleSet snapshot hashes (small count, one pipeline)
        redisTemplate.executePipelined((org.springframework.data.redis.core.RedisCallback<Object>) connection -> {
            for (int t = 0; t < templateCount; t++) {
                long baseRuleSetId = dataset.baseRuleSets.get(t).getRuleSetId();
                String rulesetHashKey = "perm:ruleset:" + tenantId + ":" + baseRuleSetId;
                Map<byte[], byte[]> snapshotFields = new HashMap<>();
                for (RuleSetEntry entry : dataset.allBaseEntries.get(t)) {
                    String resourceKey = entry.getResourceType() + ":" +
                        (entry.getResourceId() != null ? entry.getResourceId() : "*");
                    String field = "snapshot:" + resourceKey + ":" + entry.getActionCode();
                    snapshotFields.put(field.getBytes(StandardCharsets.UTF_8),
                        entry.getEffect().getBytes(StandardCharsets.UTF_8));
                }
                if (!snapshotFields.isEmpty()) {
                    connection.hashCommands().hMSet(rulesetHashKey.getBytes(StandardCharsets.UTF_8), snapshotFields);
                }

                RuleSet overlayRs = dataset.overlayRuleSets.get(t);
                if (overlayRs != null && dataset.allOverlayEntries.get(t) != null && !dataset.allOverlayEntries.get(t).isEmpty()) {
                    String overlayHashKey = "perm:ruleset:" + tenantId + ":" + overlayRs.getRuleSetId();
                    Map<byte[], byte[]> overlayFields = new HashMap<>();
                    for (RuleSetEntry entry : dataset.allOverlayEntries.get(t)) {
                        String resourceKey = entry.getResourceType() + ":" +
                            (entry.getResourceId() != null ? entry.getResourceId() : "*");
                        String field = "snapshot:" + resourceKey + ":" + entry.getActionCode();
                        overlayFields.put(field.getBytes(StandardCharsets.UTF_8),
                            entry.getEffect().getBytes(StandardCharsets.UTF_8));
                    }
                    if (!overlayFields.isEmpty()) {
                        connection.hashCommands().hMSet(overlayHashKey.getBytes(StandardCharsets.UTF_8), overlayFields);
                    }
                }
            }
            return null;
        });

        // Batch 2: Card refs and card status — pipelined in chunks of 5000
        int pipelineBatchSize = 5000;
        List<CardBinding> bindings = dataset.bindings;

        for (int offset = 0; offset < bindings.size(); offset += pipelineBatchSize) {
            int end = Math.min(offset + pipelineBatchSize, bindings.size());
            List<CardBinding> chunk = bindings.subList(offset, end);

            redisTemplate.executePipelined((org.springframework.data.redis.core.RedisCallback<Object>) connection -> {
                for (CardBinding binding : chunk) {
                    int t = binding.templateIdx;
                    long baseRuleSetId = dataset.baseRuleSets.get(t).getRuleSetId();
                    String refsJson;
                    if (binding.overlayRef != null) {
                        refsJson = String.format("[{\"cardId\":%d,\"ruleSetId\":%d,\"tenantId\":1,\"refType\":\"BASE\"},{\"cardId\":%d,\"ruleSetId\":%d,\"tenantId\":1,\"refType\":\"OVERLAY\"}]",
                            binding.cardId, baseRuleSetId,
                            binding.cardId, dataset.overlayRuleSets.get(t).getRuleSetId());
                    } else {
                        refsJson = String.format("[{\"cardId\":%d,\"ruleSetId\":%d,\"tenantId\":1,\"refType\":\"BASE\"}]",
                            binding.cardId, baseRuleSetId);
                    }
                    connection.stringCommands().set(
                        ("perm:refs:" + tenantId + ":" + binding.cardId).getBytes(StandardCharsets.UTF_8),
                        refsJson.getBytes(StandardCharsets.UTF_8));

                    connection.stringCommands().set(
                        ("perm:card:status:" + binding.cardId).getBytes(StandardCharsets.UTF_8),
                        "ACTIVE".getBytes(StandardCharsets.UTF_8));
                }
                return null;
            });

            if (end % 50000 == 0 || end >= bindings.size()) {
                log.info("  Redis populated {}/{} cards", end, bindings.size());
            }
        }

        log.info("Redis cache populated: {} templates, {} card statuses",
            templateCount, dataset.bindings.size());
    }

    /**
     * Flush the dedicated benchmark Redis database after explicit destructive
     * cleanup approval. This is never safe against a shared Redis deployment.
     */
    public void flushAllCaches() {
        BenchmarkCleanupUtil.cleanupRedis(redisTemplate);
        log.info("Redis FLUSHDB complete");
    }

    private UserCardTemplate createTemplate(long id, String name) {
        UserCardTemplate t = new UserCardTemplate();
        t.setTemplateId(id);
        t.setTemplateName(name);
        t.setTemplateCode("BENCH_" + id);
        t.setCardType("STUDENT");
        t.setDomainId(10L);  // Must match platform_domain created by SuperAdminTemplateInitializer
        t.setTenantId(1L);
        t.setTemplateScope("DOMAIN");
        t.setVersionNo(1);
        t.setDefaultPriority(0);
        t.setStatus("ACTIVE");
        t.setCreatedAt(LocalDateTime.now());
        t.setUpdatedAt(LocalDateTime.now());
        return t;
    }

    private RuleSet createRuleSet(String name, String sourceType, Long sourceId) {
        RuleSet rs = new RuleSet();
        rs.setRuleSetId(ruleSetIdSeq.incrementAndGet());
        rs.setName(name);
        rs.setCode("BENCH_" + name.toUpperCase());
        rs.setSourceType(sourceType);
        rs.setSourceId(sourceId);
        rs.setTenantId(1L);
        rs.setEnabled(1);
        rs.setCreatedAt(LocalDateTime.now());
        rs.setUpdatedAt(LocalDateTime.now());
        return rs;
    }

    private List<RuleSetEntry> generateEntries(Random rng, Long ruleSetId, int count,
                                                 int resourceTypeCount, int actionCount,
                                                 boolean isOverlay, double denyRatio) {
        List<RuleSetEntry> entries = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            RuleSetEntry entry = new RuleSetEntry();
            entry.setEntryId(entryIdSeq.incrementAndGet());
            entry.setRuleSetId(ruleSetId);
            entry.setTenantId(1L);
            entry.setResourceType(RESOURCE_TYPES[i % Math.min(resourceTypeCount, RESOURCE_TYPES.length)]);
            entry.setResourceId(sampleResourceId(rng, i));
            entry.setActionCode(ACTIONS[i % Math.min(actionCount, ACTIONS.length)]);
            entry.setEffect(rng.nextDouble() < denyRatio ? "DENY" : "ALLOW");
            entry.setPriority(count - i);
            entry.setEnabled(1);
            entry.setCreatedAt(LocalDateTime.now());
            entry.setUpdatedAt(LocalDateTime.now());
            entries.add(entry);
        }
        return entries;
    }

    private List<EvalRequest> generateEvalRequests(Random rng, ScaleConfig config) {
        List<EvalRequest> requests = new ArrayList<>();
        int requestCount = Math.min(config.getCardCount() * 10, 100_000);

        for (int i = 0; i < requestCount; i++) {
            EvalRequest req = new EvalRequest();
            req.cardId = (long) (rng.nextInt(config.getCardCount()) + 1);
            req.resourceType = RESOURCE_TYPES[weightedResourceIndex(rng, config.getResourceTypes())];
            req.actionCode = ACTIONS[weightedActionIndex(rng, config.getActionsPerResource())];
            req.resourceId = sampleResourceId(rng, i);
            requests.add(req);
        }
        return requests;
    }

    private int weightedResourceIndex(Random rng, int resourceTypes) {
        int limit = Math.min(resourceTypes, RESOURCE_TYPES.length);
        if (limit <= 1) {
            return 0;
        }
        int bucket = rng.nextInt(100);
        if (bucket < 45) return 0;
        if (bucket < 70) return Math.min(1, limit - 1);
        if (bucket < 85) return Math.min(2, limit - 1);
        return rng.nextInt(limit);
    }

    private int weightedActionIndex(Random rng, int actionCount) {
        int limit = Math.min(actionCount, ACTIONS.length);
        if (limit <= 1) {
            return 0;
        }
        int bucket = rng.nextInt(100);
        if (bucket < 50) return 0;
        if (bucket < 75) return Math.min(1, limit - 1);
        if (bucket < 90) return Math.min(2, limit - 1);
        return rng.nextInt(limit);
    }

    private Long sampleResourceId(Random rng, int seed) {
        int bucket = HOT_RESOURCE_BUCKETS[seed % HOT_RESOURCE_BUCKETS.length];
        if (rng.nextInt(100) < 35) {
            return null;
        }
        long base = Math.max(1, bucket * 100L);
        return base + rng.nextInt(49) + 1;
    }

    public static class GeneratedDataSet {
        public ScaleConfig config;
        public UserCardTemplate template; // backward compat: first template
        public List<UserCardTemplate> templates;
        public RuleSet baseRuleSet; // backward compat: first BASE rule set
        public RuleSet overlayRuleSet; // backward compat: first OVERLAY rule set
        public List<RuleSet> baseRuleSets;
        public List<RuleSet> overlayRuleSets;
        public List<RuleSetEntry> baseEntries; // backward compat
        public List<RuleSetEntry> overlayEntries; // backward compat
        public List<List<RuleSetEntry>> allBaseEntries;
        public List<List<RuleSetEntry>> allOverlayEntries;
        public List<CardBinding> bindings;
        public List<EvalRequest> evalRequests;
    }

    public static class CardBinding {
        public long cardId;
        public int templateIdx;
        public long domainId;
        public CardRuleSetRef baseRef;
        public CardRuleSetRef overlayRef;
    }

    public static class EvalRequest {
        public long cardId;
        public String resourceType;
        public String actionCode;
        public Long resourceId;
    }
}
