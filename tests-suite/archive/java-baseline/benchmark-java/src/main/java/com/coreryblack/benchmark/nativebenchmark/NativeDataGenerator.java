package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.ResourceRegistry;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.*;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 基准测试数据生成协调器。
 * 负责数据生成的核心编排逻辑，将持久化委托给 {@link DataPersistenceService}，
 * 缓存操作委托给 {@link RedisCacheService}，ID 生成委托给 {@link BenchmarkIdGenerator}。
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class NativeDataGenerator {

    private final BenchmarkIdGenerator idGenerator;
    private final DataPersistenceService persistenceService;
    private final RedisCacheService cacheService;

    /**
     * 从 ResourceRegistry 动态获取所有已注册的资源类型，消除硬编码副本与注册表不同步的风险。
     * 使用数组形式以支持按索引轮询（generateEntries/generateCardOnlyRules/generateEvalRequests）。
     */
    public static final String[] RESOURCE_TYPES = ResourceRegistry.getAllResourceTypes().toArray(new String[0]);

    /**
     * 从 ResourceRegistry 所有资源类型中聚合去重后的动作编码。
     * 覆盖所有已注册动作（read, create, update, delete, write, import, export, approve, publish, bind-permission, scan 等）。
     */
    public static final String[] ACTIONS = deriveAllActions();

    public static final String[] CARD_TYPES = {
        "STUDENT", "TEACHER", "ADMIN", "PARENT", "OBSERVER"
    };

    public static final String[] ABAC_CONDITION_TYPES = {
        "time_window", "ip_range", "device_binding", "org_level",
        "location", "department", "custom_attribute", "composite"
    };

    public static final String[] DEPARTMENTS = {
        "engineering", "marketing", "sales", "hr", "finance", "operations", "research"
    };

    public static final String[] LOCATIONS = {
        "beijing", "shanghai", "shenzhen", "hangzhou", "chengdu", "guangzhou"
    };

    private static final int[] HOT_RESOURCE_BUCKETS = {1, 1, 1, 2, 2, 3, 5, 8};

    private static final long DEFAULT_TENANT_ID = 1L;
    private static final long DEFAULT_DOMAIN_ID = 1L;

    /**
     * 从 ResourceRegistry 所有资源类型中聚合去重后的动作编码数组。
     * 保证 Benchmark 使用的动作集合与注册表完全同步。
     */
    private static String[] deriveAllActions() {
        Set<String> allActions = new LinkedHashSet<>();
        for (String resourceType : ResourceRegistry.getAllResourceTypes()) {
            allActions.addAll(ResourceRegistry.getActions(resourceType));
        }
        // ResourceRegistry stores action sets as Set.of(...); sorting removes
        // implementation-order dependence from the generated request trace.
        return allActions.stream().sorted().toArray(String[]::new);
    }

    private Long seed = null;
    /** Fixed clock used by benchmark generation; production callers may leave the system clock. */
    private Clock clock = Clock.systemUTC();

    public void setSeed(Long seed) {
        this.seed = seed;
    }

    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
        persistenceService.setClock(this.clock);
    }

    private LocalDateTime now() {
        return LocalDateTime.now(clock);
    }

    private Random createRng() {
        return seed != null ? new Random(seed) : new Random(42L);
    }

    public NativeGeneratedDataSet generate(NativeScaleConfig config) {
        log.info("[Native] Generating dual-card model data: cards={}, baseRules={}, overlayRules={}, " +
                "cardOnlyRules={}, abacConditionsPerRule={}, seed={}",
            config.getCardCount(), config.getBaseRulesPerCard(), config.getOverlayRulesPerCard(),
            config.getPermissionRulesPerCard(), config.getAbacConditionsPerRule(), seed);

        NativeGeneratedDataSet dataset = new NativeGeneratedDataSet();
        dataset.config = config;
        Random rng = createRng();

        // Ablation: per-card rule sets can be enabled either via the config
        // field or the -Dbenchmark.ablation.per-card-rule-sets=true system
        // property, so the campaign runner does not need to rebuild configs.
        boolean perCardRuleSets = config.isPerCardRuleSets()
                || Boolean.getBoolean("benchmark.ablation.per-card-rule-sets");

        // Reset ID sequence for reproducible data generation
        idGenerator.reset();

        // 使用 config 中的 templateCount，而非 cardCount/100（P1 修复）
        int templateCount = Math.max(1, config.getTemplateCount());
        int tenantCount = Math.max(1, config.getTenantCount());
        int domainCount = Math.max(1, config.getDomainCount());
        List<UserCardTemplate> templates = generateTemplates(templateCount, tenantCount, domainCount);
        dataset.templates = templates;

        List<RuleSet> ruleSets = new ArrayList<>();
        List<RuleSetEntry> allEntries = new ArrayList<>();
        List<RuleSetSnapshot> allSnapshots = new ArrayList<>();

        Map<Long, RuleSet> templateBaseRuleSets = new LinkedHashMap<>();
        Map<Long, RuleSet> templateOverlayRuleSets = new LinkedHashMap<>();
        Map<Long, List<RuleSetEntry>> templateBaseEntries = new LinkedHashMap<>();
        Map<Long, List<RuleSetEntry>> templateOverlayEntries = new LinkedHashMap<>();

        for (UserCardTemplate template : templates) {
            long templateId = template.getTemplateId();

            long templateTenantId = template.getTenantId() != null
                ? template.getTenantId() : DEFAULT_TENANT_ID;
            RuleSet baseRuleSet = createRuleSet(
                "BASE_Template_" + templateId, "TEMPLATE", templateId, templateTenantId);
            ruleSets.add(baseRuleSet);
            templateBaseRuleSets.put(templateId, baseRuleSet);

            List<RuleSetEntry> baseEntries = generateEntries(
                baseRuleSet.getRuleSetId(), config.getBaseRulesPerCard(),
                config.getResourceTypes(), config.getActionsPerResource(),
                false, config.getDenyRatio(), rng, templateTenantId);
            allEntries.addAll(baseEntries);
            templateBaseEntries.put(templateId, baseEntries);

            allSnapshots.addAll(buildSnapshots(baseRuleSet.getRuleSetId(), baseEntries));

            if (config.getOverlayRulesPerCard() > 0) {
                RuleSet overlayRuleSet = createRuleSet(
                    "OVERLAY_Template_" + templateId, "OVERLAY", templateId, templateTenantId);
                ruleSets.add(overlayRuleSet);
                templateOverlayRuleSets.put(templateId, overlayRuleSet);

                List<RuleSetEntry> overlayEntries = generateEntries(
                    overlayRuleSet.getRuleSetId(), config.getOverlayRulesPerCard(),
                    config.getResourceTypes(), config.getActionsPerResource(),
                    true, config.getDenyRatio(), rng, templateTenantId);
                allEntries.addAll(overlayEntries);
                templateOverlayEntries.put(templateId, overlayEntries);

                allSnapshots.addAll(buildSnapshots(overlayRuleSet.getRuleSetId(), overlayEntries));
            }
        }

        dataset.ruleSets = ruleSets;
        dataset.entries = allEntries;
        dataset.snapshots = allSnapshots;

        List<PermissionRule> permissionRules = new ArrayList<>();
        List<PermissionRuleSnapshot> permSnapshots = new ArrayList<>();
        List<NativeCardBinding> bindings = new ArrayList<>();
        List<AbacCondition> abacConditions = new ArrayList<>();

        for (int i = 0; i < config.getCardCount(); i++) {
            long cardId = i + 1L;
            UserCardTemplate template = templates.get(i % templates.size());
            long templateId = template.getTemplateId();
            String cardType = template.getCardType();

            NativeCardBinding binding = new NativeCardBinding();
            binding.cardId = cardId;
            binding.userId = (long) (rng.nextInt(Math.max(1, config.getCardCount() / 10)) + 1);
            // The binding is the source of truth for every generated request context.
            binding.domainId = template.getDomainId() != null
                ? template.getDomainId() : DEFAULT_DOMAIN_ID;
            binding.templateId = templateId;
            binding.tenantId = template.getTenantId() != null
                ? template.getTenantId() : DEFAULT_TENANT_ID;
            binding.cardType = cardType;
            double statusRoll = rng.nextDouble();
            if (statusRoll < 0.90) {
                binding.cardStatus = "ACTIVE";
            } else if (statusRoll < 0.95) {
                binding.cardStatus = "SUSPENDED";
            } else {
                binding.cardStatus = "DISABLED";
            }
            RuleSet baseRuleSet = templateBaseRuleSets.get(templateId);
            if (perCardRuleSets) {
                // Ablation: every card gets its own BASE rule set instead of
                // sharing the template-level rule set. This removes the shared
                // representation while keeping the same per-card rule count,
                // so the benchmark measures the representation cost alone.
                baseRuleSet = createRuleSet(
                    "BASE_Card_" + cardId, "TEMPLATE", templateId, binding.tenantId);
                ruleSets.add(baseRuleSet);
                List<RuleSetEntry> baseEntries = generateEntries(
                    baseRuleSet.getRuleSetId(), config.getBaseRulesPerCard(),
                    config.getResourceTypes(), config.getActionsPerResource(),
                    false, config.getDenyRatio(), rng, binding.tenantId);
                allEntries.addAll(baseEntries);
                allSnapshots.addAll(buildSnapshots(baseRuleSet.getRuleSetId(), baseEntries));
            }
            if (baseRuleSet != null) {
                CardRuleSetRef baseRef = new CardRuleSetRef();
                baseRef.setCardId(cardId);
                baseRef.setRuleSetId(baseRuleSet.getRuleSetId());
                baseRef.setTenantId(binding.tenantId);
                baseRef.setRefType("BASE");
                baseRef.setCreatedAt(now());
                binding.baseRef = baseRef;
            }

            RuleSet overlayRuleSet = templateOverlayRuleSets.get(templateId);
            if (perCardRuleSets && config.getOverlayRulesPerCard() > 0) {
                // Ablation: per-card OVERLAY rule set, mirroring the BASE case.
                overlayRuleSet = createRuleSet(
                    "OVERLAY_Card_" + cardId, "OVERLAY", templateId, binding.tenantId);
                ruleSets.add(overlayRuleSet);
                List<RuleSetEntry> overlayEntries = generateEntries(
                    overlayRuleSet.getRuleSetId(), config.getOverlayRulesPerCard(),
                    config.getResourceTypes(), config.getActionsPerResource(),
                    true, config.getDenyRatio(), rng, binding.tenantId);
                allEntries.addAll(overlayEntries);
                allSnapshots.addAll(buildSnapshots(overlayRuleSet.getRuleSetId(), overlayEntries));
            }
            if (overlayRuleSet != null) {
                // Primary overlay
                CardRuleSetRef overlayRef = new CardRuleSetRef();
                overlayRef.setCardId(cardId);
                overlayRef.setRuleSetId(overlayRuleSet.getRuleSetId());
                overlayRef.setTenantId(binding.tenantId);
                overlayRef.setRefType("OVERLAY");
                overlayRef.setCreatedAt(now());
                binding.overlayRefs.add(overlayRef);

                // B16 fix: secondary overlays controlled by config.multiOverlayEnabled instead of 10% random
                // multiOverlayCount controls how many additional OVERLAY refs per card
                // (default=1 for backward compatibility)
                if (config.isMultiOverlayEnabled() && config.getOverlayRulesPerCard() > 0) {
                    for (int oi = 0; oi < config.getMultiOverlayCount(); oi++) {
                        RuleSet extraOverlay = createRuleSet(
                            "OVERLAY" + (oi + 2) + "_Card_" + cardId + "_" + oi,
                            "OVERLAY", templateId, binding.tenantId);
                        ruleSets.add(extraOverlay);

                        int extraRuleCount = Math.max(1, config.getOverlayRulesPerCard() / 2);
                        List<RuleSetEntry> extraOverlayEntries = generateEntries(
                            extraOverlay.getRuleSetId(), extraRuleCount,
                            config.getResourceTypes(), config.getActionsPerResource(),
                            true, config.getDenyRatio(), rng, binding.tenantId);
                        allEntries.addAll(extraOverlayEntries);
                        allSnapshots.addAll(buildSnapshots(extraOverlay.getRuleSetId(), extraOverlayEntries));

                        CardRuleSetRef extraRef = new CardRuleSetRef();
                        extraRef.setCardId(cardId);
                        extraRef.setRuleSetId(extraOverlay.getRuleSetId());
                        extraRef.setTenantId(binding.tenantId);
                        extraRef.setRefType("OVERLAY");
                        extraRef.setCreatedAt(now());
                        binding.overlayRefs.add(extraRef);
                    }
                }
            }

            if (config.getPermissionRulesPerCard() > 0) {
                List<PermissionRule> cardRules = generateCardOnlyRules(
                    cardId, config.getPermissionRulesPerCard(),
                    config.getResourceTypes(), config.getActionsPerResource(),
                    config.getDenyRatio(), rng, binding.tenantId);
                permissionRules.addAll(cardRules);
                binding.permissionRules = cardRules;

                // 去重：同一卡内 (cardId, resourceKey, actionCode) 只保留最后一条（最高优先级），
                // 防止 permission_rule_snapshot 的 uk_perm_snapshot 唯一约束冲突
                Map<String, PermissionRuleSnapshot> dedupedSnapshots = new LinkedHashMap<>();
                for (PermissionRule rule : cardRules) {
                    String resourceKey = rule.getResourceType() + ":" +
                        (rule.getResourceId() != null ? rule.getResourceId() : "*");
                    String dedupKey = cardId + ":" + resourceKey + ":" + rule.getActionCode();
                    PermissionRuleSnapshot ps = new PermissionRuleSnapshot();
                    ps.setSnapshotId(idGenerator.nextSnapshotId());
                    ps.setCardId(cardId);
                    ps.setTenantId(binding.tenantId);
                    ps.setResourceKey(resourceKey);
                    ps.setActionCode(rule.getActionCode());
                    ps.setFinalEffect(rule.getEffect());
                    ps.setRuleId(rule.getRuleId());
                    ps.setVersionNo(1L);
                    ps.setCreatedAt(now());
                    ps.setUpdatedAt(now());
                    dedupedSnapshots.put(dedupKey, ps);
                }
                permSnapshots.addAll(dedupedSnapshots.values());
            }

            // B17 修复：根据 abacConditionsPerRule 概率生成 ABAC 条件，而非 100%
            if (config.getAbacConditionsPerRule() > 0) {
                // 每张卡按 abacConditionsPerRule 的概率生成 ABAC 条件
                // abacConditionsPerRule=1 表示每卡 1 个条件，>1 表示每卡多个条件
                int abacCount = config.getAbacConditionsPerRule();
                for (int ai = 0; ai < abacCount; ai++) {
                    AbacCondition abac = generateAbacCondition(cardId, rng);
                    abacConditions.add(abac);
                    if (ai == 0) {
                        binding.abacCondition = abac;
                    }
                }
            }

            bindings.add(binding);
        }

        dataset.permissionRules = permissionRules;
        dataset.permSnapshots = permSnapshots;
        dataset.bindings = bindings;
        dataset.abacConditions = abacConditions;

        dataset.evalRequests = generateEvalRequests(config, bindings, rng);
        validateDataset(dataset);

        dataset.sodPolicies = generateSodPolicies(
            Math.max(2, config.getCardCount() / 1000), rng);

        log.info("[Native] Data generation complete: {} templates, {} ruleSets, {} entries, " +
                "{} snapshots, {} cardOnlyRules, {} abacConditions, {} bindings, {} evalRequests, {} sodPolicies",
            templates.size(), ruleSets.size(), allEntries.size(), allSnapshots.size(),
            permissionRules.size(), abacConditions.size(), bindings.size(),
            dataset.evalRequests.size(), dataset.sodPolicies.size());

        return dataset;
    }

    /**
     * Validates the generated request/binding and tenant invariants before a
     * benchmark can persist or measure the dataset.
     */
    private void validateDataset(NativeGeneratedDataSet dataset) {
        Map<Long, NativeCardBinding> bindingsByCard = dataset.bindings.stream()
            .collect(java.util.stream.Collectors.toMap(b -> b.cardId, b -> b));
        for (NativeEvalRequest request : dataset.evalRequests) {
            NativeCardBinding binding = bindingsByCard.get(request.cardId);
            if (binding == null
                || request.userId != binding.userId
                || request.domainId != binding.domainId
                || request.tenantId != binding.tenantId
                || request.templateId != binding.templateId) {
                throw new IllegalStateException("Generated request context does not match its card binding: card="
                    + request.cardId);
            }
            if (request.expectedCardOnlyHit) {
                PermissionRule expectedRule = binding.permissionRules == null ? null
                    : binding.permissionRules.stream()
                        .filter(rule -> Objects.equals(rule.getRuleId(), request.expectedCardOnlyRuleId))
                        .findFirst()
                        .orElse(null);
                if (expectedRule == null
                    || !Objects.equals(expectedRule.getResourceType(), request.resourceType)
                    || !Objects.equals(expectedRule.getResourceId(), request.resourceId)
                    || !Objects.equals(expectedRule.getActionCode(), request.actionCode)
                    || !Objects.equals(expectedRule.getEffect(), request.expectedCardOnlyEffect)) {
                    throw new IllegalStateException(
                        "Generated CARD_ONLY hit request does not match its rule: card=" + request.cardId);
                }
                boolean wildcardRuleSetMatch = dataset.entries.stream().anyMatch(entry ->
                    entry.getResourceId() == null
                        && Objects.equals(entry.getResourceType(), request.resourceType)
                        && Objects.equals(entry.getActionCode(), request.actionCode));
                if (wildcardRuleSetMatch) {
                    throw new IllegalStateException(
                        "Generated CARD_ONLY hit request overlaps a wildcard rule-set key: card="
                            + request.cardId + ", resource=" + request.resourceType
                            + ", action=" + request.actionCode);
                }
                if (!"ACTIVE".equals(binding.cardStatus)) {
                    throw new IllegalStateException(
                        "Generated CARD_ONLY hit request must use an ACTIVE card: card=" + request.cardId);
                }
            }
        }
        for (NativeCardBinding binding : dataset.bindings) {
            if (binding.baseRef != null && binding.baseRef.getTenantId() != binding.tenantId) {
                throw new IllegalStateException("BASE reference tenant mismatch for card=" + binding.cardId);
            }
            for (CardRuleSetRef ref : binding.overlayRefs) {
                if (ref.getTenantId() != binding.tenantId) {
                    throw new IllegalStateException("OVERLAY reference tenant mismatch for card=" + binding.cardId);
                }
            }
        }
    }

    /** Delegate persistence to {@link DataPersistenceService} */
    public void persistToDatabase(NativeGeneratedDataSet dataset) {
        persistenceService.persistAll(dataset);
    }

    /** Delegate cache population to {@link RedisCacheService} */
    public void populateRedisCache(NativeGeneratedDataSet dataset) {
        cacheService.populateAll(dataset);
    }

    /** Delegate cache flush to {@link RedisCacheService} */
    public void flushAllCaches() {
        cacheService.flushAllCaches();
    }

    // ---- Private data generation methods (remain in this class) ----

    private List<UserCardTemplate> generateTemplates(int count, int tenantCount, int domainCount) {
        List<UserCardTemplate> templates = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            long templateId = i + 1L;
            long tenantId = tenantCount > 1 ? (i % tenantCount) + 1L : DEFAULT_TENANT_ID;
            long domainId = domainCount > 1 ? (i % domainCount) + 1L : DEFAULT_DOMAIN_ID;
            String cardType = CARD_TYPES[i % CARD_TYPES.length];
            UserCardTemplate t = new UserCardTemplate();
            t.setTemplateId(templateId);
            t.setTemplateName("BenchmarkTemplate_" + cardType + "_" + templateId);
            t.setTemplateCode("BENCH_" + cardType + "_" + templateId);
            t.setCardType(cardType);
            t.setDomainId(domainId);
            t.setTenantId(tenantId);
            t.setTemplateScope("DOMAIN");
            t.setStatus("ACTIVE");
            t.setDefaultPriority(100);
            t.setVersionNo(1);
            t.setCreatedAt(now());
            t.setUpdatedAt(now());
            templates.add(t);
        }
        return templates;
    }

    private RuleSet createRuleSet(String name, String sourceType, Long sourceId, long tenantId) {
        RuleSet rs = new RuleSet();
        rs.setRuleSetId(idGenerator.nextRuleSetId());
        rs.setName(name);
        rs.setCode("BENCH_" + name.toUpperCase());
        rs.setSourceType(sourceType);
        rs.setSourceId(sourceId);
        rs.setTenantId(tenantId);
        rs.setEnabled(1);
        rs.setCreatedAt(now());
        rs.setUpdatedAt(now());
        return rs;
    }

    private List<RuleSetEntry> generateEntries(Long ruleSetId, int count,
                                                 int resourceTypeCount, int actionCount,
                                                 boolean isOverlay, double denyRatio,
                                                 Random rng, long tenantId) {
        List<RuleSetEntry> entries = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            RuleSetEntry entry = new RuleSetEntry();
            entry.setEntryId(idGenerator.nextEntryId());
            entry.setRuleSetId(ruleSetId);
            entry.setTenantId(tenantId);
            entry.setResourceType(RESOURCE_TYPES[i % Math.min(resourceTypeCount, RESOURCE_TYPES.length)]);
            entry.setResourceId(sampleResourceId(rng, i));
            entry.setActionCode(ACTIONS[i % Math.min(actionCount, ACTIONS.length)]);
            entry.setEffect(rng.nextDouble() < denyRatio ? "DENY" : "ALLOW");
            entry.setPriority(count - i);
            entry.setEnabled(1);
            entry.setCreatedAt(now());
            entry.setUpdatedAt(now());
            entries.add(entry);
        }
        return entries;
    }

    /**
     * 生成卡级特例规则（CARD_ONLY），确保同一卡内 (resourceType, resourceId, actionCode) 唯一，
     * 避免 permission_rule_snapshot 的 uk_perm_snapshot 唯一约束冲突。
     * 当请求数量超过唯一组合上限时，自动截断并输出警告。
     */
    private List<PermissionRule> generateCardOnlyRules(long cardId, int count,
                                                        int resourceTypeCount, int actionCount,
                                                        double denyRatio, Random rng,
                                                        long tenantId) {
        List<PermissionRule> rules = new ArrayList<>();
        List<CardOnlyKey> candidateKeys = cardOnlyKeyCandidates(resourceTypeCount, actionCount);

        for (int index = 0; index < count; index++) {
            CardOnlyKey key = candidateKeys.get(index % candidateKeys.size());
            PermissionRule rule = new PermissionRule();
            rule.setRuleId(idGenerator.nextPermissionRuleId());
            rule.setCardId(cardId);
            rule.setTenantId(tenantId);
            rule.setResourceType(key.resourceType());
            // Keep CARD_ONLY ids outside the generated ruleset-id namespace.  This
            // is not sufficient by itself (a wildcard ruleset would still match),
            // hence candidateKeys also excludes every resource/action pair used by
            // BASE and OVERLAY generation.
            rule.setResourceId(1_000_000_000L + cardId * 100_000L + index);
            rule.setActionCode(key.actionCode());
            rule.setEffect(rng.nextDouble() < denyRatio ? "DENY" : "ALLOW");
            rule.setPriority(count - index);
            rule.setSourceType("CARD_ONLY");
            rule.setSourceId(cardId);
            rule.setEnabled(1);
            rule.setCreatedAt(now());
            rule.setUpdatedAt(now());
            rules.add(rule);
        }
        return rules;
    }

    /**
     * Selects registered resource/action pairs that cannot be consumed by the
     * generated BASE/OVERLAY rules.  Without this separation PolicyEngine would
     * stop at L1 and an alleged CARD_ONLY request would not measure L2 at all.
     */
    private List<CardOnlyKey> cardOnlyKeyCandidates(int resourceTypeCount, int actionCount) {
        int typeLimit = Math.min(Math.max(0, resourceTypeCount), RESOURCE_TYPES.length);
        Set<String> generatedActions = new HashSet<>();
        int actionLimit = Math.min(Math.max(0, actionCount), ACTIONS.length);
        for (int i = 0; i < actionLimit; i++) {
            generatedActions.add(ACTIONS[i]);
        }

        List<CardOnlyKey> candidates = new ArrayList<>();
        for (int typeIndex = 0; typeIndex < RESOURCE_TYPES.length; typeIndex++) {
            String resourceType = RESOURCE_TYPES[typeIndex];
            List<String> registeredActions = ResourceRegistry.getActions(resourceType).stream().sorted().toList();
            for (String action : registeredActions) {
                boolean pairUsedByRuleSet = typeIndex < typeLimit && generatedActions.contains(action);
                if (!pairUsedByRuleSet) {
                    candidates.add(new CardOnlyKey(resourceType, action));
                }
            }
        }
        if (candidates.isEmpty()) {
            throw new IllegalArgumentException(
                "Cannot generate an auditable CARD_ONLY trace: every registered resource/action pair "
                    + "is already used by the BASE/OVERLAY configuration");
        }
        return candidates;
    }

    private record CardOnlyKey(String resourceType, String actionCode) {
    }

    private List<SodPolicy> generateSodPolicies(int count, Random rng) {
        List<SodPolicy> policies = new ArrayList<>();
        String[][] conflictPairs = {
            {"learn_subject", "create", "learn_subject", "delete"},
            {"learn_question", "create", "learn_question", "delete"},
            {"identity_users", "update", "identity_users", "delete"},
            {"permission_rule", "create", "permission_rule", "delete"},
            {"learn_exam", "create", "learn_exam", "publish"},
            {"learn_statistics", "read", "learn_statistics", "export"},
            {"platform_tenant", "update", "platform_tenant", "delete"},
            {"audit", "read", "audit", "delete"},
        };
        for (int i = 0; i < count; i++) {
            String[] pair = conflictPairs[i % conflictPairs.length];
            SodPolicy policy = new SodPolicy();
            policy.setPolicyId(idGenerator.nextPolicyId());
            policy.setPolicyName("BENCH_SOD_" + i);
            policy.setDescription("Benchmark SoD policy #" + i);
            policy.setConflictType(i % 2 == 0 ? "STATIC" : "DYNAMIC");
            policy.setResourceType(pair[0]);
            policy.setActionCode(pair[1]);
            policy.setPermissionA(pair[0] + ":" + pair[1]);
            policy.setPermissionB(pair[2] + ":" + pair[3]);
            policy.setConditionScript(i % 2 == 1 ? "resourceOwnerId == currentUserId" : null);
            policy.setLimitCount(i % 2 == 1 ? 1 : null);
            policy.setLimitWindow(i % 2 == 1 ? "1h" : null);
            policy.setStatus("ACTIVE");
            policy.setCreatedAt(now());
            policy.setUpdatedAt(now());
            policies.add(policy);
        }
        return policies;
    }

    private AbacCondition generateAbacCondition(long cardId, Random rng) {
        AbacCondition abac = new AbacCondition();
        abac.cardId = cardId;
        abac.conditionType = ABAC_CONDITION_TYPES[rng.nextInt(ABAC_CONDITION_TYPES.length)];

        switch (abac.conditionType) {
            case "time_window":
                abac.conditionJson = buildTimeWindowCondition(rng);
                break;
            case "ip_range":
                abac.conditionJson = buildIpRangeCondition(rng);
                break;
            case "device_binding":
                abac.conditionJson = buildDeviceBindingCondition(rng);
                break;
            case "org_level":
                abac.conditionJson = buildOrgLevelCondition(rng);
                break;
            case "location":
                abac.conditionJson = buildLocationCondition(rng);
                break;
            case "department":
                abac.conditionJson = buildDepartmentCondition(rng);
                break;
            case "custom_attribute":
                abac.conditionJson = buildCustomAttributeCondition(rng);
                break;
            case "composite":
                abac.conditionJson = buildCompositeCondition(rng);
                break;
            default:
                abac.conditionJson = "{}";
        }
        return abac;
    }

    private String buildTimeWindowCondition(Random rng) {
        int startHour = rng.nextInt(12);
        int endHour = startHour + 4 + rng.nextInt(8);
        endHour = Math.min(endHour, 23);
        return String.format(
            "{\"timeRange\":{\"start\":\"%02d:00\",\"end\":\"%02d:00\"}}",
            startHour, endHour);
    }

    private String buildIpRangeCondition(Random rng) {
        int subnet = rng.nextInt(256);
        return String.format(
            "{\"ipRange\":[\"198.51.100.%d/32\",\"203.0.113.%d/32\"]}",
            subnet, rng.nextInt(256));
    }

    private String buildDeviceBindingCondition(Random rng) {
        String[] deviceTypes = {"desktop", "mobile", "tablet"};
        String device = deviceTypes[rng.nextInt(deviceTypes.length)];
        return String.format("{\"deviceType\":[\"%s\"]}", device);
    }

    private String buildOrgLevelCondition(Random rng) {
        int level = rng.nextInt(5) + 1;
        return String.format("{\"scope\":\"TENANT\",\"orgLevel\":%d}", level);
    }

    private String buildLocationCondition(Random rng) {
        String loc = LOCATIONS[rng.nextInt(LOCATIONS.length)];
        return String.format("{\"location\":\"%s\"}", loc);
    }

    private String buildDepartmentCondition(Random rng) {
        String dept = DEPARTMENTS[rng.nextInt(DEPARTMENTS.length)];
        return String.format("{\"department\":\"%s\"}", dept);
    }

    private String buildCustomAttributeCondition(Random rng) {
        String[] attrKeys = {"clearance", "role_level", "access_tier", "security_group"};
        String key = attrKeys[rng.nextInt(attrKeys.length)];
        int value = rng.nextInt(5) + 1;
        return String.format("{\"%s\":%d}", key, value);
    }

    private String buildCompositeCondition(Random rng) {
        String time = buildTimeWindowCondition(rng);
        String dept = buildDepartmentConditionInner(rng);
        return String.format(
            "{\"conditionGroup\":{\"allOf\":[%s,%s]}}",
            time, dept);
    }

    private String buildDepartmentConditionInner(Random rng) {
        String dept = DEPARTMENTS[rng.nextInt(DEPARTMENTS.length)];
        return String.format("{\"department\":\"%s\"}", dept);
    }

    private List<RuleSetSnapshot> buildSnapshots(long ruleSetId, List<RuleSetEntry> entries) {
        Map<String, RuleSetEntry> winners = BenchmarkWinnerSelector.select(entries);
        List<RuleSetSnapshot> snapshots = new ArrayList<>();
        for (RuleSetEntry entry : winners.values()) {
            RuleSetSnapshot snapshot = new RuleSetSnapshot();
            snapshot.setSnapshotId(idGenerator.nextSnapshotId());
            snapshot.setRuleSetId(ruleSetId);
            snapshot.setTenantId(entries.isEmpty() ? DEFAULT_TENANT_ID : entries.get(0).getTenantId());
            snapshot.setResourceKey(entry.getResourceType() + ":" +
                (entry.getResourceId() != null ? entry.getResourceId() : "*"));
            snapshot.setActionCode(entry.getActionCode());
            snapshot.setFinalEffect(entry.getEffect());
            snapshot.setEntryId(entry.getEntryId());
            snapshot.setVersionNo(1L);
            snapshot.setCreatedAt(now());
            snapshot.setUpdatedAt(now());
            snapshots.add(snapshot);
        }
        return snapshots;
    }

    private List<NativeEvalRequest> generateEvalRequests(NativeScaleConfig config,
                                                          List<NativeCardBinding> bindings,
                                                          Random rng) {
        List<NativeEvalRequest> requests = new ArrayList<>();
        int requestCount = Math.min(config.getCardCount() * 10, 100_000);

        for (int i = 0; i < requestCount; i++) {
            NativeCardBinding binding = bindings.get(rng.nextInt(bindings.size()));
            PermissionRule exactRule = null;
            // Half of the requests for cards with an active CARD_ONLY rule are
            // exact-hit probes.  The remaining requests retain the generated
            // miss/hot-resource distribution, so L2 and L3 are both observable.
            if ((i & 1) == 0 && "ACTIVE".equals(binding.cardStatus)
                    && binding.permissionRules != null && !binding.permissionRules.isEmpty()) {
                exactRule = binding.permissionRules.get((i / 2) % binding.permissionRules.size());
            }

            NativeEvalRequest req = new NativeEvalRequest();
            req.cardId = binding.cardId;
            req.userId = binding.userId;
            req.domainId = binding.domainId;
            req.tenantId = binding.tenantId;
            req.templateId = binding.templateId;
            if (exactRule != null) {
                req.resourceType = exactRule.getResourceType();
                req.actionCode = exactRule.getActionCode();
                req.resourceId = exactRule.getResourceId();
                req.expectedCardOnlyHit = true;
                req.expectedCardOnlyEffect = exactRule.getEffect();
                req.expectedCardOnlyRuleId = exactRule.getRuleId();
            } else {
                req.resourceType = RESOURCE_TYPES[weightedResourceIndex(rng, config.getResourceTypes())];
                req.actionCode = ACTIONS[weightedActionIndex(rng, config.getActionsPerResource())];
                req.resourceId = sampleResourceId(rng, i);
            }

            AbacContext abacCtx = new AbacContext();
            abacCtx.currentTime = now().format(DateTimeFormatter.ISO_LOCAL_TIME);
            abacCtx.clientIp = "192.168." + rng.nextInt(256) + "." + (rng.nextInt(254) + 1);
            abacCtx.deviceId = "device_" + rng.nextInt(1000);
            abacCtx.orgDepth = rng.nextInt(5) + 1;
            abacCtx.location = LOCATIONS[rng.nextInt(LOCATIONS.length)];
            abacCtx.department = DEPARTMENTS[rng.nextInt(DEPARTMENTS.length)];
            abacCtx.customAttributes = Map.of(
                "clearance", String.valueOf(rng.nextInt(5) + 1),
                "access_tier", String.valueOf(rng.nextInt(3) + 1)
            );
            req.abacContext = abacCtx;

            requests.add(req);
        }
        return requests;
    }

    private int weightedResourceIndex(Random rng, int resourceTypes) {
        int limit = Math.min(resourceTypes, RESOURCE_TYPES.length);
        if (limit <= 1) return 0;
        int bucket = rng.nextInt(100);
        if (bucket < 45) return 0;
        if (bucket < 70) return Math.min(1, limit - 1);
        if (bucket < 85) return Math.min(2, limit - 1);
        return rng.nextInt(limit);
    }

    private int weightedActionIndex(Random rng, int actionCount) {
        int limit = Math.min(actionCount, ACTIONS.length);
        if (limit <= 1) return 0;
        int bucket = rng.nextInt(100);
        if (bucket < 50) return 0;
        if (bucket < 75) return Math.min(1, limit - 1);
        if (bucket < 90) return Math.min(2, limit - 1);
        return rng.nextInt(limit);
    }

    private Long sampleResourceId(Random rng, int seed) {
        int bucket = HOT_RESOURCE_BUCKETS[seed % HOT_RESOURCE_BUCKETS.length];
        if (rng.nextInt(100) < 35) return null;
        long base = Math.max(1, bucket * 100L);
        return base + rng.nextInt(49) + 1;
    }

    // ---- Inner data classes (unchanged) ----

    public static class NativeGeneratedDataSet {
        public NativeScaleConfig config;
        public List<UserCardTemplate> templates;
        public List<RuleSet> ruleSets;
        public List<RuleSetEntry> entries;
        public List<RuleSetSnapshot> snapshots;
        public List<PermissionRule> permissionRules;
        public List<PermissionRuleSnapshot> permSnapshots;
        public List<NativeCardBinding> bindings;
        public List<NativeEvalRequest> evalRequests;
        public List<AbacCondition> abacConditions;
        public List<SodPolicy> sodPolicies = new ArrayList<>();
    }

    public static class NativeCardBinding {
        public long cardId;
        public long userId;
        public long domainId;
        public long templateId;
        public String cardType;
        public String cardStatus;
        public long tenantId;
        public CardRuleSetRef baseRef;
        public List<CardRuleSetRef> overlayRefs = new ArrayList<>();
        public List<PermissionRule> permissionRules;
        public AbacCondition abacCondition;
    }

    public static class NativeEvalRequest {
        public long cardId;
        public long userId;
        public long domainId;
        public long tenantId;
        public long templateId;
        public String resourceType;
        public String actionCode;
        public Long resourceId;
        /** True when this request was deliberately injected to hit a CARD_ONLY rule. */
        public boolean expectedCardOnlyHit;
        public String expectedCardOnlyEffect;
        public Long expectedCardOnlyRuleId;
        public AbacContext abacContext;
    }

    public static class AbacContext {
        public String currentTime;
        public String clientIp;
        public String deviceId;
        public int orgDepth;
        public String location;
        public String department;
        public Map<String, String> customAttributes;
    }

    public static class AbacCondition {
        public long cardId;
        public String conditionType;
        public String conditionJson;
    }
}
