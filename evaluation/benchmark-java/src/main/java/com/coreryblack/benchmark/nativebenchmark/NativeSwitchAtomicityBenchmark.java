package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.CardRuleSetRef;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.BenchmarkMockRequest;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Direct PDP card-selection concurrency benchmark, cache-repopulation latency
 * measurement, and ThreadLocal parameter-dependence experiment.
 *
 * <p>This benchmark does not invoke the production token/session switch protocol,
 * so it must not be interpreted as an end-to-end proof of switch atomicity,
 * credential replay prevention, or cache-convergence latency.
 *
 * <h3>Scenarios</h3>
 * <ul>
 *   <li><b>A — Concurrent Card-Selection Evaluation:</b> A single-threaded
 *       reference pass records direct PDP decisions for fully specified inputs.
 *       Concurrent readers then evaluate the card identifier selected from an
 *       in-memory register. A mismatch indicates direct-PDP nondeterminism under
 *       this harness; it is not evidence about the production switch protocol.</li>
 *   <li><b>B — Multi-Context Isolation:</b> Reports <em>cross-card divergence</em>
 *       (two cards returning different decisions for the same resource — the
 *       correct behavior under isolation) and <em>cross-card leakage</em>
 *       (card A's evaluation returning card B's ground-truth decision — a
 *       real isolation violation). Divergence is a positive signal; leakage
 *       is the metric of concern.</li>
 *   <li><b>C — ThreadLocal Parameter Dependence:</b> Evaluate a new-card context,
 *       then directly evaluate an old-card {@code PolicyContext} while retaining
 *       the new card in {@code CardContextHolder}. This isolates a narrow direct
 *       PDP parameter-dependence signal; it is not an old-token replay test.</li>
 *   <li><b>D — Cache Repopulation Latency:</b> Repeated warm/cold measurement
 *       pairs report local evaluation overhead only. This is not a measurement of
 *       distributed cache propagation or convergence.</li>
 * </ul>
 *
 * <h3>Reference-Run Boundary</h3>
 * <p>The baseline is a single-threaded run of the same {@link PolicyEngine}, keyed
 * by the complete evaluation input. It prevents unjudged comparisons and detects
 * contention-sensitive output changes, but it is not an independent semantic
 * oracle. Model-derived integration tests supply the independent correctness
 * evidence for the underlying policy semantics.
 */
@Slf4j
public class NativeSwitchAtomicityBenchmark {

    private static final int WARMUP_ITERATIONS = 500;
    private static final long TENANT_ID = 1L;
    private static final int DELAY_US_MIN = 50;
    private static final int DELAY_US_MAX = 500;
    /** Maximum baseline truth entries; protects against pathological scale. */
    private static final int BASELINE_MAX_ENTRIES = 200_000;

    private final PolicyEngine policyEngine;
    private final NativeDataGenerator dataGen;
    private final StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;

    public NativeSwitchAtomicityBenchmark(PolicyEngine policyEngine,
                                           NativeDataGenerator dataGen,
                                           StringRedisTemplate redisTemplate,
                                           JdbcTemplate jdbcTemplate) {
        this.policyEngine = policyEngine;
        this.dataGen = dataGen;
        this.redisTemplate = redisTemplate;
        this.jdbcTemplate = jdbcTemplate;
    }

    public NativeSwitchAtomicityResult execute(NativeScaleConfig config,
                                                int readerThreads,
                                                int writerThreads,
                                                int durationSeconds) throws Exception {
        log.info("=== Direct PDP Card-Selection Benchmark === config={}, r={}, w={}, {}s",
            config.label(), readerThreads, writerThreads, durationSeconds);

        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
        NativeScaleConfig boundedConfig = NativeScaleConfig.builder()
            .cardCount(Math.max(config.getCardCount(), 50))
            .templateCount(Math.max(1, config.getTemplateCount()))
            .baseRulesPerCard(config.getBaseRulesPerCard())
            .overlayRulesPerCard(config.getOverlayRulesPerCard())
            .permissionRulesPerCard(config.getPermissionRulesPerCard())
            .abacConditionsPerRule(config.getAbacConditionsPerRule())
            .resourceTypes(Math.max(5, config.getResourceTypes()))
            .actionsPerResource(Math.max(2, config.getActionsPerResource()))
            .denyRatio(config.getDenyRatio()).build();

        NativeDataGenerator.NativeGeneratedDataSet ds = dataGen.generate(boundedConfig);
        dataGen.persistToDatabase(ds);
        // Prime caches only through production evaluation paths. Generator-side
        // serialization can otherwise disagree with runtime snapshot selection.

        Map<Long, NativeDataGenerator.NativeCardBinding> bm = new LinkedHashMap<>();
        for (var b : ds.bindings) bm.put(b.cardId, b);

        Map<Long, List<Long>> userCards = new LinkedHashMap<>();
        for (var b : ds.bindings)
            userCards.computeIfAbsent(b.userId, k -> new ArrayList<>()).add(b.cardId);
        List<Long> switchableUsers = new ArrayList<>();
        for (var e : userCards.entrySet())
            if (e.getValue().size() >= 2) switchableUsers.add(e.getKey());
        log.info("  switchable users: {}/{}", switchableUsers.size(), userCards.size());

        NativeSwitchAtomicityResult result = new NativeSwitchAtomicityResult();
        result.cardCount = boundedConfig.getCardCount();
        result.switchableUserCount = switchableUsers.size();
        warmup(ds, bm);

        // ── Pre-compute single-threaded direct-PDP reference decisions ──
        // This reference detects contention-sensitive divergence only; it is not
        // an independent oracle for the production authorization semantics.
        log.info("--- SINGLE_THREADED_REFERENCE ---");
        BaselineTruth baseline = computeBaselineTruth(ds, bm, switchableUsers, userCards);
        log.info("  baseline entries: {}", baseline.size());

        // A: Concurrent switch + evaluate
        log.info("--- SCENARIO_A ---");
        SwitchEvalResult a = doConcurrentSwitchEval(ds, bm, switchableUsers, userCards,
            baseline, readerThreads, writerThreads, durationSeconds);
        result.scenarioA = a;
        log.info("  A: attempted={}, judged={}, skipped={}, decisionMismatches={}, errors={}, mean={}us, p99={}us",
            a.totalEvals.get(), a.judgedEvals.get(), a.skippedEvals.get(),
            a.isolationViolations.get(), a.errorCount.get(),
            fmt(a.lSnapshot.meanUs()), fmt(a.lSnapshot.p99Us()));

        // B: Multi-context isolation
        log.info("--- SCENARIO_B ---");
        IsolationResult b = doMultiCtxIsolation(ds, userCards, switchableUsers, baseline, bm);
        result.scenarioB = b;
        log.info("  B: divergenceChecks={}, divergence={}, leakageChecks={}, leakage={}",
            b.divergenceChecks, b.crossCardDivergence, b.leakageChecks, b.crossCardLeakage);

        // C: ThreadLocal parameter-dependence
        log.info("--- SCENARIO_C ---");
        ContextDependenceResult c = doParameterDependence(ds, userCards, switchableUsers, baseline, bm);
        result.scenarioC = c;
        log.info("  C: evaluations={}, anomalies={} (cross-card contamination)",
                c.totalEvaluations, c.anomalyCount);

        // D: Cache window
        log.info("--- SCENARIO_D ---");
        CacheWindowResult d = doCacheWindow(ds, userCards, switchableUsers, bm);
        result.scenarioD = d;
        log.info("  D: requested={}, samples={}, setupFailures={}, warmMedian={}us, coldMedian={}us, "
                + "overheadMedian={}us, warmP99={}us, coldP99={}us",
            d.requestedSampleCount, d.sampleCount, d.setupFailureCount,
            fmt(d.warmMedianUs), fmt(d.coldMedianUs), fmt(d.overheadMedianUs),
            fmt(d.warmP99Us), fmt(d.coldP99Us));

        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
        log.info("=== Direct PDP Card-Selection Benchmark Complete ===");
        return result;
    }

    // ==================== BASELINE TRUTH ====================

    /**
     * Compute ground-truth decisions for every (uid, cardId, resource, action, abac)
     * tuple that the concurrent phase might consult. Runs single-threaded with a
     * freshly-flushed cache for each card, so the result reflects the card's own
     * rule set only — never a sibling card's cached state.
     *
     * <p>This is a single-threaded reference run, not an independent semantic
     * oracle. It detects nondeterminism under contention; formal semantic
     * validation is performed separately by model-derived integration tests.
     *
     * <p>The reference path deletes and verifies the selected card's cache keys
     * before each evaluation. This prevents a sibling card's cached state from
     * entering the single-threaded reference without relying on a global Redis
     * flush or timing delay.
     */
    private BaselineTruth computeBaselineTruth(
            NativeDataGenerator.NativeGeneratedDataSet ds,
            Map<Long, NativeDataGenerator.NativeCardBinding> bm,
            List<Long> switchableUsers, Map<Long, List<Long>> userCards) {

        BaselineTruth baseline = new BaselineTruth();
        // Index requests by (uid, cardId) for efficient lookup.
        Map<String, List<NativeDataGenerator.NativeEvalRequest>> reqIndex = new HashMap<>();
        for (var r : ds.evalRequests) {
            NativeDataGenerator.NativeCardBinding binding = bm.get(r.cardId);
            if (binding != null && binding.userId == r.userId) {
                String k = r.userId + "|" + r.cardId;
                reqIndex.computeIfAbsent(k, x -> new ArrayList<>()).add(r);
            }
        }

        for (Long uid : switchableUsers) {
            for (Long cid : userCards.get(uid)) {
                NativeDataGenerator.NativeCardBinding binding = bm.get(cid);
                if (binding == null || binding.userId != uid || !"ACTIVE".equals(binding.cardStatus)) {
                    continue;
                }
                // Establish a verified card-local cold state before the reference
                // evaluation so the result cannot reuse a sibling card's key.
                forceColdStartForCard(cid, TENANT_ID, binding);
                setupCardEval(cid, uid, findAnyRequestForUser(ds, uid), bm);

                List<NativeDataGenerator.NativeEvalRequest> reqs = reqIndex.get(uid + "|" + cid);
                if (reqs == null) continue;
                for (var req : reqs) {
                    if (baseline.size() >= BASELINE_MAX_ENTRIES) break;
                    // Use cid's own templateId (not req.templateId) — req may
                    // belong to a different card of the same user. This keeps
                    // PolicyContext consistent with the card being evaluated.
                    PolicyContext pc = PolicyContext.builder()
                        .userId(uid).cardId(cid).tenantId(TENANT_ID)
                        .domainId(req.domainId).templateId(templateIdFor(cid, req, bm))
                        .resource(req.resourceType).action(req.actionCode)
                        .targetId(req.resourceId)
                        .request(BenchmarkMockRequest.fromAbacContext(req.abacContext)).build();
                    PolicyDecision d = policyEngine.evaluate(pc);
                    String truthKey = baselineKey(uid, cid, req);
                    baseline.put(truthKey, d != null && d.isAllowed());
                }
            }
        }
        // Each evaluation establishes its own verified card-local cold state.
        CardContextHolder.clear();
        return baseline;
    }

    /**
     * Force a verified cold state for the selected card's known cache namespaces.
     * This benchmark has no privilege to flush a shared Redis database; each key is
     * removed explicitly and its absence is checked before the cold measurement.
     */
    private void forceColdStartForCard(long cardId, long tenantId,
                                        NativeDataGenerator.NativeCardBinding binding) {
        Set<String> keys = new LinkedHashSet<>();
        keys.add("perm:refs:" + tenantId + ":" + cardId);
        keys.add("perm:refs:" + cardId);
        keys.add("perm:card:status:" + cardId);
        keys.add("perm:card:" + tenantId + ":" + cardId);
        keys.add("perm:card:" + cardId);
        if (binding != null) {
            if (binding.baseRef != null) {
                keys.add("perm:ruleset:" + tenantId + ":" + binding.baseRef.getRuleSetId());
                keys.add("perm:ruleset:" + binding.baseRef.getRuleSetId());
            }
            if (binding.overlayRefs != null) {
                for (CardRuleSetRef ref : binding.overlayRefs) {
                    keys.add("perm:ruleset:" + tenantId + ":" + ref.getRuleSetId());
                    keys.add("perm:ruleset:" + ref.getRuleSetId());
                }
            }
        }

        try {
            redisTemplate.delete(keys);
            for (String key : keys) {
                if (Boolean.TRUE.equals(redisTemplate.hasKey(key))) {
                    throw new IllegalStateException("Cache key remained after eviction: " + key);
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("Unable to establish verified cold cache state for cardId=" + cardId, e);
        }
    }

    private static String baselineKey(long uid, long cid, NativeDataGenerator.NativeEvalRequest req) {
        return uid + "|" + cid + "|" + req.domainId + "|" + req.templateId
            + "|" + req.resourceType + "|" + req.resourceId + "|" + req.actionCode
            + "|" + abacHash(req.abacContext);
    }

    private static long abacHash(NativeDataGenerator.AbacContext abac) {
        if (abac == null) return 0;
        return Objects.hash(abac.currentTime, abac.clientIp, abac.deviceId,
            abac.orgDepth, abac.location, abac.department, abac.customAttributes);
    }

    // ==================== SCENARIO_A ====================

    /**
     * Each reader observes {@code activeCard = shared.get(uid)} and evaluates
     * {@code (uid, activeCard, resource, action)}. The expected decision is
     * retrieved from the pre-computed {@link BaselineTruth} for that exact
     * (uid, activeCard, ...) tuple. A mismatch indicates the PDP returned a
     * decision inconsistent with the cardId the reader actually used, indicating
     * direct-PDP parameter or cache nondeterminism under this local harness.
     *
     * <p>CardContextHolder is set on the reader thread before each evaluation
     * to mirror production semantics where the auth filter populates it; this
     * also ensures ABAC conditions evaluate against the correct thread-local
     * context rather than a stale leftover.
     */
    private SwitchEvalResult doConcurrentSwitchEval(
            NativeDataGenerator.NativeGeneratedDataSet ds,
            Map<Long, NativeDataGenerator.NativeCardBinding> bm,
            List<Long> switchableUsers, Map<Long, List<Long>> userCards,
            BaselineTruth baseline,
            int readerThreads, int writerThreads, int durationSeconds) throws Exception {

        List<NativeDataGenerator.NativeEvalRequest> reqs = ds.evalRequests;
        AtomicInteger totalEvals = new AtomicInteger(0);
        AtomicInteger judgedEvals = new AtomicInteger(0);
        AtomicInteger skippedEvals = new AtomicInteger(0);
        AtomicInteger violations = new AtomicInteger(0);
        AtomicInteger errors = new AtomicInteger(0);
        AtomicBoolean running = new AtomicBoolean(true);
        LatencyRecorder recorder = new LatencyRecorder();

        ConcurrentHashMap<Long, Long> shared = new ConcurrentHashMap<>();
        for (Long uid : switchableUsers) {
            List<Long> cards = userCards.get(uid);
            if (!cards.isEmpty()) shared.put(uid, cards.get(0));
        }
        // Index requests by uid for quick lookup in the reader hot loop.
        Map<Long, List<NativeDataGenerator.NativeEvalRequest>> reqsByUser = new HashMap<>();
        for (var r : reqs)
            reqsByUser.computeIfAbsent(r.userId, k -> new ArrayList<>()).add(r);

        ExecutorService wPool = Executors.newFixedThreadPool(writerThreads);
        for (int t = 0; t < writerThreads; t++) {
            final int seed = t;
            wPool.submit(() -> {
                Random rng = new Random(99 + seed);
                while (running.get()) {
                    Long uid = switchableUsers.get(rng.nextInt(switchableUsers.size()));
                    List<Long> cards = userCards.get(uid);
                    if (cards.size() < 2) continue;
                    shared.put(uid, cards.get(rng.nextInt(cards.size())));
                    busyWaitUs(DELAY_US_MIN + rng.nextInt(DELAY_US_MAX - DELAY_US_MIN));
                }
            });
        }

        ExecutorService rPool = Executors.newFixedThreadPool(readerThreads);
        for (int t = 0; t < readerThreads; t++) {
            final int seed = t;
            rPool.submit(() -> {
                Random rng = new Random(42 + seed);
                while (running.get()) {
                    try {
                        Long uid = switchableUsers.get(rng.nextInt(switchableUsers.size()));
                        final long activeCard = shared.getOrDefault(uid, -1L);
                        if (activeCard < 0) continue;

                        List<NativeDataGenerator.NativeEvalRequest> userReqs = reqsByUser.get(uid);
                        if (userReqs == null || userReqs.isEmpty()) continue;
                        NativeDataGenerator.NativeEvalRequest base = userReqs.get(
                            rng.nextInt(userReqs.size()));

                        final NativeDataGenerator.NativeCardBinding fBinding = bm.get(activeCard);
                        // Use the active card's own templateId from the binding —
                        // base.templateId may belong to a different card of the
                        // same user, which would give PDP inconsistent inputs.
                        final long activeTplId = fBinding != null ? fBinding.templateId : base.templateId;

                        // Set CardContextHolder on the reader thread so ABAC
                        // conditions resolve against the correct thread-local
                        // context (mirrors production auth-filter behavior).
                        IdentityCardContext cc = new IdentityCardContext();
                        cc.setCardId(activeCard); cc.setUserId(uid);
                        cc.setDomainId(TENANT_ID); cc.setTemplateId(activeTplId);
                        cc.setTenantId(TENANT_ID);
                        cc.setCardType(fBinding != null ? fBinding.cardType : "STUDENT");
                        cc.setStatus(fBinding != null ? fBinding.cardStatus : "ACTIVE");
                        CardContextHolder.set(cc);

                        PolicyContext ctx = PolicyContext.builder()
                            .userId(uid).cardId(activeCard).tenantId(TENANT_ID)
                            .domainId(base.domainId).templateId(activeTplId)
                            .resource(base.resourceType).action(base.actionCode)
                            .targetId(base.resourceId)
                            .request(BenchmarkMockRequest.fromAbacContext(base.abacContext))
                            .build();

                        long start = recorder.start();
                        PolicyDecision decision = policyEngine.evaluate(ctx);
                        recorder.stop(start);
                        totalEvals.incrementAndGet();

                        String truthKey = baselineKey(uid, activeCard, base);
                        Boolean expected = baseline.get(truthKey);
                        if (expected == null) {
                            skippedEvals.incrementAndGet();
                            continue;
                        }
                        judgedEvals.incrementAndGet();
                        if (decision == null || decision.isAllowed() != expected) {
                            violations.incrementAndGet();
                        }
                    } catch (Exception e) { errors.incrementAndGet(); }
                }
            });
        }

        Thread.sleep(durationSeconds * 1000L);
        running.set(false);
        wPool.shutdown(); rPool.shutdown();
        wPool.awaitTermination(10, TimeUnit.SECONDS);
        rPool.awaitTermination(10, TimeUnit.SECONDS);

        SwitchEvalResult r = new SwitchEvalResult();
        r.totalEvals = totalEvals;
        r.judgedEvals = judgedEvals;
        r.skippedEvals = skippedEvals;
        r.isolationViolations = violations;
        r.errorCount = errors;
        r.lSnapshot = recorder.snapshot();
        return r;
    }

    // ==================== SCENARIO_B ====================

    /**
     * Reports two distinct metrics:
     * <ul>
     *   <li><b>crossCardDivergence</b> — number of (card-pair, resource) tuples
     *       where the two cards return different decisions. <em>Higher is better:</em>
     *       it indicates the permission sets are genuinely independent.</li>
     *   <li><b>crossCardLeakage</b> — number of evaluations where card A's PDP
     *       result does not match card A's baseline truth. A non-zero value
     *       means card A's evaluation was contaminated by another card's state
     *       (cache pollution, thread-local residue, snapshot mix-up).</li>
     * </ul>
     */
    private IsolationResult doMultiCtxIsolation(
            NativeDataGenerator.NativeGeneratedDataSet ds,
            Map<Long, List<Long>> userCards, List<Long> switchableUsers,
            BaselineTruth baseline,
            Map<Long, NativeDataGenerator.NativeCardBinding> bm) {

        int divergenceChecks = 0, divergence = 0;
        int leakageChecks = 0, leakage = 0;

        for (Long uid : switchableUsers) {
            List<Long> cards = userCards.get(uid);
            if (cards.size() < 2) continue;
            Map<Long, Map<String, Boolean>> perms = new LinkedHashMap<>();

            for (Long cid : cards) {
                // Force cold-start before each card so prior card's cached state
                // cannot leak in. Uses the same defense-in-depth as baseline truth.
                NativeDataGenerator.NativeCardBinding binding = bm.get(cid);
                forceColdStartForCard(cid, TENANT_ID, binding);
                Map<String, Boolean> m = new LinkedHashMap<>();
                for (var req : ds.evalRequests) {
                    if (req.userId != uid) continue;
                    String k = req.resourceType + "|" + req.actionCode;
                    if (m.containsKey(k)) continue;
                    setupCardEval(cid, uid, req, bm);
                    // Use cid's own templateId (not req.templateId) so PolicyContext
                    // matches the card being evaluated — req may belong to a
                    // different card of the same user.
                    PolicyContext pc = PolicyContext.builder()
                        .userId(uid).cardId(cid).tenantId(TENANT_ID)
                        .domainId(req.domainId).templateId(templateIdFor(cid, req, bm))
                        .resource(req.resourceType).action(req.actionCode)
                        .targetId(req.resourceId)
                        .request(BenchmarkMockRequest.fromAbacContext(req.abacContext)).build();
                    boolean actual = policyEngine.evaluate(pc).isAllowed();
                    m.put(k, actual);
                    leakageChecks++;
                    Boolean truth = baseline.get(baselineKey(uid, cid, req));
                    if (truth != null && actual != truth) leakage++;
                }
                perms.put(cid, m);
            }

            // Divergence: two cards returning different decisions for the same key.
            // This is the CORRECT behavior under isolation — counted as a positive
            // signal, not as a leak.
            List<Long> cardList = new ArrayList<>(perms.keySet());
            for (int i = 0; i < cardList.size(); i++) {
                for (int j = i + 1; j < cardList.size(); j++) {
                    for (String key : perms.get(cardList.get(i)).keySet()) {
                        Boolean vi = perms.get(cardList.get(i)).get(key);
                        Boolean vj = perms.get(cardList.get(j)).get(key);
                        if (vj != null && !Objects.equals(vi, vj)) {
                            divergenceChecks++;
                            divergence++;
                        } else if (vj != null) {
                            divergenceChecks++;
                        }
                    }
                }
            }
        }
        IsolationResult r = new IsolationResult();
        r.divergenceChecks = divergenceChecks;
        r.crossCardDivergence = divergence;
        r.leakageChecks = leakageChecks;
        r.crossCardLeakage = leakage;
        return r;
    }

    // ==================== SCENARIO_C ====================

    /**
     * Directly tests whether the PDP follows an explicit {@link PolicyContext}
     * card identifier under deliberately stale ThreadLocal state. It does not
     * create, switch, authenticate, or replay a token.
     *
     * <p>Design:
     * <ol>
     *   <li>Switch CardContextHolder to {@code newCard} and run one evaluation
     *       to saturate any thread-local / cached state with newCard's data.</li>
     *       {@code oldCard}'s cardId while retaining the new card in the stale
     *       thread-local context.</li>
     *   <li>Compare the evaluation result against {@code oldCard}'s baseline truth.</li>
     * </ol>
     * A mismatch indicates cross-card rule contamination — residual newCard
     * state influenced oldCard's evaluation.
     */
    private ContextDependenceResult doParameterDependence(
            NativeDataGenerator.NativeGeneratedDataSet ds,
            Map<Long, List<Long>> userCards, List<Long> switchableUsers,
            BaselineTruth baseline,
            Map<Long, NativeDataGenerator.NativeCardBinding> bm) {

        int total = 0, anomalies = 0;
        Random rng = new Random(42);
        int max = Math.min(switchableUsers.size() * 10, 3000);

        for (int i = 0; i < max; i++) {
            Long uid = switchableUsers.get(rng.nextInt(switchableUsers.size()));
            List<Long> cards = userCards.get(uid);
            if (cards.size() < 2) continue;
            Long oldCard = cards.get(0), newCard = cards.get(1);

            // Find a request that belongs to oldCard.
            NativeDataGenerator.NativeEvalRequest oldReq = null;
            for (var req : ds.evalRequests) {
                if (req.userId == (long) uid && req.cardId == (long) oldCard) {
                    oldReq = req; break;
                }
            }
            if (oldReq == null) continue;

            // Step 1: switch to newCard and evaluate once to saturate caches/ThreadLocal.
            // Use newCard's own templateId (from binding) — NOT oldReq.templateId —
            // so PolicyContext and CardContextHolder are consistent with newCard.
            // This ensures the pollution step faithfully exercises newCard's
            // evaluation path, not a hybrid of newCard's cardId with oldCard's
            // template metadata.
            setupCardEval(newCard, uid, oldReq, bm);
            long newTemplateId = templateIdFor(newCard, oldReq, bm);
            PolicyContext newPc = PolicyContext.builder()
                .userId(uid).cardId(newCard).tenantId(TENANT_ID)
                .domainId(oldReq.domainId).templateId(newTemplateId)
                .resource(oldReq.resourceType).action(oldReq.actionCode)
                .targetId(oldReq.resourceId)
                .request(BenchmarkMockRequest.fromAbacContext(oldReq.abacContext)).build();
            policyEngine.evaluate(newPc);

            // Step 2: evaluate oldCard's explicit PolicyContext while ThreadLocal remains polluted.
            // with newCard's context. PDP must still return oldCard's baseline.
            // Note: CardContextHolder is intentionally NOT reset here, to test
            // whether PDP's decision tracks PolicyContext.cardId or drifts to
            // the polluted ThreadLocal.
            // PolicyContext for oldCard uses oldCard's own templateId — this is
            // the legitimate input PDP should evaluate against.
            //
            // Force cold-start Redis for oldCard before the parameter-dependence check.
            // This ensures the evaluation reads from the same cold-start state as
            // the baseline. Without this, Redis caches populated during the
            // concurrent phase (Scenario A/B) or by step 1 (newCard evaluation)
            // could cause the evaluation to return a different decision for reasons
            // unrelated to ThreadLocal pollution — making the E11 signal
            // ambiguous. With cold-start, any anomaly can ONLY be caused by
            // PDP reading ThreadLocal (newCard) instead of PolicyContext
            // (oldCard) — the true E11 signal we want to measure.
            // Note: forceColdStartForCard clears Redis but does NOT touch
            // CardContextHolder (ThreadLocal), so the pollution from step 1
            // is preserved for the parameter-dependence check.
            NativeDataGenerator.NativeCardBinding oldBinding = bm.get(oldCard);
            forceColdStartForCard(oldCard, TENANT_ID, oldBinding);
            long oldTemplateId = templateIdFor(oldCard, oldReq, bm);
            PolicyContext oldPc = PolicyContext.builder()
                .userId(uid).cardId(oldCard).tenantId(TENANT_ID)
                .domainId(oldReq.domainId).templateId(oldTemplateId)
                .resource(oldReq.resourceType).action(oldReq.actionCode)
                .targetId(oldReq.resourceId)
                .request(BenchmarkMockRequest.fromAbacContext(oldReq.abacContext)).build();
            PolicyDecision parameterDecision = policyEngine.evaluate(oldPc);
            total++;

            Boolean expected = baseline.get(baselineKey(uid, oldCard, oldReq));
            if (expected != null && (parameterDecision == null || parameterDecision.isAllowed() != expected)) {
                anomalies++;
            }
        }
        ContextDependenceResult r = new ContextDependenceResult();
        r.totalEvaluations = total;
        r.anomalyCount = anomalies;
        return r;
    }

    private NativeDataGenerator.NativeEvalRequest findAnyRequestForUser(
            NativeDataGenerator.NativeGeneratedDataSet ds, Long uid) {
        for (var req : ds.evalRequests)
            if (req.userId == (long) uid) return req;
        return ds.evalRequests.get(0);
    }

    private void setupCardEval(long cid, long uid,
                                NativeDataGenerator.NativeEvalRequest req,
                                Map<Long, NativeDataGenerator.NativeCardBinding> bm) {
        IdentityCardContext ic = new IdentityCardContext();
        ic.setCardId(cid); ic.setUserId(uid);
        ic.setDomainId(TENANT_ID);
        // Use the card's own templateId from the binding (not the request's
        // templateId) — they may differ when a request for one card is used
        // to set up evaluation context for a different card (e.g. scenario
        // C's pollution step where oldReq belongs to oldCard but we switch
        // to newCard). This keeps CardContextHolder consistent with cid.
        NativeDataGenerator.NativeCardBinding b = bm.get(cid);
        ic.setTemplateId(b != null ? b.templateId : req.templateId);
        ic.setTenantId(TENANT_ID);
        ic.setCardType(b != null ? b.cardType : "STUDENT");
        ic.setStatus(b != null ? b.cardStatus : "ACTIVE");
        CardContextHolder.set(ic);
    }

    /**
     * Resolves the templateId for a card from its binding, falling back to
     * the request's templateId if the binding is missing. Used to keep
     * {@link PolicyContext} consistent with the card being evaluated.
     */
    private static long templateIdFor(long cid,
                                       NativeDataGenerator.NativeEvalRequest req,
                                       Map<Long, NativeDataGenerator.NativeCardBinding> bm) {
        NativeDataGenerator.NativeCardBinding b = bm.get(cid);
        return b != null ? b.templateId : req.templateId;
    }

    // ==================== SCENARIO_D ====================

    /**
     * Measures local warm-cache and post-eviction evaluation latency.
     *
     * <p>This is a request-latency experiment. It does not measure invalidation
     * propagation across replicas, cache-version convergence, or a distributed
     * consistency bound. Each retained sample is a single verified warm/cold pair
     * rather than a median of repeated states whose warmness is ambiguous.
     */
    private CacheWindowResult doCacheWindow(
            NativeDataGenerator.NativeGeneratedDataSet ds,
            Map<Long, List<Long>> userCards, List<Long> switchableUsers,
            Map<Long, NativeDataGenerator.NativeCardBinding> bm) {

        LatencyRecorder warmRecorder = new LatencyRecorder();
        LatencyRecorder coldRecorder = new LatencyRecorder();
        List<CacheRepopulationSample> rawSamples = new ArrayList<>();
        List<Long> overheadRaw = new ArrayList<>();
        Random rng = new Random(42);
        int requestedSamples = Math.min(switchableUsers.size() * 5, 1500);
        int setupFailures = 0;

        for (int i = 0; i < requestedSamples; i++) {
            Long uid = switchableUsers.get(rng.nextInt(switchableUsers.size()));
            List<Long> cards = userCards.get(uid);
            if (cards.size() < 2) {
                continue;
            }
            long target = cards.get(rng.nextInt(cards.size()));
            NativeDataGenerator.NativeEvalRequest req = findRequestForCard(ds, uid, target);
            NativeDataGenerator.NativeCardBinding binding = bm.get(target);
            if (req == null || binding == null) {
                setupFailures++;
                continue;
            }

            try {
                PolicyContext context = buildPolicyContext(uid, target, req, bm);

                // Establish and verify a warm state through the production read path.
                forceColdStartForCard(target, TENANT_ID, binding);
                setupCardEval(target, uid, req, bm);
                PolicyDecision warmupDecision = policyEngine.evaluate(context);
                if (!hasExpectedWarmCacheKeys(target, binding, warmupDecision)) {
                    setupFailures++;
                    continue;
                }

                setupCardEval(target, uid, req, bm);
                long warmStart = System.nanoTime();
                policyEngine.evaluate(context);
                long warmNanos = System.nanoTime() - warmStart;

                forceColdStartForCard(target, TENANT_ID, binding);

                setupCardEval(target, uid, req, bm);
                long coldStart = System.nanoTime();
                policyEngine.evaluate(context);
                long coldNanos = System.nanoTime() - coldStart;

                warmRecorder.record(warmNanos);
                coldRecorder.record(coldNanos);
                rawSamples.add(new CacheRepopulationSample(target, warmNanos, coldNanos));
                overheadRaw.add(coldNanos - warmNanos);
            } catch (Exception ex) {
                setupFailures++;
                log.warn("Skipping cache-repopulation sample for cardId={}: {}", target, ex.getMessage());
            } finally {
                CardContextHolder.clear();
            }
        }

        LatencyRecorder.LatencySnapshot wSnap = warmRecorder.snapshot();
        LatencyRecorder.LatencySnapshot cSnap = coldRecorder.snapshot();
        CacheWindowResult r = new CacheWindowResult();
        r.requestedSampleCount = requestedSamples;
        r.sampleCount = wSnap.sampleCount();
        r.setupFailureCount = setupFailures;
        r.rawSamples = List.copyOf(rawSamples);
        r.warmMeanUs = wSnap.meanUs();
        r.warmMedianUs = wSnap.p50Us();
        r.warmP95Us = wSnap.p95Us();
        r.warmP99Us = wSnap.p99Us();
        r.coldMeanUs = cSnap.meanUs();
        r.coldMedianUs = cSnap.p50Us();
        r.coldP95Us = cSnap.p95Us();
        r.coldP99Us = cSnap.p99Us();
        long[] overheadSorted = overheadRaw.stream().mapToLong(Long::longValue).toArray();
        Arrays.sort(overheadSorted);
        r.overheadMedianUs = percentileLong(overheadSorted, 50) / 1_000.0;
        r.overheadP95Us = percentileLong(overheadSorted, 95) / 1_000.0;
        r.overheadP99Us = percentileLong(overheadSorted, 99) / 1_000.0;
        r.overheadMinUs = overheadSorted.length > 0 ? overheadSorted[0] / 1_000L : 0;
        r.overheadMaxUs = overheadSorted.length > 0 ? overheadSorted[overheadSorted.length - 1] / 1_000L : 0;
        return r;
    }

    private NativeDataGenerator.NativeEvalRequest findRequestForCard(
            NativeDataGenerator.NativeGeneratedDataSet ds, long userId, long cardId) {
        for (NativeDataGenerator.NativeEvalRequest request : ds.evalRequests) {
            if (request.userId == userId && request.cardId == cardId) {
                return request;
            }
        }
        return null;
    }

    private PolicyContext buildPolicyContext(long userId, long cardId,
                                             NativeDataGenerator.NativeEvalRequest request,
                                             Map<Long, NativeDataGenerator.NativeCardBinding> bindings) {
        return PolicyContext.builder()
                .userId(userId).cardId(cardId).tenantId(TENANT_ID)
                .domainId(request.domainId).templateId(templateIdFor(cardId, request, bindings))
                .resource(request.resourceType).action(request.actionCode)
                .targetId(request.resourceId)
                .request(BenchmarkMockRequest.fromAbacContext(request.abacContext))
                .build();
    }

    private boolean hasExpectedWarmCacheKeys(long cardId,
                                             NativeDataGenerator.NativeCardBinding binding,
                                             PolicyDecision decision) {
        Set<String> keys = new LinkedHashSet<>();
        keys.add("perm:refs:" + TENANT_ID + ":" + cardId);
        keys.add("perm:card:status:" + cardId);

        Long matchedRuleSetId = ruleSetIdFromDecision(decision);
        if (matchedRuleSetId != null) {
            keys.add("perm:ruleset:" + TENANT_ID + ":" + matchedRuleSetId);
        }
        return keys.stream().allMatch(key -> Boolean.TRUE.equals(redisTemplate.hasKey(key)));
    }

    private Long ruleSetIdFromDecision(PolicyDecision decision) {
        if (decision == null || decision.getMatchedRule() == null
                || !decision.getMatchedRule().startsWith("ruleset:")) {
            return null;
        }
        for (PolicyDecision.EvaluationStep step : decision.getEvaluationPath()) {
            if (!"RULESET".equals(step.getPhase()) || step.getDetail() == null) {
                continue;
            }
            int marker = step.getDetail().indexOf("ruleSetId=");
            if (marker < 0 || step.getResult() == null || "NO_MATCH".equals(step.getResult())) {
                continue;
            }
            int start = marker + "ruleSetId=".length();
            int end = step.getDetail().indexOf(' ', start);
            String value = end < 0 ? step.getDetail().substring(start) : step.getDetail().substring(start, end);
            try {
                return Long.valueOf(value);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static long median(long[] arr) {
        if (arr.length == 0) return 0;
        long[] copy = arr.clone();
        Arrays.sort(copy);
        int mid = copy.length / 2;
        return copy.length % 2 == 0 ? (copy[mid - 1] + copy[mid]) / 2 : copy[mid];
    }

    private static long percentileLong(long[] sortedAsc, double pct) {
        if (sortedAsc.length == 0) return 0;
        int i = (int) Math.ceil(pct / 100.0 * sortedAsc.length) - 1;
        return sortedAsc[Math.max(0, Math.min(i, sortedAsc.length - 1))];
    }

    // ==================== Helpers ====================

    private void warmup(NativeDataGenerator.NativeGeneratedDataSet ds,
                         Map<Long, NativeDataGenerator.NativeCardBinding> bm) {
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            var req = ds.evalRequests.get(i % ds.evalRequests.size());
            IdentityCardContext ic = new IdentityCardContext();
            ic.setCardId(req.cardId); ic.setUserId(req.userId);
            ic.setDomainId(req.domainId); ic.setTemplateId(req.templateId);
            ic.setTenantId(TENANT_ID);
            NativeDataGenerator.NativeCardBinding b = bm.get(req.cardId);
            ic.setCardType(b != null ? b.cardType : "STUDENT");
            ic.setStatus(b != null ? b.cardStatus : "ACTIVE");
            CardContextHolder.set(ic);
            policyEngine.evaluate(PolicyContext.builder()
                .userId(req.userId).cardId(req.cardId).tenantId(TENANT_ID)
                .domainId(req.domainId).templateId(req.templateId)
                .resource(req.resourceType).action(req.actionCode)
                .targetId(req.resourceId)
                .request(BenchmarkMockRequest.fromAbacContext(req.abacContext)).build());
        }
    }

    private static void busyWaitUs(long us) {
        if (us <= 0) return;
        long end = System.nanoTime() + us * 1000;
        while (System.nanoTime() < end) Thread.onSpinWait();
    }

    private static String fmt(double v) { return String.format("%.1f", v); }

    // ==================== Result Types ====================

    public static class NativeSwitchAtomicityResult {
        public int cardCount, switchableUserCount;
        public SwitchEvalResult scenarioA;
        public IsolationResult scenarioB;
        public ContextDependenceResult scenarioC;
        public CacheWindowResult scenarioD;
    }
    public static class SwitchEvalResult {
        public AtomicInteger totalEvals = new AtomicInteger(0);
        public AtomicInteger judgedEvals = new AtomicInteger(0);
        public AtomicInteger skippedEvals = new AtomicInteger(0);
        public AtomicInteger isolationViolations = new AtomicInteger(0);
        public AtomicInteger errorCount = new AtomicInteger(0);
        public LatencyRecorder.LatencySnapshot lSnapshot;
    }
    public static class IsolationResult {
        /** Number of (card-pair, resource) tuples compared for divergence. */
        public int divergenceChecks;
        /** Number of tuples where two cards returned different decisions (positive signal). */
        public int crossCardDivergence;
        /** Number of single-card evaluations checked against baseline. */
        public int leakageChecks;
        /** Number of evaluations whose result did NOT match the card's own baseline (violation). */
        public int crossCardLeakage;
    }
    public static class ContextDependenceResult {
        public int totalEvaluations;
        /** Number of evaluations that did not match oldCard's explicit-context baseline. */
        public int anomalyCount;
    }
    public static class CacheWindowResult {
        public int requestedSampleCount;
        public int sampleCount;
        /** Samples excluded because expected cache state could not be established. */
        public int setupFailureCount;
        public List<CacheRepopulationSample> rawSamples = List.of();
        public double warmMeanUs, warmMedianUs, warmP95Us, warmP99Us;
        public double coldMeanUs, coldMedianUs, coldP95Us, coldP99Us;
        /** Signed: coldMedian - warmMedian. Negative means cold was faster than warm. */
        public double overheadMedianUs, overheadP95Us, overheadP99Us;
        public long overheadMinUs, overheadMaxUs;
    }

    public record CacheRepopulationSample(long cardId, long warmNanos, long coldNanos) {
    }

    /** Single-threaded direct-PDP reference map keyed by the complete input tuple. */
    private static class BaselineTruth {
        private final Map<String, Boolean> map = new ConcurrentHashMap<>();
        void put(String k, Boolean v) { map.put(k, v); }
        Boolean get(String k) { return map.get(k); }
        int size() { return map.size(); }
    }
}
