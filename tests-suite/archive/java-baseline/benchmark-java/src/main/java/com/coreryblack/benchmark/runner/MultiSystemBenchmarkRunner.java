package com.coreryblack.benchmark.runner;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSetEntry;
import com.coreryblack.permission.permission.RuleSetService;
import com.coreryblack.benchmark.baseline.*;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.data.MultiSystemComparisonResult;
import com.coreryblack.benchmark.util.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.*;
import java.util.concurrent.*;

/**
 * Multi-system comparative benchmark — apples-to-apples comparison.
 *
 * <h3>Benchmark Scenarios</h3>
 * <ul>
 *   <li><b>RQ-Compare-1</b>: Decision Latency
 *       — AL vs Casbin vs OPA vs Cedar (all vendor-recommended production configs)</li>
 *   <li><b>RQ-Compare-2</b>: Rule Growth Sensitivity
 *       — How latency scales with rule count (10→5000 rules/card)</li>
 *   <li><b>RQ-Compare-3</b>: Rule Change Cost
 *       — Incremental compile vs full reload (covered by Native RQ3)</li>
 *   <li><b>RQ-Compare-4</b>: Relationship Authorization
 * </ul>
 *
 * <h3>Fairness Configuration</h3>
 * <p>All systems are evaluated using their vendor-recommended production
 * deployment configurations:
 * <ul>
 *   <li>AstralLight — Snapshot + Redis L1 Cache</li>
 *   <li>Casbin — CachedEnforcer</li>
 *   <li>OPA — WASM compilation + Decision Cache</li>
 *   <li>Cedar — In-memory indexed PolicyStore</li>
 * </ul>
 * because it uses a fundamentally different ReBAC model.
 */
@Slf4j
public class MultiSystemBenchmarkRunner {

    private static final int WARMUP_ITERATIONS = 1000;
    private static final long BENCHMARK_TENANT_ID = 1L;

    /** Directory for per-scale checkpoints; null disables checkpointing. */
    private volatile String checkpointDir;

    public void setCheckpointDir(String checkpointDir) {
        this.checkpointDir = checkpointDir;
    }

    public String outputDirPath() {
        return checkpointDir;
    }

    /**
     * Appends one completed scale point to the checkpoint CSV so an interrupted
     * comparison run still persists every scale measured so far.
     */
    private void checkpointScalePoint(
            MultiSystemComparisonResult.ScalePoint scalePoint, String dir) {
        if (dir == null) {
            return;
        }
        try {
            java.nio.file.Path path = java.nio.file.Path.of(dir, "scale_checkpoints.csv");
            boolean header = !java.nio.file.Files.exists(path);
            java.io.File f = path.toFile();
            f.getParentFile().mkdirs();
            try (java.io.PrintWriter pw = new java.io.PrintWriter(
                    new java.io.BufferedWriter(new java.io.FileWriter(f, true)))) {
                if (header) {
                    pw.println("scale,system,optimization,mean_us,p50_us,p95_us,p99_us,p999_us,"
                        + "min_us,max_us,total_ops,error_ops,tps,cold_mean_us,concurrent_tps");
                }
                for (MultiSystemComparisonResult.SystemResult r : scalePoint.systemResults) {
                    LatencyRecorder.LatencySnapshot st = r.singleThreadSnapshot;
                    if (st == null || st.sampleCount() == 0) {
                        continue;
                    }
                    LatencyRecorder.LatencySnapshot conc = r.concurrentSnapshot;
                    LatencyRecorder.LatencySnapshot cold = r.coldStartSnapshot;
                    pw.println(String.format("%s,%s,%s,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,"
                            + "%d,%d,%.1f,%s,%s",
                        scalePoint.scale.label(),
                        r.systemLabel,
                        r.optimizationLevel,
                        st.meanUs(), st.p50Us(), st.p95Us(), st.p99Us(), st.p999Us(),
                        st.minUs(), st.maxUs(),
                        st.totalOps(), st.errorOps(), st.tps(),
                        cold == null ? "" : String.format("%.1f", cold.meanUs()),
                        conc == null ? "" : String.format("%.1f", conc.tps())));
                }
            }
            log.info("Checkpointed scale {} -> {}", scalePoint.scale.label(), path);
        } catch (Exception e) {
            log.warn("Failed to checkpoint scale {}: {}", scalePoint.scale.label(), e.getMessage());
        }
    }

    private final PolicyEngine policyEngine;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;
    private final RuleSetService ruleSetService;
    private final CasbinAdapter casbinAdapter;
    private final CasbinCachedAdapter casbinCachedAdapter;
    private final OpaAdapter opaAdapter;
    private final OpaAdapter opaNoCacheAdapter;
    private final CedarAdapter cedarOptimizedAdapter;
    private final CrossSystemCorrectnessVerifier correctnessVerifier;


    private static String getEnvOrDefault(String key, String defaultValue) {
        String value = System.getenv(key);
        return value != null ? value : defaultValue;
    }

    public MultiSystemBenchmarkRunner(
            PolicyEngine policyEngine,
            DataGenerator dataGenerator,
            StringRedisTemplate redisTemplate,
            JdbcTemplate jdbcTemplate,
            RuleSetService ruleSetService,
            CasbinAdapter casbinAdapter,
            CasbinCachedAdapter casbinCachedAdapter,
            OpaAdapter opaAdapter,
            OpaAdapter opaNoCacheAdapter) {
        this.policyEngine = policyEngine;
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.jdbcTemplate = jdbcTemplate;
        this.ruleSetService = ruleSetService;
        this.casbinAdapter = casbinAdapter;
        this.casbinCachedAdapter = casbinCachedAdapter;
        this.opaAdapter = opaAdapter;
        this.opaNoCacheAdapter = opaNoCacheAdapter;
        this.cedarOptimizedAdapter = new CedarAdapter(true);
        this.correctnessVerifier = new CrossSystemCorrectnessVerifier(
            policyEngine, casbinAdapter, casbinCachedAdapter, opaAdapter, opaNoCacheAdapter);
    }

    // ═══════════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════════

    /**
    * RQ-Compare-1 + RQ-Compare-2 combined run.
    * Systems: AstralLight, Casbin(Cached), OPA(NoCache), Cedar(Optimized).
     */
    public MultiSystemComparisonResult.BenchmarkResult runLayer1Comparison(
            ScaleConfig[] gradientScales,
            int iterationsPerScale,
            int concurrency) {

        log.info("============================================================");
        log.info("=== RQ-Compare-1: Decision Latency (4 systems) ===");
        log.info("=== Systems: AstralLight, Casbin, Casbin(Cached), OPA ===");
        log.info("=== All systems at vendor-recommended production configs ===");
        log.info("=== Scales: {}, Iterations: {}, Concurrency: {} ===",
            gradientScales.length, iterationsPerScale, concurrency);
        log.info("============================================================");

        // RQ-Compare-2-only mode: skip the Layer A gate, semantic divergence and
        // the decision-latency scale loop, measuring only rule-growth and card-scale
        // sensitivity. Used to recover/fix RQ-Compare-2 artifacts without re-running
        // the ~1.5h primary comparison.
        boolean rq2Only = Boolean.getBoolean("benchmark.rq2.only");
        if (rq2Only) {
            log.info("RQ-Compare-2 only: skipping Layer A gate/divergence/scale loop");
        }

        MultiSystemComparisonResult.BenchmarkResult result =
            new MultiSystemComparisonResult.BenchmarkResult();
        result.addMetadata("layer", "Layer1_DirectAuthorization");
        result.addMetadata("timestamp", java.time.LocalDateTime.now().toString());
        result.addMetadata("iterations_per_scale", String.valueOf(iterationsPerScale));
        result.addMetadata("concurrency", String.valueOf(concurrency));
        result.addMetadata("fairness", "common expressible subset (see capability matrix)");
        result.addMetadata("subset", com.coreryblack.benchmark.baseline.BaselineCapabilityMatrix.subsetStatement());

        // Correctness Gate: common semantic subset — 3 cases (must pass with 0 mismatches)
        // After gate passes: "All compared engines passed the semantic equivalence
        // gate under the common authorization subset."
        if (!rq2Only) {
            runCorrectnessGate(ScaleConfig.builder()
                .cardCount(100).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.0)
                .build(), "Case 1: ALLOW_ONLY");
            runCorrectnessGate(ScaleConfig.builder()
                .cardCount(100).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(1.0)
                .build(), "Case 2: DENY_ONLY");
            runCorrectnessGate(ScaleConfig.builder()
                .cardCount(100).templateCount(1).baseRulesPerCard(0).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.0)
                .build(), "Case 3: DEFAULT_DENY (empty rule set)");
            log.info("CORRECTNESS GATE: All compared engines passed the semantic equivalence gate under the common authorization subset.");

            // --- Semantic Divergence Analysis (informational, not a gate) ---
            // Divergences are expected because AstralLight adopts priority-based
            // conflict resolution whereas Casbin, OPA and Cedar employ deny-override
            // semantics.
            log.info("--- Semantic Divergence Analysis ---");
            runSemanticDivergenceAnalysis(ScaleConfig.builder()
                .cardCount(100).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3)
                .build(),
                "Priority Conflict: Allow(100)+Deny(50)");
            log.info("--- Semantic Divergence Analysis Complete ---");

            for (ScaleConfig scale : gradientScales) {
                log.info("--- Scale: {} ---", scale.label());
                // Every measured scale must stay inside the common subset.
                com.coreryblack.benchmark.baseline.BaselineCapabilityMatrix.requireCommonSubset(scale, -1);
                // Flush caches between scales to prevent contamination (strict mode)
                BenchmarkCleanupUtil.cleanupAllStrict(jdbcTemplate, redisTemplate);
                System.gc();
                MultiSystemComparisonResult.ScalePoint scalePoint =
                    runLayer1ScalePoint(scale, iterationsPerScale, concurrency);
                result.scalePoints.add(scalePoint);
                // Checkpoint: persist this scale point immediately so an interrupted
                // run still yields the data measured so far instead of losing it.
                checkpointScalePoint(scalePoint, outputDirPath());
                // Stabilization: allow GC, JIT deopt, and connection pool recycling
                sleepMs(5000);
            }
        }

        // RQ-Compare-2: Rule Growth Sensitivity
        log.info("--- RQ-Compare-2: Rule Growth Sensitivity ---");
        result.complexityPoints = runLayer1ComplexitySensitivity(5000);
        result.cardScalePoints = runLayer1CardScaleSensitivity(5000);

        log.info("=== Layer 1 Comparison Complete ===");
        return result;
    }

    /**
    * Best-practice only: AL(Optimized) vs Casbin(Cached) vs OPA(NoCache) vs Cedar(Optimized).
     * This is the primary optimized comparison set.
     */
    public MultiSystemComparisonResult.BenchmarkResult runBestPracticeComparison(
            ScaleConfig[] gradientScales,
            int iterationsPerScale,
            int concurrency) {

        log.info("=== Best-Practice Comparison (Layer 1, optimized only) ===");

        // The best-practice head-to-head set must satisfy the same correctness
        // gate as the primary comparison — omitting it would let a broken
        // adapter produce incomparable numbers without a PASS guard.
        runCorrectnessGate(ScaleConfig.builder()
            .cardCount(100).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(0)
            .resourceTypes(10).actionsPerResource(4).denyRatio(0.0)
            .build(), "Case 1: ALLOW_ONLY");
        runCorrectnessGate(ScaleConfig.builder()
            .cardCount(100).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(0)
            .resourceTypes(10).actionsPerResource(4).denyRatio(1.0)
            .build(), "Case 2: DENY_ONLY");
        runCorrectnessGate(ScaleConfig.builder()
            .cardCount(100).templateCount(1).baseRulesPerCard(0).overlayRulesPerCard(0)
            .resourceTypes(10).actionsPerResource(4).denyRatio(0.0)
            .build(), "Case 3: DEFAULT_DENY (empty rule set)");

        MultiSystemComparisonResult.BenchmarkResult result =
            new MultiSystemComparisonResult.BenchmarkResult();
        result.addMetadata("layer", "Layer1_Optimized");
        result.addMetadata("fairness", "common expressible subset (see capability matrix)");
        result.addMetadata("subset", com.coreryblack.benchmark.baseline.BaselineCapabilityMatrix.subsetStatement());

        for (ScaleConfig scale : gradientScales) {
            MultiSystemComparisonResult.ScalePoint scalePoint =
                new MultiSystemComparisonResult.ScalePoint();
            scalePoint.scale = scale;

            com.coreryblack.benchmark.baseline.BaselineCapabilityMatrix.requireCommonSubset(scale, -1);
            cleanupBenchmarkData();
            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            scalePoint.systemResults.add(
                benchmarkAstralLight("AstralLight", "OPTIMIZED", dataset, iterationsPerScale, concurrency));

            // Casbin(Cached) — g-inheritance keeps policy count at M+N, no skip needed
            try {
                scalePoint.systemResults.add(
                    benchmarkCasbinCached("Casbin(Cached)", "OPTIMIZED", dataset, iterationsPerScale, concurrency));
            } catch (Throwable t) {
                log.error("Casbin(Cached) FAILED at scale {}: {}", scale.label(), t.getMessage());
                scalePoint.systemResults.add(errorResult("Casbin(Cached)", "OPTIMIZED", t));
            }

            scalePoint.systemResults.add(
                benchmarkOpaNoCache("OPA(NoCache)", "OPTIMIZED", dataset, iterationsPerScale, concurrency));

            scalePoint.systemResults.add(
                benchmarkCedar("Cedar(Optimized)", "OPTIMIZED", dataset, iterationsPerScale, concurrency, cedarOptimizedAdapter));

            result.scalePoints.add(scalePoint);
            sleepMs(2000);
        }

        return result;
    }

    // ═══════════════════════════════════════════════════════════════
    // RQ-Compare-3: Rule Update Overhead (cross-system)
    // AL Incremental Compile vs Casbin Policy Reload vs OPA Bundle Reload vs Cedar Index Rebuild
    // ═══════════════════════════════════════════════════════════════

    public List<MultiSystemComparisonResult.RuleChangeCostPoint> runLayer1RuleChangeCost(
            ScaleConfig[] scales, int iterations) {

        log.info("============================================================");
        log.info("=== RQ-Compare-3: Rule Update Overhead ===");
        log.info("=== AL:Incremental Compile vs Casbin:Policy Reload vs OPA:Bundle Reload vs Cedar:Index Rebuild ===");
        log.info("============================================================");

        List<MultiSystemComparisonResult.RuleChangeCostPoint> results = new ArrayList<>();

        for (ScaleConfig scale : scales) {
            log.info("--- Scale: {} ---", scale.label());
            cleanupBenchmarkData();
            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            long ruleSetId = dataset.baseRuleSets.get(0).getRuleSetId();
            int rulesPerCard = scale.getBaseRulesPerCard() + scale.getOverlayRulesPerCard();

            // ── Pre-update: measure baseline decision latency ──
            double alPreLatency = benchmarkAstralComplexity(dataset, 100).meanUs();

            // ── AstralLight: Incremental Compile ──
            LatencyRecorder alRecorder = new LatencyRecorder();
            for (int i = 0; i < iterations; i++) {
                setupCardContext(1L);
                RuleSetEntry newEntry = new RuleSetEntry();
                newEntry.setRuleSetId(ruleSetId);
                newEntry.setTenantId(1L);
                newEntry.setResourceType("learn_subject");
                newEntry.setActionCode("read");
                newEntry.setEffect(i % 2 == 0 ? "ALLOW" : "DENY");
                newEntry.setPriority(10000 + i);
                newEntry.setEnabled(1);
                newEntry.setCreatedAt(java.time.LocalDateTime.now());
                long start = alRecorder.start();
                ruleSetService.rebuildSnapshot(ruleSetId,
                    "learn_subject:*", "read", newEntry, false);
                alRecorder.stop(start);
            }
            // Post-update: measure decision latency after incremental compile
            double alPostLatency = benchmarkAstralComplexity(dataset, 100).meanUs();
            MultiSystemComparisonResult.RuleChangeCostPoint alPoint = new MultiSystemComparisonResult.RuleChangeCostPoint();
            alPoint.systemLabel = "AstralLight";
            alPoint.updateMethod = "Incremental Compile";
            alPoint.rulesPerCard = rulesPerCard;
            alPoint.cardCount = scale.getCardCount();
            alPoint.updateMeanUs = alRecorder.snapshot().meanUs();
            alPoint.updateP99Us = alRecorder.snapshot().p99Us();
            alPoint.preUpdateLatencyUs = alPreLatency;
            alPoint.postUpdateLatencyUs = alPostLatency;
            results.add(alPoint);
            log.info("  AL incremental compile: mean={}us, p99={}us, pre={}us, post={}us",
                String.format("%.1f", alPoint.updateMeanUs), String.format("%.1f", alPoint.updateP99Us),
                String.format("%.1f", alPreLatency), String.format("%.1f", alPostLatency));

            // ── Casbin: Policy Reload (re-initialize CachedEnforcer) ──
            // No skip — g-inheritance keeps policy count at M+N
            try {
                casbinCachedAdapter.initialize(dataset);
                LatencyRecorder casbinRecorder = new LatencyRecorder();
                double casbinPreLatency = casbinCachedAdapter.benchmarkEval(dataset, 100).meanUs();
                for (int i = 0; i < Math.min(iterations, 50); i++) {
                    long start = casbinRecorder.start();
                    casbinCachedAdapter.initialize(dataset);
                    casbinRecorder.stop(start);
                }
                // Post-update: measure decision latency after policy reload
                double casbinPostLatency = casbinCachedAdapter.benchmarkEval(dataset, 100).meanUs();
                MultiSystemComparisonResult.RuleChangeCostPoint casbinPoint = new MultiSystemComparisonResult.RuleChangeCostPoint();
                casbinPoint.systemLabel = "Casbin(Cached)";
                casbinPoint.updateMethod = "Policy Reload";
                casbinPoint.rulesPerCard = rulesPerCard;
                casbinPoint.cardCount = scale.getCardCount();
                casbinPoint.updateMeanUs = casbinRecorder.snapshot().meanUs();
                casbinPoint.updateP99Us = casbinRecorder.snapshot().p99Us();
                casbinPoint.preUpdateLatencyUs = casbinPreLatency;
                casbinPoint.postUpdateLatencyUs = casbinPostLatency;
                results.add(casbinPoint);
                log.info("  Casbin policy reload: mean={}us, p99={}us, pre={}us, post={}us",
                    String.format("%.1f", casbinPoint.updateMeanUs), String.format("%.1f", casbinPoint.updateP99Us),
                    String.format("%.1f", casbinPreLatency), String.format("%.1f", casbinPostLatency));
            } catch (Throwable t) {
                log.error("  Casbin policy reload FAILED at scale {}: {}", scale.label(), t.getMessage());
            }

            // ── OPA: Bundle Reload (re-push data to OPA server) ──
            try {
                opaNoCacheAdapter.initialize(dataset);
                LatencyRecorder opaRecorder = new LatencyRecorder();
                double opaPreLatency = 0;
                try { opaPreLatency = opaNoCacheAdapter.benchmarkEval(dataset, 100).meanUs(); }
                catch (Exception ignored) {}
                for (int i = 0; i < Math.min(iterations, 30); i++) {
                    long start = opaRecorder.start();
                    opaNoCacheAdapter.initialize(dataset);
                    opaRecorder.stop(start);
                }
                // Post-update: measure decision latency after bundle reload
                double opaPostLatency = 0;
                try { opaPostLatency = opaNoCacheAdapter.benchmarkEval(dataset, 100).meanUs(); }
                catch (Exception ignored) {}
                MultiSystemComparisonResult.RuleChangeCostPoint opaPoint = new MultiSystemComparisonResult.RuleChangeCostPoint();
                opaPoint.systemLabel = "OPA(NoCache)";
                opaPoint.updateMethod = "Bundle Reload";
                opaPoint.rulesPerCard = rulesPerCard;
                opaPoint.cardCount = scale.getCardCount();
                opaPoint.updateMeanUs = opaRecorder.snapshot().meanUs();
                opaPoint.updateP99Us = opaRecorder.snapshot().p99Us();
                opaPoint.preUpdateLatencyUs = opaPreLatency;
                opaPoint.postUpdateLatencyUs = opaPostLatency;
                results.add(opaPoint);
                log.info("  OPA bundle reload: mean={}us, p99={}us, pre={}us, post={}us",
                    String.format("%.1f", opaPoint.updateMeanUs), String.format("%.1f", opaPoint.updateP99Us),
                    String.format("%.1f", opaPreLatency), String.format("%.1f", opaPostLatency));
            } catch (Exception e) {
                log.warn("OPA bundle reload failed: {}", e.getMessage());
            }

            // ── Cedar: Index Rebuild (re-initialize optimized index) ──
            cedarOptimizedAdapter.initialize(dataset);
            LatencyRecorder cedarRecorder = new LatencyRecorder();
            double cedarPreLatency = cedarOptimizedAdapter.benchmarkEval(dataset, 100).meanUs();
            for (int i = 0; i < Math.min(iterations, 50); i++) {
                long start = cedarRecorder.start();
                cedarOptimizedAdapter.initialize(dataset);
                cedarRecorder.stop(start);
            }
            // Post-update: measure decision latency after index rebuild
            double cedarPostLatency = cedarOptimizedAdapter.benchmarkEval(dataset, 100).meanUs();
            MultiSystemComparisonResult.RuleChangeCostPoint cedarPoint = new MultiSystemComparisonResult.RuleChangeCostPoint();
            cedarPoint.systemLabel = "Cedar(Optimized)";
            cedarPoint.updateMethod = "Index Rebuild";
            cedarPoint.rulesPerCard = rulesPerCard;
            cedarPoint.cardCount = scale.getCardCount();
            cedarPoint.updateMeanUs = cedarRecorder.snapshot().meanUs();
            cedarPoint.updateP99Us = cedarRecorder.snapshot().p99Us();
            cedarPoint.preUpdateLatencyUs = cedarPreLatency;
            cedarPoint.postUpdateLatencyUs = cedarPostLatency;
            results.add(cedarPoint);
            log.info("  Cedar index rebuild: mean={}us, p99={}us, pre={}us, post={}us",
                String.format("%.1f", cedarPoint.updateMeanUs), String.format("%.1f", cedarPoint.updateP99Us),
                String.format("%.1f", cedarPreLatency), String.format("%.1f", cedarPostLatency));

            cleanupBenchmarkData();
            sleepMs(1000);
        }

        log.info("=== Rule Update Overhead Complete ===");
        return results;
    }

    // ═══════════════════════════════════════════════════════════════
    // Layer 1 Scale Point
    // ═══════════════════════════════════════════════════════════════

    private MultiSystemComparisonResult.ScalePoint runLayer1ScalePoint(
            ScaleConfig scale, int iterations, int concurrency) {

        MultiSystemComparisonResult.ScalePoint scalePoint =
            new MultiSystemComparisonResult.ScalePoint();
        scalePoint.scale = scale;

        cleanupBenchmarkData();
        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
        dataGenerator.persistToDatabase(dataset);
        dataGenerator.populateRedisCache(dataset);

        // AstralLight
        scalePoint.systemResults.add(
            benchmarkAstralLight("AstralLight", "OPTIMIZED", dataset, iterations, concurrency));

        // Casbin (DEFAULT + OPTIMIZED) — g-inheritance keeps policy count at M+N, no skip needed
        try {
            casbinAdapter.initialize(dataset);
            scalePoint.systemResults.add(
                benchmarkCasbin("Casbin", "DEFAULT", dataset, iterations, concurrency));
        } catch (Throwable t) {
            log.error("Casbin(DEFAULT) benchmark FAILED at scale {}: {}", scale.label(), t.getMessage());
            scalePoint.systemResults.add(errorResult("Casbin", "DEFAULT", t));
        }

        try {
            casbinCachedAdapter.initialize(dataset);
            scalePoint.systemResults.add(
                benchmarkCasbinCached("Casbin(Cached)", "OPTIMIZED", dataset, iterations, concurrency));
        } catch (Throwable t) {
            log.error("Casbin(Cached) benchmark FAILED at scale {}: {}", scale.label(), t.getMessage());
            scalePoint.systemResults.add(errorResult("Casbin(Cached)", "OPTIMIZED", t));
        }

        // OPA (DEFAULT for main table, OPTIMIZED/NoCache for appendix)
        scalePoint.systemResults.add(
            benchmarkOpa("OPA(REST)", "DEFAULT", dataset, iterations, concurrency));
        scalePoint.systemResults.add(
            benchmarkOpaNoCache("OPA(NoCache)", "OPTIMIZED", dataset, iterations, concurrency));

        // Cedar (OPTIMIZED only — in-memory indexed is its production config)
        try {
            cedarOptimizedAdapter.initialize(dataset);
            scalePoint.systemResults.add(
                benchmarkCedar("Cedar(Optimized)", "OPTIMIZED", dataset, iterations, concurrency, cedarOptimizedAdapter));
        } catch (Exception e) {
            log.warn("Cedar(Optimized) benchmark failed: {}", e.getMessage());
            scalePoint.systemResults.add(skippedResult("Cedar(Optimized)", "OPTIMIZED"));
        }

        return scalePoint;
    }

    // ═══════════════════════════════════════════════════════════════
    // Layer 1 Sensitivity
    // ═══════════════════════════════════════════════════════════════

    private List<MultiSystemComparisonResult.ComplexityPoint> runLayer1ComplexitySensitivity(
            int iterationsPerPoint) {
        ScaleConfig[] gradient = ScaleConfig.ruleComplexityGradient();
        List<MultiSystemComparisonResult.ComplexityPoint> results = new ArrayList<>();

        for (ScaleConfig scale : gradient) {
            log.info("  Rules per card: {}", scale.getBaseRulesPerCard());
            cleanupBenchmarkData();
            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            MultiSystemComparisonResult.ComplexityPoint point =
                new MultiSystemComparisonResult.ComplexityPoint();
            point.rulesPerCard = scale.getBaseRulesPerCard();

            point.systemSnapshots.put("AstralLight",
                benchmarkAstralComplexity(dataset, iterationsPerPoint));

            // Casbin(Cached) — no skip, g-inheritance keeps policy count manageable
            try {
                casbinCachedAdapter.initialize(dataset);
                point.systemSnapshots.put("Casbin(Cached)",
                    casbinCachedAdapter.benchmarkEval(dataset, iterationsPerPoint));
            } catch (Throwable t) {
                log.error("Casbin(Cached) complexity sensitivity FAILED: {}", t.getMessage());
            }

            try {
                cedarOptimizedAdapter.initialize(dataset);
                point.systemSnapshots.put("Cedar(Optimized)",
                    cedarOptimizedAdapter.benchmarkComplexity(dataset, iterationsPerPoint));
            } catch (Exception e) {
                log.warn("Cedar(Optimized) complexity sensitivity failed: {}", e.getMessage());
            }

            results.add(point);
        }
        return results;
    }

    private List<MultiSystemComparisonResult.CardScalePoint> runLayer1CardScaleSensitivity(
            int iterationsPerPoint) {
        ScaleConfig[] gradient = ScaleConfig.cardScaleGradient();
        List<MultiSystemComparisonResult.CardScalePoint> results = new ArrayList<>();

        for (ScaleConfig scale : gradient) {
            log.info("  Cards: {}", scale.getCardCount());
            cleanupBenchmarkData();
            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            MultiSystemComparisonResult.CardScalePoint point =
                new MultiSystemComparisonResult.CardScalePoint();
            point.cardCount = scale.getCardCount();

            point.systemSnapshots.put("AstralLight",
                benchmarkAstralComplexity(dataset, iterationsPerPoint));

            // Casbin(Cached) — no skip at 50K, g-inheritance keeps policy count at M+N
            try {
                casbinCachedAdapter.initialize(dataset);
                point.systemSnapshots.put("Casbin(Cached)",
                    casbinCachedAdapter.benchmarkEval(dataset, iterationsPerPoint));
            } catch (Throwable t) {
                log.error("Casbin(Cached) card scale sensitivity FAILED: {}", t.getMessage());
            }

            try {
                cedarOptimizedAdapter.initialize(dataset);
                point.systemSnapshots.put("Cedar(Optimized)",
                    cedarOptimizedAdapter.benchmarkComplexity(dataset, iterationsPerPoint));
            } catch (Exception e) {
                log.warn("Cedar(Optimized) card scale sensitivity failed: {}", e.getMessage());
            }

            results.add(point);
        }
        return results;
    }

    // ═══════════════════════════════════════════════════════════════
    // Individual System Benchmarks
    // ═══════════════════════════════════════════════════════════════

    private MultiSystemComparisonResult.SystemResult benchmarkAstralLight(
            String label, String optLevel,
            DataGenerator.GeneratedDataSet dataset,
            int iterations, int concurrency) {

        log.info("  {} single-thread: {} iterations", label, iterations);
        MultiSystemComparisonResult.SystemResult result =
            new MultiSystemComparisonResult.SystemResult();
        result.systemLabel = label;
        result.optimizationLevel = optLevel;

        long initStart = System.currentTimeMillis();

        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            policyEngine.evaluate(buildContext(req));
        }

        for (int i = 0; i < iterations; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            long start = recorder.start();
            policyEngine.evaluate(buildContext(req));
            recorder.stop(start);
        }
        result.singleThreadSnapshot = recorder.snapshot();

        log.info("  {} concurrent: {} threads", label, concurrency);
        result.concurrentSnapshot = benchmarkAstralConcurrent(dataset, iterations, concurrency);

        dataGenerator.flushAllCaches();
        log.info("  {} cold-start", label);
        result.coldStartSnapshot = benchmarkAstralConcurrent(dataset, iterations, concurrency);

        result.initTimeMs = System.currentTimeMillis() - initStart;
        logResult(label, result.singleThreadSnapshot, result.concurrentSnapshot);
        return result;
    }

    private MultiSystemComparisonResult.SystemResult benchmarkCasbin(
            String label, String optLevel,
            DataGenerator.GeneratedDataSet dataset,
            int iterations, int concurrency) {

        MultiSystemComparisonResult.SystemResult result =
            new MultiSystemComparisonResult.SystemResult();
        result.systemLabel = label;
        result.optimizationLevel = optLevel;

        long initStart = System.currentTimeMillis();
        try {
            result.singleThreadSnapshot = casbinAdapter.benchmarkEval(dataset, iterations);
            result.concurrentSnapshot = benchmarkCasbinConcurrent(dataset, iterations, concurrency);
        } catch (Exception e) {
            log.warn("{} benchmark failed: {}", label, e.getMessage());
            result.singleThreadSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
            result.concurrentSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        }
        result.initTimeMs = System.currentTimeMillis() - initStart;
        logResult(label, result.singleThreadSnapshot, result.concurrentSnapshot);
        return result;
    }

    private MultiSystemComparisonResult.SystemResult benchmarkCasbinCached(
            String label, String optLevel,
            DataGenerator.GeneratedDataSet dataset,
            int iterations, int concurrency) {

        MultiSystemComparisonResult.SystemResult result =
            new MultiSystemComparisonResult.SystemResult();
        result.systemLabel = label;
        result.optimizationLevel = optLevel;

        try {
            result.singleThreadSnapshot = casbinCachedAdapter.benchmarkEval(dataset, iterations);
            result.concurrentSnapshot = benchmarkCasbinCachedConcurrent(dataset, iterations, concurrency);
        } catch (Exception e) {
            log.warn("{} benchmark failed: {}", label, e.getMessage());
            result.singleThreadSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
            result.concurrentSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        }
        logResult(label, result.singleThreadSnapshot, result.concurrentSnapshot);
        return result;
    }

    private MultiSystemComparisonResult.SystemResult benchmarkOpa(
            String label, String optLevel,
            DataGenerator.GeneratedDataSet dataset,
            int iterations, int concurrency) {

        MultiSystemComparisonResult.SystemResult result =
            new MultiSystemComparisonResult.SystemResult();
        result.systemLabel = label;
        result.optimizationLevel = optLevel;

        try {
            opaAdapter.initialize(dataset);
            result.singleThreadSnapshot = opaAdapter.benchmarkEval(dataset, iterations);
            result.concurrentSnapshot = benchmarkOpaConcurrent(dataset, iterations, concurrency);
        } catch (Exception e) {
            log.warn("{} benchmark failed: {}", label, e.getMessage());
            result.singleThreadSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
            result.concurrentSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        }
        logResult(label, result.singleThreadSnapshot, result.concurrentSnapshot);
        return result;
    }

    private MultiSystemComparisonResult.SystemResult benchmarkOpaNoCache(
            String label, String optLevel,
            DataGenerator.GeneratedDataSet dataset,
            int iterations, int concurrency) {

        MultiSystemComparisonResult.SystemResult result =
            new MultiSystemComparisonResult.SystemResult();
        result.systemLabel = label;
        result.optimizationLevel = optLevel;

        try {
            opaNoCacheAdapter.initialize(dataset);
            result.singleThreadSnapshot = opaNoCacheAdapter.benchmarkEval(dataset, iterations);
            result.concurrentSnapshot = benchmarkOpaCachedConcurrent(dataset, iterations, concurrency);
        } catch (Exception e) {
            log.warn("{} benchmark failed: {}", label, e.getMessage());
            result.singleThreadSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
            result.concurrentSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        }
        logResult(label, result.singleThreadSnapshot, result.concurrentSnapshot);
        return result;
    }

    private MultiSystemComparisonResult.SystemResult benchmarkCedar(
            String label, String optLevel,
            DataGenerator.GeneratedDataSet dataset,
            int iterations, int concurrency,
            CedarAdapter adapter) {

        MultiSystemComparisonResult.SystemResult result =
            new MultiSystemComparisonResult.SystemResult();
        result.systemLabel = label;
        result.optimizationLevel = optLevel;

        long initStart = System.currentTimeMillis();
        try {
            adapter.initialize(dataset);
            result.singleThreadSnapshot = adapter.benchmarkEval(dataset, iterations);
            result.concurrentSnapshot = benchmarkCedarConcurrent(adapter, dataset, iterations, concurrency);
        } catch (Exception e) {
            log.warn("{} benchmark failed: {}", label, e.getMessage());
            result.singleThreadSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
            result.concurrentSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        }
        result.initTimeMs = System.currentTimeMillis() - initStart;
        logResult(label, result.singleThreadSnapshot, result.concurrentSnapshot);
        return result;
    }

    // ═══════════════════════════════════════════════════════════════
    // Concurrent Benchmarks
    // ═══════════════════════════════════════════════════════════════

    /**
     * Pre-assign cycled request indices per thread for uniform round-robin,
     * avoiding non-uniform distribution from concurrent getAndIncrement.
     */
    private static List<Integer>[] distributeRequests(int concurrency, int totalIterations, int requestPoolSize) {
        @SuppressWarnings("unchecked")
        List<Integer>[] assignments = new List[concurrency];
        for (int t = 0; t < concurrency; t++) {
            assignments[t] = new ArrayList<>();
        }
        int perThread = totalIterations / concurrency;
        int remainder = totalIterations % concurrency;
        int globalIdx = 0;
        for (int t = 0; t < concurrency; t++) {
            int count = perThread + (t < remainder ? 1 : 0);
            for (int i = 0; i < count; i++) {
                assignments[t].add(globalIdx++ % requestPoolSize);
            }
        }
        return assignments;
    }

    private LatencyRecorder.LatencySnapshot benchmarkAstralConcurrent(
            DataGenerator.GeneratedDataSet dataset, int iterations, int concurrency) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        List<Integer>[] assignments = distributeRequests(concurrency, iterations, requests.size());
        CountDownLatch readyLatch = new CountDownLatch(concurrency);
        CountDownLatch startLatch = new CountDownLatch(1);

        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < concurrency; t++) {
            final List<Integer> indices = assignments[t];
            futures.add(executor.submit(() -> {
                readyLatch.countDown();
                try { startLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return null; } // all threads start simultaneously
                for (int idx : indices) {
                    DataGenerator.EvalRequest req = requests.get(idx);
                    setupCardContext(req.cardId);
                    long start = recorder.start();
                    try {
                        policyEngine.evaluate(buildContext(req));
                        recorder.stop(start);
                    } catch (Exception e) {
                        recorder.recordError(System.nanoTime() - start);
                    }
                }
                return null;
            }));
        }
        try { readyLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
        recorder.wallClockStart(); // wall clock starts when all threads are ready
        startLatch.countDown();
        awaitAll(futures);
        shutdownExecutor(executor);
        return recorder.snapshot();
    }

    private LatencyRecorder.LatencySnapshot benchmarkCasbinConcurrent(
            DataGenerator.GeneratedDataSet dataset, int iterations, int concurrency) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        List<Integer>[] assignments = distributeRequests(concurrency, iterations, requests.size());
        CountDownLatch readyLatch = new CountDownLatch(concurrency);
        CountDownLatch startLatch = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < concurrency; t++) {
            final List<Integer> indices = assignments[t];
            futures.add(executor.submit(() -> {
                readyLatch.countDown();
                try { startLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return null; }
                for (int idx : indices) {
                    DataGenerator.EvalRequest req = requests.get(idx);
                    long start = recorder.start();
                    try {
                        casbinAdapter.enforce(req.cardId, req.resourceType, req.actionCode);
                        recorder.stop(start);
                    } catch (Exception e) {
                        recorder.recordError(System.nanoTime() - start);
                    }
                }
                return null;
            }));
        }
        try { readyLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
        recorder.wallClockStart();
        startLatch.countDown();
        awaitAll(futures);
        shutdownExecutor(executor);
        return recorder.snapshot();
    }

    private LatencyRecorder.LatencySnapshot benchmarkCasbinCachedConcurrent(
            DataGenerator.GeneratedDataSet dataset, int iterations, int concurrency) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        List<Integer>[] assignments = distributeRequests(concurrency, iterations, requests.size());
        CountDownLatch readyLatch = new CountDownLatch(concurrency);
        CountDownLatch startLatch = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < concurrency; t++) {
            final List<Integer> indices = assignments[t];
            futures.add(executor.submit(() -> {
                readyLatch.countDown();
                try { startLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return null; }
                for (int idx : indices) {
                    DataGenerator.EvalRequest req = requests.get(idx);
                    long start = recorder.start();
                    try {
                        casbinCachedAdapter.enforce(req.cardId, req.resourceType, req.actionCode);
                        recorder.stop(start);
                    } catch (Exception e) {
                        recorder.recordError(System.nanoTime() - start);
                    }
                }
                return null;
            }));
        }
        try { readyLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
        recorder.wallClockStart();
        startLatch.countDown();
        awaitAll(futures);
        shutdownExecutor(executor);
        return recorder.snapshot();
    }

    private LatencyRecorder.LatencySnapshot benchmarkOpaConcurrent(
            DataGenerator.GeneratedDataSet dataset, int iterations, int concurrency) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        List<Integer>[] assignments = distributeRequests(concurrency, iterations, requests.size());
        CountDownLatch readyLatch = new CountDownLatch(concurrency);
        CountDownLatch startLatch = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < concurrency; t++) {
            final List<Integer> indices = assignments[t];
            futures.add(executor.submit(() -> {
                readyLatch.countDown();
                try { startLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return null; }
                for (int idx : indices) {
                    DataGenerator.EvalRequest req = requests.get(idx);
                    long start = recorder.start();
                    try {
                        opaAdapter.enforce(req.cardId, req.resourceType, req.actionCode);
                        recorder.stop(start);
                    } catch (Exception e) {
                        recorder.recordError(System.nanoTime() - start);
                    }
                }
                return null;
            }));
        }
        try { readyLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
        recorder.wallClockStart();
        startLatch.countDown();
        awaitAll(futures);
        shutdownExecutor(executor);
        return recorder.snapshot();
    }

    private LatencyRecorder.LatencySnapshot benchmarkOpaCachedConcurrent(
            DataGenerator.GeneratedDataSet dataset, int iterations, int concurrency) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        List<Integer>[] assignments = distributeRequests(concurrency, iterations, requests.size());
        CountDownLatch readyLatch = new CountDownLatch(concurrency);
        CountDownLatch startLatch = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < concurrency; t++) {
            final List<Integer> indices = assignments[t];
            futures.add(executor.submit(() -> {
                readyLatch.countDown();
                try { startLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return null; }
                for (int idx : indices) {
                    DataGenerator.EvalRequest req = requests.get(idx);
                    long start = recorder.start();
                    try {
                        opaNoCacheAdapter.enforce(req.cardId, req.resourceType, req.actionCode);
                        recorder.stop(start);
                    } catch (Exception e) {
                        recorder.recordError(System.nanoTime() - start);
                    }
                }
                return null;
            }));
        }
        try { readyLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
        recorder.wallClockStart();
        startLatch.countDown();
        awaitAll(futures);
        shutdownExecutor(executor);
        return recorder.snapshot();
    }

    private LatencyRecorder.LatencySnapshot benchmarkCedarConcurrent(
            CedarAdapter adapter, DataGenerator.GeneratedDataSet dataset,
            int iterations, int concurrency) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        List<Integer>[] assignments = distributeRequests(concurrency, iterations, requests.size());
        CountDownLatch readyLatch = new CountDownLatch(concurrency);
        CountDownLatch startLatch = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < concurrency; t++) {
            final List<Integer> indices = assignments[t];
            futures.add(executor.submit(() -> {
                readyLatch.countDown();
                try { startLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return null; }
                for (int idx : indices) {
                    DataGenerator.EvalRequest req = requests.get(idx);
                    long start = recorder.start();
                    try {
                        adapter.isAuthorized(req.cardId, req.resourceType, req.actionCode);
                        recorder.stop(start);
                    } catch (Exception e) {
                        recorder.recordError(System.nanoTime() - start);
                    }
                }
                return null;
            }));
        }
        try { readyLatch.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new RuntimeException(e); }
        recorder.wallClockStart();
        startLatch.countDown();
        awaitAll(futures);
        shutdownExecutor(executor);
        return recorder.snapshot();
    }

    // ═══════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════

    private LatencyRecorder.LatencySnapshot benchmarkAstralComplexity(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            policyEngine.evaluate(buildContext(req));
        }

        for (int i = 0; i < iterations; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            long start = recorder.start();
            policyEngine.evaluate(buildContext(req));
            recorder.stop(start);
        }
        return recorder.snapshot();
    }

    private void setupCardContext(Long cardId) {
        IdentityCardContext ctx = new IdentityCardContext();
        ctx.setCardId(cardId);
        ctx.setUserId(1L);
        ctx.setTenantId(BENCHMARK_TENANT_ID);
        ctx.setDomainId(1L);
        ctx.setTemplateId(1L);
        ctx.setCardType("PLATFORM_CARD");
        ctx.setStatus("ACTIVE");
        CardContextHolder.set(ctx);
    }

    private PolicyContext buildContext(DataGenerator.EvalRequest req) {
        return PolicyContext.builder()
            .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
            .domainId(1L).templateId(1L)
            .resource(req.resourceType).action(req.actionCode)
            .targetId(req.resourceId).build();
    }

    private void cleanupBenchmarkData() {
        BenchmarkCleanupUtil.cleanupAllStrict(jdbcTemplate, redisTemplate);
    }

    private void runCorrectnessGate(ScaleConfig gateScale, String caseLabel) {
        // The gate only tests the common expressible subset. A scale that
        // strays outside it (overlay rules, multi-domain, wrong deny ratio)
        // would produce incomparable numbers and is rejected here.
        double expectedDenyRatio = caseLabel.contains("DENY_ONLY") ? 1.0
            : caseLabel.contains("DEFAULT_DENY") ? 0.0 : 0.0;
        com.coreryblack.benchmark.baseline.BaselineCapabilityMatrix.requireCommonSubset(
            gateScale, expectedDenyRatio);

        log.info("CORRECTNESS GATE: {}", caseLabel);
        cleanupBenchmarkData();
        DataGenerator.GeneratedDataSet gateDataset = dataGenerator.generate(gateScale);
        dataGenerator.persistToDatabase(gateDataset);
        dataGenerator.populateRedisCache(gateDataset);

        CrossSystemCorrectnessVerifier.VerificationReport correctnessReport =
            correctnessVerifier.verify(gateDataset, 1000);

        if (!correctnessReport.allPassed) {
            log.error("CORRECTNESS GATE FAILED [{}]: {}", caseLabel, correctnessReport.verdict);
            log.error(correctnessReport.toSummary());
            throw new IllegalStateException(
                "Benchmark aborted: cross-system correctness verification BLOCKED.\n" +
                "[" + caseLabel + "] " + correctnessReport.toSummary());
        } else {
            log.info("CORRECTNESS GATE PASSED [{}]: All {} systems agree on {} samples.",
                caseLabel, correctnessReport.systemLabelsChecked.size(),
                correctnessReport.totalSamplesChecked);
        }

        cleanupBenchmarkData();
    }

    /**
     * Run semantic divergence analysis that does NOT block the benchmark.
     *
     * <p>This is separate from the Correctness Gate because divergences
     * are caused by fundamental semantic differences in authorization models,
     * not adapter bugs or implementation errors.</p>
     *
     * <p>Divergences are expected because AstralLight adopts priority-based
     * conflict resolution whereas Casbin, OPA and Cedar employ deny-override
     * semantics. The results are retained for documentation but do not affect
     * the benchmark verdict.</p>
     */
    private void runSemanticDivergenceAnalysis(ScaleConfig scale, String scenarioLabel) {
        cleanupBenchmarkData();
        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
        dataGenerator.persistToDatabase(dataset);
        dataGenerator.populateRedisCache(dataset);

        CrossSystemCorrectnessVerifier.VerificationReport report =
            correctnessVerifier.verify(dataset, 1000);

        if (report.allPassed) {
            log.info("SEMANTIC DIVERGENCE [{}]: All systems agree (unexpected).", scenarioLabel);
            log.info("\t--- All {} systems agree on {} samples", report.systemLabelsChecked.size(), report.totalSamplesChecked);
        } else {
            log.info("SEMANTIC DIVERGENCE [{}]: {} mismatches (does not affect benchmark)", scenarioLabel, report.discrepancies.size());
            log.info(report.toSummary());
            log.info("\t--- Expected: AstralLight adopts priority-based conflict resolution; "
                + "Casbin/OPA/Cedar employ deny-override semantics. ---");
            log.info("\t--- This is a fundamental language semantics difference, "
                + "not an adapter bug or implementation error. ---");
        }

        cleanupBenchmarkData();
    }

    private MultiSystemComparisonResult.SystemResult skippedResult(String label, String optLevel) {
        MultiSystemComparisonResult.SystemResult result =
            new MultiSystemComparisonResult.SystemResult();
        result.systemLabel = label;
        result.optimizationLevel = optLevel;
        result.singleThreadSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        result.concurrentSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        result.coldStartSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        return result;
    }

    /** Create an error result when a system crashes (OOM, timeout, etc.) at a given scale point. */
    private MultiSystemComparisonResult.SystemResult errorResult(String label, String optLevel, Throwable cause) {
        MultiSystemComparisonResult.SystemResult result =
            new MultiSystemComparisonResult.SystemResult();
        result.systemLabel = label + "(ERROR)";
        result.optimizationLevel = optLevel;
        result.singleThreadSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        result.concurrentSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        result.coldStartSnapshot = LatencyRecorder.LatencySnapshot.empty(TimeUnit.NANOSECONDS);
        result.errorMessage = cause.getClass().getSimpleName() + ": " + cause.getMessage();
        return result;
    }

    private void awaitAll(List<Future<?>> futures) {
        for (Future<?> f : futures) {
            try { f.get(30, TimeUnit.SECONDS); }
            catch (Exception e) {
                log.warn("Benchmark thread encountered issue (degraded): {}", e.getMessage());
            }
        }
    }

    private void shutdownExecutor(ExecutorService executor) {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private void logResult(String label,
                           LatencyRecorder.LatencySnapshot singleThreadSnapshot,
                           LatencyRecorder.LatencySnapshot concurrentSnapshot) {
        logSnapshot(label + " [single-thread]", singleThreadSnapshot);
        logSnapshot(label + " [concurrent]", concurrentSnapshot);
    }

    private void logSnapshot(String label, LatencyRecorder.LatencySnapshot snapshot) {
        if (snapshot == null || snapshot.sampleCount() == 0) {
            log.info("  {} — SKIPPED", label);
            return;
        }

        log.info("  {}: mean={}us, p95={}us, p99={}us, tps={}",
            label,
            String.format("%.1f", snapshot.meanUs()),
            String.format("%.1f", snapshot.p95Us()),
            String.format("%.1f", snapshot.p99Us()),
            String.format("%.0f", snapshot.tps()));
    }

    private void sleepMs(long ms) {
        try { Thread.sleep(ms); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
