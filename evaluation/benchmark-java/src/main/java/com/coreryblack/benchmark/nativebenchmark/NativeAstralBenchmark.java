package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.permission.auth.SodService;
import com.coreryblack.permission.auth.SnapshotConsistencyChecker;
import com.coreryblack.astral_permission.infrastructure.persistence.mapper.RuleSetEntryMapper;
import com.coreryblack.astral_permission.infrastructure.persistence.mapper.RuleSetSnapshotMapper;
import com.coreryblack.astral_platform.persistence.mapper.PlatformDomainMapper;
import com.coreryblack.permission.permission.RuleSetService;
import com.coreryblack.benchmark.config.SandboxConfig;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.ClusterRunContext;
import com.coreryblack.benchmark.util.DecisionOutcomeRecorder;
import com.coreryblack.benchmark.util.HardwareMonitor;
import com.coreryblack.benchmark.util.ReportGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import com.coreryblack.astral_general.AstralGeneralRuntimeConfiguration;
import com.coreryblack.astral_audit.runtime.AstralAuditRuntimeConfiguration;
import com.coreryblack.astral_identity.persistence.AstralIdentityPersistenceConfiguration;
import com.coreryblack.astral_platform.persistence.AstralPlatformPersistenceConfiguration;
import com.coreryblack.astral_messaging_runtime.AstralMessagingRuntimeConfiguration;
import com.coreryblack.astral_permission_runtime.AstralPermissionRuntimeConfiguration;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@SpringBootApplication(scanBasePackages = {
    "com.coreryblack.benchmark.nativebenchmark",
    "com.coreryblack.benchmark.util",
    "com.coreryblack.benchmark.config"
})
@ConditionalOnProperty(name = "benchmark.type", havingValue = "native")
@org.springframework.context.annotation.Import({AstralGeneralRuntimeConfiguration.class, AstralAuditRuntimeConfiguration.class, AstralIdentityPersistenceConfiguration.class, AstralPlatformPersistenceConfiguration.class, AstralMessagingRuntimeConfiguration.class, AstralPermissionRuntimeConfiguration.class})
public class NativeAstralBenchmark implements CommandLineRunner {

    private final PolicyEngine policyEngine;
    private final RuleSetService ruleSetService;
    private final SodService sodService;
    private final RuleSetEntryMapper entryMapper;
    private final RuleSetSnapshotMapper snapshotMapper;
    private final SnapshotConsistencyChecker consistencyChecker;
    private final StringRedisTemplate redisTemplate;
    private final NativeDataGenerator nativeDataGenerator;
    private final JdbcTemplate jdbcTemplate;
    private final ConfigurableApplicationContext applicationContext;

    private SandboxConfig sandboxConfig;
    /** Hardware usage summaries collected per RQ phase */
    private final List<HardwareMonitor.HardwareSummary> hardwareSummaries = new ArrayList<>();
    /** Cluster context when launched with -Dbenchmark.cluster.*; single-node otherwise. */
    private ClusterRunContext clusterContext = ClusterRunContext.singleNode();

    public NativeAstralBenchmark(PolicyEngine policyEngine,
                                  RuleSetService ruleSetService,
                                  SodService sodService,
                                  RuleSetEntryMapper entryMapper,
                                  RuleSetSnapshotMapper snapshotMapper,
                                  SnapshotConsistencyChecker consistencyChecker,
                                  StringRedisTemplate redisTemplate,
                                  NativeDataGenerator nativeDataGenerator,
                                  JdbcTemplate jdbcTemplate,
                                  ConfigurableApplicationContext applicationContext) {
        this.policyEngine = policyEngine;
        this.ruleSetService = ruleSetService;
        this.sodService = sodService;
        this.entryMapper = entryMapper;
        this.snapshotMapper = snapshotMapper;
        this.consistencyChecker = consistencyChecker;
        this.redisTemplate = redisTemplate;
        this.nativeDataGenerator = nativeDataGenerator;
        this.jdbcTemplate = jdbcTemplate;
        this.applicationContext = applicationContext;
    }

    public static void main(String[] args) {
        System.setProperty("spring.main.banner-mode", "off");
        SpringApplication.run(NativeAstralBenchmark.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        ClusterRunContext parsed;
        try {
            parsed = ClusterRunContext.fromSystemProperties();
        } catch (IllegalStateException e) {
            if (!ClusterRunContext.clusterPropertiesPresent()) {
                throw e;
            }
            Path outputDir = resolveOutputDirectory("cluster-invalid");
            writeClusterAborted(outputDir, null, "CONTEXT_VALIDATION", e.getMessage());
            throw e;
        }
        this.clusterContext = parsed;

        if (parsed.isClusterRun() && !Boolean.getBoolean("benchmark.native.auto-run")) {
            // Cluster runs are driven by the orchestrator and must opt in to
            // destructive cleanup exactly like single-node runs.
            Path outputDir = resolveOutputDirectory("cluster-" + parsed.runId()
                    + "-" + parsed.nodeId());
            writeClusterAborted(outputDir, parsed, parsed.phase(),
                    "CLUSTER_REQUIRES_BENCHMARK_NATIVE_AUTO_RUN");
            throw new IllegalStateException("CLUSTER_REQUIRES_BENCHMARK_NATIVE_AUTO_RUN");
        }

        if (!Boolean.getBoolean("benchmark.native.auto-run")) {
            log.info("Native benchmark suite is disabled. Set -Dbenchmark.native.auto-run=true and "
                    + "-Dbenchmark.allow-destructive-cleanup=true only for dedicated MySQL and Redis.");
            return;
        }
        if (!Boolean.getBoolean("benchmark.allow-destructive-cleanup")) {
            throw new IllegalStateException("Native benchmark requires -Dbenchmark.allow-destructive-cleanup=true "
                    + "because it clears the configured Redis database and benchmark tables.");
        }

        String outputPrefix = parsed.isClusterRun()
                ? "cluster-" + parsed.runId() + "-" + parsed.nodeId()
                : "native";
        Path outputPath = resolveOutputDirectory(outputPrefix);
        String outputDir = outputPath.toString();
        Files.createDirectories(outputPath);

        if (parsed.isClusterRun()) {
            writeClusterNodeMetadata(outputPath, parsed);
        }

        sandboxConfig = SandboxConfig.builder().build();
        nativeDataGenerator.setSeed(42L);
        // Freeze generated timestamps for reproducibility; run metadata still
        // records the actual execution time separately.
        String benchmarkClock = System.getProperty("benchmark.fixed-clock", "2026-01-01T00:00:00Z");
        nativeDataGenerator.setClock(Clock.fixed(Instant.parse(benchmarkClock), ZoneOffset.UTC));

        log.info("=== AstralLight Native Benchmark Suite (No External Baselines) ===");
        if (parsed.isClusterRun()) {
            log.info("Cluster run: node={} role={} permutation={} hardware={} phase={} runId={}",
                    parsed.nodeId(), parsed.nodeRole(), parsed.rolePermutation(),
                    parsed.hardwareLabel(), parsed.phase(), parsed.runId());
        }
        log.info("Sandbox: {}", sandboxConfig.toLatexTable());

        // Start suite-level hardware monitoring
        HardwareMonitor suiteMonitor = new HardwareMonitor(5, Path.of(outputDir));
        suiteMonitor.start("full_suite");

        boolean runRq1 = true;
        boolean runRq2 = true;
        boolean runRq3 = true;
        boolean runRq4 = true;
        boolean runRq5 = true;
        boolean runDecisionPerformance = true;
        // Controls which RQ2 sub-benchmarks to run; null means all
        String startFromRq2Sub = null;
        // Controls which RQ4 sub-benchmark to start from; null means all
        String startFromRq4Sub = null;

        for (String arg : args) {
            switch (arg.toLowerCase()) {
                case "--skip-rq1" -> runRq1 = false;
                case "--skip-rq2" -> runRq2 = false;
                case "--skip-rq3" -> runRq3 = false;
                case "--skip-rq4" -> runRq4 = false;
                case "--skip-rq5" -> runRq5 = false;
                case "--skip-decision-performance" -> runDecisionPerformance = false;
                case "--only-rq1" -> { runRq2 = false; runRq3 = false; runRq4 = false; runRq5 = false; }
                case "--only-rq2" -> { runRq1 = false; runRq3 = false; runRq4 = false; runRq5 = false; }
                case "--only-rq3" -> { runRq1 = false; runRq2 = false; runRq4 = false; runRq5 = false; }
                case "--only-rq4" -> { runRq1 = false; runRq2 = false; runRq3 = false; runRq5 = false; }
                case "--only-rq5" -> { runRq1 = false; runRq2 = false; runRq3 = false; runRq4 = false; }
                default -> {
                    if (arg.toLowerCase().startsWith("--start-from=")) {
                        startFromRq2Sub = arg.substring("--start-from=".length()).toUpperCase();
                        log.info("Will skip RQ2 sub-benchmarks before: {}", startFromRq2Sub);
                    } else if (arg.toLowerCase().startsWith("--start-from-rq4=")) {
                        startFromRq4Sub = arg.substring("--start-from-rq4=".length()).toUpperCase();
                        log.info("Will skip RQ4 sub-benchmarks before: {}", startFromRq4Sub);
                    }
                }
            }
        }

        writeRunManifest(Path.of(outputDir), args, runRq1, runRq2, runRq3, runRq4, runRq5,
                startFromRq2Sub, startFromRq4Sub);
        cleanupData();

        if (runRq1) {
            runRq1(outputDir);
        }

        if (runRq2) {
            runRq2SubBenchmarks(outputDir, startFromRq2Sub);
        }

        if (runRq3) {
            log.info("=== Forcing GC before RQ3 to free RQ2-K residual memory ===");
            System.gc();
            Thread.sleep(3000);
            System.gc();
            runRq3(outputDir);
        }

        if (runRq4) {
            runRq4(outputDir, startFromRq4Sub);
        }

        // ── RQ5: Direct-PDP, local-cache, and throughput experiments ──
        if (runRq5) {
            log.info("=== Forcing GC before RQ5 ===");
            System.gc();
            Thread.sleep(2000);
            System.gc();
            runRq5(outputDir);
        }

        // DecisionPerformanceBenchmark (with Casbin/OPA baselines) runs LAST
        if (runRq2 && runDecisionPerformance) {
            log.info("=== Forcing GC before DecisionPerformance ===");
            System.gc();
            Thread.sleep(2000);
            System.gc();
            runRq2DecisionPerformance(outputDir);
        }

        // Stop suite-level monitoring and write hardware reports
        HardwareMonitor.HardwareSummary suiteSummary = suiteMonitor.stop();
        hardwareSummaries.add(suiteSummary);
        writeHardwareReports(outputDir);
        Files.writeString(Path.of(outputDir, "COMPLETED"), "completed\n", StandardCharsets.UTF_8);

        log.info("=== Native benchmark suite complete. Results in: {} ===", outputDir);
        // This is a command-line benchmark, not a long-lived service. Close
        // the Spring context so Hikari/Lettuce/Rabbit resources do not keep
        // the JVM alive after the artifact has been finalized.
        int exitCode = SpringApplication.exit(applicationContext);
        applicationContext.close();
        log.debug("Native benchmark application context closed with exit code {}", exitCode);
    }

    private void runRq1(String outputDir) throws Exception {
        log.info("=== RQ1: Native Space Efficiency Benchmark ===");
        cleanupData();

        HardwareMonitor rq1Monitor = new HardwareMonitor(2, Path.of(outputDir));
        rq1Monitor.start("RQ1");

        NativeSpaceEfficiencyBenchmark rq1 = new NativeSpaceEfficiencyBenchmark(
            nativeDataGenerator, redisTemplate);
        NativeSpaceEfficiencyBenchmark.NativeSpaceEfficiencyResult rq1Result = rq1.execute();
        log.info(rq1.toLatexTable(rq1Result));

        hardwareSummaries.add(rq1Monitor.stop());

        ReportGenerator rq1Report = new ReportGenerator(outputDir);
        rq1Report.addResult("AstralLight|storage", rq1Result.astralSnapshot);
        rq1Report.writeCsvReport("rq1_native_space_efficiency.csv");
        rq1Report.writeSummaryReport("rq1_native_summary.csv");
        rq1Report.writeRawSamples("rq1_native_raw");
        // RQ1 does not evaluate decisions, so this breakdown is expected to be empty (count=0).
        writeBreakdownCsv(outputDir, "rq1");
        policyEngine.resetBreakdownStats();

        cleanupData();
    }

    private void runRq2DecisionPerformance(String outputDir) throws Exception {
        log.info("=== RQ2: Native Decision Performance Benchmark (Full 6-Step Pipeline + Baselines) [LAST] ===");
        cleanupData();

        HardwareMonitor rq2Monitor = new HardwareMonitor(2, Path.of(outputDir));
        rq2Monitor.start("RQ2-decision");

        NativeDecisionPerformanceBenchmark rq2 = new NativeDecisionPerformanceBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        NativeDecisionPerformanceBenchmark.NativeDecisionPerformanceResult rq2Result =
            rq2.execute(NativeScaleConfig.nativeGradientScale(), 10000, 8);

        hardwareSummaries.add(rq2Monitor.stop());

        ReportGenerator rq2Report = new ReportGenerator(outputDir);
        for (var sr : rq2Result.scaleResults) {
            rq2Report.addResult("AstralLight|ST|" + sr.scale.label(), sr.singleThreadSnapshot);
            rq2Report.addResult("AstralLight|MT|" + sr.scale.label(), sr.concurrentSnapshot);
            rq2Report.addResult("AstralLight|cold|" + sr.scale.label(), sr.coldStartSnapshot);
        }
        rq2Report.writeLatexRq2Table("rq2_native_latency_table.tex");
        rq2Report.writeLatexRq2TableWithCI("rq2_native_latency_table_ci.tex");
        rq2Report.writeCsvReport("rq2_native_latency_data.csv");
        rq2Report.writeSummaryReport("rq2_native_summary.csv");
        rq2Report.writeStatisticalReport("rq2_native_statistical_tests.csv");
        rq2Report.writeRawSamples("rq2_native_raw");
        writeBreakdownCsv(outputDir, "rq2-decision");
        policyEngine.resetBreakdownStats();

        cleanupData();
    }

    private void runRq2SubBenchmarks(String outputDir, String startFrom) throws Exception {
        // Ordered sub-benchmark list; skip all before startFrom
        record SubBenchmark(String id, Runnable action) {}
        List<SubBenchmark> subs = List.of(
            new SubBenchmark("A", () -> wrapRun(() -> runRq2A(outputDir))),
            new SubBenchmark("B", () -> wrapRun(() -> runRq2B(outputDir))),
            new SubBenchmark("C", () -> wrapRun(() -> runRq2C(outputDir))),
            new SubBenchmark("D", () -> wrapRun(() -> runRq2D(outputDir))),
            new SubBenchmark("E", () -> wrapRun(() -> runRq2E(outputDir))),
            new SubBenchmark("F", () -> wrapRun(() -> runRq2F(outputDir))),
            new SubBenchmark("G", () -> wrapRun(() -> runRq2G(outputDir))),
            new SubBenchmark("H", () -> wrapRun(() -> runRq2H(outputDir))),
            new SubBenchmark("I", () -> wrapRun(() -> runRq2I(outputDir))),
            new SubBenchmark("J", () -> wrapRun(() -> runRq2J(outputDir))),
            new SubBenchmark("K", () -> wrapRun(() -> runRq2K(outputDir)))
        );

        // Start RQ2-sub overall monitor
        HardwareMonitor rq2SubMonitor = new HardwareMonitor(3, Path.of(outputDir));
        rq2SubMonitor.start("RQ2-sub");

        boolean found = (startFrom == null);
        for (SubBenchmark sub : subs) {
            if (!found) {
                if (sub.id().equals(startFrom)) {
                    found = true;
                    log.info(">>> Resuming from RQ2-{} <<<", sub.id());
                } else {
                    log.info("Skipping RQ2-{} (before start-from={})", sub.id(), startFrom);
                    continue;
                }
            }
            policyEngine.resetBreakdownStats();
            sub.action().run();
            writeBreakdownCsv(outputDir, "rq2-" + sub.id().toLowerCase());
            policyEngine.resetBreakdownStats();
        }

        hardwareSummaries.add(rq2SubMonitor.stop());
    }

    /** Helper to convert checked exceptions to unchecked in lambda */
    private void wrapRun(RunnableWithException r) {
        try { r.run(); } catch (Exception e) { throw new RuntimeException(e); }
    }

    @FunctionalInterface
    private interface RunnableWithException {
        void run() throws Exception;
    }

    private void runRq2A(String outputDir) throws Exception {
        log.info("=== RQ2-A: Native Rule Complexity Benchmark (with ABAC) ===");
        cleanupData();

        NativeRuleComplexityBenchmark rq2a = new NativeRuleComplexityBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        var rq2aResults = rq2a.execute(NativeScaleConfig.nativeRuleComplexityGradient(), 5000);

        ReportGenerator rq2aReport = new ReportGenerator(outputDir);
        for (var cr : rq2aResults) {
            rq2aReport.addResult("AstralLight|rules=" + cr.rulesPerCard, cr.latencySnapshot);
        }
        rq2aReport.writeCsvReport("rq2a_native_rule_complexity.csv");
        rq2aReport.writeSummaryReport("rq2a_native_summary.csv");
        rq2aReport.writeRawSamples("rq2a_native_raw");

        cleanupData();
    }

    private void runRq2B(String outputDir) throws Exception {
        log.info("=== RQ2-B: Native Card Scale Benchmark (Multi-Template) ===");
        cleanupData();

        NativeCardScaleBenchmark rq2b = new NativeCardScaleBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        var rq2bResults = rq2b.execute(NativeScaleConfig.nativeCardScaleGradient(), 5000);

        ReportGenerator rq2bReport = new ReportGenerator(outputDir);
        for (var csr : rq2bResults) {
            rq2bReport.addResult("AstralLight|cards=" + csr.cardCount, csr.latencySnapshot);
        }
        rq2bReport.writeCsvReport("rq2b_native_card_scale.csv");
        rq2bReport.writeSummaryReport("rq2b_native_summary.csv");
        rq2bReport.writeRawSamples("rq2b_native_raw");

        try (var pw = new java.io.PrintWriter(outputDir + "/rq2b_native_storage_tps.csv")) {
            pw.println("card_count,total_rules,storage_bytes,astral_tps");
            for (var csr : rq2bResults) {
                pw.printf("%d,%d,%d,%.0f%n",
                    csr.cardCount, csr.totalRules, csr.storageBytes, csr.astralTps);
            }
        }

        cleanupData();
    }

    private void runRq2C(String outputDir) throws Exception {
        log.info("=== RQ2-C: Native Overlay Depth Benchmark (with Simulated Evaluation) ===");
        cleanupData();

        NativeOverlayDepthBenchmark rq2c = new NativeOverlayDepthBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        var rq2cResults = rq2c.execute(NativeScaleConfig.nativeOverlayDepthGradient(), 5000);

        ReportGenerator rq2cReport = new ReportGenerator(outputDir);
        for (var or : rq2cResults) {
            rq2cReport.addResult("overlay=" + or.overlayRules + "|base=" + or.baseRules, or.latencySnapshot);
        }
        rq2cReport.writeCsvReport("rq2c_native_overlay_depth.csv");
        rq2cReport.writeSummaryReport("rq2c_native_overlay_summary.csv");
        rq2cReport.writeRawSamples("rq2c_native_overlay_raw");

        cleanupData();
    }

    private void runRq2D(String outputDir) throws Exception {
        log.info("=== RQ2-D: Native Conflict Density Benchmark ===");
        cleanupData();

        NativeConflictDensityBenchmark rq2d = new NativeConflictDensityBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        var rq2dResults = rq2d.execute(NativeScaleConfig.nativeConflictDensityGradient(), 5000);

        ReportGenerator rq2dReport = new ReportGenerator(outputDir);
        for (var cdr : rq2dResults) {
            rq2dReport.addResult("AstralLight|deny=" + (int) (cdr.denyRatio * 100) + "%", cdr.latencySnapshot);
        }
        rq2dReport.writeCsvReport("rq2d_native_conflict_density.csv");
        rq2dReport.writeSummaryReport("rq2d_native_conflict_summary.csv");
        rq2dReport.writeRawSamples("rq2d_native_conflict_raw");

        cleanupData();
    }

    private void runRq2E(String outputDir) throws Exception {
        log.info("=== RQ2-E: Native SOD Policy Benchmark ===");
        cleanupData();

        NativeSodPolicyBenchmark sodBench = new NativeSodPolicyBenchmark(
            policyEngine, sodService, nativeDataGenerator, redisTemplate, jdbcTemplate);
        var sodResult = sodBench.execute(NativeScaleConfig.nativeRq1Default(), 5000);

        try (var pw = new java.io.PrintWriter(outputDir + "/rq2e_native_sod_policy.csv")) {
            pw.println("metric,mean_us,p99_us,p50_us,count");
            pw.printf("static_sod,%.1f,%.1f,%.1f,%d%n",
                sodResult.staticSodSnapshot.meanUs(), sodResult.staticSodSnapshot.p99Us(),
                sodResult.staticSodSnapshot.p50Us(), sodResult.staticSodSnapshot.sampleCount());
            pw.printf("dynamic_sod,%.1f,%.1f,%.1f,%d%n",
                sodResult.dynamicSodSnapshot.meanUs(), sodResult.dynamicSodSnapshot.p99Us(),
                sodResult.dynamicSodSnapshot.p50Us(), sodResult.dynamicSodSnapshot.sampleCount());
            pw.printf("conflict_detect,%.1f,%.1f,%.1f,%d%n",
                sodResult.conflictDetectSnapshot.meanUs(), sodResult.conflictDetectSnapshot.p99Us(),
                sodResult.conflictDetectSnapshot.p50Us(), sodResult.conflictDetectSnapshot.sampleCount());
        }

        try (var pw = new java.io.PrintWriter(outputDir + "/rq2e_native_sod_correctness.csv")) {
            pw.println("policy_count,total_checks,static_violations,dynamic_violations");
            pw.printf("%d,%d,%d,%d%n",
                sodResult.policyCount,
                sodResult.correctnessStats.totalChecks,
                sodResult.correctnessStats.staticViolationCount,
                sodResult.correctnessStats.dynamicViolationCount);
        }

        cleanupData();
    }

    private void runRq2F(String outputDir) throws Exception {
        log.info("=== RQ2-F: Native Tenant Isolation Benchmark ===");
        cleanupData();

        NativeTenantIsolationBenchmark tenantBench = new NativeTenantIsolationBenchmark(
            policyEngine, ruleSetService, nativeDataGenerator, redisTemplate, jdbcTemplate);
        var tenantResult = tenantBench.execute(NativeScaleConfig.nativeRq1Default(), 5000);

        try (var pw = new java.io.PrintWriter(outputDir + "/rq2f_native_tenant_isolation.csv")) {
            pw.println("metric,value");
            pw.printf("cross_tenant_binding_rejected,%d/%d%n",
                tenantResult.crossTenantBindingResult.rejectedCount,
                tenantResult.crossTenantBindingResult.attemptCount);
            pw.printf("redis_tenant_a_keys,%d%n", tenantResult.redisScopingResult.tenantAKeyCount);
            pw.printf("redis_tenant_b_keys,%d%n", tenantResult.redisScopingResult.tenantBKeyCount);
            pw.printf("redis_cross_leak,%d%n", tenantResult.redisScopingResult.crossLeakCount);
            pw.printf("same_tenant_allow,%d%n", tenantResult.crossTenantEvalResult.sameTenantAllowCount);
            pw.printf("cross_tenant_deny,%d%n", tenantResult.crossTenantEvalResult.crossTenantDenyCount);
            pw.printf("isolation_gap,%d%n", tenantResult.crossTenantEvalResult.isolationGapCount);
            pw.printf("multi_tenant_mean_us,%.1f%n", tenantResult.multiTenantSnapshot.meanUs());
            pw.printf("multi_tenant_p99_us,%.1f%n", tenantResult.multiTenantSnapshot.p99Us());
        }

        cleanupData();
    }

    private void runRq2G(String outputDir) throws Exception {
        log.info("=== RQ2-G: Native Template Isolation Benchmark (O(1) w.r.t. T) ===");
        cleanupData();

        NativeTemplateIsolationBenchmark rq2g = new NativeTemplateIsolationBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        var rq2gResults = rq2g.execute(NativeScaleConfig.nativeTemplateIsolationGradient(), 5000);

        ReportGenerator rq2gReport = new ReportGenerator(outputDir);
        for (var r : rq2gResults) {
            rq2gReport.addResult("AstralLight|templates=" + r.templateCount, r.latencySnapshot);
        }
        rq2gReport.writeCsvReport("rq2g_native_template_isolation.csv");
        rq2gReport.writeSummaryReport("rq2g_native_summary.csv");
        rq2gReport.writeRawSamples("rq2g_native_raw");

        try (var pw = new java.io.PrintWriter(outputDir + "/rq2g_native_template_o1.csv")) {
            pw.println("template_count,card_count,base_rules,mean_us,p99_us,p50_us,l1_hit_rate,l2_hit_rate,l3_hit_rate");
            for (var r : rq2gResults) {
                pw.printf("%d,%d,%d,%.1f,%.1f,%.1f,%.3f,%.3f,%.3f%n",
                    r.templateCount, r.cardCount, r.baseRulesPerCard,
                    r.latencySnapshot.meanUs(), r.latencySnapshot.p99Us(), r.latencySnapshot.p50Us(),
                    r.l1HitRate, r.l2HitRate, r.l3HitRate);
            }
        }

        cleanupData();
    }

    private void runRq2H(String outputDir) throws Exception {
        log.info("=== RQ2-H: Native Card Isolation Benchmark (O(1) w.r.t. N) ===");
        cleanupData();

        NativeCardIsolationBenchmark rq2h = new NativeCardIsolationBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        var rq2hResults = rq2h.execute(NativeScaleConfig.nativeCardIsolationGradient(), 5000);

        ReportGenerator rq2hReport = new ReportGenerator(outputDir);
        for (var r : rq2hResults) {
            rq2hReport.addResult("AstralLight|cards=" + r.cardCount, r.latencySnapshot);
        }
        rq2hReport.writeCsvReport("rq2h_native_card_isolation.csv");
        rq2hReport.writeSummaryReport("rq2h_native_summary.csv");
        rq2hReport.writeRawSamples("rq2h_native_raw");

        try (var pw = new java.io.PrintWriter(outputDir + "/rq2h_native_card_o1.csv")) {
            pw.println("card_count,template_count,base_rules,mean_us,p99_us,p50_us,l1_hit_rate,l2_hit_rate,l3_hit_rate");
            for (var r : rq2hResults) {
                pw.printf("%d,%d,%d,%.1f,%.1f,%.1f,%.3f,%.3f,%.3f%n",
                    r.cardCount, r.templateCount, r.baseRulesPerCard,
                    r.latencySnapshot.meanUs(), r.latencySnapshot.p99Us(), r.latencySnapshot.p50Us(),
                    r.l1HitRate, r.l2HitRate, r.l3HitRate);
            }
        }

        cleanupData();
    }

    private void runRq2I(String outputDir) throws Exception {
        log.info("=== RQ2-I: Native Overlay Ref Count Benchmark (O(K) verification) ===");
        cleanupData();

        NativeOverlayRefBenchmark rq2i = new NativeOverlayRefBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        var rq2iResults = rq2i.execute(NativeScaleConfig.nativeOverlayRefGradient(), 5000);

        ReportGenerator rq2iReport = new ReportGenerator(outputDir);
        for (var r : rq2iResults) {
            rq2iReport.addResult("AstralLight|refs=" + r.totalRefCount, r.latencySnapshot);
        }
        rq2iReport.writeCsvReport("rq2i_native_overlay_ref.csv");
        rq2iReport.writeSummaryReport("rq2i_native_summary.csv");
        rq2iReport.writeRawSamples("rq2i_native_raw");

        try (var pw = new java.io.PrintWriter(outputDir + "/rq2i_native_overlay_ref_ok.csv")) {
            pw.println("overlay_ref_count,base_ref_count,total_ref_count,mean_us,p99_us,l1_hit_rate,l2_hit_rate,l3_hit_rate");
            for (var r : rq2iResults) {
                pw.printf("%d,%d,%d,%.1f,%.1f,%.3f,%.3f,%.3f%n",
                    r.overlayRefCount, r.baseRefCount, r.totalRefCount,
                    r.latencySnapshot.meanUs(), r.latencySnapshot.p99Us(),
                    r.l1HitRate, r.l2HitRate, r.l3HitRate);
            }
        }

        cleanupData();
    }

    private void runRq2J(String outputDir) throws Exception {
        log.info("=== RQ2-J: Native ABAC Complexity Benchmark (O(C) verification) ===");
        cleanupData();

        NativeAbacComplexityBenchmark rq2j = new NativeAbacComplexityBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        var rq2jResults = rq2j.execute(NativeScaleConfig.nativeAbacComplexityIsolationGradient(), 5000);

        ReportGenerator rq2jReport = new ReportGenerator(outputDir);
        for (var r : rq2jResults) {
            rq2jReport.addResult("AstralLight|abac=" + r.abacConditionsPerRule, r.latencySnapshot);
        }
        rq2jReport.writeCsvReport("rq2j_native_abac_complexity.csv");
        rq2jReport.writeSummaryReport("rq2j_native_summary.csv");
        rq2jReport.writeRawSamples("rq2j_native_raw");

        try (var pw = new java.io.PrintWriter(outputDir + "/rq2j_native_abac_oc.csv")) {
            pw.println("abac_conditions,abac_deny_ratio,mean_us,p99_us,l1_hit_rate,l2_hit_rate,l3_hit_rate");
            for (var r : rq2jResults) {
                pw.printf("%d,%.2f,%.1f,%.1f,%.3f,%.3f,%.3f%n",
                    r.abacConditionsPerRule, r.abacDenyRatio,
                    r.latencySnapshot.meanUs(), r.latencySnapshot.p99Us(),
                    r.l1HitRate, r.l2HitRate, r.l3HitRate);
            }
        }

        cleanupData();
    }

    private void runRq2K(String outputDir) throws Exception {
        log.info("=== RQ2-K: Native Permission Rule Benchmark (L2 path verification) ===");
        cleanupData();

        NativePermRuleBenchmark rq2k = new NativePermRuleBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        boolean smoke = Boolean.getBoolean("benchmark.rq2.smoke");
        int defaultIterations = smoke ? 100 : 5000;
        int iterations = Integer.getInteger("benchmark.rq2.iterations", defaultIterations);
        NativeScaleConfig[] rq2kConfigs = smoke
            ? NativeScaleConfig.nativePermRuleSmokeGradient()
            : NativeScaleConfig.nativePermRuleGradient();
        var rq2kResults = rq2k.execute(rq2kConfigs, iterations);
        if (rq2kResults.stream().anyMatch(result -> !result.hasConservedCounts())) {
            throw new IllegalStateException("RQ2-K counter conservation failed; refusing to write a valid artifact");
        }

        ReportGenerator rq2kReport = new ReportGenerator(outputDir);
        for (var r : rq2kResults) {
            rq2kReport.addResult("AstralLight|permRules=" + r.permissionRulesPerCard, r.latencySnapshot);
        }
        rq2kReport.writeCsvReport("rq2k_native_perm_rule.csv");
        rq2kReport.writeSummaryReport("rq2k_native_summary.csv");
        rq2kReport.writeRawSamples("rq2k_native_raw");

        try (var pw = new java.io.PrintWriter(outputDir + "/rq2k_native_perm_rule_l2.csv")) {
            pw.println("perm_rules_per_card,base_rules,overlay_rules,mean_us,p99_us,l1_hit_rate,l2_hit_rate,l3_hit_rate,l1_stage_rate,l2_stage_rate,l3_stage_rate,early_deny_count,rule_stage_evaluations,total_evaluations,measured_requests,injected_card_only_hits,expected_allow,expected_deny,actual_l2_allow,actual_l2_deny,l2_mismatches,errors,counts_conserved,dataset_fingerprint");
            for (var r : rq2kResults) {
                pw.printf("%d,%d,%d,%.1f,%.1f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%b,%s%n",
                    r.permissionRulesPerCard, r.baseRulesPerCard, r.overlayRulesPerCard,
                    r.latencySnapshot.meanUs(), r.latencySnapshot.p99Us(),
                    r.l1HitRate, r.l2HitRate, r.l3HitRate,
                    r.l1StageRate, r.l2StageRate, r.l3StageRate,
                    r.earlyDenyCount, r.ruleStageEvaluations,
                    r.totalEvaluations, r.measuredRequests, r.injectedCardOnlyHitRequests,
                    r.expectedAllow, r.expectedDeny,
                    r.actualL2Allow, r.actualL2Deny,
                    r.l2Mismatches, r.errors, r.hasConservedCounts(),
                    r.datasetFingerprint);
            }
        }

        try (var pw = new java.io.PrintWriter(outputDir + "/rq2k_native_perm_rule_reasons.csv")) {
            pw.println("perm_rules_per_card,dataset_fingerprint,reason,count");
            for (var r : rq2kResults) {
                for (var entry : r.reasonDistribution.entrySet()) {
                    pw.printf("%d,%s,%s,%d%n",
                        r.permissionRulesPerCard,
                        r.datasetFingerprint,
                        entry.getKey(),
                        entry.getValue());
                }
            }
        }

        cleanupData();
    }

    private void runRq3(String outputDir) throws Exception {
        log.info("=== RQ3: Native Incremental Compile Benchmark (with ABAC Recompile) ===");
        cleanupData();

        HardwareMonitor rq3Monitor = new HardwareMonitor(2, Path.of(outputDir));
        rq3Monitor.start("RQ3");

        NativeIncrementalCompileBenchmark rq3 = new NativeIncrementalCompileBenchmark(
            ruleSetService, entryMapper, snapshotMapper,
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);

        NativeIncrementalCompileBenchmark.NativeIncrementalCompileResult rq3Result = rq3.execute();

        hardwareSummaries.add(rq3Monitor.stop());

        ReportGenerator rq3Report = new ReportGenerator(outputDir);
        for (var rcr : rq3Result.normalIncremental.ruleCountResults) {
            rq3Report.addResult("incremental_add|rules=" + rcr.ruleCount, rcr.incrementalAddSnapshot);
            rq3Report.addResult("full_rebuild|rules=" + rcr.ruleCount, rcr.fullRebuildSnapshot);
        }
        for (var dwp : rq3Result.deleteWinnerDegradation.points) {
            rq3Report.addResult("delete_non_winner|rules=" + dwp.ruleCount, dwp.deleteNonWinnerSnapshot);
            rq3Report.addResult("delete_winner|rules=" + dwp.ruleCount, dwp.deleteWinnerSnapshot);
        }
        rq3Report.addResult("high_freq_auth", rq3Result.highFrequencyWrite.authLatencySnapshot);
        rq3Report.addResult("high_freq_rule_change", rq3Result.highFrequencyWrite.ruleChangeLatencySnapshot);
        for (var fcr : rq3Result.scanVsHdel.fieldCountResults) {
            rq3Report.addResult("SCAN|fields=" + fcr.fieldCount, fcr.scanSnapshot);
            rq3Report.addResult("HDEL|fields=" + fcr.fieldCount, fcr.hdelSnapshot);
        }

        rq3Report.writeLatexRq3Table("rq3_native_incremental_table.tex");
        rq3Report.writeCsvReport("rq3_native_incremental_data.csv");
        rq3Report.writeSummaryReport("rq3_native_summary.csv");
        rq3Report.writeRawSamples("rq3_native_raw");
        writeBreakdownCsv(outputDir, "rq3");
        policyEngine.resetBreakdownStats();

        cleanupData();
    }

    private void runRq4(String outputDir, String startFrom) throws Exception {
        HardwareMonitor rq4Monitor = new HardwareMonitor(2, Path.of(outputDir));
        rq4Monitor.start("RQ4");

        if (shouldRun("A", startFrom)) runRq4A(outputDir);
        else log.info("Skipping RQ4-A (start-from={})", startFrom);
        if (shouldRun("B", startFrom)) {
            if ("B".equals(startFrom)) log.info(">>> Resuming from RQ4-B <<<");
            log.info("=== Forcing GC before RQ4-B to free residual memory ===");
            System.gc();
            Thread.sleep(3000);
            System.gc();
            runRq4B(outputDir);
        } else log.info("Skipping RQ4-B (start-from={})", startFrom);
        if (shouldRun("C", startFrom)) {
            if ("C".equals(startFrom)) log.info(">>> Resuming from RQ4-C <<<");
            System.gc();
            Thread.sleep(1000);
            runRq4C(outputDir);
        } else log.info("Skipping RQ4-C (start-from={})", startFrom);

        hardwareSummaries.add(rq4Monitor.stop());
    }

    /** Run sub-benchmark if startFrom is null, or thisStage >= startFrom alphabetically. */
    private boolean shouldRun(String stage, String startFrom) {
        return startFrom == null || stage.compareTo(startFrom) >= 0;
    }

    private void runRq4A(String outputDir) throws Exception {
        log.info("=== RQ4-A: Native Cache Failure Benchmark (with Circuit Breaker) ===");
        cleanupData();

        NativeCacheFailureBenchmark cacheBench = new NativeCacheFailureBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate,
            System.getProperty("benchmark.fault.external-marker-dir", ""), clusterContext);
        var cacheResult = cacheBench.execute(NativeScaleConfig.nativeRq1Default(), 3000);

        ReportGenerator cacheReport = new ReportGenerator(outputDir);
        cacheReport.addResult("Normal", cacheResult.normalSnapshot);
        cacheReport.addResult("Redis_Down", cacheResult.downSnapshot);
        cacheReport.addResult("Recovery", cacheResult.recoverySnapshot);
        cacheReport.addResult("Circuit_Breaker_Open", cacheResult.circuitBreakerOpenSnapshot);
        cacheReport.writeCsvReport("rq4a_native_cache_failure.csv");
        cacheReport.writeSummaryReport("rq4a_native_summary.csv");
        cacheReport.writeRawSamples("rq4a_native_cache_raw");
        DecisionOutcomeRecorder.writeCsv(
                Path.of(outputDir, "rq4a_native_decision_outcomes.csv"),
                cacheResult.decisionOutcomes);        writeDecisionOutcomeSummary(Path.of(outputDir, "rq4a_native_decision_summary.csv"), cacheResult);
        DecisionOutcomeRecorder.AuditResult audit = DecisionOutcomeRecorder.audit(
                cacheResult.decisionOutcomes, cacheResult.measuredRequestsPerPhase);
        Files.writeString(Path.of(outputDir, "rq4a_native_decision_validity.txt"),
                "valid=" + audit.valid() + System.lineSeparator()
                        + "detail=" + audit.detail() + System.lineSeparator(),
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
        writeBreakdownCsv(outputDir, "rq4a");

        log.info("  Decision outcomes: total={} allow={} deny={} failures={} expectedAllowMismatches={} expectedDenyMismatches={}",
            cacheResult.decisionOutcomes.size(), cacheResult.allowedDecisionCount,
            cacheResult.deniedDecisionCount, cacheResult.failureDecisionCount,
            cacheResult.expectedAllowMismatchCount, cacheResult.expectedDenyMismatchCount);

        log.info("  Cache failure: Normal mean={}us, Down mean={}us, Recovery mean={}us, CB-Open mean={}us",
            String.format("%.1f", cacheResult.normalSnapshot.meanUs()),
            String.format("%.1f", cacheResult.downSnapshot.meanUs()),
            String.format("%.1f", cacheResult.recoverySnapshot.meanUs()),
            String.format("%.1f", cacheResult.circuitBreakerOpenSnapshot.meanUs()));

        cleanupData();
    }

    private void writeDecisionOutcomeSummary(Path path,
                                              NativeCacheFailureBenchmark.NativeCacheFailureResult result)
            throws IOException {
        Map<String, long[]> counts = new java.util.LinkedHashMap<>();
        for (DecisionOutcomeRecorder.DecisionOutcome outcome : result.decisionOutcomes) {
            String key = outcome.phase() + "|" + outcome.outcome() + "|"
                    + (outcome.reason() == null ? "" : outcome.reason()) + "|"
                    + (outcome.decisionSource() == null ? "" : outcome.decisionSource()) + "|"
                    + (outcome.decisionPath() == null ? "" : outcome.decisionPath());
            long[] values = counts.computeIfAbsent(key, ignored -> new long[2]);
            values[0]++;
            values[1] += outcome.latencyNanos();
        }
        try (var writer = Files.newBufferedWriter(path,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.TRUNCATE_EXISTING)) {
            writer.write("phase,outcome,reason,decision_source,decision_path,count,mean_latency_us");
            writer.newLine();
            for (Map.Entry<String, long[]> entry : counts.entrySet()) {
                String[] parts = entry.getKey().split("\\|", -1);
                long[] values = entry.getValue();
                double meanUs = values[0] == 0 ? 0.0 : values[1] / (double) values[0] / 1000.0;
                writer.write(String.format("%s,%s,%s,%s,%s,%d,%.3f%n",
                        csvField(parts[0]), csvField(parts[1]), csvField(parts[2]),
                        csvField(parts[3]), csvField(parts[4]), values[0], meanUs));
            }
            writer.write(String.format("TOTAL,,,,,%d,%.3f%n", result.decisionOutcomes.size(),
                    result.decisionOutcomes.isEmpty() ? 0.0 : result.decisionOutcomes.stream()
                            .mapToLong(DecisionOutcomeRecorder.DecisionOutcome::latencyNanos)
                            .average().orElse(0.0) / 1000.0));
        }
    }

    private static String csvField(String value) {
        if (value == null) {
            return "";
        }
        String escaped = value.replace("\"", "\"\"");
        return escaped.indexOf(',') >= 0 || escaped.indexOf('"') >= 0
                ? "\"" + escaped + "\""
                : escaped;
    }

    /**
     * Writes the PolicyEngine per-stage latency breakdown accumulated since the
     * last {@link PolicyEngine#resetBreakdownStats()} (or since JVM start). The
     * engine records five measured stages: card-context validation, rule-set
     * reference loading, OVERLAY evaluation, BASE evaluation, and the
     * permission-rule evaluation path. Shares are relative to the sum of the
     * measured stages, which is a lower bound of the total per-decision latency
     * (projection-status read, statistics, and audit side effects are not
     * individually timed). The caller must reset the counters before running a
     * stage so the CSV reflects only that stage.
     */
    private void writeBreakdownCsv(String outputDir, String prefix) {
        try {
            Map<String, Object> stats = policyEngine.getBreakdownStats();
            long count = ((Number) stats.getOrDefault("breakdownCount", 0L)).longValue();
            String[] stages = {"cardActiveAvgUs", "refsLoadAvgUs", "overlayEvalAvgUs",
                    "baseEvalAvgUs", "permRuleEvalAvgUs"};
            double total = 0.0;
            for (String key : stages) {
                total += ((Number) stats.getOrDefault(key, 0.0)).doubleValue();
            }
            try (var pw = new java.io.PrintWriter(outputDir + "/" + prefix + "_native_breakdown.csv")) {
                pw.println("stage,avg_us,share_pct_of_measured");
                for (String key : stages) {
                    double us = ((Number) stats.getOrDefault(key, 0.0)).doubleValue();
                    double share = total > 0 ? us / total * 100.0 : 0.0;
                    pw.printf("%s,%.2f,%.2f%n", key.replace("AvgUs", ""), us, share);
                }
                pw.printf("breakdownCount,%d,%s%n", count, "");
            }
            log.info("  Breakdown CSV written ({}, count={}, measured_total={}us)", prefix, count,
                    String.format("%.1f", total));
        } catch (Exception e) {
            log.warn("Failed to write breakdown CSV {}: {}", prefix, e.getMessage());
        }
    }

    /**
     * Captures the breakdown for the currently running stage and resets the
     * engine counters so the next stage starts from zero. Used around each
     * sub-benchmark so every RQ stage emits its own breakdown CSV.
     */
    private void captureAndResetBreakdown(String outputDir, String prefix) {
        writeBreakdownCsv(outputDir, prefix);
        policyEngine.resetBreakdownStats();
    }

    private void runRq4B(String outputDir) throws Exception {
        log.info("=== RQ4-B: Native High-Frequency Write Benchmark (with Consistency Check) ===");
        cleanupData();

        NativeHighFrequencyWriteBenchmark writeBench = new NativeHighFrequencyWriteBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate, consistencyChecker);
        var writeResults = writeBench.execute(
            NativeScaleConfig.nativeRq1Default(), new int[]{100, 500, 1000, 5000}, 10);

        try (var pw = new java.io.PrintWriter(outputDir + "/rq4b_native_high_freq_write.csv")) {
            pw.println("target_tps,actual_auth,actual_writes,auth_p99_us,write_p99_us,auth_error_rate,write_error_rate,write_conflicts,consistency_check_passed");
            for (var wr : writeResults) {
                pw.printf("%d,%d,%d,%.1f,%.1f,%.4f,%.4f,%d,%b%n",
                    wr.targetWriteTps, wr.actualAuthCount, wr.actualWriteCount,
                    wr.authP99Us, wr.writeP99Us, wr.authErrorRate, wr.writeErrorRate,
                    wr.writeConflicts, wr.consistencyCheckPassed);
            }
        }
        writeBreakdownCsv(outputDir, "rq4b");
        policyEngine.resetBreakdownStats();

        cleanupData();
    }

    private void runRq4C(String outputDir) throws Exception {
        log.info("=== RQ4-C: Native Optimistic Lock Benchmark (with Version Chain) ===");
        cleanupData();

        NativeOptimisticLockBenchmark lockBench = new NativeOptimisticLockBenchmark(
            nativeDataGenerator, redisTemplate, jdbcTemplate);
        var lockResults = lockBench.execute(
            NativeScaleConfig.nativeRq1Default(), new int[]{1, 8, 32, 128}, 100);

        try (var pw = new java.io.PrintWriter(outputDir + "/rq4c_native_optimistic_lock.csv")) {
            pw.println("thread_count,total_ops,success,retries,failures,p50_us,p99_us,mean_us,version_chain_depth");
            for (var lr : lockResults) {
                pw.printf("%d,%d,%d,%d,%d,%.1f,%.1f,%.1f,%d%n",
                    lr.threadCount, lr.totalOps, lr.successCount, lr.retryCount,
                    lr.failureCount, lr.p50Us, lr.p99Us, lr.meanUs, lr.versionChainDepth);
            }
        }
        writeBreakdownCsv(outputDir, "rq4c");
        policyEngine.resetBreakdownStats();

        cleanupData();
    }

    // ═══════════════════════════════════════════════════════════════
    // RQ5: Additional Benchmark Scenarios
    // E2: Direct PDP card-selection consistency; E4: local cache-repopulation latency;
    // E11: ThreadLocal parameter-dependence. These are not end-to-end credential tests.
    // E3+E5: Throughput QPS Scalability
    // ═══════════════════════════════════════════════════════════════

    private void runRq5(String outputDir) throws Exception {
        log.info("=== RQ5-A: Direct PDP Concurrency, Cache Repopulation, and Context Dependence ===");
        cleanupData();

        HardwareMonitor rq5aMonitor = new HardwareMonitor(2, Path.of(outputDir));
        rq5aMonitor.start("RQ5-A");

        NativeSwitchAtomicityBenchmark rq5a = new NativeSwitchAtomicityBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);

        NativeScaleConfig satConfig = RQ5Configs.SAT_CONFIG;

        NativeSwitchAtomicityBenchmark.NativeSwitchAtomicityResult satResult =
            rq5a.execute(satConfig, 8, 4, 30);
        NativeRq5ArtifactWriter.writeDirectPdpArtifacts(Path.of(outputDir), satResult);

        hardwareSummaries.add(rq5aMonitor.stop());

        // Report results
        var a = satResult.scenarioA;
        double violationRate = a.judgedEvals.get() > 0 ?
            (double) a.isolationViolations.get() / a.judgedEvals.get() : -1;
        log.info("  E2 direct-PDP reference comparison: attempted={} judged={} skipped={} mismatches={} rate={} mean={}us p99={}us",
            a.totalEvals.get(), a.judgedEvals.get(), a.skippedEvals.get(), a.isolationViolations.get(),
            String.format("%.8f", violationRate),
            String.format("%.1f", a.lSnapshot.meanUs()),
            String.format("%.1f", a.lSnapshot.p99Us()));

        var b = satResult.scenarioB;
        log.info("  E2 Isolation: divergenceChecks={} divergence={} leakageChecks={} leakage={}",
            b.divergenceChecks, b.crossCardDivergence, b.leakageChecks, b.crossCardLeakage);

        var c = satResult.scenarioC;
        double anomalyRate = c.totalEvaluations > 0 ?
            (double) c.anomalyCount / c.totalEvaluations : 0;
        log.info("  E11 direct PDP parameter-dependence: evaluations={} anomalies={} rate={}",
            c.totalEvaluations, c.anomalyCount, String.format("%.8f", anomalyRate));

        var d = satResult.scenarioD;
        log.info("  E4 local cache-repopulation latency: samples={} setupFailures={} warmMedian={}us coldMedian={}us "
                + "pairedOverheadMedian={}us warmP99={}us coldP99={}us",
            d.sampleCount, d.setupFailureCount, fmt(d.warmMedianUs), fmt(d.coldMedianUs), fmt(d.overheadMedianUs),
            fmt(d.warmP99Us), fmt(d.coldP99Us));
        writeBreakdownCsv(outputDir, "rq5a");
        policyEngine.resetBreakdownStats();

        cleanupData();

        // ── RQ5-B: Throughput QPS ──
        log.info("=== RQ5-B: Throughput (QPS) Benchmark ===");
        System.gc();
        Thread.sleep(2000);
        System.gc();

        HardwareMonitor rq5bMonitor = new HardwareMonitor(2, Path.of(outputDir));
        rq5bMonitor.start("RQ5-B");

        NativeThroughputBenchmark rq5b = new NativeThroughputBenchmark(
            policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);

        NativeScaleConfig[] scales = RQ5Configs.SCALES;
        int[] concurrencies = RQ5Configs.CONCURRENCIES;

        NativeThroughputBenchmark.NativeThroughputResult tpResult =
            rq5b.execute(scales, concurrencies, RQ5Configs.MEASURE_SEC);
        NativeRq5ArtifactWriter.writeThroughputArtifacts(Path.of(outputDir), tpResult);

        hardwareSummaries.add(rq5bMonitor.stop());

        log.info("  Throughput results (mean ± SD across repeats):");
        for (var sr : tpResult.scaleResults) {
            for (var cr : sr.concurrencyResults) {
                log.info("    cards={} concur={} meanQPS={}±{} p99QPS={} latP50={}us latP99={}us CI95=[{},{}]",
                    sr.cardCount, cr.concurrency,
                    String.format("%.0f", cr.meanQps),
                    String.format("%.0f", cr.stddevQpsAcrossRepeats),
                    String.format("%.0f", cr.p99Qps),
                    String.format("%.1f", cr.latP50), String.format("%.1f", cr.latP99),
                    String.format("%.1f", cr.latCILowerUs),
                    String.format("%.1f", cr.latCIUpperUs));
            }
            if (sr.coldResult != null) {
                log.info("    cards={} COLD  meanQPS={}±{} latP50={}us latP99={}us",
                    sr.cardCount,
                    String.format("%.0f", sr.coldResult.meanQps),
                    String.format("%.0f", sr.coldResult.stddevQpsAcrossRepeats),
                    String.format("%.1f", sr.coldResult.latP50),
                    String.format("%.1f", sr.coldResult.latP99));
            }
        }
        writeBreakdownCsv(outputDir, "rq5b");
        policyEngine.resetBreakdownStats();

        cleanupData();
    }

    private static String fmt(double v) { return String.format("%.1f", v); }

    private Path resolveOutputDirectory(String defaultPrefix) {
        String configuredOutputDir = System.getProperty("benchmark.output-dir");
        if (configuredOutputDir != null && !configuredOutputDir.isBlank()) {
            return Path.of(configuredOutputDir);
        }
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        return Path.of("benchmark-results", defaultPrefix + "-" + timestamp);
    }

    private void writeClusterNodeMetadata(Path outputDir, ClusterRunContext context) throws IOException {
        String json = "{\n"
                + "  \"formatVersion\": 1,\n"
                + "  \"status\": \"CLUSTER_NODE\",\n"
                + "  \"generatedAt\": \"" + escapeJson(java.time.Instant.now().toString()) + "\",\n"
                + "  \"protocolVersion\": " + jsonStringOrNull(ClusterRunContext.PROTOCOL_VERSION) + ",\n"
                + "  \"campaignId\": " + jsonStringOrNull(context.campaignId()) + ",\n"
                + "  \"runId\": " + jsonStringOrNull(context.runId()) + ",\n"
                + "  \"replicate\": " + context.replicate() + ",\n"
                + "  \"attempt\": " + context.attempt() + ",\n"
                + "  \"nodeId\": " + jsonStringOrNull(context.nodeId()) + ",\n"
                + "  \"hardwareLabel\": " + jsonStringOrNull(context.hardwareLabel()) + ",\n"
                + "  \"nodeRole\": " + jsonStringOrNull(context.nodeRole()) + ",\n"
                + "  \"rolePermutation\": " + jsonStringOrNull(context.rolePermutation()) + ",\n"
                + "  \"phase\": " + jsonStringOrNull(context.phase()) + ",\n"
                + "  \"coordinator\": " + context.coordinator() + "\n"
                + "}\n";
        Files.writeString(outputDir.resolve("CLUSTER_NODE.json"), json, StandardCharsets.UTF_8);
    }

    private void writeClusterAborted(Path outputDir, ClusterRunContext context,
                                     String phase, String reason) throws IOException {
        Files.createDirectories(outputDir);
        String json = "{\n"
                + "  \"formatVersion\": 1,\n"
                + "  \"status\": \"ABORTED\",\n"
                + "  \"generatedAt\": \"" + escapeJson(java.time.Instant.now().toString()) + "\",\n"
                + "  \"protocolVersion\": " + jsonStringOrNull(ClusterRunContext.PROTOCOL_VERSION) + ",\n"
                + "  \"campaignId\": " + jsonStringOrNull(context == null ? null : context.campaignId()) + ",\n"
                + "  \"runId\": " + jsonStringOrNull(context == null ? null : context.runId()) + ",\n"
                + "  \"replicate\": " + (context == null ? 0 : context.replicate()) + ",\n"
                + "  \"attempt\": " + (context == null ? 0 : context.attempt()) + ",\n"
                + "  \"nodeId\": " + jsonStringOrNull(context == null ? null : context.nodeId()) + ",\n"
                + "  \"hardwareLabel\": " + jsonStringOrNull(context == null ? null : context.hardwareLabel()) + ",\n"
                + "  \"nodeRole\": " + jsonStringOrNull(context == null ? null : context.nodeRole()) + ",\n"
                + "  \"phase\": " + jsonStringOrNull(phase) + ",\n"
                + "  \"reason\": " + jsonStringOrNull(reason) + "\n"
                + "}\n";
        Path temporary = outputDir.resolve(".CLUSTER_ABORTED.json.tmp");
        Path marker = outputDir.resolve("CLUSTER_ABORTED.json");
        Files.writeString(temporary, json, StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                java.nio.file.StandardOpenOption.WRITE);
        try {
            Files.move(temporary, marker, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(temporary, marker, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        log.error("Cluster benchmark aborted before workload execution: {}", marker);
    }

    private void writeRunManifest(Path outputDir, String[] args,
                                  boolean runRq1, boolean runRq2, boolean runRq3,
                                  boolean runRq4, boolean runRq5,
                                  String startFromRq2Sub, String startFromRq4Sub) throws IOException {
        String manifest = "{\n"
                + "  \"formatVersion\": 1,\n"
                + "  \"generatedAt\": \"" + LocalDateTime.now() + "\",\n"
                + "  \"randomSeed\": 42,\n"
                + "  \"fixedBenchmarkClock\": \"" + escapeJson(System.getProperty("benchmark.fixed-clock", "2026-01-01T00:00:00Z")) + "\",\n"
                + "  \"outputDirectory\": \"" + escapeJson(outputDir.toString()) + "\",\n"
                + "  \"javaVersion\": \"" + escapeJson(System.getProperty("java.version")) + "\",\n"
                + "  \"jvmName\": \"" + escapeJson(System.getProperty("java.vm.name")) + "\",\n"
                + "  \"osName\": \"" + escapeJson(System.getProperty("os.name")) + "\",\n"
                + "  \"availableProcessors\": " + Runtime.getRuntime().availableProcessors() + ",\n"
                + "  \"destructiveCleanupApproved\": "
                + Boolean.getBoolean("benchmark.allow-destructive-cleanup") + ",\n"
                + "  \"selectedRqs\": {\"rq1\": " + runRq1 + ", \"rq2\": " + runRq2
                + ", \"rq3\": " + runRq3 + ", \"rq4\": " + runRq4 + ", \"rq5\": " + runRq5 + "},\n"
                + "  \"startFromRq2\": " + jsonStringOrNull(startFromRq2Sub) + ",\n"
                + "  \"startFromRq4\": " + jsonStringOrNull(startFromRq4Sub) + ",\n"
                + "  \"rq2kSmoke\": " + Boolean.getBoolean("benchmark.rq2.smoke") + ",\n"
                + "  \"rq2kIterations\": " + Integer.getInteger("benchmark.rq2.iterations", 5000) + ",\n"
                + "  \"arguments\": " + jsonStringArray(args) + "\n"
                + "}\n";
        Files.writeString(outputDir.resolve("run-manifest.json"), manifest, StandardCharsets.UTF_8);
    }

    private static String jsonStringOrNull(String value) {
        return value == null ? "null" : "\"" + escapeJson(value) + "\"";
    }

    private static String jsonStringArray(String[] values) {
        StringBuilder result = new StringBuilder("[");
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                result.append(", ");
            }
            result.append('"').append(escapeJson(values[i])).append('"');
        }
        return result.append(']').toString();
    }

    private static String escapeJson(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private void cleanupData() {
        // Native results require a fresh DB/Redis state; continuing after a
        // cleanup failure would silently mix runs and invalidate the artifact.
        BenchmarkCleanupUtil.cleanupAllStrict(jdbcTemplate, redisTemplate);
        log.info("Data cleanup complete");
    }

    /**
     * Write hardware usage reports (CSV + LaTeX) for all monitored phases.
     */
    private void writeHardwareReports(String outputDir) throws IOException {
        if (hardwareSummaries.isEmpty()) {
            log.info("No hardware summaries collected, skipping hardware reports");
            return;
        }

        // CSV summary (all metrics including efficiency)
        HardwareMonitor.writeSummaryCsv(outputDir + "/hardware_summary.csv", hardwareSummaries);
        log.info("Hardware summary CSV written to {}/hardware_summary.csv", outputDir);

        // LaTeX: hardware usage table (CPU, memory, disk, GC overhead, efficiency)
        HardwareMonitor.writeLatexHardwareTable(outputDir + "/hardware_usage.tex", hardwareSummaries);
        log.info("Hardware usage LaTeX table written to {}/hardware_usage.tex", outputDir);

        // LaTeX: efficiency metrics table (CPU/Mem/GC/Cache/Storage efficiency)
        HardwareMonitor.writeLatexEfficiencyTable(outputDir + "/hardware_efficiency.tex", hardwareSummaries);
        log.info("Hardware efficiency LaTeX table written to {}/hardware_efficiency.tex", outputDir);

        // LaTeX: GC statistics table
        HardwareMonitor.writeLatexGcTable(outputDir + "/hardware_gc.tex", hardwareSummaries);
        log.info("Hardware GC LaTeX table written to {}/hardware_gc.tex", outputDir);

        // Log a quick overview
        log.info("=== Hardware Usage Overview ===");
        for (HardwareMonitor.HardwareSummary s : hardwareSummaries) {
            log.info("  {}: CPU={}/{}, Heap={}/{}/{}MB, Phys={}/{}/{}MB, Disk={}/{}GB, " +
                            "GC={}/{}ms/{}%, Eff=[cpu={},mem={},gc={},cache={},storage={}]",
                s.label(),
                String.format("%.1f", s.cpuProcessAvg()), String.format("%.1f", s.cpuProcessMax()),
                s.heapUsedAvgMb(), s.heapUsedMaxMb(), s.heapMaxMb(),
                s.physicalUsedAvgMb(), s.physicalUsedMaxMb(), s.physicalTotalMb(),
                s.diskUsedStartGb(), s.diskTotalGb(),
                s.gcTotalCount(), s.gcTotalTimeMs(), String.format("%.2f", s.gcOverheadPct()),
                String.format("%.4f", s.cpuEfficiency()), String.format("%.4f", s.memoryEfficiency()),
                String.format("%.4f", s.gcEfficiency()), String.format("%.4f", s.cacheEfficiency()),
                String.format("%.4f", s.storageEfficiency()));
        }
    }
}
