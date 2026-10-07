package com.coreryblack.benchmark.runner;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.permission.permission.RuleSetService;
import com.coreryblack.benchmark.baseline.*;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.config.SandboxConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.data.MultiSystemComparisonResult;
import org.springframework.beans.factory.annotation.Qualifier;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.ComparisonReportGenerator;
import com.coreryblack.benchmark.util.HardwareMonitor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.ArrayList;

import org.springframework.jdbc.core.JdbcTemplate;
import com.coreryblack.astral_general.AstralGeneralRuntimeConfiguration;
import com.coreryblack.astral_audit.runtime.AstralAuditRuntimeConfiguration;
import com.coreryblack.astral_identity.persistence.AstralIdentityPersistenceConfiguration;
import com.coreryblack.astral_platform.persistence.AstralPlatformPersistenceConfiguration;
import com.coreryblack.astral_messaging_runtime.AstralMessagingRuntimeConfiguration;
import com.coreryblack.astral_permission_runtime.AstralPermissionRuntimeConfiguration;

/**
 * Multi-system comparison benchmark entry point.
 *
 * <h3>Benchmark Scenarios</h3>
 * <ul>
 *   <li><b>RQ-Compare-1</b>: Decision Latency — AL vs Casbin vs OPA vs Cedar</li>
 *   <li><b>RQ-Compare-2</b>: Rule Growth Sensitivity — latency vs rule count</li>
 *   <li><b>RQ-Compare-3</b>: Rule Update Overhead — Incremental Compile vs Policy Reload vs Bundle Reload vs Index Rebuild</li>
 *   <li><b>RQ-Compare-4</b>: Removed — SpiceDB ReBAC model incomparable to RBAC systems</li>
 * </ul>
 *
 * <h3>Baseline Configuration (Section 5.2)</h3>
 * <p>All systems are evaluated using their vendor-recommended production
 * deployment configurations. The goal is not to compare development defaults,
 * but production-ready deployments.</p>
 *
 * <h3>Repeat Runs</h3>
 * <p>Run this benchmark multiple times manually, then use
 * {@code LatencyRecorder.LatencySnapshot.merge()} to aggregate raw samples
 * for mean ± stddev reporting.</p>
 *
 * <p>AstralLight internal tests are run independently via {@code NativeAstralBenchmark}.</p>
 */
@Slf4j
@SpringBootApplication(scanBasePackages = "com.coreryblack.benchmark")
@ConditionalOnProperty(name = "benchmark.type", havingValue = "comparison")
@org.springframework.context.annotation.Import({AstralGeneralRuntimeConfiguration.class, AstralAuditRuntimeConfiguration.class, AstralIdentityPersistenceConfiguration.class, AstralPlatformPersistenceConfiguration.class, AstralMessagingRuntimeConfiguration.class, AstralPermissionRuntimeConfiguration.class})
public class BenchmarkRunner implements CommandLineRunner {

    private final PolicyEngine policyEngine;
    private final RuleSetService ruleSetService;
    private final org.springframework.data.redis.core.StringRedisTemplate redisTemplate;
    private final DataGenerator dataGenerator;
    private final JdbcTemplate jdbcTemplate;
    private final CasbinAdapter casbinAdapter;
    private final CasbinCachedAdapter casbinCachedAdapter;
    private final OpaAdapter opaAdapter;
    private final OpaAdapter opaCachedAdapter;

    /** Hardware usage summaries collected per phase */
    private final List<HardwareMonitor.HardwareSummary> hardwareSummaries = new ArrayList<>();

    public BenchmarkRunner(PolicyEngine policyEngine,
                            RuleSetService ruleSetService,
                            org.springframework.data.redis.core.StringRedisTemplate redisTemplate,
                            DataGenerator dataGenerator,
                            JdbcTemplate jdbcTemplate,
                            CasbinAdapter casbinAdapter,
                            CasbinCachedAdapter casbinCachedAdapter,
                            @Qualifier("opaAdapter") OpaAdapter opaAdapter,
                            @Qualifier("opaNoCacheAdapter") OpaAdapter opaCachedAdapter) {
        this.policyEngine = policyEngine;
        this.ruleSetService = ruleSetService;
        this.redisTemplate = redisTemplate;
        this.dataGenerator = dataGenerator;
        this.jdbcTemplate = jdbcTemplate;
        this.casbinAdapter = casbinAdapter;
        this.casbinCachedAdapter = casbinCachedAdapter;
        this.opaAdapter = opaAdapter;
        this.opaCachedAdapter = opaCachedAdapter;
    }

    public static void main(String[] args) {
        System.setProperty("spring.main.banner-mode", "off");
        SpringApplication.run(BenchmarkRunner.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String outputDir = "benchmark-results/comparison-" + timestamp;
        Files.createDirectories(Path.of(outputDir));

        // Appendix-only mode: skip the primary Layer A comparison and RQ-Compare-3,
        // running only the Cedar semantic-emulation appendix. Used to recover from
        // an appendix failure without re-burning the ~1.5h primary comparison.
        boolean appendixOnly = Boolean.getBoolean("benchmark.appendix.only");

        SandboxConfig sandboxConfig = SandboxConfig.builder().build();
        dataGenerator.setSeed(42L);
        log.info("=== Multi-System Comparison Benchmark (appendixOnly={}) ===", appendixOnly);
        log.info("Sandbox: {}", sandboxConfig.toLatexTable());

        // Start suite-level hardware monitoring
        HardwareMonitor suiteMonitor = new HardwareMonitor(5, Path.of(outputDir));
        suiteMonitor.start("comparison_suite");

        cleanupData();

        MultiSystemBenchmarkRunner multiRunner = new MultiSystemBenchmarkRunner(
            policyEngine, dataGenerator, redisTemplate, jdbcTemplate,
            ruleSetService,
            casbinAdapter, casbinCachedAdapter, opaAdapter, opaCachedAdapter);
        multiRunner.setCheckpointDir(outputDir + "/layer1/checkpoints");

        // Layer A: only cardCount varies (controlled variable)
        ScaleConfig[] layerAScales = ScaleConfig.decisionLatencyGradient();
        int iterations = 10000;
        int concurrency = 8;

        // ── RQ-Compare-1 + RQ-Compare-2: Layer A — Common Semantic Subset (4 systems) ──
        if (!appendixOnly) {
            HardwareMonitor l1Monitor = new HardwareMonitor(3, Path.of(outputDir));
            l1Monitor.start("LayerA");

            try {
                MultiSystemComparisonResult.BenchmarkResult l1Result = multiRunner.runLayer1Comparison(
                    layerAScales, iterations, concurrency);

                hardwareSummaries.add(l1Monitor.stop());

                ComparisonReportGenerator l1Report = new ComparisonReportGenerator(outputDir + "/layer1");
                l1Report.generateFullReport(l1Result);
                log.info("  Layer A reports: {}/layer1/", outputDir);
            } catch (Exception e) {
                log.error("Layer A (RQ-Compare-1/2) failed, continuing with remaining phases", e);
            }

            cleanupData();
        }

        // ── Cedar appendix (semantic emulation — reference only) ──
        try {
            log.info("--- Cedar (semantic emulation — appendix) ---");
            ScaleConfig[] cedarScales = MultiSystemComparisonResult.comparisonGradient();
            MultiSystemComparisonResult.BenchmarkResult cedarResult = multiRunner.runLayer1Comparison(
                cedarScales, iterations, concurrency);
            ComparisonReportGenerator cedarReport = new ComparisonReportGenerator(outputDir + "/cedar_appendix");
            cedarReport.generateFullReport(cedarResult);
            log.info("  Cedar appendix: {}/cedar_appendix/", outputDir);
        } catch (Exception e) {
            log.error("Cedar appendix failed, continuing with RQ-Compare-3", e);
        }

        cleanupData();

        // ── RQ-Compare-3: Rule Update Overhead ──
        if (!appendixOnly) {
            try {
                HardwareMonitor rq3Monitor = new HardwareMonitor(3, Path.of(outputDir));
                rq3Monitor.start("RQ-Compare3");

                List<MultiSystemComparisonResult.RuleChangeCostPoint> ruleChangeCosts =
                    multiRunner.runLayer1RuleChangeCost(layerAScales, 500);

                hardwareSummaries.add(rq3Monitor.stop());

                ComparisonReportGenerator rq3Report = new ComparisonReportGenerator(outputDir + "/layer1");
                rq3Report.writeRuleUpdateOverheadTable(ruleChangeCosts);
                log.info("  RQ-Compare-3 reports: {}/layer1/", outputDir);
            } catch (Exception e) {
                log.error("RQ-Compare-3 failed", e);
            }
        }


        // Stop suite-level monitoring and write hardware reports
        hardwareSummaries.add(suiteMonitor.stop());
        writeHardwareReports(outputDir);

        log.info("=== Comparison benchmark complete. Results in: {} ===", outputDir);
        log.info("For repeat runs: run again and use LatencySnapshot.merge() to aggregate.");
    }

    private void cleanupData() {
        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
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

        HardwareMonitor.writeSummaryCsv(outputDir + "/hardware_summary.csv", hardwareSummaries);
        log.info("Hardware summary CSV written to {}/hardware_summary.csv", outputDir);

        HardwareMonitor.writeLatexHardwareTable(outputDir + "/hardware_usage.tex", hardwareSummaries);
        log.info("Hardware usage LaTeX table written to {}/hardware_usage.tex", outputDir);

        HardwareMonitor.writeLatexEfficiencyTable(outputDir + "/hardware_efficiency.tex", hardwareSummaries);
        log.info("Hardware efficiency LaTeX table written to {}/hardware_efficiency.tex", outputDir);

        HardwareMonitor.writeLatexGcTable(outputDir + "/hardware_gc.tex", hardwareSummaries);
        log.info("Hardware GC LaTeX table written to {}/hardware_gc.tex", outputDir);

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
