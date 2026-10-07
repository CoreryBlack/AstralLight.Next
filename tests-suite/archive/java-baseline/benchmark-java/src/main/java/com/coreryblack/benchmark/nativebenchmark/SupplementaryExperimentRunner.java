package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Standalone runner for the additional benchmark scenarios.
 *
 * <p>Uses explicit SpringApplicationBuilder to avoid @ComponentScan conflicts.
 *
 * <h3>Configuration</h3>
 * Connection parameters are read from environment variables so other
 * operators can run against their own dedicated test infrastructure
 * infrastructure without editing source code:
 * <table>
 *   <tr><th>Variable</th><th>Default</th><th>Description</th></tr>
 *   <tr><td>BENCH_MYSQL_HOST</td><td>localhost</td><td>MySQL host</td></tr>
 *   <tr><td>BENCH_MYSQL_PORT</td><td>3307</td><td>MySQL port</td></tr>
 *   <tr><td>BENCH_MYSQL_USER</td><td>required</td><td>MySQL user</td></tr>
 *   <tr><td>BENCH_MYSQL_PASSWORD</td><td>required</td><td>MySQL password (env-only — never commit)</td></tr>
 *   <tr><td>BENCH_MYSQL_DATABASE</td><td>astrallight</td><td>Dedicated benchmark database</td></tr>
 *   <tr><td>BENCH_REDIS_HOST</td><td>localhost</td><td>Redis host</td></tr>
 *   <tr><td>BENCH_REDIS_PORT</td><td>6380</td><td>Redis port</td></tr>
 * </table>
 *
 * <p>The scale and concurrency configurations intentionally mirror
 * {@link NativeAstralBenchmark#runRq5(String)} so that the standalone runner
 * and the full suite produce comparable results.
 */
public class SupplementaryExperimentRunner {

    public static void main(String[] args) throws Exception {
        requireDestructiveCleanupApproval();
        ConfigurableApplicationContext ctx = new SpringApplicationBuilder()
            .sources(com.coreryblack.benchmark.nativebenchmark.NativeAstralBenchmark.class)
            .web(WebApplicationType.NONE)
            .profiles("benchmark")
            .properties(buildConnectionProperties())
            .run(args);

        // Write environment metadata snapshot for reproducibility.
        Path outputDir = writeEnvironmentMetadata();

        PolicyEngine policyEngine = ctx.getBean(PolicyEngine.class);
        NativeDataGenerator dataGenerator = ctx.getBean(NativeDataGenerator.class);
        dataGenerator.setSeed(42L);
        StringRedisTemplate redisTemplate = ctx.getBean(StringRedisTemplate.class);
        JdbcTemplate jdbcTemplate = ctx.getBean(JdbcTemplate.class);

        System.out.println();
        System.out.println("================================================");
        System.out.println("  Additional Benchmark Scenarios");
        System.out.println("  E2+E4+E11: Direct PDP + Local Cache + Context Parameters");
        System.out.println("  E3+E5: Throughput QPS Scalability");
        System.out.println("  Output dir: " + outputDir.toAbsolutePath());
        System.out.println("================================================");
        System.out.println();

        // ── E2+E4+E11: Direct PDP and local cache measurements ──
        NativeSwitchAtomicityBenchmark satBench = new NativeSwitchAtomicityBenchmark(
            policyEngine, dataGenerator, redisTemplate, jdbcTemplate);

        NativeScaleConfig satConfig = RQ5Configs.SAT_CONFIG;

        NativeSwitchAtomicityBenchmark.NativeSwitchAtomicityResult satResult =
            satBench.execute(satConfig, 8, 4, 30);
        NativeRq5ArtifactWriter.writeDirectPdpArtifacts(outputDir, satResult);

        System.out.println("=== DIRECT PDP CARD-SELECTION RESULTS ===");
        var a = satResult.scenarioA;
        double violationRate = a.totalEvals.get() > 0 ?
            (double) a.isolationViolations.get() / a.totalEvals.get() : -1;
        System.out.printf("E2 Direct PDP selection: evals=%,d mismatches=%,d errors=%,d rate=%.8f mean=%.1fus p99=%.1fus%n",
            a.totalEvals.get(), a.isolationViolations.get(), a.errorCount.get(),
            violationRate, a.lSnapshot.meanUs(), a.lSnapshot.p99Us());

        var b = satResult.scenarioB;
        System.out.printf("E2 Isolation: divergenceChecks=%d divergence=%d leakageChecks=%d leakage=%d%n",
            b.divergenceChecks, b.crossCardDivergence, b.leakageChecks, b.crossCardLeakage);

        var c = satResult.scenarioC;
        double anomalyRate = c.totalEvaluations > 0 ?
            (double) c.anomalyCount / c.totalEvaluations : 0;
        System.out.printf("E11 Context parameter dependence: evaluations=%,d anomalies=%d rate=%.8f%n",
            c.totalEvaluations, c.anomalyCount, anomalyRate);

        var d = satResult.scenarioD;
        System.out.printf("E4 Local cache repopulation: samples=%,d warmMedian=%.1fus coldMedian=%.1fus "
                + "overheadMedian=%.1fus (signed) warmP99=%.1fus coldP99=%.1fus%n",
            d.sampleCount, d.warmMedianUs, d.coldMedianUs, d.overheadMedianUs,
            d.warmP99Us, d.coldP99Us);
        System.out.println();

        // ── E3+E5: Throughput QPS ──
        NativeThroughputBenchmark tpBench = new NativeThroughputBenchmark(
            policyEngine, dataGenerator, redisTemplate, jdbcTemplate);

        NativeScaleConfig[] scales = RQ5Configs.SCALES;
        int[] concurrencies = RQ5Configs.CONCURRENCIES;

        NativeThroughputBenchmark.NativeThroughputResult tpResult =
            tpBench.execute(scales, concurrencies, 15);
        NativeRq5ArtifactWriter.writeThroughputArtifacts(outputDir, tpResult);

        System.out.println("=== THROUGHPUT (QPS) RESULTS ===");
        System.out.printf("%-10s %10s %14s %12s %12s %12s %12s%n",
            "Cards", "Concur", "MeanQPS(±SD)", "P99QPS", "LatP50(us)", "LatP99(us)", "LatCI95");
        for (var sr : tpResult.scaleResults) {
            for (var cr : sr.concurrencyResults) {
                System.out.printf("%,-10d %10d %8.0f±%.0f %12.0f %12.1f %12.1f [%5.1f,%5.1f]%n",
                    sr.cardCount, cr.concurrency,
                    cr.meanQps, cr.stddevQpsAcrossRepeats,
                    cr.p99Qps, cr.latP50, cr.latP99,
                    cr.latCILowerUs, cr.latCIUpperUs);
            }
            if (sr.coldResult != null) {
                var cr = sr.coldResult;
                System.out.printf("%,-10d %10s %8.0f±%.0f %12.0f %12.1f %12.1f (cold)%n",
                    sr.cardCount, "cold", cr.meanQps, cr.stddevQpsAcrossRepeats,
                    cr.p99Qps, cr.latP50, cr.latP99);
            }
        }
        System.out.println();

        ctx.close();
        System.out.println("All supplementary experiments complete.");
        System.out.println("Environment metadata written to: " + outputDir.toAbsolutePath());
    }

    /**
     * Build Spring connection properties from environment variables.
     * Sensitive values (password) are read exclusively from BENCH_MYSQL_PASSWORD
     * so they never appear in source code.
     */
    private static Properties buildConnectionProperties() {
        Properties props = new Properties();
        props.setProperty("spring.cloud.nacos.config.import-check.enabled", "false");
        props.setProperty("spring.cloud.nacos.discovery.enabled", "false");
        props.setProperty("spring.cloud.nacos.config.enabled", "false");
        props.setProperty("benchmark.type", "native");
        props.setProperty("benchmark.native.auto-run", "false");
        props.setProperty("spring.datasource.url", "jdbc:mysql://" + env("BENCH_MYSQL_HOST", "localhost")
                + ":" + env("BENCH_MYSQL_PORT", "3307")
                + "/" + env("BENCH_MYSQL_DATABASE", "astrallight")
                + "?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
        props.setProperty("spring.datasource.username", requiredEnv("BENCH_MYSQL_USER"));
        props.setProperty("spring.datasource.password", requiredEnv("BENCH_MYSQL_PASSWORD"));
        String jwtSecret = requiredEnv("BENCH_JWT_SECRET");
        props.setProperty("spring.jwt.secret", jwtSecret);
        props.setProperty("spring.data.redis.host", env("BENCH_REDIS_HOST", "localhost"));
        props.setProperty("spring.data.redis.port", env("BENCH_REDIS_PORT", "6380"));
        return props;
    }

    static void requireDestructiveCleanupApproval() {
        if (!Boolean.getBoolean("benchmark.allow-destructive-cleanup")) {
            throw new IllegalStateException("Additional benchmark scenarios require -Dbenchmark.allow-destructive-cleanup=true "
                    + "because they clear the configured Redis database and benchmark tables.");
        }
    }

    private static String env(String name, String defaultValue) {
        String v = System.getenv(name);
        return (v == null || v.isEmpty()) ? defaultValue : v;
    }

    private static String requiredEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing required environment variable: " + name);
        }
        return value;
    }

    /**
     * Write environment metadata (CPU, JVM, OS, runtime) to a JSON file in
     * the output directory for reproducibility.
     */
    private static Path writeEnvironmentMetadata() throws IOException {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        Path dir = Path.of("benchmark-results", "supp-" + timestamp);
        Files.createDirectories(dir);
        Path envFile = dir.resolve("environment.json");

        Map<String, String> env = new LinkedHashMap<>();
        env.put("timestamp", timestamp);
        env.put("javaVersion", System.getProperty("java.version"));
        env.put("javaVendor", System.getProperty("java.vendor"));
        env.put("jvmName", System.getProperty("java.vm.name"));
        env.put("jvmVersion", System.getProperty("java.vm.version"));
        env.put("osName", System.getProperty("os.name"));
        env.put("osVersion", System.getProperty("os.version"));
        env.put("osArch", System.getProperty("os.arch"));
        env.put("availableProcessors", String.valueOf(Runtime.getRuntime().availableProcessors()));
        env.put("maxMemoryBytes", String.valueOf(Runtime.getRuntime().maxMemory()));
        env.put("randomSeed", "42");
        env.put("destructiveCleanupApproved",
                String.valueOf(Boolean.getBoolean("benchmark.allow-destructive-cleanup")));
        // Credentials and infrastructure addresses are deliberately not archived.

        StringBuilder sb = new StringBuilder("{\n");
        int i = 0;
        for (var e : env.entrySet()) {
            sb.append("  \"").append(e.getKey()).append("\": \"").append(e.getValue()).append("\"");
            if (++i < env.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("}\n");
        Files.writeString(envFile, sb.toString(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        return dir;
    }

}
