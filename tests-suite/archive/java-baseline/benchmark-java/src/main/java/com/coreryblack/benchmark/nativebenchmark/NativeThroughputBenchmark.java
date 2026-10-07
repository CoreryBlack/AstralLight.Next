package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_permission.contract.PolicyContext;
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
 * Sustained throughput (QPS) and scalability benchmark.
 *
 * <p>Measures mean-QPS, latency distribution (P50/P95/P99/P999), and cold-start
 * QPS across varying card scales and concurrency levels. Reports throughput and scalability results
 * for E3 + E5.
 *
 * <h3>Dimensions</h3>
 * <ul>
 *   <li><b>QPS vs Card Scale:</b> fixed 8 threads, vary cards 100 → 50k</li>
 *   <li><b>QPS vs Concurrency:</b> fixed 10k cards, vary threads 1 → 32</li>
 *   <li><b>Cold-start Throughput:</b> flush all caches, 4 threads, 10s window</li>
 * </ul>
 *
 * <h3>Statistical Rigor</h3>
 * <ul>
 *   <li><b>No selective QPS discarding:</b> the previous design sorted the
 *       per-second QPS samples and dropped the lowest 20%, which systematically
 *       biased the mean upward. The current design reports the mean over ALL
 *       measurement windows and separately reports the warmup window so the
 *       reader can see cold-start effects without contaminating the steady-state
 *       mean.</li>
 *   <li><b>Repeat runs with mean ± SD:</b> each (scale, concurrency) pair is
 *       repeated {@link #DEFAULT_REPEATS} times. The reported QPS and latency
 *       are the mean across repeats; the standard deviation is reported
 *       alongside so variance can be assessed.</li>
 *   <li><b>Bootstrap confidence intervals:</b> latency distributions carry
 *       95% CIs from {@link LatencyRecorder.LatencySnapshot#confidenceInterval95Us()}.</li>
 * </ul>
 */
@Slf4j
public class NativeThroughputBenchmark {

    private static final int WARMUP_SEC = 5;
    private static final long TENANT_ID = 1L;
    /** Default number of repeat runs per (scale, concurrency) configuration. */
    private static final int DEFAULT_REPEATS = 3;

    private final PolicyEngine policyEngine;
    private final NativeDataGenerator dataGen;
    private final StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;

    public NativeThroughputBenchmark(PolicyEngine policyEngine,
                                      NativeDataGenerator dataGen,
                                      StringRedisTemplate redisTemplate,
                                      JdbcTemplate jdbcTemplate) {
        this.policyEngine = policyEngine;
        this.dataGen = dataGen;
        this.redisTemplate = redisTemplate;
        this.jdbcTemplate = jdbcTemplate;
    }

    public NativeThroughputResult execute(NativeScaleConfig[] scales,
                                            int[] concurrencyLevels,
                                            int measureSec) throws Exception {
        return execute(scales, concurrencyLevels, measureSec, DEFAULT_REPEATS);
    }

    public NativeThroughputResult execute(NativeScaleConfig[] scales,
                                            int[] concurrencyLevels,
                                            int measureSec,
                                            int repeats) throws Exception {
        log.info("=== Throughput (QPS) Benchmark === scales={}, concurrencies={}, measure={}s, repeats={}",
            scales.length, concurrencyLevels.length, measureSec, repeats);

        NativeThroughputResult result = new NativeThroughputResult();
        result.scaleResults = new ArrayList<>();

        for (NativeScaleConfig scale : scales) {
            log.info("--- Scale: {} ---", scale.label());
            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);

            NativeDataGenerator.NativeGeneratedDataSet ds = dataGen.generate(scale);
            dataGen.persistToDatabase(ds);
            dataGen.populateRedisCache(ds);

            Map<Long, NativeDataGenerator.NativeCardBinding> bm = new LinkedHashMap<>();
            for (var b : ds.bindings) bm.put(b.cardId, b);
            List<NativeDataGenerator.NativeEvalRequest> reqs = ds.evalRequests;

            warmup(ds, bm, reqs);

            ScaleResult sr = new ScaleResult();
            sr.cardCount = scale.getCardCount();
            sr.totalRules = scale.totalNominalRules();
            sr.concurrencyResults = new ArrayList<>();

            for (int concurrency : concurrencyLevels) {
                log.info("  concurrency={} ({} repeats)", concurrency, repeats);
                ConcurrencyResult cr = measureRepeated(ds, reqs, bm, concurrency, measureSec, repeats);
                sr.concurrencyResults.add(cr);
                log.info("    QPS: mean={} (SD={}), p95={}, p99={} | Latency: p50={}us, p99={}us, p999={}us",
                    fmt(cr.meanQps), fmt(cr.stddevQpsAcrossRepeats),
                    fmt(cr.p95Qps), fmt(cr.p99Qps),
                    fmt(cr.latP50), fmt(cr.latP99), fmt(cr.latP999));
            }

            // Cold-start
            log.info("  cold-start ...");
            dataGen.flushAllCaches();
            sr.coldResult = measureRepeated(ds, reqs, bm, Math.min(concurrencyLevels[0], 4),
                Math.min(measureSec, 10), Math.min(repeats, 2));
            log.info("    cold QPS: mean={} (SD={}), lat p99={}us",
                fmt(sr.coldResult.meanQps), fmt(sr.coldResult.stddevQpsAcrossRepeats),
                fmt(sr.coldResult.latP99));

            result.scaleResults.add(sr);
            if (scale.getCardCount() >= 50000) {
                System.gc(); Thread.sleep(2000);
            }
        }
        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
        log.info("=== Throughput Benchmark Complete ===");
        return result;
    }

    /**
     * Run {@code repeats} independent measurements and aggregate the results.
     * Aggregation computes mean and SD across the per-run mean-QPS values.
     */
    private ConcurrencyResult measureRepeated(NativeDataGenerator.NativeGeneratedDataSet ds,
                                                List<NativeDataGenerator.NativeEvalRequest> reqs,
                                                Map<Long, NativeDataGenerator.NativeCardBinding> bm,
                                                int concurrency, int measureSec, int repeats) throws Exception {
        List<ConcurrencyResult> runs = new ArrayList<>(repeats);
        for (int r = 0; r < repeats; r++) {
            runs.add(measure(ds, reqs, bm, concurrency, measureSec));
        }
        return aggregate(runs, concurrency, measureSec);
    }

    private ConcurrencyResult measure(NativeDataGenerator.NativeGeneratedDataSet ds,
                                        List<NativeDataGenerator.NativeEvalRequest> reqs,
                                        Map<Long, NativeDataGenerator.NativeCardBinding> bm,
                                        int concurrency, int measureSec) throws Exception {
        // +1 window: the first second is the warmup-into-steady-state transition;
        // we record it separately and EXCLUDE it from the steady-state mean,
        // but we do NOT discard low values from the steady-state windows themselves.
        int totalWindows = measureSec + 1;
        double[] windowQps = new double[totalWindows];
        LatencyRecorder recorder = new LatencyRecorder();
        AtomicInteger errors = new AtomicInteger(0);
        AtomicBoolean running = new AtomicBoolean(true);
        AtomicLong windowCount = new AtomicLong(0);

        ExecutorService exec = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();

        for (int t = 0; t < concurrency; t++) {
            final int seed = t;
            futures.add(exec.submit(() -> {
                Random rng = new Random(42 + seed);
                while (running.get()) {
                    try {
                        var req = reqs.get(rng.nextInt(reqs.size()));
                        // Set CardContextHolder on the worker thread so ABAC
                        // conditions resolve against the correct thread-local
                        // context — mirrors production auth-filter behavior.
                        IdentityCardContext ic = new IdentityCardContext();
                        ic.setCardId(req.cardId); ic.setUserId(req.userId);
                        ic.setDomainId(req.domainId); ic.setTemplateId(req.templateId);
                        ic.setTenantId(TENANT_ID);
                        NativeDataGenerator.NativeCardBinding b = bm.get(req.cardId);
                        ic.setCardType(b != null ? b.cardType : "STUDENT");
                        ic.setStatus(b != null ? b.cardStatus : "ACTIVE");
                        CardContextHolder.set(ic);

                        long start = recorder.start();
                        policyEngine.evaluate(PolicyContext.builder()
                            .userId(req.userId).cardId(req.cardId).tenantId(TENANT_ID)
                            .domainId(req.domainId).templateId(req.templateId)
                            .resource(req.resourceType).action(req.actionCode)
                            .targetId(req.resourceId)
                            .request(BenchmarkMockRequest.fromAbacContext(req.abacContext)).build());
                        recorder.stop(start);
                        windowCount.incrementAndGet();
                    } catch (Exception e) { errors.incrementAndGet(); }
                }
            }));
        }

        Thread sampler = new Thread(() -> {
            try {
                for (int w = 0; w < totalWindows && running.get(); w++) {
                    Thread.sleep(1000);
                    windowQps[w] = windowCount.getAndSet(0);
                }
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        });
        sampler.setDaemon(true); sampler.start();

        Thread.sleep(measureSec * 1000L + 1000L);  // +1s for the transition window
        running.set(false);
        sampler.join(2000);
        exec.shutdown(); exec.awaitTermination(10, TimeUnit.SECONDS);
        for (Future<?> f : futures) {
            try { f.get(1, TimeUnit.SECONDS); } catch (Exception ignored) {}
        }

        LatencyRecorder.LatencySnapshot ls = recorder.snapshot();
        // Steady-state windows: indices [1..totalWindows-1] (exclude window 0, the
        // warmup-into-steady-state transition). All steady-state samples are kept;
        // no selective discarding of low values.
        double[] steadyQps = Arrays.copyOfRange(windowQps, 1, totalWindows);
        Arrays.sort(steadyQps);

        ConcurrencyResult r = new ConcurrencyResult();
        r.concurrency = concurrency; r.measureSeconds = measureSec;
        r.meanQps = mean(steadyQps); r.stddevQps = stddev(steadyQps, r.meanQps);
        r.p50Qps = pct(steadyQps, 50); r.p95Qps = pct(steadyQps, 95); r.p99Qps = pct(steadyQps, 99);
        r.minQps = steadyQps.length > 0 ? steadyQps[0] : 0;
        r.maxQps = steadyQps.length > 0 ? steadyQps[steadyQps.length - 1] : 0;
        // Warmup transition QPS — reported separately for transparency.
        r.warmupTransitionQps = windowQps[0];
        r.latMean = ls.meanUs(); r.latP50 = ls.p50Us(); r.latP95 = ls.p95Us();
        r.latP99 = ls.p99Us(); r.latP999 = ls.p999Us();
        r.latStddev = ls.stddevUs(); r.totalOps = ls.totalOps(); r.errors = errors.get();
        r.latencySnapshot = ls;
        LatencyRecorder.ConfidenceInterval ci = ls.confidenceInterval95Us();
        if (ci != null) {
            r.latCILowerUs = ci.lower;
            r.latCIUpperUs = ci.upper;
        }
        return r;
    }

    /**
     * Aggregate per-run results into a single ConcurrencyResult.
     * meanQps becomes the mean of per-run meanQps; stddevQpsAcrossRepeats
     * is the SD of per-run meanQps. Latency stats are merged across runs.
     */
    private ConcurrencyResult aggregate(List<ConcurrencyResult> runs, int concurrency, int measureSec) {
        if (runs.size() == 1) {
            ConcurrencyResult r = runs.get(0);
            r.stddevQpsAcrossRepeats = 0.0;
            return r;
        }
        double[] perRunMeanQps = new double[runs.size()];
        for (int i = 0; i < runs.size(); i++) perRunMeanQps[i] = runs.get(i).meanQps;
        double meanOfMeans = mean(perRunMeanQps);
        double sdOfMeans = stddev(perRunMeanQps, meanOfMeans);

        // Merge latency snapshots for combined distribution.
        LatencyRecorder.LatencySnapshot[] snaps = new LatencyRecorder.LatencySnapshot[runs.size()];
        for (int i = 0; i < runs.size(); i++) snaps[i] = runs.get(i).latencySnapshot;
        LatencyRecorder.LatencySnapshot merged = LatencyRecorder.LatencySnapshot.merge(TimeUnit.NANOSECONDS, snaps);

        ConcurrencyResult r = new ConcurrencyResult();
        r.concurrency = concurrency; r.measureSeconds = measureSec;
        r.meanQps = meanOfMeans;
        r.stddevQps = runs.get(0).stddevQps;          // within-run SD (representative)
        r.stddevQpsAcrossRepeats = sdOfMeans;          // across-run SD
        r.p50Qps = meanAcross(runs, c -> c.p50Qps);
        r.p95Qps = meanAcross(runs, c -> c.p95Qps);
        r.p99Qps = meanAcross(runs, c -> c.p99Qps);
        r.minQps = meanAcross(runs, c -> c.minQps);
        r.maxQps = meanAcross(runs, c -> c.maxQps);
        r.warmupTransitionQps = meanAcross(runs, c -> c.warmupTransitionQps);
        r.latMean = merged.meanUs(); r.latP50 = merged.p50Us(); r.latP95 = merged.p95Us();
        r.latP99 = merged.p99Us(); r.latP999 = merged.p999Us();
        r.latStddev = merged.stddevUs(); r.totalOps = merged.totalOps();
        r.errors = runs.stream().mapToInt(c -> c.errors).sum();
        r.latencySnapshot = merged;
        LatencyRecorder.ConfidenceInterval ci = merged.confidenceInterval95Us();
        if (ci != null) {
            r.latCILowerUs = ci.lower;
            r.latCIUpperUs = ci.upper;
        }
        return r;
    }

    private interface DoubleGetter { double get(ConcurrencyResult c); }

    private static double meanAcross(List<ConcurrencyResult> runs, DoubleGetter g) {
        double s = 0; for (var c : runs) s += g.get(c); return runs.isEmpty() ? 0 : s / runs.size();
    }

    private void warmup(NativeDataGenerator.NativeGeneratedDataSet ds,
                         Map<Long, NativeDataGenerator.NativeCardBinding> bm,
                         List<NativeDataGenerator.NativeEvalRequest> reqs) {
        long end = System.currentTimeMillis() + WARMUP_SEC * 1000;
        Random rng = new Random(42);
        while (System.currentTimeMillis() < end) {
            var req = reqs.get(rng.nextInt(reqs.size()));
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

    private static double mean(double[] d) {
        double s = 0; for (double v : d) s += v; return d.length > 0 ? s / d.length : 0;
    }
    private static double stddev(double[] d, double m) {
        if (d.length < 2) return 0;
        double ss = 0; for (double v : d) { double x = v - m; ss += x * x; }
        return Math.sqrt(ss / (d.length - 1));
    }
    private static double pct(double[] d, double p) {
        if (d.length == 0) return 0;
        int i = (int) Math.ceil(p / 100.0 * d.length) - 1;
        return d[Math.max(0, Math.min(i, d.length - 1))];
    }
    private static String fmt(double v) { return String.format("%.1f", v); }

    public static class NativeThroughputResult { public List<ScaleResult> scaleResults; }
    public static class ScaleResult {
        public int cardCount, totalRules;
        public List<ConcurrencyResult> concurrencyResults;
        public ConcurrencyResult coldResult;
    }
    public static class ConcurrencyResult {
        public int concurrency, measureSeconds;
        public double meanQps, stddevQps, p50Qps, p95Qps, p99Qps, minQps, maxQps;
        /** SD of meanQps across repeat runs (0 if repeats == 1). */
        public double stddevQpsAcrossRepeats;
        /** QPS of the warmup→steady-state transition window (reported separately, not in meanQps). */
        public double warmupTransitionQps;
        public double latMean, latP50, latP95, latP99, latP999, latStddev;
        public double latCILowerUs, latCIUpperUs;  // 95% bootstrap CI for latency mean
        public long totalOps; public int errors;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
    }
}
