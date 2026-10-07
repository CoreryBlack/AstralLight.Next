package com.coreryblack.benchmark.permission;

import com.coreryblack.permission.auth.PolicyEngine;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
public class PermissionBenchmark {

    private final PolicyEngine policyEngine;

    public PermissionBenchmark(PolicyEngine policyEngine) {
        this.policyEngine = policyEngine;
    }

    public BenchmarkResult runBenchmark(BenchmarkConfig config) {
        BenchmarkResult result = new BenchmarkResult();
        result.setConfig(config);
        result.setResults(new ArrayList<>());

        List<Long> latencies = new ArrayList<>();
        int allowCount = 0;
        int denyCount = 0;
        int errorCount = 0;

        for (int i = 0; i < config.getWarmupIterations(); i++) {
            try {
                evaluateOnce(config, i);
            } catch (Exception ignored) {}
        }

        long totalStartNanos = System.nanoTime();

        for (int i = 0; i < config.getIterations(); i++) {
            long startNanos = System.nanoTime();
            try {
                com.coreryblack.astral_permission.contract.PolicyDecision decision =
                        evaluateOnce(config, i);
                long elapsedNanos = System.nanoTime() - startNanos;
                latencies.add(elapsedNanos);
                if (decision.isAllowed()) {
                    allowCount++;
                } else {
                    denyCount++;
                }
            } catch (Exception e) {
                long elapsedNanos = System.nanoTime() - startNanos;
                latencies.add(elapsedNanos);
                errorCount++;
            }
        }

        long totalElapsedNanos = System.nanoTime() - totalStartNanos;

        if (!latencies.isEmpty()) {
            latencies.sort(Long::compareTo);
            result.setTotalIterations(config.getIterations());
            result.setTotalTimeMs(TimeUnit.NANOSECONDS.toMillis(totalElapsedNanos));
            result.setTps(calculateTps(config.getIterations(), totalElapsedNanos));
            result.setMeanLatencyUs(calculateMean(latencies) / 1000.0);
            result.setP50LatencyUs(percentile(latencies, 50) / 1000.0);
            result.setP90LatencyUs(percentile(latencies, 90) / 1000.0);
            result.setP95LatencyUs(percentile(latencies, 95) / 1000.0);
            result.setP99LatencyUs(percentile(latencies, 99) / 1000.0);
            result.setMinLatencyUs(latencies.get(0) / 1000.0);
            result.setMaxLatencyUs(latencies.get(latencies.size() - 1) / 1000.0);
            result.setAllowCount(allowCount);
            result.setDenyCount(denyCount);
            result.setErrorCount(errorCount);
            result.setAllowRate((double) allowCount / config.getIterations() * 100);
        }

        log.info("Benchmark completed: iterations={}, tps={}, p50={}us, p99={}us, allowRate={}%",
                config.getIterations(), result.getTps(),
                String.format("%.1f", result.getP50LatencyUs()),
                String.format("%.1f", result.getP99LatencyUs()),
                String.format("%.1f", result.getAllowRate()));

        return result;
    }

    private com.coreryblack.astral_permission.contract.PolicyDecision evaluateOnce(
            BenchmarkConfig config, int iteration) {
        String[] resources = config.getResources();
        String[] actions = config.getActions();
        String resource = resources[iteration % resources.length];
        String action = actions[iteration % actions.length];

        com.coreryblack.astral_permission.contract.PolicyContext context =
                com.coreryblack.astral_permission.contract.PolicyContext.builder()
                        .userId(config.getUserId())
                        .cardId(config.getCardId())
                        .tenantId(1L).domainId(1L).templateId(1L)
                        .resource(resource)
                        .action(action)
                        .targetId(config.getTargetIds() != null && config.getTargetIds().length > 0
                                ? config.getTargetIds()[iteration % config.getTargetIds().length] : null)
                        .build();

        return policyEngine.evaluate(context);
    }

    private double calculateTps(int iterations, long totalNanos) {
        if (totalNanos == 0) return 0;
        return iterations * 1_000_000_000.0 / totalNanos;
    }

    private double calculateMean(List<Long> values) {
        if (values.isEmpty()) return 0;
        long sum = 0;
        for (Long v : values) sum += v;
        return (double) sum / values.size();
    }

    private long percentile(List<Long> sortedValues, int percentile) {
        if (sortedValues.isEmpty()) return 0;
        int index = (int) Math.ceil(percentile / 100.0 * sortedValues.size()) - 1;
        return sortedValues.get(Math.max(0, Math.min(index, sortedValues.size() - 1)));
    }

    public static class BenchmarkConfig {
        private int warmupIterations = 100;
        private int iterations = 1000;
        private Long userId = 1L;
        private Long cardId = 1L;
        private String[] resources = {"learn_subject", "learn_question", "learn_chapter"};
        private String[] actions = {"read", "create", "update", "delete"};
        private Long[] targetIds = {null, 1L, 42L, 100L};

        public int getWarmupIterations() { return warmupIterations; }
        public void setWarmupIterations(int warmupIterations) { this.warmupIterations = warmupIterations; }
        public int getIterations() { return iterations; }
        public void setIterations(int iterations) { this.iterations = iterations; }
        public Long getUserId() { return userId; }
        public void setUserId(Long userId) { this.userId = userId; }
        public Long getCardId() { return cardId; }
        public void setCardId(Long cardId) { this.cardId = cardId; }
        public String[] getResources() { return resources; }
        public void setResources(String[] resources) { this.resources = resources; }
        public String[] getActions() { return actions; }
        public void setActions(String[] actions) { this.actions = actions; }
        public Long[] getTargetIds() { return targetIds; }
        public void setTargetIds(Long[] targetIds) { this.targetIds = targetIds; }
    }

    public static class BenchmarkResult {
        private BenchmarkConfig config;
        private List<com.coreryblack.astral_permission.contract.PolicyDecision> results;
        private int totalIterations;
        private long totalTimeMs;
        private double tps;
        private double meanLatencyUs;
        private double p50LatencyUs;
        private double p90LatencyUs;
        private double p95LatencyUs;
        private double p99LatencyUs;
        private double minLatencyUs;
        private double maxLatencyUs;
        private int allowCount;
        private int denyCount;
        private int errorCount;
        private double allowRate;

        public BenchmarkConfig getConfig() { return config; }
        public void setConfig(BenchmarkConfig config) { this.config = config; }
        public List<com.coreryblack.astral_permission.contract.PolicyDecision> getResults() { return results; }
        public void setResults(List<com.coreryblack.astral_permission.contract.PolicyDecision> results) { this.results = results; }
        public int getTotalIterations() { return totalIterations; }
        public void setTotalIterations(int totalIterations) { this.totalIterations = totalIterations; }
        public long getTotalTimeMs() { return totalTimeMs; }
        public void setTotalTimeMs(long totalTimeMs) { this.totalTimeMs = totalTimeMs; }
        public double getTps() { return tps; }
        public void setTps(double tps) { this.tps = tps; }
        public double getMeanLatencyUs() { return meanLatencyUs; }
        public void setMeanLatencyUs(double meanLatencyUs) { this.meanLatencyUs = meanLatencyUs; }
        public double getP50LatencyUs() { return p50LatencyUs; }
        public void setP50LatencyUs(double p50LatencyUs) { this.p50LatencyUs = p50LatencyUs; }
        public double getP90LatencyUs() { return p90LatencyUs; }
        public void setP90LatencyUs(double p90LatencyUs) { this.p90LatencyUs = p90LatencyUs; }
        public double getP95LatencyUs() { return p95LatencyUs; }
        public void setP95LatencyUs(double p95LatencyUs) { this.p95LatencyUs = p95LatencyUs; }
        public double getP99LatencyUs() { return p99LatencyUs; }
        public void setP99LatencyUs(double p99LatencyUs) { this.p99LatencyUs = p99LatencyUs; }
        public double getMinLatencyUs() { return minLatencyUs; }
        public void setMinLatencyUs(double minLatencyUs) { this.minLatencyUs = minLatencyUs; }
        public double getMaxLatencyUs() { return maxLatencyUs; }
        public void setMaxLatencyUs(double maxLatencyUs) { this.maxLatencyUs = maxLatencyUs; }
        public int getAllowCount() { return allowCount; }
        public void setAllowCount(int allowCount) { this.allowCount = allowCount; }
        public int getDenyCount() { return denyCount; }
        public void setDenyCount(int denyCount) { this.denyCount = denyCount; }
        public int getErrorCount() { return errorCount; }
        public void setErrorCount(int errorCount) { this.errorCount = errorCount; }
        public double getAllowRate() { return allowRate; }
        public void setAllowRate(double allowRate) { this.allowRate = allowRate; }
    }
}
