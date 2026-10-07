package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.benchmark.util.LatencyRecorder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Persists the direct-PDP and throughput measurements that are otherwise only
 * visible in benchmark logs.
 */
final class NativeRq5ArtifactWriter {

    private NativeRq5ArtifactWriter() {
    }

    static void writeDirectPdpArtifacts(Path outputDir,
                                        NativeSwitchAtomicityBenchmark.NativeSwitchAtomicityResult result)
            throws IOException {
        Files.createDirectories(outputDir);
        writeDirectPdpSummary(outputDir.resolve("rq5a_direct_pdp_summary.csv"), result);
        writeLatencySamples(outputDir.resolve("rq5a_direct_pdp_latency_nanos.csv"),
                result.scenarioA == null ? null : result.scenarioA.lSnapshot);
        writeCachePairs(outputDir.resolve("rq5a_cache_repopulation_pairs.csv"), result.scenarioD);
    }

    static void writeThroughputArtifacts(Path outputDir,
                                         NativeThroughputBenchmark.NativeThroughputResult result)
            throws IOException {
        Files.createDirectories(outputDir);
        StringBuilder summary = new StringBuilder();
        summary.append("card_count,total_rules,mode,concurrency,measure_seconds,mean_qps,stddev_qps_across_repeats,")
                .append("p50_qps,p95_qps,p99_qps,lat_mean_us,lat_p50_us,lat_p95_us,lat_p99_us,")
                .append("lat_ci95_low_us,lat_ci95_high_us,total_ops,errors\n");
        StringBuilder latencies = new StringBuilder("card_count,mode,concurrency,sample_index,latency_nanos\n");

        if (result != null && result.scaleResults != null) {
            for (NativeThroughputBenchmark.ScaleResult scale : result.scaleResults) {
                if (scale.concurrencyResults != null) {
                    for (NativeThroughputBenchmark.ConcurrencyResult concurrency : scale.concurrencyResults) {
                        appendThroughputSummary(summary, scale, "warm", concurrency);
                        appendLatencySamples(latencies, scale.cardCount, "warm", concurrency);
                    }
                }
                if (scale.coldResult != null) {
                    appendThroughputSummary(summary, scale, "cold", scale.coldResult);
                    appendLatencySamples(latencies, scale.cardCount, "cold", scale.coldResult);
                }
            }
        }

        Files.writeString(outputDir.resolve("rq5b_throughput_summary.csv"), summary.toString(), StandardCharsets.UTF_8);
        Files.writeString(outputDir.resolve("rq5b_throughput_latency_nanos.csv"), latencies.toString(), StandardCharsets.UTF_8);
    }

    private static void writeDirectPdpSummary(Path outputPath,
                                              NativeSwitchAtomicityBenchmark.NativeSwitchAtomicityResult result)
            throws IOException {
        StringBuilder summary = new StringBuilder("scenario,metric,value\n");
        if (result != null) {
            append(summary, "run", "card_count", result.cardCount);
            append(summary, "run", "switchable_user_count", result.switchableUserCount);
            if (result.scenarioA != null) {
                append(summary, "E2", "attempted_evaluations", result.scenarioA.totalEvals.get());
                append(summary, "E2", "judged_evaluations", result.scenarioA.judgedEvals.get());
                append(summary, "E2", "skipped_evaluations", result.scenarioA.skippedEvals.get());
                append(summary, "E2", "reference_mismatches", result.scenarioA.isolationViolations.get());
                append(summary, "E2", "errors", result.scenarioA.errorCount.get());
                appendLatencyMetrics(summary, "E2", result.scenarioA.lSnapshot);
            }
            if (result.scenarioB != null) {
                append(summary, "E2-isolation", "divergence_checks", result.scenarioB.divergenceChecks);
                append(summary, "E2-isolation", "cross_card_divergence", result.scenarioB.crossCardDivergence);
                append(summary, "E2-isolation", "leakage_checks", result.scenarioB.leakageChecks);
                append(summary, "E2-isolation", "cross_card_leakage", result.scenarioB.crossCardLeakage);
            }
            if (result.scenarioC != null) {
                append(summary, "E11", "context_evaluations", result.scenarioC.totalEvaluations);
                append(summary, "E11", "parameter_dependence_anomalies", result.scenarioC.anomalyCount);
            }
            if (result.scenarioD != null) {
                append(summary, "E4", "requested_samples", result.scenarioD.requestedSampleCount);
                append(summary, "E4", "retained_samples", result.scenarioD.sampleCount);
                append(summary, "E4", "setup_failures", result.scenarioD.setupFailureCount);
                append(summary, "E4", "warm_median_us", result.scenarioD.warmMedianUs);
                append(summary, "E4", "cold_median_us", result.scenarioD.coldMedianUs);
                append(summary, "E4", "paired_overhead_median_us", result.scenarioD.overheadMedianUs);
                append(summary, "E4", "warm_p99_us", result.scenarioD.warmP99Us);
                append(summary, "E4", "cold_p99_us", result.scenarioD.coldP99Us);
            }
        }
        Files.writeString(outputPath, summary.toString(), StandardCharsets.UTF_8);
    }

    private static void writeLatencySamples(Path outputPath, LatencyRecorder.LatencySnapshot snapshot)
            throws IOException {
        StringBuilder samples = new StringBuilder("sample_index,latency_nanos\n");
        if (snapshot != null) {
            int index = 0;
            for (Long latencyNanos : snapshot.rawSamples()) {
                samples.append(index++).append(',').append(latencyNanos).append('\n');
            }
        }
        Files.writeString(outputPath, samples.toString(), StandardCharsets.UTF_8);
    }

    private static void writeCachePairs(Path outputPath,
                                        NativeSwitchAtomicityBenchmark.CacheWindowResult result)
            throws IOException {
        StringBuilder samples = new StringBuilder("card_id,warm_nanos,cold_nanos,overhead_nanos\n");
        if (result != null && result.rawSamples != null) {
            for (NativeSwitchAtomicityBenchmark.CacheRepopulationSample sample : result.rawSamples) {
                samples.append(sample.cardId()).append(',')
                        .append(sample.warmNanos()).append(',')
                        .append(sample.coldNanos()).append(',')
                        .append(sample.coldNanos() - sample.warmNanos()).append('\n');
            }
        }
        Files.writeString(outputPath, samples.toString(), StandardCharsets.UTF_8);
    }

    private static void appendThroughputSummary(StringBuilder summary,
                                                NativeThroughputBenchmark.ScaleResult scale,
                                                String mode,
                                                NativeThroughputBenchmark.ConcurrencyResult result) {
        summary.append(scale.cardCount).append(',')
                .append(scale.totalRules).append(',')
                .append(mode).append(',')
                .append(result.concurrency).append(',')
                .append(result.measureSeconds).append(',')
                .append(result.meanQps).append(',')
                .append(result.stddevQpsAcrossRepeats).append(',')
                .append(result.p50Qps).append(',')
                .append(result.p95Qps).append(',')
                .append(result.p99Qps).append(',')
                .append(result.latMean).append(',')
                .append(result.latP50).append(',')
                .append(result.latP95).append(',')
                .append(result.latP99).append(',')
                .append(result.latCILowerUs).append(',')
                .append(result.latCIUpperUs).append(',')
                .append(result.totalOps).append(',')
                .append(result.errors).append('\n');
    }

    private static void appendLatencySamples(StringBuilder samples, int cardCount,
                                             String mode,
                                             NativeThroughputBenchmark.ConcurrencyResult result) {
        if (result.latencySnapshot == null) {
            return;
        }
        int index = 0;
        for (Long latencyNanos : result.latencySnapshot.rawSamples()) {
            samples.append(cardCount).append(',')
                    .append(mode).append(',')
                    .append(result.concurrency).append(',')
                    .append(index++).append(',')
                    .append(latencyNanos).append('\n');
        }
    }

    private static void appendLatencyMetrics(StringBuilder summary, String scenario,
                                             LatencyRecorder.LatencySnapshot snapshot) {
        if (snapshot == null) {
            return;
        }
        append(summary, scenario, "latency_samples", snapshot.sampleCount());
        append(summary, scenario, "latency_mean_us", snapshot.meanUs());
        append(summary, scenario, "latency_p50_us", snapshot.p50Us());
        append(summary, scenario, "latency_p95_us", snapshot.p95Us());
        append(summary, scenario, "latency_p99_us", snapshot.p99Us());
    }

    private static void append(StringBuilder target, String scenario, String metric, Object value) {
        target.append(scenario).append(',').append(metric).append(',').append(value).append('\n');
    }
}
