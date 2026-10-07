package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.benchmark.util.LatencyRecorder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeRq5ArtifactWriterTest {

    @TempDir
    Path outputDir;

    @Test
    void writesDirectPdpAndThroughputSummariesWithRawSamples() throws Exception {
        NativeRq5ArtifactWriter.writeDirectPdpArtifacts(outputDir, directPdpResult());
        NativeRq5ArtifactWriter.writeThroughputArtifacts(outputDir, throughputResult());

        assertTrue(Files.readString(outputDir.resolve("rq5a_direct_pdp_summary.csv"))
                .contains("parameter_dependence_anomalies"));
        assertTrue(Files.readString(outputDir.resolve("rq5a_direct_pdp_latency_nanos.csv"))
                .contains("100"));
        assertTrue(Files.readString(outputDir.resolve("rq5a_cache_repopulation_pairs.csv"))
                .contains("2001,100,200,100"));
        assertTrue(Files.readString(outputDir.resolve("rq5b_throughput_summary.csv"))
                .contains("100,50,warm"));
        assertTrue(Files.readString(outputDir.resolve("rq5b_throughput_latency_nanos.csv"))
                .contains("100,warm,4,0,100"));
    }

    private NativeSwitchAtomicityBenchmark.NativeSwitchAtomicityResult directPdpResult() {
        LatencyRecorder recorder = new LatencyRecorder();
        recorder.record(100L);

        NativeSwitchAtomicityBenchmark.SwitchEvalResult scenarioA =
                new NativeSwitchAtomicityBenchmark.SwitchEvalResult();
        scenarioA.totalEvals.set(1);
        scenarioA.judgedEvals.set(1);
        scenarioA.lSnapshot = recorder.snapshot();

        NativeSwitchAtomicityBenchmark.ContextDependenceResult scenarioC =
                new NativeSwitchAtomicityBenchmark.ContextDependenceResult();
        scenarioC.totalEvaluations = 1;

        NativeSwitchAtomicityBenchmark.CacheWindowResult scenarioD =
                new NativeSwitchAtomicityBenchmark.CacheWindowResult();
        scenarioD.requestedSampleCount = 1;
        scenarioD.sampleCount = 1;
        scenarioD.rawSamples = List.of(
                new NativeSwitchAtomicityBenchmark.CacheRepopulationSample(2001L, 100L, 200L));

        NativeSwitchAtomicityBenchmark.NativeSwitchAtomicityResult result =
                new NativeSwitchAtomicityBenchmark.NativeSwitchAtomicityResult();
        result.cardCount = 2;
        result.scenarioA = scenarioA;
        result.scenarioC = scenarioC;
        result.scenarioD = scenarioD;
        return result;
    }

    private NativeThroughputBenchmark.NativeThroughputResult throughputResult() {
        LatencyRecorder recorder = new LatencyRecorder();
        recorder.record(100L);

        NativeThroughputBenchmark.ConcurrencyResult concurrency =
                new NativeThroughputBenchmark.ConcurrencyResult();
        concurrency.concurrency = 4;
        concurrency.measureSeconds = 15;
        concurrency.meanQps = 10.0;
        concurrency.latencySnapshot = recorder.snapshot();

        NativeThroughputBenchmark.ScaleResult scale = new NativeThroughputBenchmark.ScaleResult();
        scale.cardCount = 100;
        scale.totalRules = 50;
        scale.concurrencyResults = new ArrayList<>(List.of(concurrency));

        NativeThroughputBenchmark.NativeThroughputResult result =
                new NativeThroughputBenchmark.NativeThroughputResult();
        result.scaleResults = List.of(scale);
        return result;
    }
}
