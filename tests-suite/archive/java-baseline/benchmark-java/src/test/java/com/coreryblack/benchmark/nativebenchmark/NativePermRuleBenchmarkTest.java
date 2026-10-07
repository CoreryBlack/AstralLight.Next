package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.benchmark.util.LatencyRecorder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativePermRuleBenchmarkTest {

    @Test
    void conservedCountersAcceptSuccessfulAuditableTrace() {
        LatencyRecorder recorder = new LatencyRecorder();
        recorder.record(1_000L);
        recorder.record(2_000L);

        NativePermRuleBenchmark.NativePermRuleResult result = new NativePermRuleBenchmark.NativePermRuleResult();
        result.latencySnapshot = recorder.snapshot();
        result.earlyDenyCount = 0;
        result.ruleStageEvaluations = 2;
        result.totalEvaluations = 2;
        result.measuredRequests = 2;
        result.injectedCardOnlyHitRequests = 1;
        result.expectedAllow = 1;
        result.actualL2Allow = 1;
        result.reasonDistribution = java.util.Map.of("RULE_ALLOW", 1L, "DEFAULT_DENY", 1L);
        result.errors = 0;

        assertTrue(result.hasConservedCounts());
    }

    @Test
    void conservedCountersRejectMissingReasonOrErrorAccounting() {
        LatencyRecorder recorder = new LatencyRecorder();
        recorder.record(1_000L);
        recorder.recordError(2_000L);

        NativePermRuleBenchmark.NativePermRuleResult result = new NativePermRuleBenchmark.NativePermRuleResult();
        result.latencySnapshot = recorder.snapshot();
        result.measuredRequests = 2;
        result.injectedCardOnlyHitRequests = 1;
        result.expectedAllow = 1;
        result.reasonDistribution = java.util.Map.of("RULE_ALLOW", 1L);
        result.errors = 0;

        assertFalse(result.hasConservedCounts());
    }
}
