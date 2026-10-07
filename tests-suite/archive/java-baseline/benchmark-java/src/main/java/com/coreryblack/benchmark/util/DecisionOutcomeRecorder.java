package com.coreryblack.benchmark.util;

import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.LongAdder;

/**
 * Records one observable authorization outcome per benchmark request.
 *
 * <p>Latency-only failure campaigns cannot distinguish a fail-closed decision
 * from an exception or a skipped call. This recorder keeps those states
 * separate and preserves the raw rows for later audit and re-analysis.</p>
 *
 * <p>In a heterogeneous cluster run the recorder additionally captures the
 * node identity/role, a deterministic global sequence, and the projection
 * state observed for the request (source/projected generation, revoke fence,
 * projection status), so a stale authorization window can be attributed to a
 * specific node and phase.</p>
 */
public final class DecisionOutcomeRecorder {

    private final ConcurrentLinkedQueue<DecisionOutcome> outcomes = new ConcurrentLinkedQueue<>();
    private final LongAdder allowed = new LongAdder();
    private final LongAdder denied = new LongAdder();
    private final LongAdder failures = new LongAdder();
    private final LongAdder expectedAllowMismatches = new LongAdder();
    private final LongAdder expectedDenyMismatches = new LongAdder();

    public void recordDecision(String phase, int requestIndex,
                               NativeDataGenerator.NativeEvalRequest request,
                               PolicyDecision decision, long latencyNanos) {
        Objects.requireNonNull(decision, "decision");
        String expected = expectedOutcome(request);
        String outcome = decision.isAllowed() ? "ALLOW" : "DENY";
        record(new DecisionOutcome(
                Instant.now().toString(), phase, requestIndex,
                request == null ? null : request.cardId,
                request == null ? null : request.userId,
                request == null ? null : request.resourceType,
                request == null ? null : request.actionCode,
                outcome, decision.isAllowed(), decision.getReason(), null,
                decisionSource(decision), terminalSource(decision), expected, latencyNanos,
                null, null, null, 0L, null, null, null, null, null, null));
    }

    /**
     * Cluster-aware decision recording. In addition to the single-node fields,
     * captures the node identity/role, a deterministic global sequence, the
     * request operation id, and the projection state observed at evaluation
     * time so stale-authorization windows can be attributed per node and phase.
     */
    public void recordDecision(ClusterRunContext ctx, long globalSequence, String operationId,
                               String phase, int requestIndex,
                               NativeDataGenerator.NativeEvalRequest request,
                               PolicyDecision decision, long latencyNanos,
                               Long sourceGeneration, Long projectedGeneration,
                               Long revokeFence, String projectionStatus, String faultState) {
        Objects.requireNonNull(decision, "decision");
        String expected = expectedOutcome(request);
        String outcome = decision.isAllowed() ? "ALLOW" : "DENY";
        record(new DecisionOutcome(
                Instant.now().toString(), phase, requestIndex,
                request == null ? null : request.cardId,
                request == null ? null : request.userId,
                request == null ? null : request.resourceType,
                request == null ? null : request.actionCode,
                outcome, decision.isAllowed(), decision.getReason(), null,
                decisionSource(decision), terminalSource(decision), expected, latencyNanos,
                ctx == null ? null : ctx.nodeId(),
                ctx == null ? null : ctx.nodeRole(),
                ctx == null ? null : ctx.rolePermutation(),
                globalSequence, operationId,
                sourceGeneration, projectedGeneration, revokeFence, projectionStatus, faultState));
    }

    public void recordCircuitOpen(String phase, int requestIndex,
                                  NativeDataGenerator.NativeEvalRequest request,
                                  long latencyNanos) {
        record(new DecisionOutcome(
                Instant.now().toString(), phase, requestIndex,
                request == null ? null : request.cardId,
                request == null ? null : request.userId,
                request == null ? null : request.resourceType,
                request == null ? null : request.actionCode,
                "DENY", false, "CIRCUIT_BREAKER_OPEN", null,
                "BENCHMARK_SHORT_CIRCUIT", "CIRCUIT_BREAKER", expectedOutcome(request), latencyNanos,
                null, null, null, 0L, null, null, null, null, null, null));
    }

    public void recordCircuitOpen(ClusterRunContext ctx, long globalSequence, String operationId,
                                  String phase, int requestIndex,
                                  NativeDataGenerator.NativeEvalRequest request,
                                  long latencyNanos, String faultState) {
        record(new DecisionOutcome(
                Instant.now().toString(), phase, requestIndex,
                request == null ? null : request.cardId,
                request == null ? null : request.userId,
                request == null ? null : request.resourceType,
                request == null ? null : request.actionCode,
                "DENY", false, "CIRCUIT_BREAKER_OPEN", null,
                "BENCHMARK_SHORT_CIRCUIT", "CIRCUIT_BREAKER", expectedOutcome(request), latencyNanos,
                ctx == null ? null : ctx.nodeId(),
                ctx == null ? null : ctx.nodeRole(),
                ctx == null ? null : ctx.rolePermutation(),
                globalSequence, operationId, null, null, null, null, faultState));
    }

    public void recordFailure(String phase, int requestIndex,
                              NativeDataGenerator.NativeEvalRequest request,
                              Throwable failure, long latencyNanos) {
        Throwable cause = failure == null ? null : failure;
        record(new DecisionOutcome(
                Instant.now().toString(), phase, requestIndex,
                request == null ? null : request.cardId,
                request == null ? null : request.userId,
                request == null ? null : request.resourceType,
                request == null ? null : request.actionCode,
                "ERROR", false, null,
                cause == null ? null : cause.getClass().getName(),
                "EXCEPTION", null, expectedOutcome(request), latencyNanos,
                null, null, null, 0L, null, null, null, null, null, null));
    }

    public void recordFailure(ClusterRunContext ctx, long globalSequence, String operationId,
                              String phase, int requestIndex,
                              NativeDataGenerator.NativeEvalRequest request,
                              Throwable failure, long latencyNanos,
                              Long sourceGeneration, Long projectedGeneration,
                              Long revokeFence, String projectionStatus, String faultState) {
        Throwable cause = failure == null ? null : failure;
        record(new DecisionOutcome(
                Instant.now().toString(), phase, requestIndex,
                request == null ? null : request.cardId,
                request == null ? null : request.userId,
                request == null ? null : request.resourceType,
                request == null ? null : request.actionCode,
                "ERROR", false, null,
                cause == null ? null : cause.getClass().getName(),
                "EXCEPTION", null, expectedOutcome(request), latencyNanos,
                ctx == null ? null : ctx.nodeId(),
                ctx == null ? null : ctx.nodeRole(),
                ctx == null ? null : ctx.rolePermutation(),
                globalSequence, operationId,
                sourceGeneration, projectedGeneration, revokeFence, projectionStatus, faultState));
    }

    private void record(DecisionOutcome outcome) {
        outcomes.add(outcome);
        switch (outcome.outcome()) {
            case "ALLOW" -> allowed.increment();
            case "DENY" -> denied.increment();
            default -> failures.increment();
        }
        if (outcome.expectedOutcome() != null) {
            if ("ALLOW".equals(outcome.expectedOutcome()) && !outcome.allowed()) {
                expectedAllowMismatches.increment();
            }
            if ("DENY".equals(outcome.expectedOutcome()) && outcome.allowed()) {
                expectedDenyMismatches.increment();
            }
        }
    }

    private static String expectedOutcome(NativeDataGenerator.NativeEvalRequest request) {
        if (request == null || !request.expectedCardOnlyHit) {
            return null;
        }
        return request.expectedCardOnlyEffect == null
                ? null
                : request.expectedCardOnlyEffect.toUpperCase();
    }

    private static String decisionSource(PolicyDecision decision) {
        return "CIRCUIT_BREAKER_OPEN".equals(decision.getReason())
                ? "POLICY_ENGINE_CIRCUIT_BREAKER"
                : "POLICY_ENGINE";
    }

    private static String terminalSource(PolicyDecision decision) {
        if (decision.getEvaluationPath() == null || decision.getEvaluationPath().isEmpty()) {
            return null;
        }
        PolicyDecision.EvaluationStep step = decision.getEvaluationPath()
                .get(decision.getEvaluationPath().size() - 1);
        return step == null ? null : step.getSource();
    }

    public List<DecisionOutcome> snapshot() {
        return List.copyOf(new ArrayList<>(outcomes));
    }

    public long allowedCount() {
        return allowed.sum();
    }

    public long deniedCount() {
        return denied.sum();
    }

    public long failureCount() {
        return failures.sum();
    }

    public long expectedAllowMismatchCount() {
        return expectedAllowMismatches.sum();
    }

    public long expectedDenyMismatchCount() {
        return expectedDenyMismatches.sum();
    }

    public static AuditResult audit(List<DecisionOutcome> rows) {
        return audit(rows, 0);
    }

    /**
     * Audits the measured request rows. A positive expected count requires every
     * RQ4-A phase to preserve one row per attempted request.
     */
    public static AuditResult audit(List<DecisionOutcome> rows, int expectedRequestsPerPhase) {
        if (rows == null || rows.isEmpty()) {
            return new AuditResult(false, "no decision samples");
        }
        Set<String> phases = rows.stream().map(DecisionOutcome::phase).collect(java.util.stream.Collectors.toSet());
        if (!phases.containsAll(Set.of("NORMAL", "REDIS_DOWN", "CB_OPEN", "RECOVERY"))) {
            return new AuditResult(false, "missing one or more required phases: " + phases);
        }
        for (DecisionOutcome row : rows) {
            if (row.phase() == null || row.phase().isBlank()) {
                return new AuditResult(false, "decision row has no phase");
            }
            if (!Set.of("ALLOW", "DENY", "ERROR").contains(row.outcome())) {
                return new AuditResult(false, "unknown outcome at request " + row.requestIndex());
            }
            if ("ERROR".equals(row.outcome()) && row.allowed()) {
                return new AuditResult(false, "ERROR row marked allowed at request " + row.requestIndex());
            }
            if (!"ERROR".equals(row.outcome())
                    && (row.decisionSource() == null || row.decisionSource().isBlank())) {
                return new AuditResult(false, "returned decision has no decision_source at request "
                        + row.requestIndex());
            }
            if ("CIRCUIT_BREAKER_OPEN".equals(row.reason())
                    && (!"DENY".equals(row.outcome()) || row.allowed()
                    || !Set.of("BENCHMARK_SHORT_CIRCUIT", "POLICY_ENGINE_CIRCUIT_BREAKER")
                            .contains(row.decisionSource()))) {
                return new AuditResult(false, "circuit-open outcome was not an observable DENY");
            }
        }
        if (expectedRequestsPerPhase > 0) {
            for (String phase : Set.of("NORMAL", "REDIS_DOWN", "CB_OPEN", "RECOVERY")) {
                long count = rows.stream().filter(row -> phase.equals(row.phase())).count();
                if (count != expectedRequestsPerPhase) {
                    return new AuditResult(false, phase + " row count=" + count
                            + ", expected=" + expectedRequestsPerPhase);
                }
            }
        }
        boolean downPolicyDecision = rows.stream()
                .anyMatch(row -> "REDIS_DOWN".equals(row.phase())
                        && row.decisionSource() != null
                        && row.decisionSource().startsWith("POLICY_ENGINE"));
        if (!downPolicyDecision) {
            return new AuditResult(false, "REDIS_DOWN must contain an actual POLICY_ENGINE invocation");
        }
        boolean normalPolicyDecision = rows.stream()
                .anyMatch(row -> "NORMAL".equals(row.phase()) && "POLICY_ENGINE".equals(row.decisionSource()));
        boolean recoveryPolicyDecision = rows.stream()
                .anyMatch(row -> "RECOVERY".equals(row.phase()) && "POLICY_ENGINE".equals(row.decisionSource()));
        if (!normalPolicyDecision || !recoveryPolicyDecision) {
            return new AuditResult(false,
                    "NORMAL and RECOVERY must contain actual POLICY_ENGINE decisions");
        }
        return new AuditResult(true, "decision samples, provenance, and phase coverage are valid");
    }

    public record AuditResult(boolean valid, String detail) {
    }

    public static void writeCsv(Path path, List<DecisionOutcome> rows) throws IOException {
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try (BufferedWriter writer = Files.newBufferedWriter(path,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            writer.write(DecisionOutcome.csvHeader());
            writer.newLine();
            for (DecisionOutcome row : rows) {
                writer.write(row.toCsvRow());
                writer.newLine();
            }
        }
    }

    public record DecisionOutcome(
            String timestamp,
            String phase,
            int requestIndex,
            Long cardId,
            Long userId,
            String resource,
            String action,
            String outcome,
            boolean allowed,
            String reason,
            String exceptionType,
            String decisionSource,
            String decisionPath,
            String expectedOutcome,
            long latencyNanos,
            String nodeId,
            String nodeRole,
            String rolePermutation,
            long globalSequence,
            String operationId,
            Long sourceGeneration,
            Long projectedGeneration,
            Long revokeFence,
            String projectionStatus,
            String faultState) {

        public static String csvHeader() {
            return "timestamp,phase,request_index,card_id,user_id,resource,action,outcome,allowed,reason,exception_type,decision_source,decision_path,expected_outcome,latency_nanos,node_id,node_role,role_permutation,global_sequence,operation_id,source_generation,projected_generation,revoke_fence,projection_status,fault_state";
        }

        public String toCsvRow() {
            return String.join(",",
                    csv(timestamp), csv(phase), Integer.toString(requestIndex),
                    value(cardId), value(userId), csv(resource), csv(action),
                    csv(outcome), Boolean.toString(allowed), csv(reason),
                    csv(exceptionType), csv(decisionSource), csv(decisionPath),
                    csv(expectedOutcome), Long.toString(latencyNanos),
                    csv(nodeId), csv(nodeRole), csv(rolePermutation),
                    Long.toString(globalSequence), csv(operationId),
                    value(sourceGeneration), value(projectedGeneration), value(revokeFence),
                    csv(projectionStatus), csv(faultState));
        }

        private static String value(Object value) {
            return value == null ? "" : value.toString();
        }

        private static String csv(String value) {
            if (value == null) {
                return "";
            }
            String escaped = value.replace("\"", "\"\"");
            return escaped.indexOf(',') >= 0 || escaped.indexOf('"') >= 0
                    || escaped.indexOf('\n') >= 0
                    ? "\"" + escaped + "\""
                    : escaped;
        }
    }
}
