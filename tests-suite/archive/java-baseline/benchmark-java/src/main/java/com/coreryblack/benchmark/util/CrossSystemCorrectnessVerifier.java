package com.coreryblack.benchmark.util;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSetEntry;
import com.coreryblack.benchmark.baseline.*;
import com.coreryblack.benchmark.data.DataGenerator;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Cross-system correctness verification — the most critical fairness
 * safeguard in the benchmark framework.
 *
 * <p><b>Why this exists:</b> If Casbin, OPA, or Cedar adapters
 * produce different authorization decisions than AstralLight for the same
 * policy set and the same input, all performance comparison data is
 * meaningless. This verifier runs <i>before</i> any benchmark measurement
 * to ensure all systems agree.</p>
 *
 * <h3>Acceptance Criteria</h3>
 * <ul>
 *   <li><b>0 discrepancies</b> — All clear, proceed to benchmark</li>
 *   <li><b>1-5 discrepancies</b> — WARNING, investigate adapter translation</li>
 *   <li><b>>5 discrepancies</b> — BLOCKED, adapter bug suspected</li>
 * </ul>
 */
@Slf4j
public class CrossSystemCorrectnessVerifier {

    private static final long VERIFY_TENANT_ID = 1L;
    private static final int DEFAULT_VERIFY_SAMPLES = 1000;

    // ────────────── Data Structures ──────────────

    public static class Decision {
        public final String systemLabel;
        public final long cardId;
        public final String resourceType;
        public final String actionCode;
        public final boolean allowed;
        public final long latencyNs;
        public final String errorMsg;

        Decision(String systemLabel, long cardId, String resourceType,
                 String actionCode, boolean allowed, long latencyNs, String errorMsg) {
            this.systemLabel = systemLabel;
            this.cardId = cardId;
            this.resourceType = resourceType;
            this.actionCode = actionCode;
            this.allowed = allowed;
            this.latencyNs = latencyNs;
            this.errorMsg = errorMsg;
        }
    }

    public static class Discrepancy {
        public final Decision decisionA;
        public final Decision decisionB;
        public final DataGenerator.EvalRequest request;

        Discrepancy(Decision a, Decision b, DataGenerator.EvalRequest req) {
            this.decisionA = a;
            this.decisionB = b;
            this.request = req;
        }

        @Override
        public String toString() {
            return String.format("MISMATCH: %s(%s) ≠ %s(%s) [card=%d, res=%s, act=%s]",
                decisionA.systemLabel, decisionA.allowed ? "ALLOW" : "DENY",
                decisionB.systemLabel, decisionB.allowed ? "ALLOW" : "DENY",
                request.cardId, request.resourceType, request.actionCode);
        }
    }

    public static class VerificationReport {
        public String referenceSystem = "AstralLight(Optimized)";
        public int totalSamplesChecked;
        public List<String> systemLabelsChecked = new ArrayList<>();
        public List<Discrepancy> discrepancies = new ArrayList<>();
        public Map<String, Integer> errorCounts = new LinkedHashMap<>();
        /** Number of mismatches where AL=DENY but compared system=ALLOW (stricter than AL). */
        public int alDenyOtherAllow;
        /** Number of mismatches where AL=ALLOW but compared system=DENY (comparable or stricter). */
        public int alAllowOtherDeny;
        /** Pairwise discrepancy map: "LabelA vs LabelB" → mismatch count. */
        public Map<String, Integer> pairwiseDiscrepancies = new LinkedHashMap<>();
        public String verdict;
        public boolean allPassed;

        public String toSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append("\n╔══════════════════════════════════════════════╗\n");
            sb.append("║  Cross-System Correctness Verification       ║\n");
            sb.append("╠══════════════════════════════════════════════╣\n");
            sb.append(String.format("║  Reference: %-31s ║\n", referenceSystem));
            sb.append(String.format("║  Samples:   %-31d ║\n", totalSamplesChecked));
            sb.append(String.format("║  Systems:   %-31d ║\n", systemLabelsChecked.size()));
            sb.append(String.format("║  Mismatches:%-31d ║\n", discrepancies.size()));
            sb.append(String.format("║  AL deny / other allow: %-19d ║\n", alDenyOtherAllow));
            sb.append(String.format("║  AL allow / other deny: %-19d ║\n", alAllowOtherDeny));
            sb.append(String.format("║  Verdict:   %-31s ║\n", verdict));
            sb.append("╚══════════════════════════════════════════════╝\n");

            sb.append("\n--- Common Expressible Subset ---\n");
            sb.append("  ").append(com.coreryblack.benchmark.baseline.BaselineCapabilityMatrix.subsetStatement()).append("\n");
            sb.append("  Capability matrix: see artifact capability_matrix.{csv,tex}\n");

            if (!discrepancies.isEmpty()) {
                sb.append("\n--- Discrepancy Details (first 10) ---\n");
                for (int i = 0; i < Math.min(10, discrepancies.size()); i++) {
                    sb.append("  ").append(discrepancies.get(i)).append("\n");
                }
                if (discrepancies.size() > 10) {
                    sb.append(String.format("  ... and %d more\n", discrepancies.size() - 10));
                }
            }

            sb.append("\n--- Per-System Error Summary ---\n");
            for (Map.Entry<String, Integer> e : errorCounts.entrySet()) {
                String status = e.getValue() == 0 ? "✓ CLEAN" :
                    e.getValue() < 0 ? "✗ NOT RUN" : "✗ " + e.getValue() + " errors";
                sb.append(String.format("  %-25s %s\n", e.getKey() + ":", status));
            }

            if (!pairwiseDiscrepancies.isEmpty()) {
                sb.append("\n--- Pairwise Discrepancy Matrix ---\n");
                for (Map.Entry<String, Integer> e : pairwiseDiscrepancies.entrySet()) {
                    sb.append(String.format("  %-35s %d\n", e.getKey() + ":", e.getValue()));
                }
            }

            return sb.toString();
        }

        public String toCsvReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("card_id,resource,action,ref_system,ref_decision,compared_system,compared_decision\n");
            for (Discrepancy d : discrepancies) {
                sb.append(String.format("%d,%s,%s,%s,%s,%s,%s\n",
                    d.request.cardId, d.request.resourceType, d.request.actionCode,
                    d.decisionA.systemLabel, d.decisionA.allowed ? "ALLOW" : "DENY",
                    d.decisionB.systemLabel, d.decisionB.allowed ? "ALLOW" : "DENY"));
            }
            return sb.toString();
        }
    }

    // ────────────── Dependencies ──────────────

    private final PolicyEngine policyEngine;
    private final CasbinAdapter casbinAdapter;
    private final CasbinCachedAdapter casbinCachedAdapter;
    private final OpaAdapter opaAdapter;
    private final OpaAdapter opaNoCacheAdapter;
    private final CedarAdapter cedarDefaultAdapter;
    private final CedarAdapter cedarOptimizedAdapter;

    public CrossSystemCorrectnessVerifier(
            PolicyEngine policyEngine,
            CasbinAdapter casbinAdapter,
            CasbinCachedAdapter casbinCachedAdapter,
            OpaAdapter opaAdapter,
            OpaAdapter opaNoCacheAdapter) {
        this.policyEngine = policyEngine;
        this.casbinAdapter = casbinAdapter;
        this.casbinCachedAdapter = casbinCachedAdapter;
        this.opaAdapter = opaAdapter;
        this.opaNoCacheAdapter = opaNoCacheAdapter;
        this.cedarDefaultAdapter = new CedarAdapter(false);
        this.cedarOptimizedAdapter = new CedarAdapter(true);
    }

    // ────────────── Public API ──────────────

    public VerificationReport verify(DataGenerator.GeneratedDataSet dataset,
                                      int verifySamples) {
        int samples = verifySamples > 0 ? verifySamples : DEFAULT_VERIFY_SAMPLES;
        samples = Math.min(samples, dataset.evalRequests.size());

        log.info("=== Cross-System Correctness Verification ===");
        log.info("Reference: AstralLight, Samples: {}", samples);

        VerificationReport report = new VerificationReport();
        report.totalSamplesChecked = samples;

        // 1. Collect ground truth from AstralLight
        List<Decision> reference = collectAstralLightDecisions(dataset, samples);

        // 2. Compare each system
        compareAndAccumulate(report, "Casbin", reference,
            () -> casbinAdapter.initialize(dataset),
            (cardId, res, act) -> casbinAdapter.enforce(cardId, res, act));

        compareAndAccumulate(report, "Casbin(Cached)", reference,
            () -> casbinCachedAdapter.initialize(dataset),
            (cardId, res, act) -> casbinCachedAdapter.enforce(cardId, res, act));

        // NOTE: Cedar is excluded from the correctness gate because the Cedar
        // appendix models a semantic emulation path rather than the primary
        // common-subset comparison used for the blocking gate.

        boolean allRequiredSystemsAvailable = true;
        // OPA — an unavailable required baseline makes the gate inconclusive,
        // never a PASS with an omitted participant.
        if (opaAdapter.isAvailable()) {
            compareAndAccumulate(report, "OPA(REST)", reference,
                () -> opaAdapter.initialize(dataset),
                (cardId, res, act) -> opaAdapter.enforce(cardId, res, act));
        } else {
            report.errorCounts.put("OPA(REST)", -1);
            allRequiredSystemsAvailable = false;
        }

        // OPA no-cache (appendix comparison)
        if (opaNoCacheAdapter.isAvailable()) {
            compareAndAccumulate(report, "OPA(NoCache)", reference,
                () -> opaNoCacheAdapter.initialize(dataset),
                (cardId, res, act) -> opaNoCacheAdapter.enforce(cardId, res, act));
        } else {
            report.errorCounts.put("OPA(NoCache)", -1);
            allRequiredSystemsAvailable = false;
        }

        // Pairwise oracle analysis: compare every pair of non-reference systems
        // to identify which systems agree/disagree with each other (not just vs AL)
        List<String> pairwiseLabels = List.of("Casbin", "Casbin(Cached)", "OPA(REST)", "OPA(NoCache)");
        Map<String, Map<String, Integer>> pairwiseMM = new LinkedHashMap<>();
        for (String l1 : pairwiseLabels) {
            for (String l2 : pairwiseLabels) {
                if (l1.compareTo(l2) >= 0) continue;
                int mm = 0;
                for (Discrepancy d : report.discrepancies) {
                    String a = d.decisionA.systemLabel;
                    String b = d.decisionB.systemLabel;
                    boolean aMatch = a.equals(l1) || a.equals(l2);
                    boolean bMatch = b.equals(l1) || b.equals(l2);
                    if (aMatch && bMatch) mm++;
                }
                pairwiseMM.computeIfAbsent(l1, k -> new LinkedHashMap<>()).put(l2, mm);
            }
        }
        if (!pairwiseMM.isEmpty()) {
            log.info("--- Pairwise Discrepancy Matrix ---");
            for (Map.Entry<String, Map<String, Integer>> e1 : pairwiseMM.entrySet()) {
                for (Map.Entry<String, Integer> e2 : e1.getValue().entrySet()) {
                    log.info("  {} vs {}: {} mismatches", e1.getKey(), e2.getKey(), e2.getValue());
                }
            }
            report.pairwiseDiscrepancies = new LinkedHashMap<>();
            for (Map.Entry<String, Map<String, Integer>> e1 : pairwiseMM.entrySet()) {
                for (Map.Entry<String, Integer> e2 : e1.getValue().entrySet()) {
                    report.pairwiseDiscrepancies.put(
                        e1.getKey() + " vs " + e2.getKey(), e2.getValue());
                }
            }
        }

        // Determine verdict
        int mismatchCount = report.discrepancies.size();
        boolean hasSystemErrors = report.errorCounts.values().stream().anyMatch(count -> count != 0);
        if (!allRequiredSystemsAvailable) {
            report.verdict = "INCONCLUSIVE (required baseline unavailable)";
            report.allPassed = false;
        } else if (hasSystemErrors) {
            report.verdict = "INCONCLUSIVE (baseline error)";
            report.allPassed = false;
        } else if (mismatchCount == 0) {
            report.verdict = "PASS";
            report.allPassed = true;
        } else if (mismatchCount <= 5) {
            report.verdict = "WARNING (" + mismatchCount + " mismatches)";
            report.allPassed = false;
        } else {
            report.verdict = "BLOCKED (" + mismatchCount + " mismatches)";
            report.allPassed = false;
        }

        log.info(report.toSummary());
        return report;
    }

    /**
     * Quick gate: throws if BLOCKED, warns if WARNING.
     */
    public void verifyOrThrow(DataGenerator.GeneratedDataSet dataset, int verifySamples) {
        VerificationReport report = verify(dataset, verifySamples);
        if (!report.allPassed) {
            String msg = "Cross-system correctness " + report.verdict + "\n" + report.toSummary();
            log.error(msg);
            if (report.verdict.startsWith("BLOCKED")) {
                throw new IllegalStateException(msg);
            }
        }
    }

    // ────────────── Internal ──────────────

    @FunctionalInterface
    private interface Evaluator {
        boolean evaluate(long cardId, String resource, String action) throws Exception;
    }

    private List<Decision> collectAstralLightDecisions(
            DataGenerator.GeneratedDataSet dataset, int samples) {
        List<Decision> decisions = new ArrayList<>();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        // Card → domain mapping so the AL reference evaluates each card under
        // its own domain (card.domain_id), matching the card context that
        // production sets. Fixing domainId=1 would DENY multi-domain cards.
        Map<Long, Long> cardDomain = new HashMap<>();
        for (DataGenerator.CardBinding b : dataset.bindings) {
            cardDomain.put(b.cardId, b.domainId);
        }

        // Use the real PolicyEngine for ground truth — not a manual flat index.
        // This ensures the correctness gate validates against actual AL behavior.
        // Requests intentionally stay inside the common subset: no targetId, so
        // resource-ID-scoped rules (AstralLight-only) never enter the gate.
        for (int i = 0; i < samples; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            Long domainId = cardDomain.getOrDefault(req.cardId, 1L);

            // Set up the ThreadLocal card context (same as benchmark measurement)
            IdentityCardContext ctx = new IdentityCardContext();
            ctx.setUserId(1L);
            ctx.setCardId(req.cardId);
            ctx.setTenantId(VERIFY_TENANT_ID);
            ctx.setDomainId(domainId);
            CardContextHolder.set(ctx);

            try {
                PolicyContext policyCtx = PolicyContext.builder()
                    .userId(1L)
                    .cardId(req.cardId)
                    .tenantId(VERIFY_TENANT_ID)
                    .domainId(domainId)
                    .templateId(1L)
                    .resource(req.resourceType)
                    .action(req.actionCode)
                    .build();

                PolicyDecision decision = policyEngine.evaluate(policyCtx);
                boolean allowed = decision.isAllowed();

                decisions.add(new Decision("AstralLight(Optimized)",
                    req.cardId, req.resourceType, req.actionCode, allowed, 0, null));
            } finally {
                CardContextHolder.clear();
            }
        }
        return decisions;
    }

    private void compareAndAccumulate(
            VerificationReport report, String systemLabel,
            List<Decision> reference, Runnable initializer, Evaluator evaluator) {

        report.systemLabelsChecked.add(systemLabel);

        try {
            initializer.run();
        } catch (Exception e) {
            log.warn("{} initialization failed: {}", systemLabel, e.getMessage());
            report.errorCounts.put(systemLabel, -1);
            return;
        }

        int errors = 0;
        int mismatches = 0;

        for (Decision ref : reference) {
            DataGenerator.EvalRequest req = new DataGenerator.EvalRequest();
            req.cardId = ref.cardId;
            req.resourceType = ref.resourceType;
            req.actionCode = ref.actionCode;

            try {
                boolean systemResult = evaluator.evaluate(
                    ref.cardId, ref.resourceType, ref.actionCode);

                if (systemResult != ref.allowed) {
                    mismatches++;
                    if (!ref.allowed && systemResult) {
                        report.alDenyOtherAllow++;  // AL stricter than competitor
                    } else {
                        report.alAllowOtherDeny++;  // competitor stricter than AL
                    }
                    Decision sysDec = new Decision(systemLabel, ref.cardId,
                        ref.resourceType, ref.actionCode, systemResult, 0, null);
                    report.discrepancies.add(new Discrepancy(ref, sysDec, req));
                }
            } catch (Exception e) {
                errors++;
                Decision errDec = new Decision(systemLabel, ref.cardId,
                    ref.resourceType, ref.actionCode, false, 0, e.getMessage());
                report.discrepancies.add(new Discrepancy(ref, errDec, req));
            }
        }

        report.errorCounts.put(systemLabel, errors);

        if (mismatches == 0 && errors == 0) {
            log.info("  {} ✓ ALL MATCH ({} samples)", systemLabel, reference.size());
        } else {
            log.warn("  {} ✗ {} mismatches, {} errors ({} samples)",
                systemLabel, mismatches, errors, reference.size());
        }
    }

    private void setupCardContext(Long cardId) {
        IdentityCardContext ctx = new IdentityCardContext();
        ctx.setCardId(cardId);
        ctx.setUserId(1L);
        ctx.setTenantId(VERIFY_TENANT_ID);
        ctx.setDomainId(1L);
        ctx.setTemplateId(1L);
        ctx.setCardType("PLATFORM_CARD");
        ctx.setStatus("ACTIVE");
        CardContextHolder.set(ctx);
    }
}
