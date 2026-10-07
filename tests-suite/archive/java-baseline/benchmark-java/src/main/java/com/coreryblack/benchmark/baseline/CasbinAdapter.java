package com.coreryblack.benchmark.baseline;

import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.LatencyRecorder;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSetEntry;
import lombok.extern.slf4j.Slf4j;
import org.casbin.jcasbin.main.Enforcer;

import java.util.List;

@Slf4j
public class CasbinAdapter {

    private Enforcer enforcer;
    private final boolean useMemoryIndex;

    public CasbinAdapter(boolean useMemoryIndex) {
        this.useMemoryIndex = useMemoryIndex;
    }

    public void initialize(DataGenerator.GeneratedDataSet dataset) {
        try {
            String model = """
                [request_definition]
                r = sub, res, act

                [policy_definition]
                p = sub, res, act, eft

                [role_definition]
                g = _, _

                [policy_effect]
                e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

                [matchers]
                m = g(r.sub, p.sub) && r.res == p.res && r.act == p.act
                """;

            org.casbin.jcasbin.model.Model m = new org.casbin.jcasbin.model.Model();
            m.loadModelFromText(model);

            this.enforcer = new Enforcer(m);

            loadFromDataset(dataset);

            enforcer.buildRoleLinks();

            log.info("Casbin initialized: {} policies, {} roles, cards={}",
                enforcer.getPolicy().size(), enforcer.getGroupingPolicy().size(), dataset.bindings.size());
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize Casbin", e);
        }
    }

    private void loadFromDataset(DataGenerator.GeneratedDataSet dataset) {
        // Phase 1: Load template-level policies (shared, not per-card)
        java.util.Set<String> loadedTemplates = new java.util.HashSet<>();
        for (DataGenerator.CardBinding binding : dataset.bindings) {
            int t = binding.templateIdx;
            String tplSubject = "template_" + t;

            if (loadedTemplates.add(tplSubject)) {
                // BASE entries — loaded once per template
                if (dataset.allBaseEntries != null && t < dataset.allBaseEntries.size()) {
                    for (RuleSetEntry entry : dataset.allBaseEntries.get(t)) {
                        enforcer.addPolicy(tplSubject,
                            entry.getResourceType(), entry.getActionCode(),
                            entry.getEffect().equalsIgnoreCase("DENY") ? "deny" : "allow");
                    }
                }

                // OVERLAY entries — loaded once per template
                if (dataset.allOverlayEntries != null && t < dataset.allOverlayEntries.size()
                    && dataset.allOverlayEntries.get(t) != null) {
                    for (RuleSetEntry entry : dataset.allOverlayEntries.get(t)) {
                        enforcer.addPolicy(tplSubject,
                            entry.getResourceType(), entry.getActionCode(),
                            entry.getEffect().equalsIgnoreCase("DENY") ? "deny" : "allow");
                    }
                }
            }
        }

        // Phase 2: Card → template g() mapping
        for (DataGenerator.CardBinding binding : dataset.bindings) {
            String cardSub = "card_" + binding.cardId;
            String tplSub = "template_" + binding.templateIdx;
            enforcer.addGroupingPolicy(cardSub, tplSub);
        }
    }

    public boolean enforce(long cardId, String resource, String action) {
        String subject = "card_" + cardId;
        return enforcer.enforce(subject, resource, action);
    }

    public LatencyRecorder.LatencySnapshot benchmarkEval(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            enforce(req.cardId, req.resourceType, req.actionCode);
        }

        for (int i = 0; i < iterations; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            long start = recorder.start();
            enforce(req.cardId, req.resourceType, req.actionCode);
            recorder.stop(start);
        }

        return recorder.snapshot();
    }

    public LatencyRecorder.LatencySnapshot benchmarkComplexity(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        return benchmarkEval(dataset, iterations);
    }

    private static final int WARMUP = 1000;

    public String getSystemLabel() {
        return "Casbin" + (useMemoryIndex ? "(indexed)" : "(default)");
    }
}
