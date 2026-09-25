package com.coreryblack.benchmark.baseline;

import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.extern.slf4j.Slf4j;
import org.casbin.jcasbin.main.CachedEnforcer;

import java.util.List;

@Slf4j
public class CasbinCachedAdapter {

    private CachedEnforcer cachedEnforcer;

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

            this.cachedEnforcer = new CachedEnforcer(m);

            loadFromDataset(dataset);

            cachedEnforcer.buildRoleLinks();
            cachedEnforcer.invalidateCache();

            log.info("CasbinCached initialized: {} policies, {} roles, cards={}",
                cachedEnforcer.getPolicy().size(), cachedEnforcer.getGroupingPolicy().size(), dataset.bindings.size());
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize CasbinCached", e);
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
                    for (var entry : dataset.allBaseEntries.get(t)) {
                        String eft = entry.getEffect().equalsIgnoreCase("DENY") ? "deny" : "allow";
                        cachedEnforcer.addPolicy(tplSubject, entry.getResourceType(), entry.getActionCode(), eft);
                    }
                }

                // OVERLAY entries — loaded once per template
                if (dataset.allOverlayEntries != null && t < dataset.allOverlayEntries.size()
                    && dataset.allOverlayEntries.get(t) != null) {
                    for (var entry : dataset.allOverlayEntries.get(t)) {
                        String eft = entry.getEffect().equalsIgnoreCase("DENY") ? "deny" : "allow";
                        cachedEnforcer.addPolicy(tplSubject, entry.getResourceType(), entry.getActionCode(), eft);
                    }
                }
            }
        }

        // Phase 2: Card → template g() mapping
        for (DataGenerator.CardBinding binding : dataset.bindings) {
            String cardSub = "card_" + binding.cardId;
            String tplSub = "template_" + binding.templateIdx;
            cachedEnforcer.addGroupingPolicy(cardSub, tplSub);
        }
    }

    public boolean enforce(long cardId, String resource, String action) {
        String subject = "card_" + cardId;
        return cachedEnforcer.enforce(subject, resource, action);
    }

    private static final int WARMUP = 1000;

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

    public String getSystemLabel() {
        return "Casbin(Cached)";
    }
}
