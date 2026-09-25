package com.coreryblack.benchmark.baseline;

import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Random;

@Slf4j
public class NaiveFullCopyAdapter {

    private final Map<String, List<Rule>> cardRules = new ConcurrentHashMap<>();
    private ScaleConfig lastConfig;

    public void initialize(ScaleConfig config) {
        this.lastConfig = config;
        cardRules.clear();

        Random rng = new Random(42L);
        String[] resourceTypes = DataGenerator.RESOURCE_TYPES;
        String[] actions = DataGenerator.ACTIONS;

        for (int cardIdx = 0; cardIdx < config.getCardCount(); cardIdx++) {
            String cardKey = "card_" + (cardIdx + 1);
            List<Rule> rules = new ArrayList<>();

            for (int ruleIdx = 0; ruleIdx < config.getBaseRulesPerCard(); ruleIdx++) {
                Rule rule = new Rule();
                rule.resourceType = resourceTypes[ruleIdx % resourceTypes.length];
                rule.actionCode = actions[ruleIdx % actions.length];
                rule.effect = "ALLOW";
                rule.priority = config.getBaseRulesPerCard() - ruleIdx;
                rules.add(rule);
            }

            for (int ruleIdx = 0; ruleIdx < config.getOverlayRulesPerCard(); ruleIdx++) {
                Rule rule = new Rule();
                rule.resourceType = resourceTypes[ruleIdx % resourceTypes.length];
                rule.actionCode = actions[ruleIdx % actions.length];
                rule.effect = rng.nextDouble() < 0.3 ? "DENY" : "ALLOW";
                rule.priority = config.getBaseRulesPerCard() + config.getOverlayRulesPerCard() - ruleIdx;
                rules.add(rule);
            }

            cardRules.put(cardKey, rules);
        }

        log.info("NaiveFullCopy initialized: {} cards, {} total rules (full copy)",
            config.getCardCount(), config.getCardCount() * (config.getBaseRulesPerCard() + config.getOverlayRulesPerCard()));
    }

    public boolean enforce(long cardId, String resource, String action) {
        String cardKey = "card_" + cardId;
        List<Rule> rules = cardRules.get(cardKey);
        if (rules == null) return false;

        Rule winner = null;
        for (Rule rule : rules) {
            if (rule.resourceType.equals(resource) && rule.actionCode.equals(action)) {
                if (winner == null || rule.priority > winner.priority) {
                    winner = rule;
                }
            }
        }
        return winner != null && "ALLOW".equals(winner.effect);
    }

    public long estimateMemoryBytes() {
        long bytes = 0;
        for (Map.Entry<String, List<Rule>> entry : cardRules.entrySet()) {
            bytes += entry.getKey().length() * 2L;
            bytes += 48L;
            for (Rule rule : entry.getValue()) {
                bytes += rule.resourceType.length() * 2L;
                bytes += rule.actionCode.length() * 2L;
                bytes += rule.effect.length() * 2L;
                bytes += 32L;
            }
        }
        return bytes;
    }

    public long estimateStorageBytes() {
        long rowSize = 0;
        rowSize += 8;
        rowSize += 8;
        rowSize += 32;
        rowSize += 32;
        rowSize += 8;
        rowSize += 8;
        rowSize += 16;
        rowSize += 8;
        rowSize += 8;
        rowSize += 16;
        rowSize += 16;
        return rowSize * lastConfig.getCardCount() * (lastConfig.getBaseRulesPerCard() + lastConfig.getOverlayRulesPerCard());
    }

    public String getSystemLabel() {
        return "NaiveFullCopy";
    }

    public static class Rule {
        public String resourceType;
        public String actionCode;
        public String effect;
        public int priority;
    }
}
