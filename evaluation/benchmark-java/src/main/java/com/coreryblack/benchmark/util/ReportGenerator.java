package com.coreryblack.benchmark.util;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.List;

public class ReportGenerator {

    private final List<LatencyRecorder.LatencySnapshot> snapshots = new ArrayList<>();
    private final List<String> labels = new ArrayList<>();
    private final String outputDir;

    public ReportGenerator(String outputDir) {
        this.outputDir = outputDir;
    }

    public void addResult(String label, LatencyRecorder.LatencySnapshot snapshot) {
        labels.add(label);
        snapshots.add(snapshot);
    }

    public void writeCsvReport(String filename) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outputDir + "/" + filename)))) {
            pw.println(LatencyRecorder.LatencySnapshot.csvHeader());
            for (int i = 0; i < labels.size(); i++) {
                pw.println(snapshots.get(i).toCsvRow(labels.get(i)));
            }
        }
    }

    public void writeLatexRq2Table(String filename) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outputDir + "/" + filename)))) {
            pw.println("% RQ2: Decision Latency Distribution - Auto-generated " + LocalDateTime.now());
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Decision Latency Distribution Across Systems (microseconds)}");
            pw.println("\\label{tab:rq2-latency}");
            pw.println("\\begin{tabular}{llrrrrrr}");
            pw.println("\\toprule");
            pw.println("\\textbf{System} & \\textbf{Scale} & \\textbf{Mean} & \\textbf{StdDev} & \\textbf{P95} & \\textbf{P99} & \\textbf{Max} & \\textbf{TPS} \\\\");
            pw.println("\\midrule");
            for (int i = 0; i < labels.size(); i++) {
                String[] parts = labels.get(i).split("\\|");
                String system = parts.length > 0 ? parts[0] : labels.get(i);
                String scale = parts.length > 1 ? parts[1] : "-";
                LatencyRecorder.LatencySnapshot s = snapshots.get(i);
                if (s == null) continue;
                pw.println(s.toLatexRowWithStddev(system, scale));
            }
            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println("\\end{table}");
        }
    }

    public void writeLatexRq3Table(String filename) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outputDir + "/" + filename)))) {
            pw.println("% RQ3: Incremental Compilation Overhead - Auto-generated " + LocalDateTime.now());
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Incremental vs Full Rebuild Latency (microseconds)}");
            pw.println("\\label{tab:rq3-incremental}");
            pw.println("\\begin{tabular}{lrrrr}");
            pw.println("\\toprule");
            pw.println("\\textbf{Operation} & \\textbf{Mean} & \\textbf{P95} & \\textbf{P99} & \\textbf{Max} \\\\");
            pw.println("\\midrule");
            for (int i = 0; i < labels.size(); i++) {
                LatencyRecorder.LatencySnapshot s = snapshots.get(i);
                if (s == null) continue;
                pw.printf("%s & %.1f & %.1f & %.1f & %.1f \\\\%n",
                    labels.get(i), s.meanUs(), s.p95Us(), s.p99Us(), s.maxUs());
            }
            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println("\\end{table}");
        }
    }

    public void writeGnuplotData(String filename) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outputDir + "/" + filename)))) {
            pw.println("# scale mean p95 p99 max");
            for (int i = 0; i < labels.size(); i++) {
                LatencyRecorder.LatencySnapshot s = snapshots.get(i);
                pw.printf("%s %.2f %.2f %.2f %.2f%n",
                    labels.get(i), s.meanUs(), s.p95Us(), s.p99Us(), s.maxUs());
            }
        }
    }

    public void writeSummaryReport(String filename) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outputDir + "/" + filename)))) {
            pw.println("label,mean_us,ci95_lower_us,ci95_upper_us,p95_us,p99_us,p999_us,max_us,total_ops,error_ops");
            for (int i = 0; i < labels.size(); i++) {
                LatencyRecorder.LatencySnapshot s = snapshots.get(i);
                if (s == null) continue;
                LatencyRecorder.ConfidenceInterval ci = s.confidenceInterval95Us();
                pw.printf("%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d%n",
                    labels.get(i), ci.mean, ci.lower, ci.upper,
                    s.p95Us(), s.p99Us(), s.p999Us(), s.maxUs(), s.totalOps(), s.errorOps());
            }
        }
    }

    public Map<String, LatencyRecorder.LatencySnapshot> asMap() {
        Map<String, LatencyRecorder.LatencySnapshot> map = new LinkedHashMap<>();
        for (int i = 0; i < labels.size(); i++) {
            map.put(labels.get(i), snapshots.get(i));
        }
        return map;
    }

    public void writeStatisticalReport(String filename) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outputDir + "/" + filename)))) {
            pw.println("pair,test_type,wilcoxon_p_value,mann_whitney_p_value,cliffs_delta,effect_size_interpretation,significant_005");
            pw.println("# Statistical test results: Wilcoxon (paired, same-system) / Mann-Whitney U (independent, cross-system) + Cliff's delta");

            for (int i = 0; i < labels.size(); i++) {
                for (int j = i + 1; j < labels.size(); j++) {
                    String labelA = labels.get(i);
                    String labelB = labels.get(j);
                    LatencyRecorder.LatencySnapshot snapA = snapshots.get(i);
                    LatencyRecorder.LatencySnapshot snapB = snapshots.get(j);

                    if (snapA.sampleCount() < 5 || snapB.sampleCount() < 5) {
                        continue;
                    }

                    java.util.List<Long> sampleA = snapA.rawSamples();
                    java.util.List<Long> sampleB = snapB.rawSamples();

                    String systemA = labelA.split("\\|")[0];
                    String systemB = labelB.split("\\|")[0];
                    boolean sameSystem = systemA.equals(systemB);

                    double pValue;
                    String testType;
                    if (sameSystem && sampleA.size() == sampleB.size()) {
                        pValue = StatisticalTest.wilcoxonSignedRankTest(sampleA, sampleB);
                        testType = "Wilcoxon(paired)";
                    } else {
                        pValue = StatisticalTest.mannWhitneyUTest(sampleA, sampleB);
                        testType = "Mann-Whitney(independent)";
                    }

                    double delta = StatisticalTest.cliffsDelta(sampleA, sampleB);
                    String interpretation = StatisticalTest.interpretCliffsDelta(delta);

                    pw.printf("%s_vs_%s,%s,%.6f,%.6f,%.4f,%s,%s%n",
                        labelA.replace("|", "_"), labelB.replace("|", "_"),
                        testType,
                        sameSystem ? pValue : Double.NaN,
                        sameSystem ? Double.NaN : pValue,
                        delta, interpretation,
                        pValue < 0.05 ? "YES" : "NO");
                }
            }
        }
    }

    /**
     * Writes per-sample raw latency data for each labeled snapshot.
     * Produces one CSV file per snapshot: raw_{sanitized_label}.csv
     * Each file contains one column — latency_nanos — with one row per measurement.
     * This enables third-party re-analysis and preserves raw sample provenance.
     */
    public void writeRawSamples(String filenamePrefix) throws IOException {
        for (int i = 0; i < labels.size(); i++) {
            String safeName = labels.get(i).replaceAll("[^a-zA-Z0-9_\\-=]", "_");
            String path = outputDir + "/" + filenamePrefix + "_" + safeName + ".csv";
            LatencyRecorder.LatencySnapshot s = snapshots.get(i);
            java.util.List<Long> raw = s.rawSamples();
            try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
                pw.println("latency_nanos");
                for (Long v : raw) {
                    pw.println(v);
                }
            }
        }
    }

    public void writeLatexRq2TableWithCI(String filename) throws IOException {
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(outputDir + "/" + filename)))) {
            pw.println("% RQ2: Decision Latency Distribution with 95% CI - Auto-generated " + LocalDateTime.now());
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Decision Latency Distribution Across Systems (microseconds, 95\\% CI)}");
            pw.println("\\label{tab:rq2-latency-ci}");
            pw.println("\\begin{tabular}{llrrrrrr}");
            pw.println("\\toprule");
            pw.println("\\textbf{System} & \\textbf{Scale} & \\textbf{Mean} & \\textbf{CI$_{95}$} & \\textbf{P95} & \\textbf{P99} & \\textbf{Max} & \\textbf{TPS} \\\\");
            pw.println("\\midrule");
            for (int i = 0; i < labels.size(); i++) {
                String[] parts = labels.get(i).split("\\|");
                String system = parts.length > 0 ? parts[0] : labels.get(i);
                String scale = parts.length > 1 ? parts[1] : "-";
                LatencyRecorder.LatencySnapshot s = snapshots.get(i);
                LatencyRecorder.ConfidenceInterval ci = s.confidenceInterval95Us();
                pw.printf("%s & %s & %.1f & [%.1f, %.1f] & %.1f & %.1f & %.1f & %.0f \\\\%n",
                    system, scale, s.meanUs(), ci.lower, ci.upper,
                    s.p95Us(), s.p99Us(), s.maxUs(), s.tps());
            }
            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println("\\end{table}");
        }
    }

}
