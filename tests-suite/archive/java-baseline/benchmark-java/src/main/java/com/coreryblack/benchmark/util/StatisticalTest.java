package com.coreryblack.benchmark.util;

import java.util.ArrayList;
import java.util.List;

/**
 * Statistical testing utilities for benchmark result analysis.
 * Implements non-parametric tests and effect size measures without external dependencies.
 */
public class StatisticalTest {

    /**
     * Performs the Wilcoxon signed-rank test for paired non-parametric comparison.
     * Calculates differences, ranks absolute differences (averaging ties),
     * sums positive ranks (W+), and computes the Z-statistic with continuity correction.
     *
     * @param sampleA first sample of paired observations
     * @param sampleB second sample of paired observations
     * @return two-sided p-value, or NaN if effective sample size (after excluding zeros) is less than 10
     * @throws IllegalArgumentException if samples have different sizes or are empty
     */
    public static double wilcoxonSignedRankTest(List<Long> sampleA, List<Long> sampleB) {
        if (sampleA.size() != sampleB.size()) {
            throw new IllegalArgumentException("Samples must have equal size for paired test");
        }
        if (sampleA.isEmpty()) {
            throw new IllegalArgumentException("Samples must not be empty");
        }

        List<Double> differences = new ArrayList<>();
        for (int i = 0; i < sampleA.size(); i++) {
            double diff = sampleB.get(i).doubleValue() - sampleA.get(i).doubleValue();
            if (diff != 0.0) {
                differences.add(diff);
            }
        }

        int n = differences.size();
        if (n < 10) {
            return Double.NaN;
        }

        List<double[]> absDiffs = new ArrayList<>();
        for (double d : differences) {
            absDiffs.add(new double[]{Math.abs(d), d > 0 ? 1.0 : -1.0});
        }

        absDiffs.sort((a, b) -> Double.compare(a[0], b[0]));

        double[] ranks = new double[n];
        int i = 0;
        while (i < n) {
            int j = i;
            while (j < n && absDiffs.get(j)[0] == absDiffs.get(i)[0]) {
                j++;
            }
            double avgRank = (i + 1 + j) / 2.0;
            for (int k = i; k < j; k++) {
                ranks[k] = avgRank;
            }
            i = j;
        }

        double wPlus = 0.0;
        for (int k = 0; k < n; k++) {
            if (absDiffs.get(k)[1] > 0) {
                wPlus += ranks[k];
            }
        }

        double mu = n * (n + 1.0) / 4.0;

        double tieCorrection = 0.0;
        int ti = 0;
        while (ti < n) {
            int tj = ti;
            while (tj < n && absDiffs.get(tj)[0] == absDiffs.get(ti)[0]) {
                tj++;
            }
            int groupSize = tj - ti;
            if (groupSize > 1) {
                tieCorrection += (Math.pow(groupSize, 3) - groupSize) / 48.0;
            }
            ti = tj;
        }

        double sigma2 = n * (n + 1.0) * (2.0 * n + 1.0) / 24.0 - tieCorrection;
        if (sigma2 <= 0) {
            return Double.NaN;
        }

        double z;
        if (wPlus > mu) {
            z = (wPlus - mu - 0.5) / Math.sqrt(sigma2);
        } else {
            z = (wPlus - mu + 0.5) / Math.sqrt(sigma2);
        }

        return 2.0 * (1.0 - normalCDF(Math.abs(z)));
    }

    /**
     * Computes Cliff's delta non-parametric effect size between two independent samples.
     * Formula: delta = (#{a > b} - #{a < b}) / (n1 * n2).
     *
     * @param sampleA first sample
     * @param sampleB second sample
     * @return Cliff's delta value in [-1, 1]
     * @throws IllegalArgumentException if either sample is empty
     */
    public static double cliffsDelta(List<Long> sampleA, List<Long> sampleB) {
        if (sampleA.isEmpty() || sampleB.isEmpty()) {
            throw new IllegalArgumentException("Samples must not be empty");
        }

        long more = 0;
        long less = 0;
        for (Long a : sampleA) {
            for (Long b : sampleB) {
                if (a > b) more++;
                else if (a < b) less++;
            }
        }

        return (double) (more - less) / ((long) sampleA.size() * sampleB.size());
    }

    /**
     * Interprets Cliff's delta effect size magnitude.
     * Thresholds: |delta| &lt; 0.147 negligible, &lt; 0.33 small, &lt; 0.474 medium, &gt;= 0.474 large.
     *
     * @param delta Cliff's delta value
     * @return "negligible", "small", "medium", or "large"
     */
    public static String interpretCliffsDelta(double delta) {
        double absDelta = Math.abs(delta);
        if (absDelta < 0.147) return "negligible";
        if (absDelta < 0.33) return "small";
        if (absDelta < 0.474) return "medium";
        return "large";
    }

    /**
     * Performs the Mann-Whitney U test (Wilcoxon rank-sum test) for independent samples.
     * Combines both samples, ranks all values (averaging ties), computes U statistics
     * for both groups, and returns the two-sided p-value via normal approximation
     * with continuity correction and tie correction.
     *
     * @param sampleA first independent sample
     * @param sampleB second independent sample
     * @return two-sided p-value, or NaN if effective sample size is less than 10
     */
    public static double mannWhitneyUTest(List<Long> sampleA, List<Long> sampleB) {
        int n1 = sampleA.size();
        int n2 = sampleB.size();
        if (n1 < 5 || n2 < 5) {
            return Double.NaN;
        }

        List<double[]> combined = new ArrayList<>(n1 + n2);
        for (Long v : sampleA) combined.add(new double[]{v.doubleValue(), 0});
        for (Long v : sampleB) combined.add(new double[]{v.doubleValue(), 1});

        combined.sort((a, b) -> Double.compare(a[0], b[0]));

        double[] ranks = new double[n1 + n2];
        int i = 0;
        while (i < combined.size()) {
            int j = i;
            while (j < combined.size() && combined.get(j)[0] == combined.get(i)[0]) {
                j++;
            }
            double avgRank = (i + 1 + j) / 2.0;
            for (int k = i; k < j; k++) {
                ranks[k] = avgRank;
            }
            i = j;
        }

        double r1 = 0.0;
        for (int k = 0; k < combined.size(); k++) {
            if (combined.get(k)[1] == 0) {
                r1 += ranks[k];
            }
        }

        double u1 = r1 - n1 * (n1 + 1.0) / 2.0;
        double u2 = n1 * (long) n2 - u1;

        double tieCorrection = 0.0;
        int ti = 0;
        while (ti < combined.size()) {
            int tj = ti;
            while (tj < combined.size() && combined.get(tj)[0] == combined.get(ti)[0]) {
                tj++;
            }
            int groupSize = tj - ti;
            if (groupSize > 1) {
                tieCorrection += (Math.pow(groupSize, 3) - groupSize);
            }
            ti = tj;
        }

        long N = (long) n1 * n2;
        double muU = N / 2.0;
        double sigmaU2 = N / 12.0 * ((n1 + n2 + 1.0) - tieCorrection / ((n1 + n2) * (long)(n1 + n2 - 1)));
        if (sigmaU2 <= 0) {
            sigmaU2 = N / 12.0 * (n1 + n2 + 1.0);
        }

        double uMin = Math.min(u1, u2);
        double z = Math.abs(uMin - muU - 0.5) / Math.sqrt(sigmaU2);

        return 2.0 * (1.0 - normalCDF(z));
    }

    /**
     * Performs the Friedman test for comparing k related samples.
     * Ranks values within each block, computes the chi-square statistic,
     * and returns the p-value from the chi-square distribution with k-1 degrees of freedom.
     *
     * @param groups list of k groups, each containing n observations (blocks)
     * @return p-value from the chi-square approximation
     * @throws IllegalArgumentException if fewer than 3 groups or groups have unequal sizes
     */
    public static double friedmanTest(List<List<Long>> groups) {
        if (groups.size() < 3) {
            throw new IllegalArgumentException("Friedman test requires at least 3 groups");
        }

        int k = groups.size();
        int n = groups.get(0).size();
        for (List<Long> group : groups) {
            if (group.size() != n) {
                throw new IllegalArgumentException("All groups must have the same number of observations");
            }
        }
        if (n < 1) {
            throw new IllegalArgumentException("Groups must not be empty");
        }

        double[] rankSums = new double[k];
        for (int block = 0; block < n; block++) {
            List<double[]> blockValues = new ArrayList<>();
            for (int group = 0; group < k; group++) {
                blockValues.add(new double[]{groups.get(group).get(block).doubleValue(), group});
            }

            blockValues.sort((a, b) -> Double.compare(a[0], b[0]));

            double[] blockRanks = new double[k];
            int i = 0;
            while (i < k) {
                int j = i;
                while (j < k && blockValues.get(j)[0] == blockValues.get(i)[0]) {
                    j++;
                }
                double avgRank = (i + 1 + j) / 2.0;
                for (int m = i; m < j; m++) {
                    blockRanks[(int) blockValues.get(m)[1]] = avgRank;
                }
                i = j;
            }

            for (int group = 0; group < k; group++) {
                rankSums[group] += blockRanks[group];
            }
        }

        double expectedRankSum = n * (k + 1.0) / 2.0;
        double chiSquare = 0.0;
        for (int group = 0; group < k; group++) {
            double diff = rankSums[group] - expectedRankSum;
            chiSquare += diff * diff;
        }
        chiSquare = 12.0 / (n * k * (k + 1.0)) * chiSquare;

        return 1.0 - chiSquareCDF(chiSquare, k - 1);
    }

    /**
     * Approximates the cumulative distribution function for the standard normal distribution.
     * Uses the Abramowitz and Stegun rational approximation (formula 26.2.17).
     *
     * @param z standard normal z-value
     * @return P(Z &lt;= z)
     */
    public static double normalCDF(double z) {
        if (z < -8.0) return 0.0;
        if (z > 8.0) return 1.0;

        double p = 0.2316419;
        double b1 = 0.319381530;
        double b2 = -0.356563782;
        double b3 = 1.781477937;
        double b4 = -1.821255978;
        double b5 = 1.330274429;

        double t = 1.0 / (1.0 + p * Math.abs(z));
        double t2 = t * t;
        double t3 = t2 * t;
        double t4 = t3 * t;
        double t5 = t4 * t;

        double pdf = Math.exp(-z * z / 2.0) / Math.sqrt(2.0 * Math.PI);
        double cdf = 1.0 - pdf * (b1 * t + b2 * t2 + b3 * t3 + b4 * t4 + b5 * t5);

        return z >= 0 ? cdf : 1.0 - cdf;
    }

    private static double chiSquareCDF(double x, double df) {
        if (x <= 0.0) return 0.0;
        return regularizedLowerIncompleteGamma(df / 2.0, x / 2.0);
    }

    private static double regularizedLowerIncompleteGamma(double a, double x) {
        if (x <= 0.0) return 0.0;
        if (x < a + 1.0) {
            return gammaSeries(a, x);
        }
        return 1.0 - gammaContinuedFraction(a, x);
    }

    private static double gammaSeries(double a, double x) {
        double logGammaA = logGamma(a);
        double ap = a;
        double sum = 1.0 / a;
        double delta = sum;

        for (int n = 1; n < 200; n++) {
            ap += 1.0;
            delta *= x / ap;
            sum += delta;
            if (Math.abs(delta) < Math.abs(sum) * 1e-12) {
                break;
            }
        }

        return sum * Math.exp(-x + a * Math.log(x) - logGammaA);
    }

    private static double gammaContinuedFraction(double a, double x) {
        double logGammaA = logGamma(a);
        double b = x + 1.0 - a;
        double c = 1.0 / Double.MIN_VALUE;
        double d = 1.0 / b;
        double h = d;

        for (int i = 1; i < 200; i++) {
            double an = -i * (i - a);
            b += 2.0;
            d = an * d + b;
            if (Math.abs(d) < Double.MIN_VALUE) d = Double.MIN_VALUE;
            c = b + an / c;
            if (Math.abs(c) < Double.MIN_VALUE) c = Double.MIN_VALUE;
            d = 1.0 / d;
            double delta = d * c;
            h *= delta;
            if (Math.abs(delta - 1.0) < 1e-12) {
                break;
            }
        }

        return Math.exp(-x + a * Math.log(x) - logGammaA) * h;
    }

    private static double logGamma(double x) {
        double[] c = {
            0.99999999999980993,
            676.5203681218851,
            -1259.1392167224028,
            771.32342877765313,
            -176.61502916214059,
            12.507343278686905,
            -0.13857109526572012,
            9.9843695780195716e-6,
            1.5056327351493116e-7
        };

        if (x < 0.5) {
            return Math.log(Math.PI / Math.sin(Math.PI * x)) - logGamma(1.0 - x);
        }

        x -= 1.0;
        double g = 7.0;
        double sum = c[0];
        for (int i = 1; i < c.length; i++) {
            sum += c[i] / (x + i);
        }

        double t = x + g + 0.5;
        return 0.5 * Math.log(2.0 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(sum);
    }
}
