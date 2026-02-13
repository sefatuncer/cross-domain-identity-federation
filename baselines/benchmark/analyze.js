/**
 * Statistical Analysis Script for Academic Paper
 * Generates publication-ready statistics and comparison tables
 *
 * Usage: node analyze.js <results-file.json>
 */

import fs from 'fs';
import path from 'path';
import * as ss from 'simple-statistics';

const RESULTS_DIR = process.env.RESULTS_DIR || './results';

// Statistical functions
class AcademicStatistics {
  /**
   * Calculate comprehensive statistics for a dataset
   */
  static comprehensive(data) {
    const sorted = [...data].sort((a, b) => a - b);
    const n = data.length;

    return {
      n,
      mean: ss.mean(data),
      median: ss.median(data),
      mode: ss.mode(data),
      stdDev: ss.standardDeviation(data),
      variance: ss.variance(data),
      sem: ss.standardDeviation(data) / Math.sqrt(n), // Standard Error of Mean
      min: ss.min(data),
      max: ss.max(data),
      range: ss.max(data) - ss.min(data),
      iqr: ss.interquartileRange(data),
      skewness: ss.sampleSkewness(data),
      kurtosis: this.kurtosis(data),
      percentiles: {
        p10: ss.quantile(sorted, 0.10),
        p25: ss.quantile(sorted, 0.25),
        p50: ss.quantile(sorted, 0.50),
        p75: ss.quantile(sorted, 0.75),
        p90: ss.quantile(sorted, 0.90),
        p95: ss.quantile(sorted, 0.95),
        p99: ss.quantile(sorted, 0.99)
      },
      ci95: this.confidenceInterval(data, 0.95),
      ci99: this.confidenceInterval(data, 0.99)
    };
  }

  /**
   * Confidence interval calculation
   */
  static confidenceInterval(data, level = 0.95) {
    const n = data.length;
    const mean = ss.mean(data);
    const stdErr = ss.standardDeviation(data) / Math.sqrt(n);

    // Z-scores for common confidence levels
    const zScores = { 0.90: 1.645, 0.95: 1.96, 0.99: 2.576 };
    const z = zScores[level] || 1.96;

    return {
      mean,
      lower: mean - z * stdErr,
      upper: mean + z * stdErr,
      marginOfError: z * stdErr,
      level: level * 100
    };
  }

  /**
   * Kurtosis calculation (excess kurtosis)
   */
  static kurtosis(data) {
    const n = data.length;
    const mean = ss.mean(data);
    const stdDev = ss.standardDeviation(data);

    let sum = 0;
    for (const x of data) {
      sum += Math.pow((x - mean) / stdDev, 4);
    }

    return (n * (n + 1) * sum) / ((n - 1) * (n - 2) * (n - 3)) -
      (3 * Math.pow(n - 1, 2)) / ((n - 2) * (n - 3));
  }

  /**
   * Two-sample t-test with full details
   */
  static tTest(sample1, sample2, paired = false) {
    const n1 = sample1.length;
    const n2 = sample2.length;
    const mean1 = ss.mean(sample1);
    const mean2 = ss.mean(sample2);
    const var1 = ss.variance(sample1);
    const var2 = ss.variance(sample2);

    // Welch's t-test (unequal variances)
    const pooledSE = Math.sqrt(var1 / n1 + var2 / n2);
    const tStat = (mean1 - mean2) / pooledSE;

    // Welch-Satterthwaite degrees of freedom
    const df = Math.pow(var1 / n1 + var2 / n2, 2) /
      (Math.pow(var1 / n1, 2) / (n1 - 1) + Math.pow(var2 / n2, 2) / (n2 - 1));

    // Approximate p-value (two-tailed)
    const pValue = 2 * (1 - this.tCDF(Math.abs(tStat), df));

    return {
      method: "Welch's Two Sample t-test",
      sample1: { n: n1, mean: mean1, variance: var1 },
      sample2: { n: n2, mean: mean2, variance: var2 },
      tStatistic: tStat,
      degreesOfFreedom: df,
      pValue,
      significant: {
        alpha001: pValue < 0.001,
        alpha005: pValue < 0.005,
        alpha01: pValue < 0.01,
        alpha05: pValue < 0.05
      },
      meanDifference: mean1 - mean2,
      percentDifference: ((mean1 - mean2) / mean2) * 100
    };
  }

  /**
   * t-distribution CDF approximation
   */
  static tCDF(t, df) {
    const x = df / (df + t * t);
    return 1 - 0.5 * this.incompleteBeta(df / 2, 0.5, x);
  }

  static incompleteBeta(a, b, x) {
    if (x === 0) return 0;
    if (x === 1) return 1;
    const bt = Math.exp(
      ss.logGamma(a + b) - ss.logGamma(a) - ss.logGamma(b) +
      a * Math.log(x) + b * Math.log(1 - x)
    );
    if (x < (a + 1) / (a + b + 2)) {
      return bt * this.betaCF(a, b, x) / a;
    }
    return 1 - bt * this.betaCF(b, a, 1 - x) / b;
  }

  static betaCF(a, b, x) {
    const qab = a + b;
    const qap = a + 1;
    const qam = a - 1;
    let c = 1;
    let d = 1 - qab * x / qap;
    if (Math.abs(d) < 1e-30) d = 1e-30;
    d = 1 / d;
    let h = d;

    for (let m = 1; m <= 100; m++) {
      const m2 = 2 * m;
      let aa = m * (b - m) * x / ((qam + m2) * (a + m2));
      d = 1 + aa * d;
      if (Math.abs(d) < 1e-30) d = 1e-30;
      c = 1 + aa / c;
      if (Math.abs(c) < 1e-30) c = 1e-30;
      d = 1 / d;
      h *= d * c;

      aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
      d = 1 + aa * d;
      if (Math.abs(d) < 1e-30) d = 1e-30;
      c = 1 + aa / c;
      if (Math.abs(c) < 1e-30) c = 1e-30;
      d = 1 / d;
      const del = d * c;
      h *= del;

      if (Math.abs(del - 1) < 3e-7) break;
    }
    return h;
  }

  /**
   * Effect size (Cohen's d)
   */
  static cohensD(sample1, sample2) {
    const n1 = sample1.length;
    const n2 = sample2.length;
    const mean1 = ss.mean(sample1);
    const mean2 = ss.mean(sample2);

    // Pooled standard deviation
    const pooledStd = Math.sqrt(
      ((n1 - 1) * ss.variance(sample1) + (n2 - 1) * ss.variance(sample2)) /
      (n1 + n2 - 2)
    );

    const d = (mean1 - mean2) / pooledStd;

    let interpretation;
    const absD = Math.abs(d);
    if (absD < 0.2) interpretation = 'negligible';
    else if (absD < 0.5) interpretation = 'small';
    else if (absD < 0.8) interpretation = 'medium';
    else interpretation = 'large';

    return { d, interpretation };
  }

  /**
   * ANOVA F-test for multiple groups
   */
  static anova(groups) {
    const k = groups.length; // Number of groups
    const allData = groups.flat();
    const N = allData.length; // Total sample size
    const grandMean = ss.mean(allData);

    // Between-group sum of squares
    let ssBetween = 0;
    for (const group of groups) {
      const groupMean = ss.mean(group);
      ssBetween += group.length * Math.pow(groupMean - grandMean, 2);
    }

    // Within-group sum of squares
    let ssWithin = 0;
    for (const group of groups) {
      const groupMean = ss.mean(group);
      for (const x of group) {
        ssWithin += Math.pow(x - groupMean, 2);
      }
    }

    const dfBetween = k - 1;
    const dfWithin = N - k;
    const msBetween = ssBetween / dfBetween;
    const msWithin = ssWithin / dfWithin;
    const fStat = msBetween / msWithin;

    // Approximate p-value using F-distribution
    // (simplified approximation)
    const pValue = this.fPValue(fStat, dfBetween, dfWithin);

    return {
      method: 'One-way ANOVA',
      k,
      N,
      ssBetween,
      ssWithin,
      dfBetween,
      dfWithin,
      msBetween,
      msWithin,
      fStatistic: fStat,
      pValue,
      significant: pValue < 0.05
    };
  }

  /**
   * Approximate F-distribution p-value
   */
  static fPValue(f, df1, df2) {
    const x = df2 / (df2 + df1 * f);
    return this.incompleteBeta(df2 / 2, df1 / 2, x);
  }
}

/**
 * Report generator for academic papers
 */
class AcademicReportGenerator {
  constructor(results) {
    this.results = results;
  }

  /**
   * Generate LaTeX table for latency comparison
   */
  generateLatexTable() {
    let latex = `\\begin{table}[htbp]
\\centering
\\caption{Performance Comparison Across Baseline Systems}
\\label{tab:performance}
\\begin{tabular}{lrrrrrrr}
\\hline
\\textbf{System} & \\textbf{n} & \\textbf{Mean} & \\textbf{Median} & \\textbf{SD} & \\textbf{P95} & \\textbf{P99} & \\textbf{95\\% CI} \\\\
\\hline
`;

    for (const [benchmark, data] of Object.entries(this.results.benchmarks)) {
      if (benchmark === 'throughput') continue;

      latex += `\\multicolumn{8}{l}{\\textit{${this.formatBenchmarkName(benchmark)}}} \\\\\n`;

      for (const [system, results] of Object.entries(data)) {
        if (!results.statistics) continue;
        const s = results.statistics;
        const ci = s.ci95;
        latex += `${this.formatSystemName(system)} & ${s.n} & ${s.mean.toFixed(1)} & ${s.median.toFixed(1)} & `;
        latex += `${s.stdDev.toFixed(1)} & ${s.p95.toFixed(1)} & ${s.p99.toFixed(1)} & `;
        latex += `[${ci.lower.toFixed(1)}, ${ci.upper.toFixed(1)}] \\\\\n`;
      }
      latex += `\\hline\n`;
    }

    latex += `\\end{tabular}
\\end{table}`;

    return latex;
  }

  /**
   * Generate statistical comparison table
   */
  generateComparisonTable() {
    let latex = `\\begin{table}[htbp]
\\centering
\\caption{Statistical Comparison: Our Solution vs Baselines}
\\label{tab:comparison}
\\begin{tabular}{llrrrrl}
\\hline
\\textbf{Benchmark} & \\textbf{Comparison} & \\textbf{Diff (ms)} & \\textbf{Diff (\\%)} & \\textbf{t} & \\textbf{p} & \\textbf{Effect} \\\\
\\hline
`;

    for (const [benchmark, comparisons] of Object.entries(this.results.comparisons || {})) {
      for (const [comparison, data] of Object.entries(comparisons)) {
        const sigMarker = data.tTest.pValue < 0.001 ? '***' :
          data.tTest.pValue < 0.01 ? '**' :
            data.tTest.pValue < 0.05 ? '*' : '';

        latex += `${this.formatBenchmarkName(benchmark)} & `;
        latex += `${comparison.replace(/_/g, ' ')} & `;
        latex += `${data.difference.toFixed(1)} & `;
        latex += `${data.percentDifference.toFixed(1)} & `;
        latex += `${data.tTest.tStatistic.toFixed(2)} & `;
        latex += `${data.tTest.pValue.toFixed(4)}${sigMarker} & `;
        latex += `${data.effectSize.toFixed(2)} (${data.effectSizeInterpretation}) \\\\\n`;
      }
    }

    latex += `\\hline
\\multicolumn{7}{l}{\\footnotesize *p<0.05, **p<0.01, ***p<0.001} \\\\
\\end{tabular}
\\end{table}`;

    return latex;
  }

  /**
   * Generate markdown summary for paper
   */
  generateMarkdownSummary() {
    let md = `# Performance Analysis Results

## Executive Summary

`;

    // Calculate overall comparisons
    if (this.results.benchmarks.fullFlow) {
      md += `### Full Cross-Domain Flow Performance

`;
      for (const [system, data] of Object.entries(this.results.benchmarks.fullFlow)) {
        if (!data.statistics) continue;
        md += `- **${this.formatSystemName(system)}**: ${data.statistics.mean.toFixed(1)}ms ± ${data.statistics.stdDev.toFixed(1)}ms (n=${data.statistics.n})\n`;
      }
    }

    md += `
## Detailed Statistics

`;

    for (const [benchmark, data] of Object.entries(this.results.benchmarks)) {
      if (benchmark === 'throughput') continue;

      md += `### ${this.formatBenchmarkName(benchmark)}

| System | n | Mean | Median | SD | P95 | P99 | 95% CI |
|--------|---|------|--------|----|----|-----|--------|
`;

      for (const [system, results] of Object.entries(data)) {
        if (!results.statistics) continue;
        const s = results.statistics;
        const ci = s.ci95;
        md += `| ${this.formatSystemName(system)} | ${s.n} | ${s.mean.toFixed(1)} | ${s.median.toFixed(1)} | `;
        md += `${s.stdDev.toFixed(1)} | ${s.p95.toFixed(1)} | ${s.p99.toFixed(1)} | `;
        md += `[${ci.lower.toFixed(1)}, ${ci.upper.toFixed(1)}] |\n`;
      }
      md += `\n`;
    }

    md += `## Statistical Comparisons

`;

    for (const [benchmark, comparisons] of Object.entries(this.results.comparisons || {})) {
      md += `### ${this.formatBenchmarkName(benchmark)}

`;
      for (const [comparison, data] of Object.entries(comparisons)) {
        const sig = data.tTest.significant ? '✓ Significant' : '✗ Not significant';
        md += `**${comparison.replace(/_/g, ' ')}**
- Mean difference: ${data.difference.toFixed(1)}ms (${data.percentDifference.toFixed(1)}%)
- t-statistic: ${data.tTest.tStatistic.toFixed(3)}
- p-value: ${data.tTest.pValue.toFixed(4)} (${sig})
- Effect size: Cohen's d = ${data.effectSize.toFixed(3)} (${data.effectSizeInterpretation})

`;
      }
    }

    return md;
  }

  formatBenchmarkName(name) {
    return name.replace(/([A-Z])/g, ' $1').trim();
  }

  formatSystemName(name) {
    const names = {
      'oidc': 'OIDC Federation',
      'centralized': 'Centralized',
      'indy': 'Indy (Simulated)',
      'ourSolution': 'Our Solution'
    };
    return names[name] || name;
  }
}

// Main analysis function
async function analyze() {
  // Find most recent results file
  const resultsDir = RESULTS_DIR;
  let resultsFile = process.argv[2];

  if (!resultsFile) {
    const files = fs.readdirSync(resultsDir)
      .filter(f => f.startsWith('benchmark-') && f.endsWith('.json'))
      .sort()
      .reverse();

    if (files.length === 0) {
      console.error('No results files found. Run benchmark first.');
      process.exit(1);
    }

    resultsFile = path.join(resultsDir, files[0]);
  }

  console.log(`Analyzing: ${resultsFile}\n`);

  const results = JSON.parse(fs.readFileSync(resultsFile, 'utf8'));
  const generator = new AcademicReportGenerator(results);

  // Generate reports
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  // LaTeX tables
  const latexTable = generator.generateLatexTable();
  const latexPath = path.join(resultsDir, `latex-tables-${timestamp}.tex`);
  fs.writeFileSync(latexPath, latexTable + '\n\n' + generator.generateComparisonTable());
  console.log(`LaTeX tables saved: ${latexPath}`);

  // Markdown summary
  const mdSummary = generator.generateMarkdownSummary();
  const mdPath = path.join(resultsDir, `analysis-${timestamp}.md`);
  fs.writeFileSync(mdPath, mdSummary);
  console.log(`Markdown analysis saved: ${mdPath}`);

  // Print summary
  console.log('\n' + '='.repeat(60));
  console.log('ANALYSIS SUMMARY');
  console.log('='.repeat(60) + '\n');

  // Print key findings
  if (results.comparisons) {
    console.log('Key Statistical Findings:\n');
    for (const [benchmark, comparisons] of Object.entries(results.comparisons)) {
      for (const [comparison, data] of Object.entries(comparisons)) {
        const pStr = data.tTest.pValue < 0.001 ? 'p < 0.001 ***' :
          data.tTest.pValue < 0.01 ? `p = ${data.tTest.pValue.toFixed(3)} **` :
            data.tTest.pValue < 0.05 ? `p = ${data.tTest.pValue.toFixed(3)} *` :
              `p = ${data.tTest.pValue.toFixed(3)} (ns)`;

        console.log(`${benchmark} - ${comparison}:`);
        console.log(`  Δ = ${data.difference.toFixed(1)}ms (${data.percentDifference > 0 ? '+' : ''}${data.percentDifference.toFixed(1)}%)`);
        console.log(`  ${pStr}, Cohen's d = ${data.effectSize.toFixed(2)} (${data.effectSizeInterpretation})`);
        console.log();
      }
    }
  }
}

analyze().catch(console.error);
