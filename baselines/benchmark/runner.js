/**
 * Baseline Benchmark Runner
 * Runs comparative benchmarks across all baseline systems
 *
 * For academic comparison with statistical analysis
 */

import axios from 'axios';
import * as ss from 'simple-statistics';
import fs from 'fs';
import path from 'path';

// Configuration
const CONFIG = {
  OIDC_URL: process.env.OIDC_BASELINE_URL || 'http://localhost:3100',
  CENTRALIZED_URL: process.env.CENTRALIZED_BASELINE_URL || 'http://localhost:3200',
  INDY_URL: process.env.INDY_BASELINE_URL || 'http://localhost:3300',
  OUR_SOLUTION_URL: process.env.OUR_SOLUTION_URL || 'http://localhost:4000',
  RESULTS_DIR: process.env.RESULTS_DIR || './results',
  // Test parameters (adjustable for quick vs full tests)
  RUNS: process.argv.includes('--quick') ? 30 : 100,
  WARMUP_RUNS: 5,
  CONCURRENCY_LEVELS: process.argv.includes('--quick')
    ? [1, 5, 10]
    : [1, 5, 10, 20, 50, 100],
  CONFIDENCE_LEVEL: 0.95
};

// Ensure results directory exists
if (!fs.existsSync(CONFIG.RESULTS_DIR)) {
  fs.mkdirSync(CONFIG.RESULTS_DIR, { recursive: true });
}

// Statistical helper functions
class Statistics {
  static mean(data) {
    return ss.mean(data);
  }

  static median(data) {
    return ss.median(data);
  }

  static stdDev(data) {
    return ss.standardDeviation(data);
  }

  static percentile(data, p) {
    return ss.quantile(data, p / 100);
  }

  static confidenceInterval(data, level = 0.95) {
    const mean = ss.mean(data);
    const stdErr = ss.standardDeviation(data) / Math.sqrt(data.length);
    const zScore = level === 0.95 ? 1.96 : (level === 0.99 ? 2.576 : 1.645);
    return {
      mean,
      lower: mean - zScore * stdErr,
      upper: mean + zScore * stdErr,
      marginOfError: zScore * stdErr
    };
  }

  static tTest(sample1, sample2) {
    // Two-sample t-test for comparing baselines
    const n1 = sample1.length;
    const n2 = sample2.length;
    const mean1 = ss.mean(sample1);
    const mean2 = ss.mean(sample2);
    const var1 = ss.variance(sample1);
    const var2 = ss.variance(sample2);

    const pooledSE = Math.sqrt(var1 / n1 + var2 / n2);
    const tStat = (mean1 - mean2) / pooledSE;

    // Degrees of freedom (Welch's approximation)
    const df = Math.pow(var1 / n1 + var2 / n2, 2) /
      (Math.pow(var1 / n1, 2) / (n1 - 1) + Math.pow(var2 / n2, 2) / (n2 - 1));

    // Simplified p-value approximation
    const pValue = 2 * (1 - this.tCDF(Math.abs(tStat), df));

    return {
      tStatistic: tStat,
      degreesOfFreedom: df,
      pValue,
      significant: pValue < 0.05,
      meanDifference: mean1 - mean2
    };
  }

  // Approximate t-distribution CDF
  static tCDF(t, df) {
    const x = df / (df + t * t);
    return 1 - 0.5 * this.incompleteBeta(df / 2, 0.5, x);
  }

  // Incomplete beta function approximation
  static incompleteBeta(a, b, x) {
    if (x === 0) return 0;
    if (x === 1) return 1;
    const bt = Math.exp(
      this.logGamma(a + b) - this.logGamma(a) - this.logGamma(b) +
      a * Math.log(x) + b * Math.log(1 - x)
    );
    if (x < (a + 1) / (a + b + 2)) {
      return bt * this.betaCF(a, b, x) / a;
    }
    return 1 - bt * this.betaCF(b, a, 1 - x) / b;
  }

  // Beta continued fraction
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

  // Log gamma function
  static logGamma(x) {
    const cof = [
      76.18009172947146, -86.50532032941677, 24.01409824083091,
      -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5
    ];
    let y = x;
    let tmp = x + 5.5;
    tmp -= (x + 0.5) * Math.log(tmp);
    let ser = 1.000000000190015;
    for (let j = 0; j < 6; j++) {
      ser += cof[j] / ++y;
    }
    return -tmp + Math.log(2.5066282746310005 * ser / x);
  }

  static cohenD(sample1, sample2) {
    // Effect size calculation
    const mean1 = ss.mean(sample1);
    const mean2 = ss.mean(sample2);
    const pooledStd = Math.sqrt(
      ((sample1.length - 1) * ss.variance(sample1) +
        (sample2.length - 1) * ss.variance(sample2)) /
      (sample1.length + sample2.length - 2)
    );
    return (mean1 - mean2) / pooledStd;
  }

  static summary(data) {
    if (!data || data.length === 0) {
      return {
        n: 0,
        mean: 0,
        median: 0,
        stdDev: 0,
        min: 0,
        max: 0,
        p50: 0,
        p95: 0,
        p99: 0,
        ci95: { mean: 0, lower: 0, upper: 0, marginOfError: 0 }
      };
    }
    const sorted = [...data].sort((a, b) => a - b);
    return {
      n: data.length,
      mean: this.mean(data),
      median: this.median(data),
      stdDev: this.stdDev(data),
      min: Math.min(...data),
      max: Math.max(...data),
      p50: this.percentile(sorted, 50),
      p95: this.percentile(sorted, 95),
      p99: this.percentile(sorted, 99),
      ci95: this.confidenceInterval(data, 0.95)
    };
  }
}

// Benchmark runner for single system
class BenchmarkRunner {
  constructor(name, baseUrl) {
    this.name = name;
    this.baseUrl = baseUrl;
    this.client = axios.create({
      baseURL: baseUrl,
      timeout: 30000
    });
  }

  async isHealthy() {
    try {
      const response = await this.client.get('/health');
      return response.data.status === 'healthy';
    } catch {
      return false;
    }
  }

  async resetMetrics() {
    try {
      await this.client.post('/metrics/reset');
    } catch {
      // Ignore
    }
  }

  async runSingle(operation, payload) {
    const start = Date.now();
    try {
      const response = await this.client.post(operation, payload);
      const latency = response.data.latencyMs || (Date.now() - start);
      return {
        success: true,
        latency,
        breakdown: response.data.breakdown || {},
        data: response.data
      };
    } catch (error) {
      return {
        success: false,
        latency: Date.now() - start,
        error: error.message
      };
    }
  }

  async runBenchmark(operation, payload, runs = CONFIG.RUNS) {
    const results = [];

    // Warmup
    console.log(`  Warming up ${this.name} (${CONFIG.WARMUP_RUNS} runs)...`);
    for (let i = 0; i < CONFIG.WARMUP_RUNS; i++) {
      await this.runSingle(operation, payload);
    }

    // Actual runs
    console.log(`  Running ${runs} iterations...`);
    for (let i = 0; i < runs; i++) {
      const result = await this.runSingle(operation, payload);
      results.push(result);

      if ((i + 1) % 10 === 0) {
        process.stdout.write(`    Progress: ${i + 1}/${runs}\r`);
      }
    }
    console.log();

    const latencies = results.filter(r => r.success).map(r => r.latency);
    const successRate = results.filter(r => r.success).length / results.length;

    return {
      system: this.name,
      operation,
      results,
      latencies,
      successRate,
      statistics: Statistics.summary(latencies)
    };
  }

  async runConcurrentBenchmark(operation, payload, concurrency, totalRequests = CONFIG.RUNS) {
    const results = [];
    const requestsPerBatch = concurrency;
    const batches = Math.ceil(totalRequests / requestsPerBatch);

    console.log(`  Running ${totalRequests} requests at concurrency ${concurrency}...`);

    const batchStart = Date.now();
    for (let batch = 0; batch < batches; batch++) {
      const batchPromises = [];
      for (let i = 0; i < requestsPerBatch && (batch * requestsPerBatch + i) < totalRequests; i++) {
        batchPromises.push(this.runSingle(operation, payload));
      }
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
    }
    const totalTime = Date.now() - batchStart;

    const latencies = results.filter(r => r.success).map(r => r.latency);
    const successRate = results.filter(r => r.success).length / results.length;
    const throughput = (results.filter(r => r.success).length / totalTime) * 1000;

    return {
      system: this.name,
      operation,
      concurrency,
      totalRequests,
      totalTimeMs: totalTime,
      results,
      latencies,
      successRate,
      throughput,
      statistics: Statistics.summary(latencies)
    };
  }
}

// Main benchmark orchestrator
class BaselineBenchmark {
  constructor() {
    this.runners = {
      oidc: new BenchmarkRunner('OIDC-Federation', CONFIG.OIDC_URL),
      centralized: new BenchmarkRunner('Centralized', CONFIG.CENTRALIZED_URL),
      indy: new BenchmarkRunner('Indy-Simulated', CONFIG.INDY_URL),
      ourSolution: new BenchmarkRunner('Fabric-OpenID4VC', CONFIG.OUR_SOLUTION_URL)
    };

    this.results = {
      timestamp: new Date().toISOString(),
      config: CONFIG,
      benchmarks: {},
      comparisons: {}
    };
  }

  async checkHealth() {
    console.log('Checking system health...\n');
    const health = {};
    for (const [name, runner] of Object.entries(this.runners)) {
      const healthy = await runner.isHealthy();
      health[name] = healthy;
      console.log(`  ${name}: ${healthy ? '✓ Healthy' : '✗ Unavailable'}`);
    }
    console.log();
    return health;
  }

  async runCredentialIssuanceBenchmark() {
    console.log('\n=== Credential Issuance Benchmark ===\n');
    const benchmarkResults = {};

    // Test payloads for each system
    const payloads = {
      oidc: {
        subjectId: 'test-user',
        credentialType: 'KYCCredential',
        claims: { name: 'Test User', verified: true }
      },
      centralized: {
        userId: '550e8400-e29b-41d4-a716-446655440000',
        credentialType: 'KYCCredential',
        issuerDomain: 'finance',
        claims: { name: 'Test User', verified: true }
      },
      indy: {
        sourceDomain: 'finance',
        targetDomain: 'healthcare',
        credentialType: 'KYCCredential',
        attributes: { name: 'Test User', verified: 'true' }
      },
      ourSolution: {
        type: 'KYCCredential',
        subjectDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        claims: { name: 'Test User', verified: true }
      }
    };

    const operations = {
      oidc: '/credentials/issue',
      centralized: '/credentials/issue',
      indy: '/test/full-flow', // Indy requires setup, use full-flow
      ourSolution: '/credentials/issue' // Uses new benchmark endpoint
    };

    for (const [name, runner] of Object.entries(this.runners)) {
      if (await runner.isHealthy()) {
        console.log(`Benchmarking ${name}...`);
        await runner.resetMetrics();
        benchmarkResults[name] = await runner.runBenchmark(
          operations[name],
          payloads[name]
        );
      } else {
        console.log(`Skipping ${name} (unavailable)`);
      }
    }

    this.results.benchmarks.credentialIssuance = benchmarkResults;
    return benchmarkResults;
  }

  async runCrossDomainVerificationBenchmark() {
    console.log('\n=== Cross-Domain Verification Benchmark ===\n');
    const benchmarkResults = {};

    const payloads = {
      oidc: {
        accessToken: 'simulated-token',
        sourceDomain: 'finance',
        targetDomain: 'healthcare',
        requiredClaims: ['name']
      },
      centralized: {
        credentialId: '550e8400-e29b-41d4-a716-446655440001',
        sourceDomain: 'finance',
        targetDomain: 'healthcare',
        requiredClaims: ['name']
      },
      indy: {
        credentialId: 'test-credential-id',
        sourceDomain: 'finance',
        targetDomain: 'healthcare',
        proofRequest: {}
      },
      ourSolution: {
        credentialId: 'test-credential',
        sourceDomain: 'finance',
        targetDomain: 'healthcare',
        credentialType: 'KYCCredential'
      }
    };

    for (const [name, runner] of Object.entries(this.runners)) {
      if (await runner.isHealthy()) {
        console.log(`Benchmarking ${name}...`);
        await runner.resetMetrics();
        benchmarkResults[name] = await runner.runBenchmark(
          '/verify/cross-domain',
          payloads[name]
        );
      }
    }

    this.results.benchmarks.crossDomainVerification = benchmarkResults;
    return benchmarkResults;
  }

  async runFullFlowBenchmark() {
    console.log('\n=== Full Flow Benchmark ===\n');
    const benchmarkResults = {};

    const payload = {
      sourceDomain: 'finance',
      targetDomain: 'healthcare',
      credentialType: 'KYCCredential',
      claims: { name: 'Test User', verified: true },
      attributes: { name: 'Test User', verified: 'true' }
    };

    for (const [name, runner] of Object.entries(this.runners)) {
      if (await runner.isHealthy()) {
        console.log(`Benchmarking ${name}...`);
        await runner.resetMetrics();
        benchmarkResults[name] = await runner.runBenchmark(
          '/test/full-flow',
          payload
        );
      }
    }

    this.results.benchmarks.fullFlow = benchmarkResults;
    return benchmarkResults;
  }

  async runThroughputBenchmark() {
    console.log('\n=== Throughput Benchmark ===\n');
    const benchmarkResults = {};

    const payload = {
      sourceDomain: 'finance',
      targetDomain: 'healthcare',
      credentialType: 'KYCCredential',
      claims: { name: 'Test User' }
    };

    for (const [name, runner] of Object.entries(this.runners)) {
      if (await runner.isHealthy()) {
        console.log(`\nBenchmarking ${name} throughput...`);
        benchmarkResults[name] = {};

        for (const concurrency of CONFIG.CONCURRENCY_LEVELS) {
          console.log(`\n  Concurrency level: ${concurrency}`);
          await runner.resetMetrics();
          benchmarkResults[name][`c${concurrency}`] = await runner.runConcurrentBenchmark(
            '/test/full-flow',
            payload,
            concurrency
          );
        }
      }
    }

    this.results.benchmarks.throughput = benchmarkResults;
    return benchmarkResults;
  }

  compareResults() {
    console.log('\n=== Statistical Comparison ===\n');
    const comparisons = {};

    for (const [benchmarkName, benchmarkData] of Object.entries(this.results.benchmarks)) {
      if (benchmarkName === 'throughput') continue;

      const systems = Object.keys(benchmarkData);
      comparisons[benchmarkName] = {};

      // Compare our solution against each baseline
      if (benchmarkData.ourSolution) {
        const ourLatencies = benchmarkData.ourSolution.latencies;

        for (const system of systems) {
          if (system === 'ourSolution') continue;
          if (!benchmarkData[system]) continue;

          const baselineLatencies = benchmarkData[system].latencies;

          // Skip comparison if either system has no data
          if (!ourLatencies || ourLatencies.length === 0 || !baselineLatencies || baselineLatencies.length === 0) {
            console.log(`${benchmarkName}: Skipping ${system} comparison (insufficient data)`);
            continue;
          }

          const tTest = Statistics.tTest(ourLatencies, baselineLatencies);
          const effectSize = Statistics.cohenD(ourLatencies, baselineLatencies);

          comparisons[benchmarkName][`ourSolution_vs_${system}`] = {
            ourMean: Statistics.mean(ourLatencies),
            baselineMean: Statistics.mean(baselineLatencies),
            difference: Statistics.mean(ourLatencies) - Statistics.mean(baselineLatencies),
            percentDifference: ((Statistics.mean(ourLatencies) - Statistics.mean(baselineLatencies)) /
              Statistics.mean(baselineLatencies)) * 100,
            tTest,
            effectSize,
            effectSizeInterpretation: Math.abs(effectSize) < 0.2 ? 'negligible' :
              Math.abs(effectSize) < 0.5 ? 'small' :
                Math.abs(effectSize) < 0.8 ? 'medium' : 'large'
          };

          console.log(`${benchmarkName}: Our Solution vs ${system}`);
          console.log(`  Mean difference: ${comparisons[benchmarkName][`ourSolution_vs_${system}`].difference.toFixed(2)}ms`);
          console.log(`  Percent difference: ${comparisons[benchmarkName][`ourSolution_vs_${system}`].percentDifference.toFixed(2)}%`);
          console.log(`  p-value: ${tTest.pValue.toFixed(4)} (${tTest.significant ? 'significant' : 'not significant'})`);
          console.log(`  Effect size (Cohen's d): ${effectSize.toFixed(3)} (${comparisons[benchmarkName][`ourSolution_vs_${system}`].effectSizeInterpretation})`);
          console.log();
        }
      }
    }

    this.results.comparisons = comparisons;
    return comparisons;
  }

  generateReport() {
    console.log('\n=== Generating Report ===\n');

    // Generate summary table
    let report = '# Baseline Comparison Report\n\n';
    report += `Generated: ${this.results.timestamp}\n`;
    report += `Runs per test: ${CONFIG.RUNS}\n`;
    report += `Confidence level: ${CONFIG.CONFIDENCE_LEVEL * 100}%\n\n`;

    report += '## Latency Summary (ms)\n\n';
    report += '| System | Mean | Median | P95 | P99 | Std Dev | 95% CI |\n';
    report += '|--------|------|--------|-----|-----|---------|--------|\n';

    for (const [benchmarkName, benchmarkData] of Object.entries(this.results.benchmarks)) {
      if (benchmarkName === 'throughput') continue;

      report += `\n### ${benchmarkName}\n\n`;
      report += '| System | Mean | Median | P95 | P99 | Std Dev | 95% CI |\n';
      report += '|--------|------|--------|-----|-----|---------|--------|\n';

      for (const [system, data] of Object.entries(benchmarkData)) {
        if (!data.statistics) continue;
        const s = data.statistics;
        const ci = s.ci95;
        report += `| ${system} | ${s.mean.toFixed(2)} | ${s.median.toFixed(2)} | `;
        report += `${s.p95.toFixed(2)} | ${s.p99.toFixed(2)} | ${s.stdDev.toFixed(2)} | `;
        report += `[${ci.lower.toFixed(2)}, ${ci.upper.toFixed(2)}] |\n`;
      }
    }

    report += '\n## Statistical Comparisons\n\n';
    for (const [benchmark, comparisons] of Object.entries(this.results.comparisons)) {
      report += `### ${benchmark}\n\n`;
      for (const [comparison, data] of Object.entries(comparisons)) {
        report += `**${comparison}**\n`;
        report += `- Mean difference: ${data.difference.toFixed(2)}ms (${data.percentDifference.toFixed(2)}%)\n`;
        report += `- t-statistic: ${data.tTest.tStatistic.toFixed(3)}\n`;
        report += `- p-value: ${data.tTest.pValue.toFixed(4)} (${data.tTest.significant ? '✓ significant' : '✗ not significant'})\n`;
        report += `- Effect size: ${data.effectSize.toFixed(3)} (${data.effectSizeInterpretation})\n\n`;
      }
    }

    return report;
  }

  async saveResults() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    // Save raw JSON results
    const jsonPath = path.join(CONFIG.RESULTS_DIR, `benchmark-${timestamp}.json`);
    fs.writeFileSync(jsonPath, JSON.stringify(this.results, null, 2));
    console.log(`Raw results saved to: ${jsonPath}`);

    // Save markdown report
    const report = this.generateReport();
    const mdPath = path.join(CONFIG.RESULTS_DIR, `report-${timestamp}.md`);
    fs.writeFileSync(mdPath, report);
    console.log(`Report saved to: ${mdPath}`);

    // Save CSV for easy analysis
    const csvData = [];
    for (const [benchmark, data] of Object.entries(this.results.benchmarks)) {
      if (benchmark === 'throughput') continue;
      for (const [system, results] of Object.entries(data)) {
        if (!results.statistics) continue;
        csvData.push({
          benchmark,
          system,
          runs: results.latencies.length,
          mean: results.statistics.mean,
          median: results.statistics.median,
          stdDev: results.statistics.stdDev,
          p50: results.statistics.p50,
          p95: results.statistics.p95,
          p99: results.statistics.p99,
          min: results.statistics.min,
          max: results.statistics.max,
          successRate: results.successRate
        });
      }
    }

    const csvPath = path.join(CONFIG.RESULTS_DIR, `latency-${timestamp}.csv`);
    const csvHeader = Object.keys(csvData[0] || {}).join(',');
    const csvRows = csvData.map(row => Object.values(row).join(','));
    fs.writeFileSync(csvPath, [csvHeader, ...csvRows].join('\n'));
    console.log(`CSV saved to: ${csvPath}`);
  }

  async run() {
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║       Baseline Benchmark for Academic Comparison           ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');

    const health = await this.checkHealth();
    const availableSystems = Object.values(health).filter(h => h).length;

    if (availableSystems === 0) {
      console.log('No systems available. Please start the baseline services first.');
      return;
    }

    console.log(`Running benchmarks with ${availableSystems} available systems...\n`);

    // Run benchmarks
    await this.runCredentialIssuanceBenchmark();
    await this.runCrossDomainVerificationBenchmark();
    await this.runFullFlowBenchmark();

    if (!process.argv.includes('--quick')) {
      await this.runThroughputBenchmark();
    }

    // Compare and analyze
    this.compareResults();

    // Save results
    await this.saveResults();

    console.log('\n✓ Benchmark complete!');
  }
}

// Run benchmark
const benchmark = new BaselineBenchmark();
benchmark.run().catch(console.error);
