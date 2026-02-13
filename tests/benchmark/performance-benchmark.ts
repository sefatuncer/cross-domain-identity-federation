/**
 * Performance Benchmark Suite for Cross-Domain Identity Federation
 *
 * This benchmark measures:
 * - Single-domain credential issuance latency
 * - Cross-domain credential verification latency
 * - Concurrent cross-domain request throughput
 * - Fabric query latency
 * - End-to-end flow latency
 * - Bridge overhead
 */

import axios from 'axios';

// Configuration
const CONFIG = {
  bridgeUrl: process.env.BRIDGE_URL || 'http://localhost:4000',
  financeIssuer: process.env.FINANCE_ISSUER || 'http://localhost:3001',
  healthcareIssuer: process.env.HEALTHCARE_ISSUER || 'http://localhost:3002',
  educationIssuer: process.env.EDUCATION_ISSUER || 'http://localhost:3003',
  verifier: process.env.VERIFIER || 'http://localhost:3020',
};

// Test parameters
const CONCURRENCY_LEVELS = [1, 5, 10, 20, 50, 100];
const ITERATIONS_PER_LEVEL = 10;
const WARMUP_ITERATIONS = 3;

interface BenchmarkResult {
  testName: string;
  concurrency: number;
  iterations: number;
  totalTime: number;
  avgLatency: number;
  minLatency: number;
  maxLatency: number;
  p50Latency: number;
  p95Latency: number;
  p99Latency: number;
  throughput: number;
  successRate: number;
  errors: number;
}

interface LatencyMeasurement {
  success: boolean;
  latency: number;
  error?: string;
}

// Helper functions
function percentile(arr: number[], p: number): number {
  const sorted = [...arr].sort((a, b) => a - b);
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)];
}

function calculateStats(measurements: LatencyMeasurement[]): Partial<BenchmarkResult> {
  const successful = measurements.filter((m) => m.success);
  const latencies = successful.map((m) => m.latency);

  if (latencies.length === 0) {
    return {
      avgLatency: 0,
      minLatency: 0,
      maxLatency: 0,
      p50Latency: 0,
      p95Latency: 0,
      p99Latency: 0,
      successRate: 0,
      errors: measurements.length,
    };
  }

  return {
    avgLatency: latencies.reduce((a, b) => a + b, 0) / latencies.length,
    minLatency: Math.min(...latencies),
    maxLatency: Math.max(...latencies),
    p50Latency: percentile(latencies, 50),
    p95Latency: percentile(latencies, 95),
    p99Latency: percentile(latencies, 99),
    successRate: (successful.length / measurements.length) * 100,
    errors: measurements.length - successful.length,
  };
}

async function measureLatency(fn: () => Promise<any>): Promise<LatencyMeasurement> {
  const start = Date.now();
  try {
    await fn();
    return { success: true, latency: Date.now() - start };
  } catch (error: any) {
    return { success: false, latency: Date.now() - start, error: error.message };
  }
}

async function runConcurrent(fn: () => Promise<any>, concurrency: number): Promise<LatencyMeasurement[]> {
  const promises = Array(concurrency)
    .fill(null)
    .map(() => measureLatency(fn));
  return Promise.all(promises);
}

// Benchmark tests
async function benchmarkIssuerValidation(concurrency: number, iterations: number): Promise<BenchmarkResult> {
  const measurements: LatencyMeasurement[] = [];
  const startTime = Date.now();

  for (let i = 0; i < iterations; i++) {
    const results = await runConcurrent(async () => {
      return axios.post(`${CONFIG.bridgeUrl}/api/issuer/validate`, {
        issuerDid: 'did:web:bank.finance.crossdomain.com',
        credentialType: 'KYCCredential',
      });
    }, concurrency);
    measurements.push(...results);
  }

  const totalTime = Date.now() - startTime;
  const stats = calculateStats(measurements);

  return {
    testName: 'Issuer Validation',
    concurrency,
    iterations: measurements.length,
    totalTime,
    throughput: (measurements.filter((m) => m.success).length / totalTime) * 1000,
    ...stats,
  } as BenchmarkResult;
}

async function benchmarkPolicyEvaluation(concurrency: number, iterations: number): Promise<BenchmarkResult> {
  const measurements: LatencyMeasurement[] = [];
  const startTime = Date.now();

  for (let i = 0; i < iterations; i++) {
    const results = await runConcurrent(async () => {
      return axios.post(`${CONFIG.bridgeUrl}/api/policy/evaluate`, {
        credentialType: 'KYCCredential',
        sourceDomain: 'FINANCE',
        targetDomain: 'HEALTHCARE',
        issuerTrustLevel: 5,
        credentialAge: 30,
        availableAttributes: ['fullName', 'dateOfBirth', 'nationalID'],
      });
    }, concurrency);
    measurements.push(...results);
  }

  const totalTime = Date.now() - startTime;
  const stats = calculateStats(measurements);

  return {
    testName: 'Policy Evaluation',
    concurrency,
    iterations: measurements.length,
    totalTime,
    throughput: (measurements.filter((m) => m.success).length / totalTime) * 1000,
    ...stats,
  } as BenchmarkResult;
}

async function benchmarkCrossDomainVerification(concurrency: number, iterations: number): Promise<BenchmarkResult> {
  const measurements: LatencyMeasurement[] = [];
  const startTime = Date.now();

  const scenarios = [
    { source: 'FINANCE', target: 'HEALTHCARE', type: 'KYCCredential', issuer: 'bank.finance' },
    { source: 'EDUCATION', target: 'FINANCE', type: 'DiplomaCredential', issuer: 'university.education' },
    { source: 'HEALTHCARE', target: 'EDUCATION', type: 'VaccinationCredential', issuer: 'hospital.healthcare' },
  ];

  for (let i = 0; i < iterations; i++) {
    const scenario = scenarios[i % scenarios.length];
    const results = await runConcurrent(async () => {
      return axios.post(`${CONFIG.bridgeUrl}/api/cross-domain/verify`, {
        sourceDomain: scenario.source,
        targetDomain: scenario.target,
        credentialType: scenario.type,
        issuerDid: `did:web:${scenario.issuer}.crossdomain.com`,
      });
    }, concurrency);
    measurements.push(...results);
  }

  const totalTime = Date.now() - startTime;
  const stats = calculateStats(measurements);

  return {
    testName: 'Cross-Domain Verification',
    concurrency,
    iterations: measurements.length,
    totalTime,
    throughput: (measurements.filter((m) => m.success).length / totalTime) * 1000,
    ...stats,
  } as BenchmarkResult;
}

async function benchmarkCredentialIssuance(concurrency: number, iterations: number): Promise<BenchmarkResult> {
  const measurements: LatencyMeasurement[] = [];
  const startTime = Date.now();

  const issuers = [CONFIG.financeIssuer, CONFIG.healthcareIssuer, CONFIG.educationIssuer];
  const credTypes = ['KYCCredential', 'HealthInsuranceCredential', 'DiplomaCredential'];

  for (let i = 0; i < iterations; i++) {
    const issuerIndex = i % issuers.length;
    const results = await runConcurrent(async () => {
      return axios.post(`${issuers[issuerIndex]}/credentials/offer`, {
        credentialType: credTypes[issuerIndex],
        subjectDid: `did:key:z6Mk${Math.random().toString(36).substring(7)}`,
        claims: {
          testField: 'testValue',
          timestamp: Date.now(),
        },
      });
    }, concurrency);
    measurements.push(...results);
  }

  const totalTime = Date.now() - startTime;
  const stats = calculateStats(measurements);

  return {
    testName: 'Credential Issuance',
    concurrency,
    iterations: measurements.length,
    totalTime,
    throughput: (measurements.filter((m) => m.success).length / totalTime) * 1000,
    ...stats,
  } as BenchmarkResult;
}

async function benchmarkEndToEndFlow(concurrency: number, iterations: number): Promise<BenchmarkResult> {
  const measurements: LatencyMeasurement[] = [];
  const startTime = Date.now();

  for (let i = 0; i < iterations; i++) {
    const results = await runConcurrent(async () => {
      // Step 1: Validate issuer
      const issuerResult = await axios.post(`${CONFIG.bridgeUrl}/api/issuer/validate`, {
        issuerDid: 'did:web:bank.finance.crossdomain.com',
        credentialType: 'KYCCredential',
      });

      if (!issuerResult.data.isValid) {
        throw new Error('Issuer validation failed');
      }

      // Step 2: Evaluate policy
      const policyResult = await axios.post(`${CONFIG.bridgeUrl}/api/policy/evaluate`, {
        credentialType: 'KYCCredential',
        sourceDomain: 'FINANCE',
        targetDomain: 'HEALTHCARE',
        issuerTrustLevel: 5,
        credentialAge: 30,
        availableAttributes: ['fullName', 'dateOfBirth'],
      });

      if (!policyResult.data.isAllowed) {
        throw new Error('Policy evaluation failed');
      }

      // Step 3: Complete verification
      const verifyResult = await axios.post(`${CONFIG.bridgeUrl}/api/cross-domain/verify`, {
        sourceDomain: 'FINANCE',
        targetDomain: 'HEALTHCARE',
        credentialType: 'KYCCredential',
        issuerDid: 'did:web:bank.finance.crossdomain.com',
      });

      return verifyResult.data;
    }, concurrency);
    measurements.push(...results);
  }

  const totalTime = Date.now() - startTime;
  const stats = calculateStats(measurements);

  return {
    testName: 'End-to-End Flow',
    concurrency,
    iterations: measurements.length,
    totalTime,
    throughput: (measurements.filter((m) => m.success).length / totalTime) * 1000,
    ...stats,
  } as BenchmarkResult;
}

async function benchmarkAuditLogging(concurrency: number, iterations: number): Promise<BenchmarkResult> {
  const measurements: LatencyMeasurement[] = [];
  const startTime = Date.now();

  for (let i = 0; i < iterations; i++) {
    const results = await runConcurrent(async () => {
      return axios.post(`${CONFIG.bridgeUrl}/api/audit/log`, {
        eventType: 'CROSS_DOMAIN_SUCCESS',
        sourceDomain: 'FINANCE',
        targetDomain: 'HEALTHCARE',
        credentialType: 'KYCCredential',
        result: 'SUCCESS',
      });
    }, concurrency);
    measurements.push(...results);
  }

  const totalTime = Date.now() - startTime;
  const stats = calculateStats(measurements);

  return {
    testName: 'Audit Logging',
    concurrency,
    iterations: measurements.length,
    totalTime,
    throughput: (measurements.filter((m) => m.success).length / totalTime) * 1000,
    ...stats,
  } as BenchmarkResult;
}

// Report generation
function generateReport(results: BenchmarkResult[]): void {
  console.log('\n' + '='.repeat(100));
  console.log('                         PERFORMANCE BENCHMARK RESULTS');
  console.log('='.repeat(100));

  // Group by test name
  const testNames = [...new Set(results.map((r) => r.testName))];

  for (const testName of testNames) {
    const testResults = results.filter((r) => r.testName === testName);
    console.log(`\n${'─'.repeat(100)}`);
    console.log(`Test: ${testName}`);
    console.log('─'.repeat(100));
    console.log(
      'Concurrency'.padEnd(12) +
        'Iterations'.padEnd(12) +
        'Avg(ms)'.padEnd(10) +
        'P50(ms)'.padEnd(10) +
        'P95(ms)'.padEnd(10) +
        'P99(ms)'.padEnd(10) +
        'Throughput'.padEnd(12) +
        'Success%'.padEnd(10)
    );
    console.log('-'.repeat(100));

    for (const r of testResults) {
      console.log(
        String(r.concurrency).padEnd(12) +
          String(r.iterations).padEnd(12) +
          r.avgLatency.toFixed(2).padEnd(10) +
          r.p50Latency.toFixed(2).padEnd(10) +
          r.p95Latency.toFixed(2).padEnd(10) +
          r.p99Latency.toFixed(2).padEnd(10) +
          r.throughput.toFixed(2).padEnd(12) +
          r.successRate.toFixed(2).padEnd(10)
      );
    }
  }

  // Summary
  console.log('\n' + '='.repeat(100));
  console.log('                              SUMMARY');
  console.log('='.repeat(100));

  for (const testName of testNames) {
    const testResults = results.filter((r) => r.testName === testName);
    const avgLatencies = testResults.map((r) => r.avgLatency);
    const avgThroughput = testResults.map((r) => r.throughput);

    console.log(`\n${testName}:`);
    console.log(`  Average Latency: ${(avgLatencies.reduce((a, b) => a + b, 0) / avgLatencies.length).toFixed(2)}ms`);
    console.log(`  Peak Throughput: ${Math.max(...avgThroughput).toFixed(2)} ops/sec`);
    console.log(`  Min Latency: ${Math.min(...testResults.map((r) => r.minLatency)).toFixed(2)}ms`);
    console.log(`  Max Latency: ${Math.max(...testResults.map((r) => r.maxLatency)).toFixed(2)}ms`);
  }

  // Generate CSV output
  console.log('\n' + '='.repeat(100));
  console.log('                              CSV OUTPUT');
  console.log('='.repeat(100));
  console.log('\ntest_name,concurrency,iterations,avg_latency_ms,p50_ms,p95_ms,p99_ms,throughput_ops_sec,success_rate');
  for (const r of results) {
    console.log(
      `${r.testName},${r.concurrency},${r.iterations},${r.avgLatency.toFixed(2)},${r.p50Latency.toFixed(2)},${r.p95Latency.toFixed(2)},${r.p99Latency.toFixed(2)},${r.throughput.toFixed(2)},${r.successRate.toFixed(2)}`
    );
  }
}

// Main execution
async function main() {
  console.log('Cross-Domain Identity Federation - Performance Benchmark');
  console.log('=========================================================');
  console.log(`Bridge URL: ${CONFIG.bridgeUrl}`);
  console.log(`Concurrency Levels: ${CONCURRENCY_LEVELS.join(', ')}`);
  console.log(`Iterations per Level: ${ITERATIONS_PER_LEVEL}`);

  // Check service availability
  try {
    console.log('\nChecking service availability...');
    await axios.get(`${CONFIG.bridgeUrl}/health`);
    console.log('Bridge service is available.');
  } catch (error) {
    console.error('Bridge service is not available. Please start the services first.');
    process.exit(1);
  }

  // Warmup
  console.log(`\nWarmup (${WARMUP_ITERATIONS} iterations)...`);
  for (let i = 0; i < WARMUP_ITERATIONS; i++) {
    await axios.post(`${CONFIG.bridgeUrl}/api/issuer/validate`, {
      issuerDid: 'did:web:bank.finance.crossdomain.com',
      credentialType: 'KYCCredential',
    });
  }
  console.log('Warmup complete.');

  const allResults: BenchmarkResult[] = [];

  // Run benchmarks
  console.log('\nRunning benchmarks...\n');

  for (const concurrency of CONCURRENCY_LEVELS) {
    console.log(`\n--- Concurrency: ${concurrency} ---`);

    console.log('  Running: Issuer Validation...');
    allResults.push(await benchmarkIssuerValidation(concurrency, ITERATIONS_PER_LEVEL));

    console.log('  Running: Policy Evaluation...');
    allResults.push(await benchmarkPolicyEvaluation(concurrency, ITERATIONS_PER_LEVEL));

    console.log('  Running: Cross-Domain Verification...');
    allResults.push(await benchmarkCrossDomainVerification(concurrency, ITERATIONS_PER_LEVEL));

    console.log('  Running: Audit Logging...');
    allResults.push(await benchmarkAuditLogging(concurrency, ITERATIONS_PER_LEVEL));

    console.log('  Running: End-to-End Flow...');
    allResults.push(await benchmarkEndToEndFlow(concurrency, ITERATIONS_PER_LEVEL));
  }

  // Generate report
  generateReport(allResults);

  console.log('\nBenchmark complete.');
}

main().catch(console.error);
