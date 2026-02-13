/**
 * Cross-Domain Identity Federation Integration Tests
 *
 * This file contains integration tests for the three main use case scenarios:
 * 1. Finance -> Healthcare: Patient uses bank KYC credential for hospital services
 * 2. Education -> Finance: Student uses diploma for bank account opening
 * 3. Healthcare -> Education: Medical personnel certification for university access
 */

import axios from 'axios';

// Test configuration
const CONFIG = {
  bridgeUrl: process.env.BRIDGE_URL || 'http://localhost:4000',
  financeIssuer: process.env.FINANCE_ISSUER || 'http://localhost:3001',
  healthcareIssuer: process.env.HEALTHCARE_ISSUER || 'http://localhost:3002',
  educationIssuer: process.env.EDUCATION_ISSUER || 'http://localhost:3003',
  holderWallet: process.env.HOLDER_WALLET || 'http://localhost:3010',
  verifier: process.env.VERIFIER || 'http://localhost:3020',
};

// Test data
const TEST_HOLDER_DID = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';

interface TestResult {
  scenario: string;
  step: string;
  success: boolean;
  duration: number;
  details?: any;
  error?: string;
}

const results: TestResult[] = [];

function recordResult(scenario: string, step: string, success: boolean, duration: number, details?: any, error?: string) {
  results.push({ scenario, step, success, duration, details, error });
  const status = success ? '✓' : '✗';
  console.log(`  ${status} ${step} (${duration}ms)`);
  if (error) console.log(`    Error: ${error}`);
}

async function measureAsync<T>(fn: () => Promise<T>): Promise<{ result: T; duration: number }> {
  const start = Date.now();
  const result = await fn();
  return { result, duration: Date.now() - start };
}

// ============================================
// SCENARIO 1: Finance -> Healthcare
// ============================================

async function testFinanceToHealthcare() {
  console.log('\n=== Scenario 1: Finance -> Healthcare ===');
  console.log('Use case: Patient uses bank KYC credential for hospital service access\n');

  const scenario = 'Finance->Healthcare';

  // Step 1: Issue KYC Credential from Finance Issuer
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.financeIssuer}/credentials/offer`, {
        credentialType: 'KYCCredential',
        subjectDid: TEST_HOLDER_DID,
        claims: {
          fullName: 'Ahmet Yilmaz',
          dateOfBirth: '1990-05-15',
          nationalID: '12345678901',
          address: {
            street: 'Ataturk Cad. No:123',
            city: 'Istanbul',
            country: 'Turkey',
          },
          verificationLevel: 'ENHANCED',
          verificationDate: new Date().toISOString(),
        },
      });
      return response.data;
    });
    recordResult(scenario, 'Issue KYC Credential from Bank', true, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Issue KYC Credential from Bank', false, 0, null, error.message);
  }

  // Step 2: Validate Issuer Trust via Bridge
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/issuer/validate`, {
        issuerDid: 'did:web:bank.finance.crossdomain.com',
        credentialType: 'KYCCredential',
      });
      return response.data;
    });
    recordResult(scenario, 'Validate Finance Issuer Trust', result.isValid, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Validate Finance Issuer Trust', false, 0, null, error.message);
  }

  // Step 3: Evaluate Cross-Domain Policy
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/policy/evaluate`, {
        credentialType: 'KYCCredential',
        sourceDomain: 'FINANCE',
        targetDomain: 'HEALTHCARE',
        issuerTrustLevel: 5,
        credentialAge: 30,
        availableAttributes: ['fullName', 'dateOfBirth', 'nationalID', 'verificationLevel'],
      });
      return response.data;
    });
    recordResult(scenario, 'Evaluate Cross-Domain Policy', result.isAllowed, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Evaluate Cross-Domain Policy', false, 0, null, error.message);
  }

  // Step 4: Cross-Domain Verification
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/cross-domain/verify`, {
        sourceDomain: 'FINANCE',
        targetDomain: 'HEALTHCARE',
        credentialType: 'KYCCredential',
        issuerDid: 'did:web:bank.finance.crossdomain.com',
      });
      return response.data;
    });
    recordResult(scenario, 'Complete Cross-Domain Verification', result.success, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Complete Cross-Domain Verification', false, 0, null, error.message);
  }
}

// ============================================
// SCENARIO 2: Education -> Finance
// ============================================

async function testEducationToFinance() {
  console.log('\n=== Scenario 2: Education -> Finance ===');
  console.log('Use case: Student uses diploma for bank account opening\n');

  const scenario = 'Education->Finance';

  // Step 1: Issue Diploma Credential from Education Issuer
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.educationIssuer}/credentials/offer`, {
        credentialType: 'DiplomaCredential',
        subjectDid: TEST_HOLDER_DID,
        claims: {
          studentName: 'Ahmet Yilmaz',
          studentID: 'STU2024001',
          degree: 'Bachelor of Science',
          major: 'Computer Science',
          graduationDate: '2024-06-15',
          gpa: 3.75,
          honors: 'MAGNA_CUM_LAUDE',
          institution: 'Istanbul Technical University',
        },
      });
      return response.data;
    });
    recordResult(scenario, 'Issue Diploma Credential from University', true, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Issue Diploma Credential from University', false, 0, null, error.message);
  }

  // Step 2: Validate Issuer Trust via Bridge
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/issuer/validate`, {
        issuerDid: 'did:web:university.education.crossdomain.com',
        credentialType: 'DiplomaCredential',
      });
      return response.data;
    });
    recordResult(scenario, 'Validate Education Issuer Trust', result.isValid, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Validate Education Issuer Trust', false, 0, null, error.message);
  }

  // Step 3: Evaluate Cross-Domain Policy
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/policy/evaluate`, {
        credentialType: 'DiplomaCredential',
        sourceDomain: 'EDUCATION',
        targetDomain: 'FINANCE',
        issuerTrustLevel: 5,
        credentialAge: 30,
        availableAttributes: ['studentName', 'degree', 'graduationDate', 'institution'],
      });
      return response.data;
    });
    recordResult(scenario, 'Evaluate Cross-Domain Policy', result.isAllowed, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Evaluate Cross-Domain Policy', false, 0, null, error.message);
  }

  // Step 4: Cross-Domain Verification
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/cross-domain/verify`, {
        sourceDomain: 'EDUCATION',
        targetDomain: 'FINANCE',
        credentialType: 'DiplomaCredential',
        issuerDid: 'did:web:university.education.crossdomain.com',
      });
      return response.data;
    });
    recordResult(scenario, 'Complete Cross-Domain Verification', result.success, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Complete Cross-Domain Verification', false, 0, null, error.message);
  }
}

// ============================================
// SCENARIO 3: Healthcare -> Education
// ============================================

async function testHealthcareToEducation() {
  console.log('\n=== Scenario 3: Healthcare -> Education ===');
  console.log('Use case: Medical personnel certification for university access\n');

  const scenario = 'Healthcare->Education';

  // Step 1: Issue Vaccination Credential from Healthcare Issuer
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.healthcareIssuer}/credentials/offer`, {
        credentialType: 'VaccinationCredential',
        subjectDid: TEST_HOLDER_DID,
        claims: {
          vaccinationType: 'COVID-19',
          vaccinationDate: '2024-01-15',
          batchNumber: 'BATCH2024001',
          provider: 'Ministry of Health',
          nextDoseDate: null,
        },
      });
      return response.data;
    });
    recordResult(scenario, 'Issue Vaccination Credential from Hospital', true, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Issue Vaccination Credential from Hospital', false, 0, null, error.message);
  }

  // Step 2: Validate Issuer Trust via Bridge
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/issuer/validate`, {
        issuerDid: 'did:web:hospital.healthcare.crossdomain.com',
        credentialType: 'VaccinationCredential',
      });
      return response.data;
    });
    recordResult(scenario, 'Validate Healthcare Issuer Trust', result.isValid, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Validate Healthcare Issuer Trust', false, 0, null, error.message);
  }

  // Step 3: Evaluate Cross-Domain Policy
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/policy/evaluate`, {
        credentialType: 'VaccinationCredential',
        sourceDomain: 'HEALTHCARE',
        targetDomain: 'EDUCATION',
        issuerTrustLevel: 5,
        credentialAge: 30,
        availableAttributes: ['vaccinationType', 'vaccinationDate', 'provider'],
      });
      return response.data;
    });
    recordResult(scenario, 'Evaluate Cross-Domain Policy', result.isAllowed, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Evaluate Cross-Domain Policy', false, 0, null, error.message);
  }

  // Step 4: Cross-Domain Verification
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/cross-domain/verify`, {
        sourceDomain: 'HEALTHCARE',
        targetDomain: 'EDUCATION',
        credentialType: 'VaccinationCredential',
        issuerDid: 'did:web:hospital.healthcare.crossdomain.com',
      });
      return response.data;
    });
    recordResult(scenario, 'Complete Cross-Domain Verification', result.success, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Complete Cross-Domain Verification', false, 0, null, error.message);
  }
}

// ============================================
// MULTI-HOP SCENARIO
// ============================================

async function testMultiHopScenario() {
  console.log('\n=== Multi-Hop Scenario ===');
  console.log('Use case: Credential chain A->B->C for transitive trust evaluation\n');

  const scenario = 'Multi-Hop';

  // Step 1: Finance -> Healthcare (first hop)
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/cross-domain/verify`, {
        sourceDomain: 'FINANCE',
        targetDomain: 'HEALTHCARE',
        credentialType: 'KYCCredential',
        issuerDid: 'did:web:bank.finance.crossdomain.com',
      });
      return response.data;
    });
    recordResult(scenario, 'First Hop: Finance -> Healthcare', result.success, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'First Hop: Finance -> Healthcare', false, 0, null, error.message);
  }

  // Step 2: Healthcare -> Education (second hop)
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/cross-domain/verify`, {
        sourceDomain: 'HEALTHCARE',
        targetDomain: 'EDUCATION',
        credentialType: 'MedicalClearanceCredential',
        issuerDid: 'did:web:hospital.healthcare.crossdomain.com',
      });
      return response.data;
    });
    recordResult(scenario, 'Second Hop: Healthcare -> Education', result.success, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Second Hop: Healthcare -> Education', false, 0, null, error.message);
  }

  // Step 3: Education -> Finance (completing the chain)
  try {
    const { result, duration } = await measureAsync(async () => {
      const response = await axios.post(`${CONFIG.bridgeUrl}/api/cross-domain/verify`, {
        sourceDomain: 'EDUCATION',
        targetDomain: 'FINANCE',
        credentialType: 'CertificateCredential',
        issuerDid: 'did:web:university.education.crossdomain.com',
      });
      return response.data;
    });
    recordResult(scenario, 'Third Hop: Education -> Finance', result.success, duration, result);
  } catch (error: any) {
    recordResult(scenario, 'Third Hop: Education -> Finance', false, 0, null, error.message);
  }
}

// ============================================
// GENERATE SUMMARY REPORT
// ============================================

function generateReport() {
  console.log('\n========================================');
  console.log('         TEST SUMMARY REPORT           ');
  console.log('========================================\n');

  const totalTests = results.length;
  const passedTests = results.filter((r) => r.success).length;
  const failedTests = totalTests - passedTests;

  console.log(`Total Tests: ${totalTests}`);
  console.log(`Passed: ${passedTests}`);
  console.log(`Failed: ${failedTests}`);
  console.log(`Success Rate: ${((passedTests / totalTests) * 100).toFixed(2)}%`);

  // Calculate average latency
  const totalDuration = results.reduce((sum, r) => sum + r.duration, 0);
  const avgDuration = totalDuration / totalTests;
  console.log(`\nAverage Latency: ${avgDuration.toFixed(2)}ms`);

  // Group by scenario
  const scenarios = ['Finance->Healthcare', 'Education->Finance', 'Healthcare->Education', 'Multi-Hop'];
  console.log('\nResults by Scenario:');
  for (const scenario of scenarios) {
    const scenarioResults = results.filter((r) => r.scenario === scenario);
    const scenarioPassed = scenarioResults.filter((r) => r.success).length;
    const scenarioAvgDuration = scenarioResults.reduce((sum, r) => sum + r.duration, 0) / scenarioResults.length;
    console.log(`  ${scenario}: ${scenarioPassed}/${scenarioResults.length} passed (avg: ${scenarioAvgDuration.toFixed(2)}ms)`);
  }

  // Failed tests details
  if (failedTests > 0) {
    console.log('\nFailed Tests:');
    results.filter((r) => !r.success).forEach((r) => {
      console.log(`  - [${r.scenario}] ${r.step}: ${r.error}`);
    });
  }

  // Return results for further processing
  return {
    totalTests,
    passedTests,
    failedTests,
    successRate: (passedTests / totalTests) * 100,
    avgDuration,
    results,
  };
}

// ============================================
// MAIN EXECUTION
// ============================================

async function main() {
  console.log('Cross-Domain Identity Federation - Integration Tests');
  console.log('====================================================');
  console.log(`Bridge URL: ${CONFIG.bridgeUrl}`);
  console.log(`Finance Issuer: ${CONFIG.financeIssuer}`);
  console.log(`Healthcare Issuer: ${CONFIG.healthcareIssuer}`);
  console.log(`Education Issuer: ${CONFIG.educationIssuer}`);

  try {
    // Check if services are available
    console.log('\nChecking service availability...');
    const healthCheck = await axios.get(`${CONFIG.bridgeUrl}/health`);
    console.log(`Bridge service: ${healthCheck.data.status}`);

    // Run all test scenarios
    await testFinanceToHealthcare();
    await testEducationToFinance();
    await testHealthcareToEducation();
    await testMultiHopScenario();

    // Generate report
    const report = generateReport();

    // Exit with appropriate code
    process.exit(report.failedTests > 0 ? 1 : 0);
  } catch (error: any) {
    console.error('\nFailed to run tests:', error.message);
    console.error('Make sure all services are running.');
    process.exit(1);
  }
}

main();
