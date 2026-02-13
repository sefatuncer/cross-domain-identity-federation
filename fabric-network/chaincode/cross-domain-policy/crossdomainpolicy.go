// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// CrossDomainPolicyContract provides functions for managing cross-domain policies
type CrossDomainPolicyContract struct {
	contractapi.Contract
}

// PolicyStatus represents the status of a policy
type PolicyStatus string

const (
	PolicyActive    PolicyStatus = "ACTIVE"
	PolicyInactive  PolicyStatus = "INACTIVE"
	PolicySuspended PolicyStatus = "SUSPENDED"
)

// DomainType represents the domain type
type DomainType string

const (
	DomainFinance    DomainType = "FINANCE"
	DomainHealthcare DomainType = "HEALTHCARE"
	DomainEducation  DomainType = "EDUCATION"
)

// TrustLevel represents the required trust level
type TrustLevel string

const (
	TrustBasic    TrustLevel = "BASIC"
	TrustStandard TrustLevel = "STANDARD"
	TrustEnhanced TrustLevel = "ENHANCED"
	TrustAssured  TrustLevel = "ASSURED"
)

// PolicyRule represents a specific rule within a policy
type PolicyRule struct {
	RuleID              string     `json:"ruleID"`
	CredentialType      string     `json:"credentialType"`
	RequiredTrustLevel  TrustLevel `json:"requiredTrustLevel"`
	RequiredAttributes  []string   `json:"requiredAttributes"`
	MaxCredentialAge    int        `json:"maxCredentialAge"` // in days
	RequireRevocationCheck bool    `json:"requireRevocationCheck"`
	AllowSelectiveDisclosure bool  `json:"allowSelectiveDisclosure"`
	AdditionalConditions map[string]string `json:"additionalConditions"`
}

// CrossDomainPolicy represents a policy for cross-domain credential acceptance
type CrossDomainPolicy struct {
	PolicyID          string            `json:"policyID"`
	PolicyName        string            `json:"policyName"`
	Description       string            `json:"description"`
	SourceDomain      DomainType        `json:"sourceDomain"`
	TargetDomain      DomainType        `json:"targetDomain"`
	Status            PolicyStatus      `json:"status"`
	Rules             []PolicyRule      `json:"rules"`
	EffectiveFrom     string            `json:"effectiveFrom"`
	EffectiveUntil    string            `json:"effectiveUntil"`
	CreatedAt         string            `json:"createdAt"`
	UpdatedAt         string            `json:"updatedAt"`
	CreatedBy         string            `json:"createdBy"`
	ApprovedBy        []string          `json:"approvedBy"`
	Metadata          map[string]string `json:"metadata"`
}

// PolicyEvaluationRequest represents a request to evaluate a policy
type PolicyEvaluationRequest struct {
	CredentialType    string            `json:"credentialType"`
	SourceDomain      string            `json:"sourceDomain"`
	TargetDomain      string            `json:"targetDomain"`
	IssuerDID         string            `json:"issuerDID"`
	IssuerTrustLevel  int               `json:"issuerTrustLevel"`
	CredentialAge     int               `json:"credentialAge"` // in days
	AvailableAttributes []string        `json:"availableAttributes"`
	Metadata          map[string]string `json:"metadata"`
}

// PolicyEvaluationResult represents the result of policy evaluation
type PolicyEvaluationResult struct {
	IsAllowed           bool     `json:"isAllowed"`
	PolicyID            string   `json:"policyID"`
	MatchedRuleID       string   `json:"matchedRuleID"`
	Reasons             []string `json:"reasons"`
	RequiredAttributes  []string `json:"requiredAttributes"`
	MissingAttributes   []string `json:"missingAttributes"`
	AllowSelectiveDisclosure bool `json:"allowSelectiveDisclosure"`
	EvaluatedAt         string   `json:"evaluatedAt"`
	RecommendedActions  []string `json:"recommendedActions"`
}

// VerificationRecord represents a cross-domain verification event
type VerificationRecord struct {
	RecordID          string            `json:"recordID"`
	PolicyID          string            `json:"policyID"`
	SourceDomain      string            `json:"sourceDomain"`
	TargetDomain      string            `json:"targetDomain"`
	CredentialType    string            `json:"credentialType"`
	IssuerDID         string            `json:"issuerDID"`
	VerifierDID       string            `json:"verifierDID"`
	Result            string            `json:"result"` // SUCCESS, FAILED, PARTIAL
	Timestamp         string            `json:"timestamp"`
	DataHash          string            `json:"dataHash"` // Hash of verification data for privacy
	Metadata          map[string]string `json:"metadata"`
}

// InitLedger initializes the chaincode with sample policies
func (c *CrossDomainPolicyContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	now := time.Now().UTC().Format(time.RFC3339)
	oneYearLater := time.Now().AddDate(1, 0, 0).UTC().Format(time.RFC3339)

	// Finance -> Healthcare Policy
	financeToHealthcare := CrossDomainPolicy{
		PolicyID:     "policy:finance-to-healthcare:v1",
		PolicyName:   "Finance to Healthcare Credential Acceptance",
		Description:  "Policy governing the acceptance of finance sector credentials in healthcare domain",
		SourceDomain: DomainFinance,
		TargetDomain: DomainHealthcare,
		Status:       PolicyActive,
		Rules: []PolicyRule{
			{
				RuleID:              "rule:kyc-for-healthcare",
				CredentialType:      "KYCCredential",
				RequiredTrustLevel:  TrustStandard,
				RequiredAttributes:  []string{"fullName", "dateOfBirth", "nationalID", "verificationLevel"},
				MaxCredentialAge:    365,
				RequireRevocationCheck: true,
				AllowSelectiveDisclosure: true,
				AdditionalConditions: map[string]string{
					"minVerificationLevel": "STANDARD",
				},
			},
			{
				RuleID:              "rule:income-for-healthcare",
				CredentialType:      "IncomeVerificationCredential",
				RequiredTrustLevel:  TrustBasic,
				RequiredAttributes:  []string{"annualIncome", "employmentStatus"},
				MaxCredentialAge:    90,
				RequireRevocationCheck: true,
				AllowSelectiveDisclosure: true,
			},
		},
		EffectiveFrom:  now,
		EffectiveUntil: oneYearLater,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      "system",
		ApprovedBy:     []string{"finance-authority", "healthcare-authority"},
		Metadata: map[string]string{
			"version":    "1.0",
			"compliance": "GDPR",
		},
	}

	// Education -> Finance Policy
	educationToFinance := CrossDomainPolicy{
		PolicyID:     "policy:education-to-finance:v1",
		PolicyName:   "Education to Finance Credential Acceptance",
		Description:  "Policy governing the acceptance of education sector credentials in finance domain",
		SourceDomain: DomainEducation,
		TargetDomain: DomainFinance,
		Status:       PolicyActive,
		Rules: []PolicyRule{
			{
				RuleID:              "rule:diploma-for-finance",
				CredentialType:      "DiplomaCredential",
				RequiredTrustLevel:  TrustStandard,
				RequiredAttributes:  []string{"studentName", "degree", "graduationDate", "institution"},
				MaxCredentialAge:    3650, // 10 years
				RequireRevocationCheck: true,
				AllowSelectiveDisclosure: false,
			},
			{
				RuleID:              "rule:transcript-for-finance",
				CredentialType:      "TranscriptCredential",
				RequiredTrustLevel:  TrustStandard,
				RequiredAttributes:  []string{"studentName", "courses", "grades", "institution"},
				MaxCredentialAge:    3650,
				RequireRevocationCheck: true,
				AllowSelectiveDisclosure: true,
			},
		},
		EffectiveFrom:  now,
		EffectiveUntil: oneYearLater,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      "system",
		ApprovedBy:     []string{"education-authority", "finance-authority"},
		Metadata: map[string]string{
			"version":    "1.0",
			"compliance": "GDPR",
		},
	}

	// Healthcare -> Education Policy
	healthcareToEducation := CrossDomainPolicy{
		PolicyID:     "policy:healthcare-to-education:v1",
		PolicyName:   "Healthcare to Education Credential Acceptance",
		Description:  "Policy governing the acceptance of healthcare sector credentials in education domain",
		SourceDomain: DomainHealthcare,
		TargetDomain: DomainEducation,
		Status:       PolicyActive,
		Rules: []PolicyRule{
			{
				RuleID:              "rule:health-cert-for-education",
				CredentialType:      "VaccinationCredential",
				RequiredTrustLevel:  TrustBasic,
				RequiredAttributes:  []string{"vaccinationType", "vaccinationDate", "provider"},
				MaxCredentialAge:    365,
				RequireRevocationCheck: true,
				AllowSelectiveDisclosure: true,
			},
			{
				RuleID:              "rule:medical-clearance-for-education",
				CredentialType:      "MedicalClearanceCredential",
				RequiredTrustLevel:  TrustStandard,
				RequiredAttributes:  []string{"clearanceType", "issueDate", "validUntil"},
				MaxCredentialAge:    180,
				RequireRevocationCheck: true,
				AllowSelectiveDisclosure: true,
			},
		},
		EffectiveFrom:  now,
		EffectiveUntil: oneYearLater,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      "system",
		ApprovedBy:     []string{"healthcare-authority", "education-authority"},
		Metadata: map[string]string{
			"version":    "1.0",
			"compliance": "HIPAA,GDPR",
		},
	}

	policies := []CrossDomainPolicy{financeToHealthcare, educationToFinance, healthcareToEducation}

	for _, policy := range policies {
		policyJSON, err := json.Marshal(policy)
		if err != nil {
			return fmt.Errorf("failed to marshal policy: %v", err)
		}

		err = ctx.GetStub().PutState(policy.PolicyID, policyJSON)
		if err != nil {
			return fmt.Errorf("failed to put policy to world state: %v", err)
		}

		// Create composite keys for indexing
		// Index by source-target domains
		domainKey, _ := ctx.GetStub().CreateCompositeKey("source~target~policyID", []string{string(policy.SourceDomain), string(policy.TargetDomain), policy.PolicyID})
		ctx.GetStub().PutState(domainKey, []byte{0x00})

		// Index by status
		statusKey, _ := ctx.GetStub().CreateCompositeKey("status~policyID", []string{string(policy.Status), policy.PolicyID})
		ctx.GetStub().PutState(statusKey, []byte{0x00})
	}

	return nil
}

// RegisterPolicy registers a new cross-domain policy
func (c *CrossDomainPolicyContract) RegisterPolicy(ctx contractapi.TransactionContextInterface, policyJSON string) (string, error) {
	var policy CrossDomainPolicy
	err := json.Unmarshal([]byte(policyJSON), &policy)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal policy: %v", err)
	}

	// Validate required fields
	if policy.SourceDomain == "" || policy.TargetDomain == "" {
		return "", fmt.Errorf("sourceDomain and targetDomain are required")
	}
	if len(policy.Rules) == 0 {
		return "", fmt.Errorf("at least one rule is required")
	}

	// Generate policy ID if not provided
	if policy.PolicyID == "" {
		policy.PolicyID = fmt.Sprintf("policy:%s-to-%s:v1", policy.SourceDomain, policy.TargetDomain)
	}

	// Check if policy already exists
	existing, _ := ctx.GetStub().GetState(policy.PolicyID)
	if existing != nil {
		return "", fmt.Errorf("policy %s already exists", policy.PolicyID)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	policy.CreatedAt = now
	policy.UpdatedAt = now
	policy.Status = PolicyActive

	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		clientID = "unknown"
	}
	policy.CreatedBy = clientID

	policyJSONBytes, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy: %v", err)
	}

	err = ctx.GetStub().PutState(policy.PolicyID, policyJSONBytes)
	if err != nil {
		return "", fmt.Errorf("failed to put policy to world state: %v", err)
	}

	// Create composite keys
	domainKey, _ := ctx.GetStub().CreateCompositeKey("source~target~policyID", []string{string(policy.SourceDomain), string(policy.TargetDomain), policy.PolicyID})
	ctx.GetStub().PutState(domainKey, []byte{0x00})

	statusKey, _ := ctx.GetStub().CreateCompositeKey("status~policyID", []string{string(policy.Status), policy.PolicyID})
	ctx.GetStub().PutState(statusKey, []byte{0x00})

	// Emit event
	eventPayload := map[string]string{
		"policyID":  policy.PolicyID,
		"action":    "REGISTERED",
		"timestamp": now,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("PolicyRegistered", eventJSON)

	return policy.PolicyID, nil
}

// GetPolicy returns a policy by ID
func (c *CrossDomainPolicyContract) GetPolicy(ctx contractapi.TransactionContextInterface, policyID string) (*CrossDomainPolicy, error) {
	policyJSON, err := ctx.GetStub().GetState(policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if policyJSON == nil {
		return nil, fmt.Errorf("policy %s does not exist", policyID)
	}

	var policy CrossDomainPolicy
	err = json.Unmarshal(policyJSON, &policy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %v", err)
	}

	return &policy, nil
}

// EvaluatePolicy evaluates a policy for a cross-domain credential verification
func (c *CrossDomainPolicyContract) EvaluatePolicy(ctx contractapi.TransactionContextInterface, requestJSON string) (*PolicyEvaluationResult, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	var request PolicyEvaluationRequest
	err := json.Unmarshal([]byte(requestJSON), &request)
	if err != nil {
		return &PolicyEvaluationResult{
			IsAllowed:   false,
			Reasons:     []string{fmt.Sprintf("invalid request: %v", err)},
			EvaluatedAt: now,
		}, nil
	}

	// Find applicable policy
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("source~target~policyID", []string{request.SourceDomain, request.TargetDomain})
	if err != nil {
		return &PolicyEvaluationResult{
			IsAllowed:   false,
			Reasons:     []string{fmt.Sprintf("failed to find policy: %v", err)},
			EvaluatedAt: now,
		}, nil
	}
	defer resultsIterator.Close()

	var applicablePolicy *CrossDomainPolicy
	var matchedRule *PolicyRule

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			continue
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil || len(compositeKeyParts) < 3 {
			continue
		}

		policyID := compositeKeyParts[2]
		policy, err := c.GetPolicy(ctx, policyID)
		if err != nil || policy.Status != PolicyActive {
			continue
		}

		// Check if policy is within effective dates
		effectiveFrom, _ := time.Parse(time.RFC3339, policy.EffectiveFrom)
		effectiveUntil, _ := time.Parse(time.RFC3339, policy.EffectiveUntil)
		currentTime := time.Now().UTC()

		if currentTime.Before(effectiveFrom) || currentTime.After(effectiveUntil) {
			continue
		}

		// Find matching rule
		for i, rule := range policy.Rules {
			if rule.CredentialType == request.CredentialType {
				applicablePolicy = policy
				matchedRule = &policy.Rules[i]
				break
			}
		}

		if matchedRule != nil {
			break
		}
	}

	if applicablePolicy == nil || matchedRule == nil {
		return &PolicyEvaluationResult{
			IsAllowed:          false,
			Reasons:            []string{"no applicable policy found for this cross-domain request"},
			EvaluatedAt:        now,
			RecommendedActions: []string{"contact domain administrator to establish cross-domain policy"},
		}, nil
	}

	// Evaluate the matched rule
	var reasons []string
	var missingAttributes []string
	isAllowed := true

	// Check trust level
	requiredTrustLevel := getTrustLevelValue(matchedRule.RequiredTrustLevel)
	if request.IssuerTrustLevel < requiredTrustLevel {
		isAllowed = false
		reasons = append(reasons, fmt.Sprintf("issuer trust level %d is below required level %d", request.IssuerTrustLevel, requiredTrustLevel))
	}

	// Check credential age
	if matchedRule.MaxCredentialAge > 0 && request.CredentialAge > matchedRule.MaxCredentialAge {
		isAllowed = false
		reasons = append(reasons, fmt.Sprintf("credential age %d days exceeds maximum allowed %d days", request.CredentialAge, matchedRule.MaxCredentialAge))
	}

	// Check required attributes
	for _, reqAttr := range matchedRule.RequiredAttributes {
		found := false
		for _, availAttr := range request.AvailableAttributes {
			if availAttr == reqAttr {
				found = true
				break
			}
		}
		if !found {
			missingAttributes = append(missingAttributes, reqAttr)
		}
	}

	if len(missingAttributes) > 0 {
		isAllowed = false
		reasons = append(reasons, fmt.Sprintf("missing required attributes: %v", missingAttributes))
	}

	if isAllowed {
		reasons = append(reasons, "all policy requirements satisfied")
	}

	return &PolicyEvaluationResult{
		IsAllowed:                isAllowed,
		PolicyID:                 applicablePolicy.PolicyID,
		MatchedRuleID:            matchedRule.RuleID,
		Reasons:                  reasons,
		RequiredAttributes:       matchedRule.RequiredAttributes,
		MissingAttributes:        missingAttributes,
		AllowSelectiveDisclosure: matchedRule.AllowSelectiveDisclosure,
		EvaluatedAt:              now,
	}, nil
}

// GetAcceptedCredentialTypes returns credential types accepted between two domains
func (c *CrossDomainPolicyContract) GetAcceptedCredentialTypes(ctx contractapi.TransactionContextInterface, sourceDomain string, targetDomain string) ([]string, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("source~target~policyID", []string{sourceDomain, targetDomain})
	if err != nil {
		return nil, fmt.Errorf("failed to get policies: %v", err)
	}
	defer resultsIterator.Close()

	credentialTypes := make(map[string]bool)

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			continue
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil || len(compositeKeyParts) < 3 {
			continue
		}

		policyID := compositeKeyParts[2]
		policy, err := c.GetPolicy(ctx, policyID)
		if err != nil || policy.Status != PolicyActive {
			continue
		}

		for _, rule := range policy.Rules {
			credentialTypes[rule.CredentialType] = true
		}
	}

	var result []string
	for ct := range credentialTypes {
		result = append(result, ct)
	}

	return result, nil
}

// LogCrossDomainVerification logs a cross-domain verification event
func (c *CrossDomainPolicyContract) LogCrossDomainVerification(ctx contractapi.TransactionContextInterface, recordJSON string) (string, error) {
	var record VerificationRecord
	err := json.Unmarshal([]byte(recordJSON), &record)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal record: %v", err)
	}

	now := time.Now().UTC()
	record.Timestamp = now.Format(time.RFC3339)

	// Generate record ID using hash
	recordData := fmt.Sprintf("%s-%s-%s-%s-%d", record.SourceDomain, record.TargetDomain, record.IssuerDID, record.VerifierDID, now.UnixNano())
	hash := sha256.Sum256([]byte(recordData))
	record.RecordID = hex.EncodeToString(hash[:])[:16]

	// Generate data hash for privacy
	dataToHash := fmt.Sprintf("%s-%s-%s-%s", record.IssuerDID, record.VerifierDID, record.CredentialType, record.Timestamp)
	dataHash := sha256.Sum256([]byte(dataToHash))
	record.DataHash = hex.EncodeToString(dataHash[:])

	recordJSONBytes, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to marshal record: %v", err)
	}

	recordKey := fmt.Sprintf("verification:%s", record.RecordID)
	err = ctx.GetStub().PutState(recordKey, recordJSONBytes)
	if err != nil {
		return "", fmt.Errorf("failed to put record to world state: %v", err)
	}

	// Create composite keys for indexing
	// Index by timestamp (year-month-day)
	dateKey, _ := ctx.GetStub().CreateCompositeKey("date~recordID", []string{now.Format("2006-01-02"), record.RecordID})
	ctx.GetStub().PutState(dateKey, []byte{0x00})

	// Index by source domain
	sourceKey, _ := ctx.GetStub().CreateCompositeKey("source~recordID", []string{record.SourceDomain, record.RecordID})
	ctx.GetStub().PutState(sourceKey, []byte{0x00})

	// Index by target domain
	targetKey, _ := ctx.GetStub().CreateCompositeKey("target~recordID", []string{record.TargetDomain, record.RecordID})
	ctx.GetStub().PutState(targetKey, []byte{0x00})

	// Emit event
	eventPayload := map[string]string{
		"recordID":   record.RecordID,
		"result":     record.Result,
		"timestamp":  record.Timestamp,
		"dataHash":   record.DataHash,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("VerificationLogged", eventJSON)

	return record.RecordID, nil
}

// GetVerificationsByDateRange returns verification records within a date range
func (c *CrossDomainPolicyContract) GetVerificationsByDateRange(ctx contractapi.TransactionContextInterface, startDate string, endDate string) ([]*VerificationRecord, error) {
	start, err := time.Parse("2006-01-02", startDate)
	if err != nil {
		return nil, fmt.Errorf("invalid start date format: %v", err)
	}

	end, err := time.Parse("2006-01-02", endDate)
	if err != nil {
		return nil, fmt.Errorf("invalid end date format: %v", err)
	}

	var records []*VerificationRecord

	for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
		dateStr := d.Format("2006-01-02")
		resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("date~recordID", []string{dateStr})
		if err != nil {
			continue
		}

		for resultsIterator.HasNext() {
			queryResponse, err := resultsIterator.Next()
			if err != nil {
				continue
			}

			_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
			if err != nil || len(compositeKeyParts) < 2 {
				continue
			}

			recordID := compositeKeyParts[1]
			recordKey := fmt.Sprintf("verification:%s", recordID)
			recordJSON, err := ctx.GetStub().GetState(recordKey)
			if err != nil || recordJSON == nil {
				continue
			}

			var record VerificationRecord
			if err := json.Unmarshal(recordJSON, &record); err == nil {
				records = append(records, &record)
			}
		}
		resultsIterator.Close()
	}

	return records, nil
}

// GetVerificationStats returns statistics for verifications
func (c *CrossDomainPolicyContract) GetVerificationStats(ctx contractapi.TransactionContextInterface, domain string, dateRange string) (string, error) {
	// Parse date range (format: "2024-01-01:2024-12-31")
	stats := map[string]interface{}{
		"totalVerifications": 0,
		"successCount":       0,
		"failedCount":        0,
		"partialCount":       0,
		"byCredentialType":   make(map[string]int),
		"bySourceDomain":     make(map[string]int),
		"byTargetDomain":     make(map[string]int),
	}

	queryString := fmt.Sprintf(`{"selector":{"sourceDomain":"%s"}}`, domain)
	if domain == "" {
		queryString = `{"selector":{"recordID":{"$gt":""}}}`
	}

	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return "", fmt.Errorf("failed to query records: %v", err)
	}
	defer resultsIterator.Close()

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			continue
		}

		var record VerificationRecord
		if err := json.Unmarshal(queryResponse.Value, &record); err != nil {
			continue
		}

		stats["totalVerifications"] = stats["totalVerifications"].(int) + 1

		switch record.Result {
		case "SUCCESS":
			stats["successCount"] = stats["successCount"].(int) + 1
		case "FAILED":
			stats["failedCount"] = stats["failedCount"].(int) + 1
		case "PARTIAL":
			stats["partialCount"] = stats["partialCount"].(int) + 1
		}

		credTypeMap := stats["byCredentialType"].(map[string]int)
		credTypeMap[record.CredentialType]++

		sourceMap := stats["bySourceDomain"].(map[string]int)
		sourceMap[record.SourceDomain]++

		targetMap := stats["byTargetDomain"].(map[string]int)
		targetMap[record.TargetDomain]++
	}

	statsJSON, err := json.Marshal(stats)
	if err != nil {
		return "", fmt.Errorf("failed to marshal stats: %v", err)
	}

	return string(statsJSON), nil
}

// UpdatePolicyStatus updates the status of a policy
func (c *CrossDomainPolicyContract) UpdatePolicyStatus(ctx contractapi.TransactionContextInterface, policyID string, newStatus string) error {
	policy, err := c.GetPolicy(ctx, policyID)
	if err != nil {
		return err
	}

	// Remove old status index
	oldStatusKey, _ := ctx.GetStub().CreateCompositeKey("status~policyID", []string{string(policy.Status), policy.PolicyID})
	ctx.GetStub().DelState(oldStatusKey)

	policy.Status = PolicyStatus(newStatus)
	policy.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %v", err)
	}

	err = ctx.GetStub().PutState(policyID, policyJSON)
	if err != nil {
		return fmt.Errorf("failed to put policy to world state: %v", err)
	}

	// Create new status index
	newStatusKey, _ := ctx.GetStub().CreateCompositeKey("status~policyID", []string{newStatus, policy.PolicyID})
	ctx.GetStub().PutState(newStatusKey, []byte{0x00})

	return nil
}

// GetAllPolicies returns all policies
func (c *CrossDomainPolicyContract) GetAllPolicies(ctx contractapi.TransactionContextInterface) ([]*CrossDomainPolicy, error) {
	queryString := `{"selector":{"policyID":{"$gt":""}}}`

	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to get query result: %v", err)
	}
	defer resultsIterator.Close()

	var policies []*CrossDomainPolicy

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			continue
		}

		var policy CrossDomainPolicy
		if err := json.Unmarshal(queryResponse.Value, &policy); err == nil {
			policies = append(policies, &policy)
		}
	}

	return policies, nil
}

// Helper function to convert trust level to numeric value
func getTrustLevelValue(level TrustLevel) int {
	switch level {
	case TrustBasic:
		return 1
	case TrustStandard:
		return 3
	case TrustEnhanced:
		return 4
	case TrustAssured:
		return 5
	default:
		return 0
	}
}

func main() {
	chaincode, err := contractapi.NewChaincode(&CrossDomainPolicyContract{})
	if err != nil {
		fmt.Printf("Error creating cross-domain policy chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting cross-domain policy chaincode: %s", err.Error())
	}
}
