// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// PrivacyAuditContract provides functions for privacy-preserving audit logging
type PrivacyAuditContract struct {
	contractapi.Contract
}

// EventType represents the type of audit event
type EventType string

const (
	EventCredentialIssued     EventType = "CREDENTIAL_ISSUED"
	EventCredentialVerified   EventType = "CREDENTIAL_VERIFIED"
	EventCredentialRevoked    EventType = "CREDENTIAL_REVOKED"
	EventCrossDomainRequest   EventType = "CROSS_DOMAIN_REQUEST"
	EventCrossDomainSuccess   EventType = "CROSS_DOMAIN_SUCCESS"
	EventCrossDomainFailed    EventType = "CROSS_DOMAIN_FAILED"
	EventPolicyEvaluated      EventType = "POLICY_EVALUATED"
	EventConsentGiven         EventType = "CONSENT_GIVEN"
	EventConsentRevoked       EventType = "CONSENT_REVOKED"
	EventDataAccessed         EventType = "DATA_ACCESSED"
)

// AuditEvent represents a privacy-preserving audit event
type AuditEvent struct {
	EventID          string            `json:"eventID"`
	EventType        EventType         `json:"eventType"`
	EventHash        string            `json:"eventHash"`        // Hash of the actual event data
	Timestamp        string            `json:"timestamp"`
	OrganizationType string            `json:"organizationType"`
	SourceDomain     string            `json:"sourceDomain,omitempty"`
	TargetDomain     string            `json:"targetDomain,omitempty"`
	CredentialType   string            `json:"credentialType,omitempty"`
	PolicyID         string            `json:"policyID,omitempty"`
	Result           string            `json:"result"`           // SUCCESS, FAILED, PARTIAL
	AnonymizedData   map[string]string `json:"anonymizedData"`   // K-anonymized metadata
	Nonce            string            `json:"nonce"`            // For preventing correlation
}

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	ReportID          string                 `json:"reportID"`
	OrganizationID    string                 `json:"organizationID"`
	ReportPeriod      string                 `json:"reportPeriod"`
	GeneratedAt       string                 `json:"generatedAt"`
	TotalEvents       int                    `json:"totalEvents"`
	EventsByType      map[string]int         `json:"eventsByType"`
	CrossDomainStats  map[string]interface{} `json:"crossDomainStats"`
	ComplianceStatus  string                 `json:"complianceStatus"`
	Findings          []string               `json:"findings"`
	Recommendations   []string               `json:"recommendations"`
}

// ConsentRecord represents a user consent record
type ConsentRecord struct {
	ConsentID        string            `json:"consentID"`
	SubjectHash      string            `json:"subjectHash"`      // Hash of subject DID
	Purpose          string            `json:"purpose"`
	GrantedTo        string            `json:"grantedTo"`
	CredentialTypes  []string          `json:"credentialTypes"`
	ValidFrom        string            `json:"validFrom"`
	ValidUntil       string            `json:"validUntil"`
	Status           string            `json:"status"`           // ACTIVE, REVOKED, EXPIRED
	CreatedAt        string            `json:"createdAt"`
	RevokedAt        string            `json:"revokedAt,omitempty"`
	Metadata         map[string]string `json:"metadata"`
}

// DataAccessLog represents a data access log entry
type DataAccessLog struct {
	LogID            string            `json:"logID"`
	AccessorHash     string            `json:"accessorHash"`     // Hash of accessor identity
	SubjectHash      string            `json:"subjectHash"`      // Hash of data subject
	DataCategory     string            `json:"dataCategory"`
	Purpose          string            `json:"purpose"`
	Timestamp        string            `json:"timestamp"`
	ConsentReference string            `json:"consentReference"`
	Result           string            `json:"result"`
	Metadata         map[string]string `json:"metadata"`
}

// InitLedger initializes the chaincode
func (c *PrivacyAuditContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	// Initialize counters
	counters := map[string]int{
		"eventCounter":   0,
		"reportCounter":  0,
		"consentCounter": 0,
		"accessCounter":  0,
	}

	for key, value := range counters {
		err := ctx.GetStub().PutState(key, []byte(strconv.Itoa(value)))
		if err != nil {
			return fmt.Errorf("failed to initialize counter %s: %v", key, err)
		}
	}

	return nil
}

// LogVerificationEvent logs a credential verification event in a privacy-preserving manner
func (c *PrivacyAuditContract) LogVerificationEvent(ctx contractapi.TransactionContextInterface, eventDataJSON string) (string, error) {
	var eventData map[string]interface{}
	err := json.Unmarshal([]byte(eventDataJSON), &eventData)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal event data: %v", err)
	}

	now := time.Now().UTC()

	// Generate event hash (privacy-preserving)
	eventHashInput := fmt.Sprintf("%v-%d", eventData, now.UnixNano())
	hash := sha256.Sum256([]byte(eventHashInput))
	eventHash := hex.EncodeToString(hash[:])

	// Generate nonce for unlinkability
	nonceInput := fmt.Sprintf("%s-%d-%s", eventHash, now.UnixNano(), "salt")
	nonceHash := sha256.Sum256([]byte(nonceInput))
	nonce := hex.EncodeToString(nonceHash[:])[:16]

	// Get event counter
	counterBytes, _ := ctx.GetStub().GetState("eventCounter")
	counter, _ := strconv.Atoi(string(counterBytes))
	counter++
	ctx.GetStub().PutState("eventCounter", []byte(strconv.Itoa(counter)))

	eventID := fmt.Sprintf("event:%s:%d", now.Format("20060102"), counter)

	// Extract and anonymize data
	anonymizedData := make(map[string]string)
	if orgType, ok := eventData["organizationType"].(string); ok {
		anonymizedData["orgTypeHash"] = hashValue(orgType)
	}
	if credType, ok := eventData["credentialType"].(string); ok {
		anonymizedData["credTypeHash"] = hashValue(credType)
	}

	event := AuditEvent{
		EventID:          eventID,
		EventType:        EventCredentialVerified,
		EventHash:        eventHash,
		Timestamp:        now.Format(time.RFC3339),
		OrganizationType: getStringValue(eventData, "organizationType"),
		SourceDomain:     getStringValue(eventData, "sourceDomain"),
		TargetDomain:     getStringValue(eventData, "targetDomain"),
		CredentialType:   getStringValue(eventData, "credentialType"),
		PolicyID:         getStringValue(eventData, "policyID"),
		Result:           getStringValue(eventData, "result"),
		AnonymizedData:   anonymizedData,
		Nonce:            nonce,
	}

	// Determine event type based on data
	if event.SourceDomain != "" && event.TargetDomain != "" {
		if event.Result == "SUCCESS" {
			event.EventType = EventCrossDomainSuccess
		} else if event.Result == "FAILED" {
			event.EventType = EventCrossDomainFailed
		} else {
			event.EventType = EventCrossDomainRequest
		}
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event: %v", err)
	}

	err = ctx.GetStub().PutState(eventID, eventJSON)
	if err != nil {
		return "", fmt.Errorf("failed to put event to world state: %v", err)
	}

	// Create composite keys for indexing
	// Index by date
	dateKey, _ := ctx.GetStub().CreateCompositeKey("date~eventID", []string{now.Format("2006-01-02"), eventID})
	ctx.GetStub().PutState(dateKey, []byte{0x00})

	// Index by event type
	typeKey, _ := ctx.GetStub().CreateCompositeKey("type~eventID", []string{string(event.EventType), eventID})
	ctx.GetStub().PutState(typeKey, []byte{0x00})

	// Index by organization type
	if event.OrganizationType != "" {
		orgKey, _ := ctx.GetStub().CreateCompositeKey("org~eventID", []string{event.OrganizationType, eventID})
		ctx.GetStub().PutState(orgKey, []byte{0x00})
	}

	// Emit privacy-preserving event
	emitPayload := map[string]string{
		"eventID":   eventID,
		"eventType": string(event.EventType),
		"eventHash": eventHash,
		"timestamp": event.Timestamp,
	}
	emitJSON, _ := json.Marshal(emitPayload)
	ctx.GetStub().SetEvent("AuditEventLogged", emitJSON)

	return eventID, nil
}

// QueryAuditLog queries audit log with privacy considerations
func (c *PrivacyAuditContract) QueryAuditLog(ctx contractapi.TransactionContextInterface, startTime string, endTime string, orgType string) ([]*AuditEvent, error) {
	start, err := time.Parse("2006-01-02", startTime)
	if err != nil {
		return nil, fmt.Errorf("invalid start time format (expected YYYY-MM-DD): %v", err)
	}

	end, err := time.Parse("2006-01-02", endTime)
	if err != nil {
		return nil, fmt.Errorf("invalid end time format (expected YYYY-MM-DD): %v", err)
	}

	var events []*AuditEvent

	for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
		dateStr := d.Format("2006-01-02")

		resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("date~eventID", []string{dateStr})
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

			eventID := compositeKeyParts[1]
			eventJSON, err := ctx.GetStub().GetState(eventID)
			if err != nil || eventJSON == nil {
				continue
			}

			var event AuditEvent
			if err := json.Unmarshal(eventJSON, &event); err == nil {
				// Filter by organization type if specified
				if orgType == "" || event.OrganizationType == orgType {
					events = append(events, &event)
				}
			}
		}
		resultsIterator.Close()
	}

	return events, nil
}

// GenerateComplianceReport generates a compliance report for an organization
func (c *PrivacyAuditContract) GenerateComplianceReport(ctx contractapi.TransactionContextInterface, orgID string, period string) (*ComplianceReport, error) {
	now := time.Now().UTC()

	// Get report counter
	counterBytes, _ := ctx.GetStub().GetState("reportCounter")
	counter, _ := strconv.Atoi(string(counterBytes))
	counter++
	ctx.GetStub().PutState("reportCounter", []byte(strconv.Itoa(counter)))

	reportID := fmt.Sprintf("report:%s:%d", now.Format("20060102"), counter)

	// Parse period (format: "2024-01" for monthly, "2024" for yearly)
	var startDate, endDate string
	if len(period) == 7 { // Monthly
		startDate = period + "-01"
		t, _ := time.Parse("2006-01-02", startDate)
		endDate = t.AddDate(0, 1, -1).Format("2006-01-02")
	} else if len(period) == 4 { // Yearly
		startDate = period + "-01-01"
		endDate = period + "-12-31"
	} else {
		return nil, fmt.Errorf("invalid period format (expected YYYY-MM or YYYY)")
	}

	// Query events for the period
	events, err := c.QueryAuditLog(ctx, startDate, endDate, "")
	if err != nil {
		return nil, fmt.Errorf("failed to query audit log: %v", err)
	}

	// Calculate statistics
	eventsByType := make(map[string]int)
	crossDomainSuccess := 0
	crossDomainFailed := 0
	totalCrossDomain := 0

	for _, event := range events {
		eventsByType[string(event.EventType)]++

		if event.SourceDomain != "" && event.TargetDomain != "" {
			totalCrossDomain++
			if event.Result == "SUCCESS" {
				crossDomainSuccess++
			} else if event.Result == "FAILED" {
				crossDomainFailed++
			}
		}
	}

	crossDomainStats := map[string]interface{}{
		"totalRequests":  totalCrossDomain,
		"successCount":   crossDomainSuccess,
		"failedCount":    crossDomainFailed,
		"successRate":    calculateSuccessRate(crossDomainSuccess, totalCrossDomain),
	}

	// Determine compliance status and findings
	complianceStatus := "COMPLIANT"
	var findings []string
	var recommendations []string

	if totalCrossDomain > 0 {
		successRate := float64(crossDomainSuccess) / float64(totalCrossDomain) * 100
		if successRate < 95 {
			findings = append(findings, fmt.Sprintf("Cross-domain success rate (%.2f%%) is below 95%% threshold", successRate))
			recommendations = append(recommendations, "Review and update cross-domain policies")
		}
	}

	// Check for any revoked credentials
	if eventsByType[string(EventCredentialRevoked)] > 0 {
		findings = append(findings, fmt.Sprintf("%d credential revocation events detected", eventsByType[string(EventCredentialRevoked)]))
	}

	if len(findings) > 0 {
		complianceStatus = "NEEDS_REVIEW"
	}

	report := ComplianceReport{
		ReportID:         reportID,
		OrganizationID:   orgID,
		ReportPeriod:     period,
		GeneratedAt:      now.Format(time.RFC3339),
		TotalEvents:      len(events),
		EventsByType:     eventsByType,
		CrossDomainStats: crossDomainStats,
		ComplianceStatus: complianceStatus,
		Findings:         findings,
		Recommendations:  recommendations,
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %v", err)
	}

	err = ctx.GetStub().PutState(reportID, reportJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to put report to world state: %v", err)
	}

	// Index by organization
	orgKey, _ := ctx.GetStub().CreateCompositeKey("org~reportID", []string{orgID, reportID})
	ctx.GetStub().PutState(orgKey, []byte{0x00})

	return &report, nil
}

// RecordConsent records user consent for data processing
func (c *PrivacyAuditContract) RecordConsent(ctx contractapi.TransactionContextInterface, consentJSON string) (string, error) {
	var consent ConsentRecord
	err := json.Unmarshal([]byte(consentJSON), &consent)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal consent: %v", err)
	}

	now := time.Now().UTC()

	// Get consent counter
	counterBytes, _ := ctx.GetStub().GetState("consentCounter")
	counter, _ := strconv.Atoi(string(counterBytes))
	counter++
	ctx.GetStub().PutState("consentCounter", []byte(strconv.Itoa(counter)))

	consent.ConsentID = fmt.Sprintf("consent:%d", counter)
	consent.CreatedAt = now.Format(time.RFC3339)
	consent.Status = "ACTIVE"

	// Hash subject identifier for privacy
	if consent.SubjectHash == "" {
		return "", fmt.Errorf("subjectHash is required")
	}

	consentJSONBytes, err := json.Marshal(consent)
	if err != nil {
		return "", fmt.Errorf("failed to marshal consent: %v", err)
	}

	err = ctx.GetStub().PutState(consent.ConsentID, consentJSONBytes)
	if err != nil {
		return "", fmt.Errorf("failed to put consent to world state: %v", err)
	}

	// Create composite keys for indexing
	subjectKey, _ := ctx.GetStub().CreateCompositeKey("subject~consentID", []string{consent.SubjectHash, consent.ConsentID})
	ctx.GetStub().PutState(subjectKey, []byte{0x00})

	grantedToKey, _ := ctx.GetStub().CreateCompositeKey("grantedTo~consentID", []string{consent.GrantedTo, consent.ConsentID})
	ctx.GetStub().PutState(grantedToKey, []byte{0x00})

	// Log consent event
	eventData := map[string]interface{}{
		"eventType":   "CONSENT_GIVEN",
		"consentID":   consent.ConsentID,
		"subjectHash": consent.SubjectHash,
		"grantedTo":   consent.GrantedTo,
		"purpose":     consent.Purpose,
	}
	eventJSON, _ := json.Marshal(eventData)
	c.LogVerificationEvent(ctx, string(eventJSON))

	return consent.ConsentID, nil
}

// RevokeConsent revokes a previously given consent
func (c *PrivacyAuditContract) RevokeConsent(ctx contractapi.TransactionContextInterface, consentID string, reason string) error {
	consentJSON, err := ctx.GetStub().GetState(consentID)
	if err != nil {
		return fmt.Errorf("failed to read consent: %v", err)
	}
	if consentJSON == nil {
		return fmt.Errorf("consent %s does not exist", consentID)
	}

	var consent ConsentRecord
	err = json.Unmarshal(consentJSON, &consent)
	if err != nil {
		return fmt.Errorf("failed to unmarshal consent: %v", err)
	}

	if consent.Status == "REVOKED" {
		return fmt.Errorf("consent %s is already revoked", consentID)
	}

	now := time.Now().UTC()
	consent.Status = "REVOKED"
	consent.RevokedAt = now.Format(time.RFC3339)
	consent.Metadata["revocationReason"] = reason

	consentJSONBytes, err := json.Marshal(consent)
	if err != nil {
		return fmt.Errorf("failed to marshal consent: %v", err)
	}

	err = ctx.GetStub().PutState(consentID, consentJSONBytes)
	if err != nil {
		return fmt.Errorf("failed to put consent to world state: %v", err)
	}

	// Log revocation event
	eventData := map[string]interface{}{
		"eventType":   "CONSENT_REVOKED",
		"consentID":   consent.ConsentID,
		"subjectHash": consent.SubjectHash,
		"revokedAt":   consent.RevokedAt,
	}
	eventJSON, _ := json.Marshal(eventData)
	c.LogVerificationEvent(ctx, string(eventJSON))

	return nil
}

// VerifyConsent verifies if active consent exists for a specific purpose
func (c *PrivacyAuditContract) VerifyConsent(ctx contractapi.TransactionContextInterface, subjectHash string, grantedTo string, purpose string) (bool, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("subject~consentID", []string{subjectHash})
	if err != nil {
		return false, fmt.Errorf("failed to query consents: %v", err)
	}
	defer resultsIterator.Close()

	now := time.Now().UTC()

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			continue
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil || len(compositeKeyParts) < 2 {
			continue
		}

		consentID := compositeKeyParts[1]
		consentJSON, err := ctx.GetStub().GetState(consentID)
		if err != nil || consentJSON == nil {
			continue
		}

		var consent ConsentRecord
		if err := json.Unmarshal(consentJSON, &consent); err != nil {
			continue
		}

		// Check if consent matches criteria and is active
		if consent.Status != "ACTIVE" {
			continue
		}

		if consent.GrantedTo != grantedTo {
			continue
		}

		if consent.Purpose != purpose && consent.Purpose != "ALL" {
			continue
		}

		// Check validity period
		validFrom, _ := time.Parse(time.RFC3339, consent.ValidFrom)
		validUntil, _ := time.Parse(time.RFC3339, consent.ValidUntil)

		if now.Before(validFrom) || now.After(validUntil) {
			continue
		}

		return true, nil
	}

	return false, nil
}

// LogDataAccess logs a data access event
func (c *PrivacyAuditContract) LogDataAccess(ctx contractapi.TransactionContextInterface, accessLogJSON string) (string, error) {
	var accessLog DataAccessLog
	err := json.Unmarshal([]byte(accessLogJSON), &accessLog)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal access log: %v", err)
	}

	now := time.Now().UTC()

	// Get access counter
	counterBytes, _ := ctx.GetStub().GetState("accessCounter")
	counter, _ := strconv.Atoi(string(counterBytes))
	counter++
	ctx.GetStub().PutState("accessCounter", []byte(strconv.Itoa(counter)))

	accessLog.LogID = fmt.Sprintf("access:%s:%d", now.Format("20060102"), counter)
	accessLog.Timestamp = now.Format(time.RFC3339)

	accessLogJSONBytes, err := json.Marshal(accessLog)
	if err != nil {
		return "", fmt.Errorf("failed to marshal access log: %v", err)
	}

	err = ctx.GetStub().PutState(accessLog.LogID, accessLogJSONBytes)
	if err != nil {
		return "", fmt.Errorf("failed to put access log to world state: %v", err)
	}

	// Create composite keys for indexing
	subjectKey, _ := ctx.GetStub().CreateCompositeKey("subject~accessID", []string{accessLog.SubjectHash, accessLog.LogID})
	ctx.GetStub().PutState(subjectKey, []byte{0x00})

	accessorKey, _ := ctx.GetStub().CreateCompositeKey("accessor~accessID", []string{accessLog.AccessorHash, accessLog.LogID})
	ctx.GetStub().PutState(accessorKey, []byte{0x00})

	dateKey, _ := ctx.GetStub().CreateCompositeKey("date~accessID", []string{now.Format("2006-01-02"), accessLog.LogID})
	ctx.GetStub().PutState(dateKey, []byte{0x00})

	return accessLog.LogID, nil
}

// GetDataAccessHistory returns data access history for a subject
func (c *PrivacyAuditContract) GetDataAccessHistory(ctx contractapi.TransactionContextInterface, subjectHash string) ([]*DataAccessLog, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("subject~accessID", []string{subjectHash})
	if err != nil {
		return nil, fmt.Errorf("failed to query access logs: %v", err)
	}
	defer resultsIterator.Close()

	var accessLogs []*DataAccessLog

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			continue
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil || len(compositeKeyParts) < 2 {
			continue
		}

		accessID := compositeKeyParts[1]
		accessLogJSON, err := ctx.GetStub().GetState(accessID)
		if err != nil || accessLogJSON == nil {
			continue
		}

		var accessLog DataAccessLog
		if err := json.Unmarshal(accessLogJSON, &accessLog); err == nil {
			accessLogs = append(accessLogs, &accessLog)
		}
	}

	return accessLogs, nil
}

// GetEventsByType returns events of a specific type
func (c *PrivacyAuditContract) GetEventsByType(ctx contractapi.TransactionContextInterface, eventType string, limit int) ([]*AuditEvent, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("type~eventID", []string{eventType})
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %v", err)
	}
	defer resultsIterator.Close()

	var events []*AuditEvent
	count := 0

	for resultsIterator.HasNext() && (limit <= 0 || count < limit) {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			continue
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil || len(compositeKeyParts) < 2 {
			continue
		}

		eventID := compositeKeyParts[1]
		eventJSON, err := ctx.GetStub().GetState(eventID)
		if err != nil || eventJSON == nil {
			continue
		}

		var event AuditEvent
		if err := json.Unmarshal(eventJSON, &event); err == nil {
			events = append(events, &event)
			count++
		}
	}

	return events, nil
}

// Helper functions

func hashValue(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])[:16]
}

func getStringValue(data map[string]interface{}, key string) string {
	if value, ok := data[key].(string); ok {
		return value
	}
	return ""
}

func calculateSuccessRate(success, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(success) / float64(total) * 100
}

func main() {
	chaincode, err := contractapi.NewChaincode(&PrivacyAuditContract{})
	if err != nil {
		fmt.Printf("Error creating privacy audit chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting privacy audit chaincode: %s", err.Error())
	}
}
