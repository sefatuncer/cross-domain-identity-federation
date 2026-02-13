// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// TrustedIssuerContract provides functions for managing trusted issuers
type TrustedIssuerContract struct {
	contractapi.Contract
}

// IssuerStatus represents the status of an issuer
type IssuerStatus string

const (
	StatusActive    IssuerStatus = "ACTIVE"
	StatusSuspended IssuerStatus = "SUSPENDED"
	StatusRevoked   IssuerStatus = "REVOKED"
)

// OrganizationType represents the sector type
type OrganizationType string

const (
	OrgFinance    OrganizationType = "FINANCE"
	OrgHealthcare OrganizationType = "HEALTHCARE"
	OrgEducation  OrganizationType = "EDUCATION"
)

// Issuer represents a trusted issuer in the registry
type Issuer struct {
	IssuerDID             string           `json:"issuerDID"`
	OrganizationType      OrganizationType `json:"organizationType"`
	OrganizationName      string           `json:"organizationName"`
	Status                IssuerStatus     `json:"status"`
	CredentialTypes       []string         `json:"credentialTypes"`
	PublicKeyJWK          string           `json:"publicKeyJWK"`
	ServiceEndpoint       string           `json:"serviceEndpoint"`
	TrustLevel            int              `json:"trustLevel"` // 1-5
	RegistrationTimestamp string           `json:"registrationTimestamp"`
	LastUpdated           string           `json:"lastUpdated"`
	Metadata              map[string]string `json:"metadata"`
	RegisteredBy          string           `json:"registeredBy"`
}

// IssuerRegistrationRequest represents a request to register an issuer
type IssuerRegistrationRequest struct {
	IssuerDID        string            `json:"issuerDID"`
	OrganizationType OrganizationType  `json:"organizationType"`
	OrganizationName string            `json:"organizationName"`
	CredentialTypes  []string          `json:"credentialTypes"`
	PublicKeyJWK     string            `json:"publicKeyJWK"`
	ServiceEndpoint  string            `json:"serviceEndpoint"`
	TrustLevel       int               `json:"trustLevel"`
	Metadata         map[string]string `json:"metadata"`
}

// ValidationResult represents the result of issuer validation
type ValidationResult struct {
	IsValid           bool     `json:"isValid"`
	IssuerDID         string   `json:"issuerDID"`
	OrganizationType  string   `json:"organizationType"`
	TrustLevel        int      `json:"trustLevel"`
	AllowedTypes      []string `json:"allowedTypes"`
	ValidationMessage string   `json:"validationMessage"`
	Timestamp         string   `json:"timestamp"`
}

// InitLedger initializes the chaincode with sample data
func (c *TrustedIssuerContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	// Sample issuers for testing
	sampleIssuers := []Issuer{
		{
			IssuerDID:             "did:web:bank.finance.crossdomain.com",
			OrganizationType:      OrgFinance,
			OrganizationName:      "Central Bank Authority",
			Status:                StatusActive,
			CredentialTypes:       []string{"KYCCredential", "CreditScoreCredential", "IncomeVerificationCredential"},
			PublicKeyJWK:          `{"kty":"EC","crv":"P-256","x":"example","y":"example"}`,
			ServiceEndpoint:       "https://bank.finance.crossdomain.com/credentials",
			TrustLevel:            5,
			RegistrationTimestamp: time.Now().UTC().Format(time.RFC3339),
			LastUpdated:           time.Now().UTC().Format(time.RFC3339),
			Metadata: map[string]string{
				"country":      "TR",
				"licenseNumber": "FIN-2024-001",
			},
			RegisteredBy: "system",
		},
		{
			IssuerDID:             "did:web:hospital.healthcare.crossdomain.com",
			OrganizationType:      OrgHealthcare,
			OrganizationName:      "National Health Authority",
			Status:                StatusActive,
			CredentialTypes:       []string{"HealthInsuranceCredential", "MedicalHistoryCredential", "VaccinationCredential"},
			PublicKeyJWK:          `{"kty":"EC","crv":"P-256","x":"example","y":"example"}`,
			ServiceEndpoint:       "https://hospital.healthcare.crossdomain.com/credentials",
			TrustLevel:            5,
			RegistrationTimestamp: time.Now().UTC().Format(time.RFC3339),
			LastUpdated:           time.Now().UTC().Format(time.RFC3339),
			Metadata: map[string]string{
				"country":      "TR",
				"licenseNumber": "HLT-2024-001",
			},
			RegisteredBy: "system",
		},
		{
			IssuerDID:             "did:web:university.education.crossdomain.com",
			OrganizationType:      OrgEducation,
			OrganizationName:      "National Education Authority",
			Status:                StatusActive,
			CredentialTypes:       []string{"DiplomaCredential", "TranscriptCredential", "CertificateCredential"},
			PublicKeyJWK:          `{"kty":"EC","crv":"P-256","x":"example","y":"example"}`,
			ServiceEndpoint:       "https://university.education.crossdomain.com/credentials",
			TrustLevel:            5,
			RegistrationTimestamp: time.Now().UTC().Format(time.RFC3339),
			LastUpdated:           time.Now().UTC().Format(time.RFC3339),
			Metadata: map[string]string{
				"country":      "TR",
				"licenseNumber": "EDU-2024-001",
			},
			RegisteredBy: "system",
		},
	}

	for _, issuer := range sampleIssuers {
		issuerJSON, err := json.Marshal(issuer)
		if err != nil {
			return fmt.Errorf("failed to marshal issuer: %v", err)
		}

		err = ctx.GetStub().PutState(issuer.IssuerDID, issuerJSON)
		if err != nil {
			return fmt.Errorf("failed to put issuer to world state: %v", err)
		}

		// Create composite key for organization type index
		compositeKey, err := ctx.GetStub().CreateCompositeKey("orgType~issuerDID", []string{string(issuer.OrganizationType), issuer.IssuerDID})
		if err != nil {
			return fmt.Errorf("failed to create composite key: %v", err)
		}
		err = ctx.GetStub().PutState(compositeKey, []byte{0x00})
		if err != nil {
			return fmt.Errorf("failed to put composite key: %v", err)
		}
	}

	return nil
}

// RegisterIssuer adds a new trusted issuer to the registry
func (c *TrustedIssuerContract) RegisterIssuer(ctx contractapi.TransactionContextInterface, requestJSON string) error {
	var request IssuerRegistrationRequest
	err := json.Unmarshal([]byte(requestJSON), &request)
	if err != nil {
		return fmt.Errorf("failed to unmarshal request: %v", err)
	}

	// Validate required fields
	if request.IssuerDID == "" {
		return fmt.Errorf("issuerDID is required")
	}
	if request.OrganizationType == "" {
		return fmt.Errorf("organizationType is required")
	}
	if request.OrganizationName == "" {
		return fmt.Errorf("organizationName is required")
	}
	if len(request.CredentialTypes) == 0 {
		return fmt.Errorf("at least one credentialType is required")
	}

	// Validate organization type
	if request.OrganizationType != OrgFinance &&
		request.OrganizationType != OrgHealthcare &&
		request.OrganizationType != OrgEducation {
		return fmt.Errorf("invalid organizationType: %s", request.OrganizationType)
	}

	// Check if issuer already exists
	existingIssuer, err := ctx.GetStub().GetState(request.IssuerDID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if existingIssuer != nil {
		return fmt.Errorf("issuer %s already exists", request.IssuerDID)
	}

	// Validate trust level
	if request.TrustLevel < 1 || request.TrustLevel > 5 {
		request.TrustLevel = 3 // Default trust level
	}

	// Get the identity of the caller
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		clientID = "unknown"
	}

	now := time.Now().UTC().Format(time.RFC3339)

	issuer := Issuer{
		IssuerDID:             request.IssuerDID,
		OrganizationType:      request.OrganizationType,
		OrganizationName:      request.OrganizationName,
		Status:                StatusActive,
		CredentialTypes:       request.CredentialTypes,
		PublicKeyJWK:          request.PublicKeyJWK,
		ServiceEndpoint:       request.ServiceEndpoint,
		TrustLevel:            request.TrustLevel,
		RegistrationTimestamp: now,
		LastUpdated:           now,
		Metadata:              request.Metadata,
		RegisteredBy:          clientID,
	}

	issuerJSON, err := json.Marshal(issuer)
	if err != nil {
		return fmt.Errorf("failed to marshal issuer: %v", err)
	}

	err = ctx.GetStub().PutState(request.IssuerDID, issuerJSON)
	if err != nil {
		return fmt.Errorf("failed to put issuer to world state: %v", err)
	}

	// Create composite key for organization type index
	compositeKey, err := ctx.GetStub().CreateCompositeKey("orgType~issuerDID", []string{string(request.OrganizationType), request.IssuerDID})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}
	err = ctx.GetStub().PutState(compositeKey, []byte{0x00})
	if err != nil {
		return fmt.Errorf("failed to put composite key: %v", err)
	}

	// Emit event
	eventPayload := map[string]string{
		"issuerDID":   request.IssuerDID,
		"action":      "REGISTERED",
		"timestamp":   now,
		"registeredBy": clientID,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("IssuerRegistered", eventJSON)

	return nil
}

// RevokeIssuer revokes a trusted issuer
func (c *TrustedIssuerContract) RevokeIssuer(ctx contractapi.TransactionContextInterface, issuerDID string, reason string) error {
	issuerJSON, err := ctx.GetStub().GetState(issuerDID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if issuerJSON == nil {
		return fmt.Errorf("issuer %s does not exist", issuerDID)
	}

	var issuer Issuer
	err = json.Unmarshal(issuerJSON, &issuer)
	if err != nil {
		return fmt.Errorf("failed to unmarshal issuer: %v", err)
	}

	if issuer.Status == StatusRevoked {
		return fmt.Errorf("issuer %s is already revoked", issuerDID)
	}

	issuer.Status = StatusRevoked
	issuer.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	issuer.Metadata["revocationReason"] = reason

	updatedJSON, err := json.Marshal(issuer)
	if err != nil {
		return fmt.Errorf("failed to marshal issuer: %v", err)
	}

	err = ctx.GetStub().PutState(issuerDID, updatedJSON)
	if err != nil {
		return fmt.Errorf("failed to put issuer to world state: %v", err)
	}

	// Emit event
	eventPayload := map[string]string{
		"issuerDID": issuerDID,
		"action":    "REVOKED",
		"reason":    reason,
		"timestamp": issuer.LastUpdated,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("IssuerRevoked", eventJSON)

	return nil
}

// SuspendIssuer temporarily suspends a trusted issuer
func (c *TrustedIssuerContract) SuspendIssuer(ctx contractapi.TransactionContextInterface, issuerDID string, reason string) error {
	issuerJSON, err := ctx.GetStub().GetState(issuerDID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if issuerJSON == nil {
		return fmt.Errorf("issuer %s does not exist", issuerDID)
	}

	var issuer Issuer
	err = json.Unmarshal(issuerJSON, &issuer)
	if err != nil {
		return fmt.Errorf("failed to unmarshal issuer: %v", err)
	}

	if issuer.Status == StatusRevoked {
		return fmt.Errorf("issuer %s is revoked and cannot be suspended", issuerDID)
	}

	issuer.Status = StatusSuspended
	issuer.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	issuer.Metadata["suspensionReason"] = reason

	updatedJSON, err := json.Marshal(issuer)
	if err != nil {
		return fmt.Errorf("failed to marshal issuer: %v", err)
	}

	err = ctx.GetStub().PutState(issuerDID, updatedJSON)
	if err != nil {
		return fmt.Errorf("failed to put issuer to world state: %v", err)
	}

	// Emit event
	eventPayload := map[string]string{
		"issuerDID": issuerDID,
		"action":    "SUSPENDED",
		"reason":    reason,
		"timestamp": issuer.LastUpdated,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("IssuerSuspended", eventJSON)

	return nil
}

// ReactivateIssuer reactivates a suspended issuer
func (c *TrustedIssuerContract) ReactivateIssuer(ctx contractapi.TransactionContextInterface, issuerDID string) error {
	issuerJSON, err := ctx.GetStub().GetState(issuerDID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if issuerJSON == nil {
		return fmt.Errorf("issuer %s does not exist", issuerDID)
	}

	var issuer Issuer
	err = json.Unmarshal(issuerJSON, &issuer)
	if err != nil {
		return fmt.Errorf("failed to unmarshal issuer: %v", err)
	}

	if issuer.Status == StatusRevoked {
		return fmt.Errorf("issuer %s is revoked and cannot be reactivated", issuerDID)
	}
	if issuer.Status == StatusActive {
		return fmt.Errorf("issuer %s is already active", issuerDID)
	}

	issuer.Status = StatusActive
	issuer.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	delete(issuer.Metadata, "suspensionReason")

	updatedJSON, err := json.Marshal(issuer)
	if err != nil {
		return fmt.Errorf("failed to marshal issuer: %v", err)
	}

	err = ctx.GetStub().PutState(issuerDID, updatedJSON)
	if err != nil {
		return fmt.Errorf("failed to put issuer to world state: %v", err)
	}

	// Emit event
	eventPayload := map[string]string{
		"issuerDID": issuerDID,
		"action":    "REACTIVATED",
		"timestamp": issuer.LastUpdated,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("IssuerReactivated", eventJSON)

	return nil
}

// QueryIssuer returns the issuer stored in the world state with given DID
func (c *TrustedIssuerContract) QueryIssuer(ctx contractapi.TransactionContextInterface, issuerDID string) (*Issuer, error) {
	issuerJSON, err := ctx.GetStub().GetState(issuerDID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if issuerJSON == nil {
		return nil, fmt.Errorf("issuer %s does not exist", issuerDID)
	}

	var issuer Issuer
	err = json.Unmarshal(issuerJSON, &issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal issuer: %v", err)
	}

	return &issuer, nil
}

// GetIssuersByType returns all issuers of a specific organization type
func (c *TrustedIssuerContract) GetIssuersByType(ctx contractapi.TransactionContextInterface, orgType string) ([]*Issuer, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("orgType~issuerDID", []string{orgType})
	if err != nil {
		return nil, fmt.Errorf("failed to get state by partial composite key: %v", err)
	}
	defer resultsIterator.Close()

	var issuers []*Issuer

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate: %v", err)
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to split composite key: %v", err)
		}

		if len(compositeKeyParts) < 2 {
			continue
		}

		issuerDID := compositeKeyParts[1]
		issuer, err := c.QueryIssuer(ctx, issuerDID)
		if err != nil {
			continue
		}

		issuers = append(issuers, issuer)
	}

	return issuers, nil
}

// GetActiveIssuers returns all active issuers
func (c *TrustedIssuerContract) GetActiveIssuers(ctx contractapi.TransactionContextInterface) ([]*Issuer, error) {
	queryString := `{"selector":{"status":"ACTIVE"}}`

	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to get query result: %v", err)
	}
	defer resultsIterator.Close()

	var issuers []*Issuer

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate: %v", err)
		}

		var issuer Issuer
		err = json.Unmarshal(queryResponse.Value, &issuer)
		if err != nil {
			continue
		}

		issuers = append(issuers, &issuer)
	}

	return issuers, nil
}

// ValidateIssuer validates if an issuer is trusted for a specific credential type
func (c *TrustedIssuerContract) ValidateIssuer(ctx contractapi.TransactionContextInterface, issuerDID string, credentialType string) (*ValidationResult, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	issuerJSON, err := ctx.GetStub().GetState(issuerDID)
	if err != nil {
		return &ValidationResult{
			IsValid:           false,
			IssuerDID:         issuerDID,
			ValidationMessage: fmt.Sprintf("failed to read from world state: %v", err),
			Timestamp:         now,
		}, nil
	}
	if issuerJSON == nil {
		return &ValidationResult{
			IsValid:           false,
			IssuerDID:         issuerDID,
			ValidationMessage: "issuer not found in trusted registry",
			Timestamp:         now,
		}, nil
	}

	var issuer Issuer
	err = json.Unmarshal(issuerJSON, &issuer)
	if err != nil {
		return &ValidationResult{
			IsValid:           false,
			IssuerDID:         issuerDID,
			ValidationMessage: fmt.Sprintf("failed to unmarshal issuer: %v", err),
			Timestamp:         now,
		}, nil
	}

	// Check if issuer is active
	if issuer.Status != StatusActive {
		return &ValidationResult{
			IsValid:           false,
			IssuerDID:         issuerDID,
			OrganizationType:  string(issuer.OrganizationType),
			TrustLevel:        issuer.TrustLevel,
			ValidationMessage: fmt.Sprintf("issuer status is %s, not active", issuer.Status),
			Timestamp:         now,
		}, nil
	}

	// Check if issuer can issue the requested credential type
	credentialTypeAllowed := false
	for _, ct := range issuer.CredentialTypes {
		if ct == credentialType {
			credentialTypeAllowed = true
			break
		}
	}

	if !credentialTypeAllowed {
		return &ValidationResult{
			IsValid:           false,
			IssuerDID:         issuerDID,
			OrganizationType:  string(issuer.OrganizationType),
			TrustLevel:        issuer.TrustLevel,
			AllowedTypes:      issuer.CredentialTypes,
			ValidationMessage: fmt.Sprintf("issuer is not authorized to issue %s credentials", credentialType),
			Timestamp:         now,
		}, nil
	}

	return &ValidationResult{
		IsValid:           true,
		IssuerDID:         issuerDID,
		OrganizationType:  string(issuer.OrganizationType),
		TrustLevel:        issuer.TrustLevel,
		AllowedTypes:      issuer.CredentialTypes,
		ValidationMessage: "issuer is valid and trusted",
		Timestamp:         now,
	}, nil
}

// UpdateIssuerCredentialTypes updates the credential types an issuer can issue
func (c *TrustedIssuerContract) UpdateIssuerCredentialTypes(ctx contractapi.TransactionContextInterface, issuerDID string, credentialTypesJSON string) error {
	issuerJSON, err := ctx.GetStub().GetState(issuerDID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if issuerJSON == nil {
		return fmt.Errorf("issuer %s does not exist", issuerDID)
	}

	var issuer Issuer
	err = json.Unmarshal(issuerJSON, &issuer)
	if err != nil {
		return fmt.Errorf("failed to unmarshal issuer: %v", err)
	}

	var credentialTypes []string
	err = json.Unmarshal([]byte(credentialTypesJSON), &credentialTypes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal credential types: %v", err)
	}

	issuer.CredentialTypes = credentialTypes
	issuer.LastUpdated = time.Now().UTC().Format(time.RFC3339)

	updatedJSON, err := json.Marshal(issuer)
	if err != nil {
		return fmt.Errorf("failed to marshal issuer: %v", err)
	}

	return ctx.GetStub().PutState(issuerDID, updatedJSON)
}

// UpdateIssuerTrustLevel updates the trust level of an issuer
func (c *TrustedIssuerContract) UpdateIssuerTrustLevel(ctx contractapi.TransactionContextInterface, issuerDID string, trustLevel int) error {
	if trustLevel < 1 || trustLevel > 5 {
		return fmt.Errorf("trust level must be between 1 and 5")
	}

	issuerJSON, err := ctx.GetStub().GetState(issuerDID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if issuerJSON == nil {
		return fmt.Errorf("issuer %s does not exist", issuerDID)
	}

	var issuer Issuer
	err = json.Unmarshal(issuerJSON, &issuer)
	if err != nil {
		return fmt.Errorf("failed to unmarshal issuer: %v", err)
	}

	issuer.TrustLevel = trustLevel
	issuer.LastUpdated = time.Now().UTC().Format(time.RFC3339)

	updatedJSON, err := json.Marshal(issuer)
	if err != nil {
		return fmt.Errorf("failed to marshal issuer: %v", err)
	}

	return ctx.GetStub().PutState(issuerDID, updatedJSON)
}

// GetAllIssuers returns all issuers in the registry
func (c *TrustedIssuerContract) GetAllIssuers(ctx contractapi.TransactionContextInterface) ([]*Issuer, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get state by range: %v", err)
	}
	defer resultsIterator.Close()

	var issuers []*Issuer

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to iterate: %v", err)
		}

		// Skip composite keys
		if len(queryResponse.Key) > 0 && queryResponse.Key[0] == 0x00 {
			continue
		}

		var issuer Issuer
		err = json.Unmarshal(queryResponse.Value, &issuer)
		if err != nil {
			continue
		}

		// Only include valid issuer records (must have IssuerDID)
		if issuer.IssuerDID != "" {
			issuers = append(issuers, &issuer)
		}
	}

	return issuers, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&TrustedIssuerContract{})
	if err != nil {
		fmt.Printf("Error creating trusted issuer registry chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting trusted issuer registry chaincode: %s", err.Error())
	}
}
