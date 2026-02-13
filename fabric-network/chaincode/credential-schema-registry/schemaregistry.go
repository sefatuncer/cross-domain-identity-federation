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

// CredentialSchemaContract provides functions for managing credential schemas
type CredentialSchemaContract struct {
	contractapi.Contract
}

// SchemaStatus represents the status of a schema
type SchemaStatus string

const (
	SchemaActive     SchemaStatus = "ACTIVE"
	SchemaDeprecated SchemaStatus = "DEPRECATED"
	SchemaRevoked    SchemaStatus = "REVOKED"
)

// SchemaType represents the type of credential schema
type SchemaType string

const (
	SchemaTypeFinance    SchemaType = "FINANCE"
	SchemaTypeHealthcare SchemaType = "HEALTHCARE"
	SchemaTypeEducation  SchemaType = "EDUCATION"
	SchemaTypeCrossDomain SchemaType = "CROSS_DOMAIN"
)

// PropertyDefinition defines a property in the schema
type PropertyDefinition struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // string, number, boolean, array, object
	Description string   `json:"description"`
	Required    bool     `json:"required"`
	Format      string   `json:"format,omitempty"`      // date, date-time, email, uri, etc.
	Enum        []string `json:"enum,omitempty"`        // allowed values
	MinLength   int      `json:"minLength,omitempty"`
	MaxLength   int      `json:"maxLength,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`     // regex pattern
}

// CredentialSchema represents a verifiable credential schema
type CredentialSchema struct {
	SchemaID             string               `json:"schemaID"`
	SchemaName           string               `json:"schemaName"`
	SchemaVersion        string               `json:"schemaVersion"`
	SchemaType           SchemaType           `json:"schemaType"`
	Status               SchemaStatus         `json:"status"`
	IssuerDID            string               `json:"issuerDID"`
	Description          string               `json:"description"`
	Properties           []PropertyDefinition `json:"properties"`
	CredentialSubject    json.RawMessage      `json:"credentialSubject"` // JSON Schema for credentialSubject
	Context              []string             `json:"context"`
	Type                 []string             `json:"type"`
	SchemaHash           string               `json:"schemaHash"`
	CreatedAt            string               `json:"createdAt"`
	UpdatedAt            string               `json:"updatedAt"`
	CrossDomainAccepted  []string             `json:"crossDomainAccepted"` // Which domains accept this schema
	Metadata             map[string]string    `json:"metadata"`
}

// SchemaRegistrationRequest represents a request to register a schema
type SchemaRegistrationRequest struct {
	SchemaName           string               `json:"schemaName"`
	SchemaVersion        string               `json:"schemaVersion"`
	SchemaType           SchemaType           `json:"schemaType"`
	IssuerDID            string               `json:"issuerDID"`
	Description          string               `json:"description"`
	Properties           []PropertyDefinition `json:"properties"`
	CredentialSubject    json.RawMessage      `json:"credentialSubject"`
	Context              []string             `json:"context"`
	Type                 []string             `json:"type"`
	CrossDomainAccepted  []string             `json:"crossDomainAccepted"`
	Metadata             map[string]string    `json:"metadata"`
}

// ValidationReport represents the result of credential validation
type ValidationReport struct {
	IsValid        bool              `json:"isValid"`
	SchemaID       string            `json:"schemaID"`
	Errors         []string          `json:"errors"`
	Warnings       []string          `json:"warnings"`
	ValidatedAt    string            `json:"validatedAt"`
	MatchedFields  []string          `json:"matchedFields"`
	MissingFields  []string          `json:"missingFields"`
}

// InitLedger initializes the chaincode with sample schemas
func (c *CredentialSchemaContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	// KYC Credential Schema (Finance)
	kycSchema := CredentialSchema{
		SchemaID:      "schema:finance:kyc:v1.0",
		SchemaName:    "KYCCredential",
		SchemaVersion: "1.0.0",
		SchemaType:    SchemaTypeFinance,
		Status:        SchemaActive,
		IssuerDID:     "did:web:bank.finance.crossdomain.com",
		Description:   "Know Your Customer verification credential for financial institutions",
		Properties: []PropertyDefinition{
			{Name: "fullName", Type: "string", Description: "Full legal name", Required: true},
			{Name: "dateOfBirth", Type: "string", Description: "Date of birth", Required: true, Format: "date"},
			{Name: "nationalID", Type: "string", Description: "National identification number", Required: true},
			{Name: "address", Type: "object", Description: "Residential address", Required: true},
			{Name: "verificationLevel", Type: "string", Description: "KYC verification level", Required: true, Enum: []string{"BASIC", "STANDARD", "ENHANCED"}},
			{Name: "verificationDate", Type: "string", Description: "Date of verification", Required: true, Format: "date-time"},
			{Name: "riskScore", Type: "number", Description: "Risk assessment score", Required: false},
		},
		Context:             []string{"https://www.w3.org/2018/credentials/v1", "https://crossdomain.com/credentials/finance/v1"},
		Type:                []string{"VerifiableCredential", "KYCCredential"},
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:           time.Now().UTC().Format(time.RFC3339),
		CrossDomainAccepted: []string{"HEALTHCARE", "EDUCATION"},
		Metadata: map[string]string{
			"jurisdiction": "TR",
			"standard":     "ISO-17442",
		},
	}

	// Health Insurance Credential Schema (Healthcare)
	healthInsuranceSchema := CredentialSchema{
		SchemaID:      "schema:healthcare:insurance:v1.0",
		SchemaName:    "HealthInsuranceCredential",
		SchemaVersion: "1.0.0",
		SchemaType:    SchemaTypeHealthcare,
		Status:        SchemaActive,
		IssuerDID:     "did:web:hospital.healthcare.crossdomain.com",
		Description:   "Health insurance coverage verification credential",
		Properties: []PropertyDefinition{
			{Name: "policyNumber", Type: "string", Description: "Insurance policy number", Required: true},
			{Name: "holderName", Type: "string", Description: "Policy holder name", Required: true},
			{Name: "coverageType", Type: "string", Description: "Type of coverage", Required: true, Enum: []string{"BASIC", "STANDARD", "PREMIUM", "COMPREHENSIVE"}},
			{Name: "validFrom", Type: "string", Description: "Coverage start date", Required: true, Format: "date"},
			{Name: "validUntil", Type: "string", Description: "Coverage end date", Required: true, Format: "date"},
			{Name: "provider", Type: "string", Description: "Insurance provider name", Required: true},
			{Name: "dependents", Type: "array", Description: "List of covered dependents", Required: false},
		},
		Context:             []string{"https://www.w3.org/2018/credentials/v1", "https://crossdomain.com/credentials/healthcare/v1"},
		Type:                []string{"VerifiableCredential", "HealthInsuranceCredential"},
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:           time.Now().UTC().Format(time.RFC3339),
		CrossDomainAccepted: []string{"FINANCE"},
		Metadata: map[string]string{
			"jurisdiction": "TR",
			"standard":     "HL7-FHIR",
		},
	}

	// Diploma Credential Schema (Education)
	diplomaSchema := CredentialSchema{
		SchemaID:      "schema:education:diploma:v1.0",
		SchemaName:    "DiplomaCredential",
		SchemaVersion: "1.0.0",
		SchemaType:    SchemaTypeEducation,
		Status:        SchemaActive,
		IssuerDID:     "did:web:university.education.crossdomain.com",
		Description:   "Academic diploma credential for educational institutions",
		Properties: []PropertyDefinition{
			{Name: "studentName", Type: "string", Description: "Full name of the student", Required: true},
			{Name: "studentID", Type: "string", Description: "Student identification number", Required: true},
			{Name: "degree", Type: "string", Description: "Degree awarded", Required: true},
			{Name: "major", Type: "string", Description: "Major field of study", Required: true},
			{Name: "graduationDate", Type: "string", Description: "Date of graduation", Required: true, Format: "date"},
			{Name: "gpa", Type: "number", Description: "Grade point average", Required: false},
			{Name: "honors", Type: "string", Description: "Honors received", Required: false, Enum: []string{"NONE", "CUM_LAUDE", "MAGNA_CUM_LAUDE", "SUMMA_CUM_LAUDE"}},
			{Name: "institution", Type: "string", Description: "Name of the institution", Required: true},
		},
		Context:             []string{"https://www.w3.org/2018/credentials/v1", "https://crossdomain.com/credentials/education/v1"},
		Type:                []string{"VerifiableCredential", "DiplomaCredential"},
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:           time.Now().UTC().Format(time.RFC3339),
		CrossDomainAccepted: []string{"FINANCE", "HEALTHCARE"},
		Metadata: map[string]string{
			"jurisdiction": "TR",
			"standard":     "W3C-VC-EDU",
		},
	}

	// Cross-Domain Identity Credential Schema
	crossDomainSchema := CredentialSchema{
		SchemaID:      "schema:crossdomain:federated-identity:v1.0",
		SchemaName:    "FederatedIdentityCredential",
		SchemaVersion: "1.0.0",
		SchemaType:    SchemaTypeCrossDomain,
		Status:        SchemaActive,
		IssuerDID:     "did:web:federation.crossdomain.com",
		Description:   "Cross-domain federated identity credential for multi-sector authentication",
		Properties: []PropertyDefinition{
			{Name: "subjectDID", Type: "string", Description: "Subject's decentralized identifier", Required: true},
			{Name: "sourceCredentials", Type: "array", Description: "List of source credential references", Required: true},
			{Name: "federationLevel", Type: "string", Description: "Level of federation trust", Required: true, Enum: []string{"BASIC", "VERIFIED", "ASSURED"}},
			{Name: "sourceDomains", Type: "array", Description: "Domains that contributed to this credential", Required: true},
			{Name: "validFrom", Type: "string", Description: "Validity start", Required: true, Format: "date-time"},
			{Name: "validUntil", Type: "string", Description: "Validity end", Required: true, Format: "date-time"},
			{Name: "trustChain", Type: "array", Description: "Chain of trust references", Required: false},
		},
		Context:             []string{"https://www.w3.org/2018/credentials/v1", "https://crossdomain.com/credentials/federation/v1"},
		Type:                []string{"VerifiableCredential", "FederatedIdentityCredential"},
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:           time.Now().UTC().Format(time.RFC3339),
		CrossDomainAccepted: []string{"FINANCE", "HEALTHCARE", "EDUCATION"},
		Metadata: map[string]string{
			"standard": "OpenID4VC",
		},
	}

	schemas := []CredentialSchema{kycSchema, healthInsuranceSchema, diplomaSchema, crossDomainSchema}

	for _, schema := range schemas {
		// Calculate schema hash
		schemaBytes, _ := json.Marshal(schema.Properties)
		hash := sha256.Sum256(schemaBytes)
		schema.SchemaHash = hex.EncodeToString(hash[:])

		schemaJSON, err := json.Marshal(schema)
		if err != nil {
			return fmt.Errorf("failed to marshal schema: %v", err)
		}

		err = ctx.GetStub().PutState(schema.SchemaID, schemaJSON)
		if err != nil {
			return fmt.Errorf("failed to put schema to world state: %v", err)
		}

		// Create composite keys for indexing
		// Index by issuer
		issuerKey, _ := ctx.GetStub().CreateCompositeKey("issuer~schemaID", []string{schema.IssuerDID, schema.SchemaID})
		ctx.GetStub().PutState(issuerKey, []byte{0x00})

		// Index by type
		typeKey, _ := ctx.GetStub().CreateCompositeKey("type~schemaID", []string{string(schema.SchemaType), schema.SchemaID})
		ctx.GetStub().PutState(typeKey, []byte{0x00})

		// Index by name
		nameKey, _ := ctx.GetStub().CreateCompositeKey("name~schemaID", []string{schema.SchemaName, schema.SchemaID})
		ctx.GetStub().PutState(nameKey, []byte{0x00})
	}

	return nil
}

// RegisterSchema registers a new credential schema
func (c *CredentialSchemaContract) RegisterSchema(ctx contractapi.TransactionContextInterface, requestJSON string) (string, error) {
	var request SchemaRegistrationRequest
	err := json.Unmarshal([]byte(requestJSON), &request)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal request: %v", err)
	}

	// Validate required fields
	if request.SchemaName == "" {
		return "", fmt.Errorf("schemaName is required")
	}
	if request.SchemaVersion == "" {
		return "", fmt.Errorf("schemaVersion is required")
	}
	if request.IssuerDID == "" {
		return "", fmt.Errorf("issuerDID is required")
	}

	// Generate schema ID
	schemaID := fmt.Sprintf("schema:%s:%s:v%s", string(request.SchemaType), request.SchemaName, request.SchemaVersion)

	// Check if schema already exists
	existing, _ := ctx.GetStub().GetState(schemaID)
	if existing != nil {
		return "", fmt.Errorf("schema %s already exists", schemaID)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Calculate schema hash
	schemaBytes, _ := json.Marshal(request.Properties)
	hash := sha256.Sum256(schemaBytes)

	schema := CredentialSchema{
		SchemaID:            schemaID,
		SchemaName:          request.SchemaName,
		SchemaVersion:       request.SchemaVersion,
		SchemaType:          request.SchemaType,
		Status:              SchemaActive,
		IssuerDID:           request.IssuerDID,
		Description:         request.Description,
		Properties:          request.Properties,
		CredentialSubject:   request.CredentialSubject,
		Context:             request.Context,
		Type:                request.Type,
		SchemaHash:          hex.EncodeToString(hash[:]),
		CreatedAt:           now,
		UpdatedAt:           now,
		CrossDomainAccepted: request.CrossDomainAccepted,
		Metadata:            request.Metadata,
	}

	schemaJSON, err := json.Marshal(schema)
	if err != nil {
		return "", fmt.Errorf("failed to marshal schema: %v", err)
	}

	err = ctx.GetStub().PutState(schemaID, schemaJSON)
	if err != nil {
		return "", fmt.Errorf("failed to put schema to world state: %v", err)
	}

	// Create composite keys
	issuerKey, _ := ctx.GetStub().CreateCompositeKey("issuer~schemaID", []string{schema.IssuerDID, schema.SchemaID})
	ctx.GetStub().PutState(issuerKey, []byte{0x00})

	typeKey, _ := ctx.GetStub().CreateCompositeKey("type~schemaID", []string{string(schema.SchemaType), schema.SchemaID})
	ctx.GetStub().PutState(typeKey, []byte{0x00})

	nameKey, _ := ctx.GetStub().CreateCompositeKey("name~schemaID", []string{schema.SchemaName, schema.SchemaID})
	ctx.GetStub().PutState(nameKey, []byte{0x00})

	// Emit event
	eventPayload := map[string]string{
		"schemaID":  schemaID,
		"action":    "REGISTERED",
		"timestamp": now,
	}
	eventJSON, _ := json.Marshal(eventPayload)
	ctx.GetStub().SetEvent("SchemaRegistered", eventJSON)

	return schemaID, nil
}

// GetSchema returns a schema by ID
func (c *CredentialSchemaContract) GetSchema(ctx contractapi.TransactionContextInterface, schemaID string) (*CredentialSchema, error) {
	schemaJSON, err := ctx.GetStub().GetState(schemaID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if schemaJSON == nil {
		return nil, fmt.Errorf("schema %s does not exist", schemaID)
	}

	var schema CredentialSchema
	err = json.Unmarshal(schemaJSON, &schema)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal schema: %v", err)
	}

	return &schema, nil
}

// GetSchemasByIssuer returns all schemas registered by a specific issuer
func (c *CredentialSchemaContract) GetSchemasByIssuer(ctx contractapi.TransactionContextInterface, issuerDID string) ([]*CredentialSchema, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("issuer~schemaID", []string{issuerDID})
	if err != nil {
		return nil, fmt.Errorf("failed to get state by partial composite key: %v", err)
	}
	defer resultsIterator.Close()

	var schemas []*CredentialSchema

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, err
		}

		if len(compositeKeyParts) < 2 {
			continue
		}

		schemaID := compositeKeyParts[1]
		schema, err := c.GetSchema(ctx, schemaID)
		if err != nil {
			continue
		}

		schemas = append(schemas, schema)
	}

	return schemas, nil
}

// GetSchemasByType returns all schemas of a specific type
func (c *CredentialSchemaContract) GetSchemasByType(ctx contractapi.TransactionContextInterface, schemaType string) ([]*CredentialSchema, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("type~schemaID", []string{schemaType})
	if err != nil {
		return nil, fmt.Errorf("failed to get state by partial composite key: %v", err)
	}
	defer resultsIterator.Close()

	var schemas []*CredentialSchema

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(queryResponse.Key)
		if err != nil {
			return nil, err
		}

		if len(compositeKeyParts) < 2 {
			continue
		}

		schemaID := compositeKeyParts[1]
		schema, err := c.GetSchema(ctx, schemaID)
		if err != nil {
			continue
		}

		if schema.Status == SchemaActive {
			schemas = append(schemas, schema)
		}
	}

	return schemas, nil
}

// ValidateCredentialAgainstSchema validates a credential against a schema
func (c *CredentialSchemaContract) ValidateCredentialAgainstSchema(ctx contractapi.TransactionContextInterface, credentialJSON string, schemaID string) (*ValidationReport, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	schema, err := c.GetSchema(ctx, schemaID)
	if err != nil {
		return &ValidationReport{
			IsValid:     false,
			SchemaID:    schemaID,
			Errors:      []string{fmt.Sprintf("schema not found: %v", err)},
			ValidatedAt: now,
		}, nil
	}

	if schema.Status != SchemaActive {
		return &ValidationReport{
			IsValid:     false,
			SchemaID:    schemaID,
			Errors:      []string{fmt.Sprintf("schema is not active, status: %s", schema.Status)},
			ValidatedAt: now,
		}, nil
	}

	var credential map[string]interface{}
	err = json.Unmarshal([]byte(credentialJSON), &credential)
	if err != nil {
		return &ValidationReport{
			IsValid:     false,
			SchemaID:    schemaID,
			Errors:      []string{fmt.Sprintf("invalid credential JSON: %v", err)},
			ValidatedAt: now,
		}, nil
	}

	var errors []string
	var warnings []string
	var matchedFields []string
	var missingFields []string

	// Extract credentialSubject
	credentialSubject, ok := credential["credentialSubject"].(map[string]interface{})
	if !ok {
		return &ValidationReport{
			IsValid:     false,
			SchemaID:    schemaID,
			Errors:      []string{"credentialSubject not found or invalid"},
			ValidatedAt: now,
		}, nil
	}

	// Validate each property
	for _, prop := range schema.Properties {
		value, exists := credentialSubject[prop.Name]

		if !exists {
			if prop.Required {
				missingFields = append(missingFields, prop.Name)
				errors = append(errors, fmt.Sprintf("required field '%s' is missing", prop.Name))
			}
			continue
		}

		matchedFields = append(matchedFields, prop.Name)

		// Type validation
		switch prop.Type {
		case "string":
			strVal, ok := value.(string)
			if !ok {
				errors = append(errors, fmt.Sprintf("field '%s' should be string", prop.Name))
				continue
			}
			if prop.MinLength > 0 && len(strVal) < prop.MinLength {
				errors = append(errors, fmt.Sprintf("field '%s' is shorter than minimum length %d", prop.Name, prop.MinLength))
			}
			if prop.MaxLength > 0 && len(strVal) > prop.MaxLength {
				errors = append(errors, fmt.Sprintf("field '%s' exceeds maximum length %d", prop.Name, prop.MaxLength))
			}
			if len(prop.Enum) > 0 {
				found := false
				for _, e := range prop.Enum {
					if e == strVal {
						found = true
						break
					}
				}
				if !found {
					errors = append(errors, fmt.Sprintf("field '%s' has invalid value '%s', expected one of %v", prop.Name, strVal, prop.Enum))
				}
			}
		case "number":
			_, ok := value.(float64)
			if !ok {
				errors = append(errors, fmt.Sprintf("field '%s' should be number", prop.Name))
			}
		case "boolean":
			_, ok := value.(bool)
			if !ok {
				errors = append(errors, fmt.Sprintf("field '%s' should be boolean", prop.Name))
			}
		case "array":
			_, ok := value.([]interface{})
			if !ok {
				errors = append(errors, fmt.Sprintf("field '%s' should be array", prop.Name))
			}
		case "object":
			_, ok := value.(map[string]interface{})
			if !ok {
				errors = append(errors, fmt.Sprintf("field '%s' should be object", prop.Name))
			}
		}
	}

	return &ValidationReport{
		IsValid:       len(errors) == 0,
		SchemaID:      schemaID,
		Errors:        errors,
		Warnings:      warnings,
		ValidatedAt:   now,
		MatchedFields: matchedFields,
		MissingFields: missingFields,
	}, nil
}

// DeprecateSchema marks a schema as deprecated
func (c *CredentialSchemaContract) DeprecateSchema(ctx contractapi.TransactionContextInterface, schemaID string, reason string) error {
	schema, err := c.GetSchema(ctx, schemaID)
	if err != nil {
		return err
	}

	schema.Status = SchemaDeprecated
	schema.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	schema.Metadata["deprecationReason"] = reason

	schemaJSON, err := json.Marshal(schema)
	if err != nil {
		return fmt.Errorf("failed to marshal schema: %v", err)
	}

	return ctx.GetStub().PutState(schemaID, schemaJSON)
}

// GetCrossDomainAcceptedSchemas returns schemas accepted by a target domain
func (c *CredentialSchemaContract) GetCrossDomainAcceptedSchemas(ctx contractapi.TransactionContextInterface, sourceDomain string, targetDomain string) ([]*CredentialSchema, error) {
	// Get all schemas from source domain
	sourceSchemas, err := c.GetSchemasByType(ctx, sourceDomain)
	if err != nil {
		return nil, err
	}

	var acceptedSchemas []*CredentialSchema

	for _, schema := range sourceSchemas {
		for _, accepted := range schema.CrossDomainAccepted {
			if accepted == targetDomain {
				acceptedSchemas = append(acceptedSchemas, schema)
				break
			}
		}
	}

	return acceptedSchemas, nil
}

// GetAllSchemas returns all schemas in the registry
func (c *CredentialSchemaContract) GetAllSchemas(ctx contractapi.TransactionContextInterface) ([]*CredentialSchema, error) {
	queryString := `{"selector":{"schemaID":{"$gt":""}}}`

	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("failed to get query result: %v", err)
	}
	defer resultsIterator.Close()

	var schemas []*CredentialSchema

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var schema CredentialSchema
		err = json.Unmarshal(queryResponse.Value, &schema)
		if err != nil {
			continue
		}

		schemas = append(schemas, &schema)
	}

	return schemas, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&CredentialSchemaContract{})
	if err != nil {
		fmt.Printf("Error creating credential schema registry chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting credential schema registry chaincode: %s", err.Error())
	}
}
