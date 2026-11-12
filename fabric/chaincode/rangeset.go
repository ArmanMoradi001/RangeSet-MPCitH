// Package main implements the RangeSet-MPCitH ledger anchor contract.
//
// The ledger stores *expectations* (registered statements) and *anchors*
// (proof records + attester verdicts). It performs no cryptography beyond
// a SHA-256 equality check binding each attestation to exact envelope
// bytes. Proof verification itself happens off-chain in the rsp-attester
// service against statement fields read from this ledger.
//
// Trust flow: admin MSPs register statements (range, set root, context,
// allowed param presets, attester MSPs). Anyone submits opaque envelopes.
// Only listed attester MSPs may flip a PENDING proof to VERIFIED/REJECTED,
// and only for the exact envelope hash submitted. See
// docs/fabric-integration.md.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Ledger key prefixes.
const (
	statementKeyPrefix = "stmt:"
	proofKeyPrefix     = "proof:"
	adminsKey          = "admins"
)

// Proof lifecycle states.
const (
	StatusPending  = "PENDING"
	StatusVerified = "VERIFIED"
	StatusRejected = "REJECTED"
)

// Verdicts an attester may report.
const (
	VerdictVerified = "VERIFIED"
	VerdictRejected = "REJECTED"
)

// MaxEnvelopeBytes caps stored raw envelope bytes (fail-closed DoS bound;
// production proofs are ~215 KiB).
const MaxEnvelopeBytes = 1 << 20 // 1 MiB

// StatementRecord is the ledger-held expectation a proof is checked against.
type StatementRecord struct {
	ID            string   `json:"id"`
	RangeLo       uint32   `json:"rangeLo"`
	RangeHi       uint32   `json:"rangeHi"`
	SetRoot       string   `json:"setRoot"` // 64 lowercase hex chars
	NumMembers    uint32   `json:"numMembers"`
	Depth         uint32   `json:"depth"`
	Context       string   `json:"context"` // 64 lowercase hex chars
	AllowedParams []string `json:"allowedParams"`
	AttesterMSPs  []string `json:"attesterMSPs"`
	Version       uint64   `json:"version"` // bumped on every re-register
}

// ProofRecord anchors one submitted envelope and its attestation trail.
type ProofRecord struct {
	ID           string        `json:"id"`
	StatementID  string        `json:"statementID"`
	EnvelopeHash string        `json:"envelopeHash"` // hex SHA-256 of raw envelope bytes
	EnvelopeB64  string        `json:"envelopeB64"`  // base64 raw envelope bytes (attester input)
	ParamsID     string        `json:"paramsID"`
	Status       string        `json:"status"`
	Attestations []Attestation `json:"attestations"`
}

// Attestation binds one attester MSP's verdict to exact envelope bytes.
type Attestation struct {
	AttesterMSPID string `json:"attesterMSP"`
	Verdict       string `json:"verdict"`
	EnvelopeHash  string `json:"envelopeHash"`
	Reason        string `json:"reason"`
}

// RangeSetContract is the chaincode contract.
type RangeSetContract struct {
	contractapi.Contract
}

func stmtKey(id string) string  { return statementKeyPrefix + id }
func proofKey(id string) string { return proofKeyPrefix + id }

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func getMSPID(ctx contractapi.TransactionContextInterface) (string, error) {
	id, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("identity: cannot read caller MSP: %w", err)
	}
	return id, nil
}

func readAdmins(ctx contractapi.TransactionContextInterface) ([]string, error) {
	raw, err := ctx.GetStub().GetState(adminsKey)
	if err != nil {
		return nil, fmt.Errorf("state: cannot read admins: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("config: chaincode not initialized")
	}
	var admins []string
	if err := json.Unmarshal(raw, &admins); err != nil {
		return nil, fmt.Errorf("state: corrupt admins record: %w", err)
	}
	return admins, nil
}

func callerIsAdmin(ctx contractapi.TransactionContextInterface) error {
	mspid, err := getMSPID(ctx)
	if err != nil {
		return err
	}
	admins, err := readAdmins(ctx)
	if err != nil {
		return err
	}
	for _, a := range admins {
		if a == mspid {
			return nil
		}
	}
	return fmt.Errorf("auth: MSP %s is not a chaincode admin", mspid)
}

func readStatement(ctx contractapi.TransactionContextInterface, id string) (*StatementRecord, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("input: empty statement id")
	}
	raw, err := ctx.GetStub().GetState(stmtKey(id))
	if err != nil {
		return nil, fmt.Errorf("state: cannot read statement %s: %w", id, err)
	}
	if raw == nil {
		return nil, fmt.Errorf("input: unknown statement %s", id)
	}
	var stmt StatementRecord
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("state: corrupt statement %s: %w", id, err)
	}
	return &stmt, nil
}

// Init stores the admin MSP list. Called once at chaincode instantiation.
func (c *RangeSetContract) Init(ctx contractapi.TransactionContextInterface, adminMSPsCSV string) error {
	existing, err := ctx.GetStub().GetState(adminsKey)
	if err != nil {
		return fmt.Errorf("state: cannot read admins: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("config: already initialized")
	}
	var admins []string
	for _, m := range strings.Split(adminMSPsCSV, ",") {
		if m = strings.TrimSpace(m); m != "" {
			admins = append(admins, m)
		}
	}
	if len(admins) == 0 {
		return fmt.Errorf("input: empty admin MSP list")
	}
	raw, err := json.Marshal(admins)
	if err != nil {
		return fmt.Errorf("state: cannot encode admins: %w", err)
	}
	if err := ctx.GetStub().PutState(adminsKey, raw); err != nil {
		return fmt.Errorf("state: cannot store admins: %w", err)
	}
	return nil
}

// RegisterStatement creates or rotates (version bump) the expectation
// other transactions verify against. Admin MSPs only.
func (c *RangeSetContract) RegisterStatement(
	ctx contractapi.TransactionContextInterface,
	id string,
	rangeLo uint32,
	rangeHi uint32,
	setRoot string,
	numMembers uint32,
	depth uint32,
	contextHex string,
	allowedParamsCSV string,
	attesterMSPsCSV string,
) (*StatementRecord, error) {
	if err := callerIsAdmin(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("input: empty statement id")
	}
	if rangeLo > rangeHi {
		return nil, fmt.Errorf("input: rangeLo %d exceeds rangeHi %d", rangeLo, rangeHi)
	}
	setRoot = strings.ToLower(strings.TrimSpace(setRoot))
	if !isHex64(setRoot) {
		return nil, fmt.Errorf("input: setRoot must be 64 lowercase hex chars")
	}
	contextHex = strings.ToLower(strings.TrimSpace(contextHex))
	if !isHex64(contextHex) {
		return nil, fmt.Errorf("input: context must be 64 lowercase hex chars")
	}
	if numMembers == 0 {
		return nil, fmt.Errorf("input: numMembers must be nonzero")
	}
	var allowed []string
	for _, p := range strings.Split(allowedParamsCSV, ",") {
		if p = strings.TrimSpace(p); p != "" {
			allowed = append(allowed, p)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("input: empty allowed-params list")
	}
	var attesters []string
	for _, m := range strings.Split(attesterMSPsCSV, ",") {
		if m = strings.TrimSpace(m); m != "" {
			attesters = append(attesters, m)
		}
	}
	if len(attesters) == 0 {
		return nil, fmt.Errorf("input: empty attester MSP list")
	}
	var version uint64 = 1
	if raw, err := ctx.GetStub().GetState(stmtKey(id)); err != nil {
		return nil, fmt.Errorf("state: cannot read statement %s: %w", id, err)
	} else if raw != nil {
		var prev StatementRecord
		if err := json.Unmarshal(raw, &prev); err != nil {
			return nil, fmt.Errorf("state: corrupt statement %s: %w", id, err)
		}
		version = prev.Version + 1
	}
	stmt := &StatementRecord{
		ID:            id,
		RangeLo:       rangeLo,
		RangeHi:       rangeHi,
		SetRoot:       setRoot,
		NumMembers:    numMembers,
		Depth:         depth,
		Context:       contextHex,
		AllowedParams: allowed,
		AttesterMSPs:  attesters,
		Version:       version,
	}
	raw, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("state: cannot encode statement: %w", err)
	}
	if err := ctx.GetStub().PutState(stmtKey(id), raw); err != nil {
		return nil, fmt.Errorf("state: cannot store statement: %w", err)
	}
	return stmt, nil
}

// SubmitProof anchors an opaque envelope for a registered statement.
// The envelope is hash-bound (SHA-256 over raw bytes must equal
// envelopeHashHex) and size-capped; its content is never interpreted here.
func (c *RangeSetContract) SubmitProof(
	ctx contractapi.TransactionContextInterface,
	proofID string,
	statementID string,
	envelopeHashHex string,
	envelopeB64 string,
	paramsID string,
) (*ProofRecord, error) {
	if strings.TrimSpace(proofID) == "" {
		return nil, fmt.Errorf("input: empty proof id")
	}
	if strings.TrimSpace(paramsID) == "" {
		return nil, fmt.Errorf("input: empty params id")
	}
	stmt, err := readStatement(ctx, statementID)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, p := range stmt.AllowedParams {
		if p == paramsID {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("input: params %s not allowed for statement %s", paramsID, statementID)
	}
	if existing, err := ctx.GetStub().GetState(proofKey(proofID)); err != nil {
		return nil, fmt.Errorf("state: cannot read proof %s: %w", proofID, err)
	} else if existing != nil {
		return nil, fmt.Errorf("input: duplicate proof id %s", proofID)
	}
	envelopeHashHex = strings.ToLower(strings.TrimSpace(envelopeHashHex))
	if !isHex64(envelopeHashHex) {
		return nil, fmt.Errorf("input: envelopeHash must be 64 lowercase hex chars")
	}
	envelopeBytes, err := base64.StdEncoding.DecodeString(envelopeB64)
	if err != nil {
		return nil, fmt.Errorf("input: envelope is not valid base64: %w", err)
	}
	if len(envelopeBytes) == 0 {
		return nil, fmt.Errorf("input: empty envelope")
	}
	if len(envelopeBytes) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("input: envelope %d bytes exceeds cap %d", len(envelopeBytes), MaxEnvelopeBytes)
	}
	sum := sha256.Sum256(envelopeBytes)
	if hex.EncodeToString(sum[:]) != envelopeHashHex {
		return nil, fmt.Errorf("input: envelopeHash does not match envelope bytes")
	}
	rec := &ProofRecord{
		ID:           proofID,
		StatementID:  statementID,
		EnvelopeHash: envelopeHashHex,
		EnvelopeB64:  envelopeB64,
		ParamsID:     paramsID,
		Status:       StatusPending,
		Attestations: []Attestation{},
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("state: cannot encode proof: %w", err)
	}
	if err := ctx.GetStub().PutState(proofKey(proofID), raw); err != nil {
		return nil, fmt.Errorf("state: cannot store proof: %w", err)
	}
	return rec, nil
}

func readProof(ctx contractapi.TransactionContextInterface, id string) (*ProofRecord, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("input: empty proof id")
	}
	raw, err := ctx.GetStub().GetState(proofKey(id))
	if err != nil {
		return nil, fmt.Errorf("state: cannot read proof %s: %w", id, err)
	}
	if raw == nil {
		return nil, fmt.Errorf("input: unknown proof %s", id)
	}
	var rec ProofRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("state: corrupt proof %s: %w", id, err)
	}
	return &rec, nil
}

// AttestVerification records one attester MSP's verdict for a PENDING
// proof and flips its status. The attestation is bound to the exact
// submitted bytes: the caller re-supplies the envelope hash and it must
// equal the anchored one.
func (c *RangeSetContract) AttestVerification(
	ctx contractapi.TransactionContextInterface,
	proofID string,
	verdict string,
	envelopeHashHex string,
	reason string,
) (*ProofRecord, error) {
	if verdict != VerdictVerified && verdict != VerdictRejected {
		return nil, fmt.Errorf("input: verdict must be VERIFIED or REJECTED")
	}
	rec, err := readProof(ctx, proofID)
	if err != nil {
		return nil, err
	}
	if rec.Status != StatusPending {
		return nil, fmt.Errorf("input: proof %s is already %s", proofID, rec.Status)
	}
	stmt, err := readStatement(ctx, rec.StatementID)
	if err != nil {
		return nil, err
	}
	mspid, err := getMSPID(ctx)
	if err != nil {
		return nil, err
	}
	authorized := false
	for _, m := range stmt.AttesterMSPs {
		if m == mspid {
			authorized = true
			break
		}
	}
	if !authorized {
		return nil, fmt.Errorf("auth: MSP %s is not an attester for statement %s", mspid, stmt.ID)
	}
	for _, a := range rec.Attestations {
		if a.AttesterMSPID == mspid {
			return nil, fmt.Errorf("input: MSP %s already attested proof %s", mspid, proofID)
		}
	}
	envelopeHashHex = strings.ToLower(strings.TrimSpace(envelopeHashHex))
	if envelopeHashHex != rec.EnvelopeHash {
		return nil, fmt.Errorf("input: attestation hash does not match anchored envelope")
	}
	if len(reason) > 1024 {
		return nil, fmt.Errorf("input: reason exceeds 1024 chars")
	}
	rec.Attestations = append(rec.Attestations, Attestation{
		AttesterMSPID: mspid,
		Verdict:       verdict,
		EnvelopeHash:  rec.EnvelopeHash,
		Reason:        reason,
	})
	if verdict == VerdictVerified {
		rec.Status = StatusVerified
	} else {
		rec.Status = StatusRejected
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("state: cannot encode proof: %w", err)
	}
	if err := ctx.GetStub().PutState(proofKey(proofID), raw); err != nil {
		return nil, fmt.Errorf("state: cannot store proof: %w", err)
	}
	return rec, nil
}

// QueryProof returns the anchored record (envelope included for attesters).
func (c *RangeSetContract) QueryProof(
	ctx contractapi.TransactionContextInterface, proofID string,
) (*ProofRecord, error) {
	return readProof(ctx, proofID)
}

// QueryStatement returns the registered expectation.
func (c *RangeSetContract) QueryStatement(
	ctx contractapi.TransactionContextInterface, statementID string,
) (*StatementRecord, error) {
	return readStatement(ctx, statementID)
}

func main() {
	chaincode, err := contractapi.NewChaincode(&RangeSetContract{})
	if err != nil {
		panic(fmt.Sprintf("chaincode init: %v", err))
	}
	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("chaincode start: %v", err))
	}
}
