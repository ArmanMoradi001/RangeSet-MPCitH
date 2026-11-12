package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// newChaincodeStub builds a MockStub wired to the real contract.
func newChaincodeStub(t *testing.T) *shimtest.MockStub {
	t.Helper()
	cc, err := contractapi.NewChaincode(&RangeSetContract{})
	if err != nil {
		t.Fatalf("NewChaincode: %v", err)
	}
	return shimtest.NewMockStub("rangeset", cc)
}

// asMSP fakes the transaction creator as the given MSP id.
// A SerializedIdentity with only Mspid set marshals to
// 0x0A len mspid-bytes; hand-encoded to keep the test helper free of a
// protobuf runtime. The auth tests below prove the bytes decode: a wrong
// MSP is rejected wherever an MSP is required.
func asMSP(stub *shimtest.MockStub, mspID string) {
	stub.Creator = append([]byte{0x0A, byte(len(mspID))}, []byte(mspID)...)
}

func newStub(t *testing.T) *shimtest.MockStub {
	t.Helper()
	stub := newChaincodeStub(t)
	asMSP(stub, "Org1MSP")
	if res := stub.MockInit("tx-init", [][]byte{[]byte("Init"), []byte("Org1MSP")}); res.Status != 200 {
		t.Fatalf("Init failed: %s", res.Message)
	}
	return stub
}

func mustRegister(t *testing.T, stub *shimtest.MockStub) {
	t.Helper()
	asMSP(stub, "Org1MSP")
	res := stub.MockInvoke("tx-reg", [][]byte{
		[]byte("RegisterStatement"),
		[]byte("stmt-2026"), []byte("10"), []byte("40"),
		[]byte(strings.Repeat("ab", 32)), []byte("4"), []byte("2"),
		[]byte(strings.Repeat("07", 32)),
		[]byte("fast-insecure-test,prototype-tau2"),
		[]byte("AttesterMSP"),
	})
	if res.Status != 200 {
		t.Fatalf("RegisterStatement failed: %s", res.Message)
	}
}

func submitArgs(proofID, stmtID, hashHex, b64, params string) [][]byte {
	return [][]byte{
		[]byte("SubmitProof"),
		[]byte(proofID), []byte(stmtID), []byte(hashHex), []byte(b64), []byte(params),
	}
}

func TestInitRejectsEmptyAdminsAndDoubleInit(t *testing.T) {
	stub := newChaincodeStub(t)
	if res := stub.MockInit("tx0", [][]byte{[]byte("Init"), []byte("")}); res.Status == 200 {
		t.Fatal("Init accepted empty admin list")
	}
	if res := stub.MockInit("tx1", [][]byte{[]byte("Init"), []byte("Org1MSP")}); res.Status != 200 {
		t.Fatalf("Init failed: %s", res.Message)
	}
	if res := stub.MockInit("tx2", [][]byte{[]byte("Init"), []byte("Org2MSP")}); res.Status == 200 {
		t.Fatal("double Init accepted")
	}
}

func TestRegisterStatementAuthAndValidation(t *testing.T) {
	stub := newStub(t)
	ok := []string{"RegisterStatement", "s1", "10", "40", strings.Repeat("ab", 32), "4", "2",
		strings.Repeat("07", 32), "fast-insecure-test", "AttesterMSP"}
	args := func() [][]byte {
		out := make([][]byte, len(ok))
		for i, s := range ok {
			out[i] = []byte(s)
		}
		return out
	}
	// Non-admin rejected.
	asMSP(stub, "EvilMSP")
	if res := stub.MockInvoke("tx-evil", args()); res.Status == 200 {
		t.Fatal("non-admin registration accepted")
	}
	// Admin with bad hex rejected.
	asMSP(stub, "Org1MSP")
	bad := args()
	bad[4] = []byte("not-hex")
	if res := stub.MockInvoke("tx-bad", bad); res.Status == 200 {
		t.Fatal("bad setRoot accepted")
	}
	// Inverted range rejected.
	bad = args()
	bad[2], bad[3] = []byte("40"), []byte("10")
	if res := stub.MockInvoke("tx-range", bad); res.Status == 200 {
		t.Fatal("inverted range accepted")
	}
	// Empty attester list rejected.
	bad = args()
	bad[9] = []byte("")
	if res := stub.MockInvoke("tx-att", bad); res.Status == 200 {
		t.Fatal("empty attester list accepted")
	}
	// Valid registration, then rotation bumps version.
	if res := stub.MockInvoke("tx-ok", args()); res.Status != 200 {
		t.Fatalf("valid registration failed: %s", res.Message)
	}
	if res := stub.MockInvoke("tx-rot", args()); res.Status != 200 {
		t.Fatalf("re-registration failed: %s", res.Message)
	}
	res := stub.MockInvoke("tx-q", [][]byte{[]byte("QueryStatement"), []byte("s1")})
	if res.Status != 200 || !strings.Contains(string(res.Payload), `"version":2`) {
		t.Fatalf("expected version 2 after rotation, got: %s", res.Payload)
	}
}

func TestSubmitProofBinding(t *testing.T) {
	stub := newStub(t)
	mustRegister(t, stub)
	envelope := []byte("fake-envelope-bytes")
	sum := sha256.Sum256(envelope)
	hashHex := hex.EncodeToString(sum[:])
	b64 := base64.StdEncoding.EncodeToString(envelope)

	// Unknown statement.
	if res := stub.MockInvoke("tx-u", submitArgs("p1", "nope", hashHex, b64, "fast-insecure-test")); res.Status == 200 {
		t.Fatal("submit to unknown statement accepted")
	}
	// Disallowed params.
	if res := stub.MockInvoke("tx-p", submitArgs("p1", "stmt-2026", hashHex, b64, "other-preset")); res.Status == 200 {
		t.Fatal("disallowed params accepted")
	}
	// Hash mismatch.
	if res := stub.MockInvoke("tx-h", submitArgs("p1", "stmt-2026", strings.Repeat("00", 32), b64, "fast-insecure-test")); res.Status == 200 {
		t.Fatal("hash mismatch accepted")
	}
	// Bad hex hash.
	if res := stub.MockInvoke("tx-x", submitArgs("p1", "stmt-2026", "not-hex", b64, "fast-insecure-test")); res.Status == 200 {
		t.Fatal("non-hex hash accepted")
	}
	// Valid submit, then duplicate id.
	if res := stub.MockInvoke("tx-ok", submitArgs("p1", "stmt-2026", hashHex, b64, "fast-insecure-test")); res.Status != 200 {
		t.Fatalf("valid submit failed: %s", res.Message)
	}
	if res := stub.MockInvoke("tx-dup", submitArgs("p1", "stmt-2026", hashHex, b64, "fast-insecure-test")); res.Status == 200 {
		t.Fatal("duplicate proof id accepted")
	}
	res := stub.MockInvoke("tx-q", [][]byte{[]byte("QueryProof"), []byte("p1")})
	if res.Status != 200 || !strings.Contains(string(res.Payload), `"status":"PENDING"`) {
		t.Fatalf("expected PENDING proof, got: %s", res.Payload)
	}
}

func TestSubmitProofOversizeRejected(t *testing.T) {
	stub := newStub(t)
	mustRegister(t, stub)
	big := make([]byte, MaxEnvelopeBytes+1)
	sum := sha256.Sum256(big)
	if res := stub.MockInvoke("tx-big", submitArgs(
		"pbig", "stmt-2026",
		hex.EncodeToString(sum[:]),
		base64.StdEncoding.EncodeToString(big),
		"fast-insecure-test",
	)); res.Status == 200 {
		t.Fatal("oversize envelope accepted")
	}
}

func TestAttestVerificationGating(t *testing.T) {
	stub := newStub(t)
	mustRegister(t, stub)
	envelope := []byte("attested-bytes")
	sum := sha256.Sum256(envelope)
	hashHex := hex.EncodeToString(sum[:])
	b64 := base64.StdEncoding.EncodeToString(envelope)
	attest := func(tx, id, verdict, hash string) (int32, string) {
		res := stub.MockInvoke(tx, [][]byte{
			[]byte("AttestVerification"), []byte(id), []byte(verdict), []byte(hash), []byte("reason"),
		})
		return res.Status, res.Message
	}

	// Submit as anyone.
	asMSP(stub, "ClientMSP")
	if res := stub.MockInvoke("tx-s", submitArgs("p1", "stmt-2026", hashHex, b64, "fast-insecure-test")); res.Status != 200 {
		t.Fatalf("submit failed: %s", res.Message)
	}
	// Unauthorized MSP cannot attest.
	asMSP(stub, "EvilMSP")
	if st, msg := attest("tx-e1", "p1", VerdictVerified, hashHex); st == 200 {
		t.Fatal("unauthorized attestation accepted")
	} else if !strings.Contains(msg, "not an attester") {
		t.Fatalf("wrong rejection: %s", msg)
	}
	// Bad verdict value.
	asMSP(stub, "AttesterMSP")
	if st, _ := attest("tx-e2", "p1", "MAYBE", hashHex); st == 200 {
		t.Fatal("bad verdict accepted")
	}
	// Hash mismatch with anchored bytes.
	if st, _ := attest("tx-e3", "p1", VerdictVerified, strings.Repeat("00", 32)); st == 200 {
		t.Fatal("attestation hash mismatch accepted")
	}
	// Unknown proof.
	if st, _ := attest("tx-e4", "nope", VerdictVerified, hashHex); st == 200 {
		t.Fatal("attestation for unknown proof accepted")
	}
	// Valid rejection path.
	if st, msg := attest("tx-ok", "p1", VerdictRejected, hashHex); st != 200 {
		t.Fatalf("valid attestation failed: %s", msg)
	}
	res := stub.MockInvoke("tx-q", [][]byte{[]byte("QueryProof"), []byte("p1")})
	if res.Status != 200 || !strings.Contains(string(res.Payload), `"status":"REJECTED"`) {
		t.Fatalf("expected REJECTED proof, got: %s", res.Payload)
	}
	// No second attestation once decided.
	asMSP(stub, "AttesterMSP")
	if st, _ := attest("tx-e5", "p1", VerdictVerified, hashHex); st == 200 {
		t.Fatal("second attestation on decided proof accepted")
	}
}

func TestAttestVerifiedPathAndSingleAttesterRule(t *testing.T) {
	stub := newStub(t)
	mustRegister(t, stub)
	envelope := []byte("verified-bytes")
	sum := sha256.Sum256(envelope)
	asMSP(stub, "ClientMSP")
	if res := stub.MockInvoke("tx-s", submitArgs("p2", "stmt-2026", hex.EncodeToString(sum[:]),
		base64.StdEncoding.EncodeToString(envelope), "prototype-tau2")); res.Status != 200 {
		t.Fatalf("submit failed: %s", res.Message)
	}
	asMSP(stub, "AttesterMSP")
	if res := stub.MockInvoke("tx-a", [][]byte{
		[]byte("AttestVerification"), []byte("p2"), []byte(VerdictVerified),
		[]byte(hex.EncodeToString(sum[:])), []byte("rsp-attester ok"),
	}); res.Status != 200 {
		t.Fatalf("verified attestation failed: %s", res.Message)
	}
	res := stub.MockInvoke("tx-q", [][]byte{[]byte("QueryProof"), []byte("p2")})
	if res.Status != 200 {
		t.Fatalf("query failed: %s", res.Message)
	}
	if !strings.Contains(string(res.Payload), `"status":"VERIFIED"`) ||
		!strings.Contains(string(res.Payload), `"attesterMSP":"AttesterMSP"`) {
		t.Fatalf("unexpected record: %s", res.Payload)
	}
}
