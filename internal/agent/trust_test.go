package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

// generateTestKey is a helper that generates an Ed25519 key pair for tests.
func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// makeGenesisWithKeys creates a genesis config with the given key pairs as
// founding operators, using min endorsements of minE.
func makeGenesisWithKeys(t *testing.T, keys []ed25519.PublicKey, minE int) *Genesis {
	t.Helper()
	ops := make([]GenesisOperator, len(keys))
	for i, pub := range keys {
		ops[i] = GenesisOperator{PublicKey: pub, Label: "test-operator-" + AgentIDFromPublicKey(pub)[:6]}
	}
	return &Genesis{
		Version:             1,
		MinEndorsements:     minE,
		RevocationThreshold: minE,
		Operators:           ops,
	}
}

func TestDefaultGenesis(t *testing.T) {
	g := DefaultGenesis()

	if g.Version != 1 {
		t.Errorf("Version = %d, want 1", g.Version)
	}
	if g.MinEndorsements != 3 {
		t.Errorf("MinEndorsements = %d, want 3", g.MinEndorsements)
	}
	if g.RevocationThreshold != 3 {
		t.Errorf("RevocationThreshold = %d, want 3", g.RevocationThreshold)
	}
	if len(g.Operators) != 1 {
		t.Fatalf("Operators count = %d, want 1", len(g.Operators))
	}
	if g.Operators[0].Label != "SSD Technologies" {
		t.Errorf("Operator label = %q, want %q", g.Operators[0].Label, "SSD Technologies")
	}
	if len(g.Operators[0].PublicKey) != ed25519.PublicKeySize {
		t.Errorf("Operator public key length = %d, want %d", len(g.Operators[0].PublicKey), ed25519.PublicKeySize)
	}
}

func TestCreateEndorsement(t *testing.T) {
	_, endorserPriv := generateTestKey(t)
	targetPub, _ := generateTestKey(t)
	ts := time.Now().Unix()

	e, err := CreateEndorsement(endorserPriv, targetPub, ts)
	if err != nil {
		t.Fatalf("CreateEndorsement: %v", err)
	}

	if e.EndorserID == "" {
		t.Error("EndorserID is empty")
	}
	if e.Signature == "" {
		t.Error("Signature is empty")
	}
	if e.Timestamp != ts {
		t.Errorf("Timestamp = %d, want %d", e.Timestamp, ts)
	}

	// Signature must be valid hex
	sigBytes, err := hex.DecodeString(e.Signature)
	if err != nil {
		t.Fatalf("Signature is not valid hex: %v", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		t.Errorf("Signature length = %d, want %d", len(sigBytes), ed25519.SignatureSize)
	}

	// EndorserID must match the endorser's public key
	endorserPub := endorserPriv.Public().(ed25519.PublicKey)
	expectedID := AgentIDFromPublicKey(endorserPub)
	if e.EndorserID != expectedID {
		t.Errorf("EndorserID = %q, want %q", e.EndorserID, expectedID)
	}
}

func TestVerifyEndorsement(t *testing.T) {
	endorserPub, endorserPriv := generateTestKey(t)
	targetPub, _ := generateTestKey(t)
	ts := time.Now().Unix()

	e, err := CreateEndorsement(endorserPriv, targetPub, ts)
	if err != nil {
		t.Fatalf("CreateEndorsement: %v", err)
	}

	if err := VerifyEndorsement(e, endorserPub, targetPub); err != nil {
		t.Fatalf("VerifyEndorsement: %v", err)
	}
}

func TestVerifyEndorsementRejectsTampered(t *testing.T) {
	_, endorserPriv := generateTestKey(t)
	targetPub, _ := generateTestKey(t)
	ts := time.Now().Unix()

	e, err := CreateEndorsement(endorserPriv, targetPub, ts)
	if err != nil {
		t.Fatalf("CreateEndorsement: %v", err)
	}

	// Verify with a different (wrong) endorser public key
	wrongPub, _ := generateTestKey(t)
	err = VerifyEndorsement(e, wrongPub, targetPub)
	if err == nil {
		t.Fatal("expected error for tampered endorser pubkey, got nil")
	}
}

func TestVerifyEndorsementRejectsWrongTarget(t *testing.T) {
	endorserPub, endorserPriv := generateTestKey(t)
	targetPub, _ := generateTestKey(t)
	ts := time.Now().Unix()

	e, err := CreateEndorsement(endorserPriv, targetPub, ts)
	if err != nil {
		t.Fatalf("CreateEndorsement: %v", err)
	}

	// Verify against a different target public key
	wrongTargetPub, _ := generateTestKey(t)
	err = VerifyEndorsement(e, endorserPub, wrongTargetPub)
	if err == nil {
		t.Fatal("expected error for wrong target pubkey, got nil")
	}
}

func TestTrustCertificateValidation(t *testing.T) {
	// Create 3 genesis operators
	pub1, priv1 := generateTestKey(t)
	pub2, priv2 := generateTestKey(t)
	pub3, priv3 := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3}, 3)
	v := NewTrustValidator(genesis)

	// New operator to be endorsed
	newPub, _ := generateTestKey(t)
	ts := time.Now().Unix()

	// All 3 genesis operators endorse the new operator
	e1, err := CreateEndorsement(priv1, newPub, ts)
	if err != nil {
		t.Fatalf("endorsement 1: %v", err)
	}
	e2, err := CreateEndorsement(priv2, newPub, ts)
	if err != nil {
		t.Fatalf("endorsement 2: %v", err)
	}
	e3, err := CreateEndorsement(priv3, newPub, ts)
	if err != nil {
		t.Fatalf("endorsement 3: %v", err)
	}

	cert := NewTrustCertificate(newPub, "new-operator", 10, []Endorsement{*e1, *e2, *e3})

	if err := v.ValidateCertificate(cert); err != nil {
		t.Fatalf("ValidateCertificate: %v", err)
	}
}

func TestTrustCertificateRejectsInsufficientEndorsements(t *testing.T) {
	pub1, priv1 := generateTestKey(t)
	pub2, _ := generateTestKey(t)
	pub3, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3}, 3)
	v := NewTrustValidator(genesis)

	// New operator to be endorsed — only 1 endorsement when 3 needed
	newPub, _ := generateTestKey(t)
	ts := time.Now().Unix()

	e1, err := CreateEndorsement(priv1, newPub, ts)
	if err != nil {
		t.Fatalf("endorsement: %v", err)
	}

	cert := NewTrustCertificate(newPub, "under-endorsed", 10, []Endorsement{*e1})

	err = v.ValidateCertificate(cert)
	if err == nil {
		t.Fatal("expected error for insufficient endorsements, got nil")
	}
}

func TestTrustCertificateRejectsUnknownEndorser(t *testing.T) {
	pub1, _ := generateTestKey(t)
	pub2, _ := generateTestKey(t)
	pub3, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3}, 3)
	v := NewTrustValidator(genesis)

	// Create endorsements from unknown (non-genesis) operators
	_, unknownPriv1 := generateTestKey(t)
	_, unknownPriv2 := generateTestKey(t)
	_, unknownPriv3 := generateTestKey(t)

	newPub, _ := generateTestKey(t)
	ts := time.Now().Unix()

	e1, _ := CreateEndorsement(unknownPriv1, newPub, ts)
	e2, _ := CreateEndorsement(unknownPriv2, newPub, ts)
	e3, _ := CreateEndorsement(unknownPriv3, newPub, ts)

	cert := NewTrustCertificate(newPub, "unknown-endorsers", 10, []Endorsement{*e1, *e2, *e3})

	err := v.ValidateCertificate(cert)
	if err == nil {
		t.Fatal("expected error for unknown endorsers, got nil")
	}
}

func TestAddTrustedOperator(t *testing.T) {
	pub1, priv1 := generateTestKey(t)
	pub2, priv2 := generateTestKey(t)
	pub3, priv3 := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3}, 3)
	v := NewTrustValidator(genesis)

	// New operator
	newPub, _ := generateTestKey(t)
	newID := AgentIDFromPublicKey(newPub)
	ts := time.Now().Unix()

	// Before adding: not trusted
	if v.IsTrusted(newID) {
		t.Fatal("new operator should not be trusted before adding")
	}

	// Create endorsements and certificate
	e1, _ := CreateEndorsement(priv1, newPub, ts)
	e2, _ := CreateEndorsement(priv2, newPub, ts)
	e3, _ := CreateEndorsement(priv3, newPub, ts)
	cert := NewTrustCertificate(newPub, "newly-trusted", 10, []Endorsement{*e1, *e2, *e3})

	// Validate and add
	if err := v.ValidateCertificate(cert); err != nil {
		t.Fatalf("ValidateCertificate: %v", err)
	}
	v.AddTrustedOperator(cert)

	// After adding: trusted
	if !v.IsTrusted(newID) {
		t.Fatal("new operator should be trusted after adding")
	}
}

func TestTransitiveTrust(t *testing.T) {
	// 3 genesis operators
	pub1, priv1 := generateTestKey(t)
	pub2, priv2 := generateTestKey(t)
	pub3, priv3 := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3}, 3)
	v := NewTrustValidator(genesis)

	// Operator A: endorsed by all 3 genesis operators
	pubA, privA := generateTestKey(t)
	ts := time.Now().Unix()

	eA1, _ := CreateEndorsement(priv1, pubA, ts)
	eA2, _ := CreateEndorsement(priv2, pubA, ts)
	eA3, _ := CreateEndorsement(priv3, pubA, ts)
	certA := NewTrustCertificate(pubA, "operator-A", 10, []Endorsement{*eA1, *eA2, *eA3})

	if err := v.ValidateCertificate(certA); err != nil {
		t.Fatalf("validate cert A: %v", err)
	}
	v.AddTrustedOperator(certA)

	// Operator B: endorsed by operator A (transitively trusted) + 2 genesis operators
	pubB, _ := generateTestKey(t)

	eBfromA, _ := CreateEndorsement(privA, pubB, ts)
	eBfrom2, _ := CreateEndorsement(priv2, pubB, ts)
	eBfrom3, _ := CreateEndorsement(priv3, pubB, ts)
	certB := NewTrustCertificate(pubB, "operator-B", 5, []Endorsement{*eBfromA, *eBfrom2, *eBfrom3})

	if err := v.ValidateCertificate(certB); err != nil {
		t.Fatalf("validate cert B (transitive): %v", err)
	}
}

func TestTransitiveTrustMaxDepth(t *testing.T) {
	// Build a chain of trust that exceeds maxTrustDepth (3).
	// We need: genesis -> op1 -> op2 -> op3 -> op4 (depth 4, should fail).
	//
	// Strategy: use minEndorsements=1 so each link in the chain only needs
	// one endorsement. The validator tracks depth via the trusted set: each
	// operator in the chain is added after validation, so the chain length
	// is really about whether the endorser is in the trusted set, not about
	// recursion depth per se.
	//
	// The maxTrustDepth in the spec limits how far the validator will go to
	// validate a chain. We test this by NOT adding intermediate operators to
	// the trusted set, forcing the validator to resolve the chain recursively.
	//
	// Since our current implementation doesn't do recursive resolution (it only
	// checks the trusted set), a chain deeper than maxTrustDepth where
	// intermediate nodes are NOT in the trusted set will fail because the
	// endorsers are unknown.
	//
	// To properly test: build a long chain, only add operators up to depth 3,
	// and verify the 4th-hop operator's cert can be validated (since all its
	// endorsers are in the trusted set), but if we remove the depth-3 operator,
	// validation fails.

	// Single genesis operator, minEndorsements = 1 for simplicity
	genPub, genPriv := generateTestKey(t)
	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{genPub}, 1)
	v := NewTrustValidator(genesis)

	ts := time.Now().Unix()

	// Chain: genesis -> op1 -> op2 -> op3 -> op4
	prevPriv := genPriv

	// Build chain of 4 hops
	var chainPubs []ed25519.PublicKey
	var chainPrivs []ed25519.PrivateKey
	for i := 0; i < 4; i++ {
		pub, priv := generateTestKey(t)
		chainPubs = append(chainPubs, pub)
		chainPrivs = append(chainPrivs, priv)

		e, _ := CreateEndorsement(prevPriv, pub, ts)
		cert := NewTrustCertificate(pub, "chain-"+string(rune('A'+i)), 5, []Endorsement{*e})

		err := v.ValidateCertificate(cert)
		if err != nil {
			// Each hop should validate because we add the previous one to the
			// trusted set. The first 3 hops (depth 0-2) should all succeed.
			// Hop 4 should also succeed if all intermediates are trusted.
			// This validates the chain works up to the max depth.
			if i <= maxTrustDepth {
				t.Fatalf("hop %d should validate but got: %v", i, err)
			}
		}
		if err == nil {
			v.AddTrustedOperator(cert)
		}

		prevPriv = priv
	}

	// Now test that an operator endorsed ONLY by non-trusted endorsers fails.
	// Create a fresh validator with only genesis, and try to validate an operator
	// endorsed only by chain operator 3 (who is not in the fresh validator's
	// trusted set).
	freshValidator := NewTrustValidator(genesis)
	deepPub, _ := generateTestKey(t)
	eDeep, _ := CreateEndorsement(chainPrivs[3], deepPub, ts)
	deepCert := NewTrustCertificate(deepPub, "too-deep", 5, []Endorsement{*eDeep})

	err := freshValidator.ValidateCertificate(deepCert)
	if err == nil {
		t.Fatal("expected error for endorser not in trusted set (simulating depth > max), got nil")
	}
}

func TestIsTrustedForGenesisOperators(t *testing.T) {
	pub1, _ := generateTestKey(t)
	pub2, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2}, 2)
	v := NewTrustValidator(genesis)

	// Genesis operators should be trusted immediately
	if !v.IsTrusted(AgentIDFromPublicKey(pub1)) {
		t.Error("genesis operator 1 should be trusted")
	}
	if !v.IsTrusted(AgentIDFromPublicKey(pub2)) {
		t.Error("genesis operator 2 should be trusted")
	}

	// Random key should not be trusted
	randomPub, _ := generateTestKey(t)
	if v.IsTrusted(AgentIDFromPublicKey(randomPub)) {
		t.Error("random key should not be trusted")
	}
}

func TestVerifyEndorsementRejectsNil(t *testing.T) {
	pub, _ := generateTestKey(t)
	err := VerifyEndorsement(nil, pub, pub)
	if err == nil {
		t.Fatal("expected error for nil endorsement, got nil")
	}
}

func TestValidateCertificateRejectsNil(t *testing.T) {
	genesis := DefaultGenesis()
	v := NewTrustValidator(genesis)

	err := v.ValidateCertificate(nil)
	if err == nil {
		t.Fatal("expected error for nil certificate, got nil")
	}
}

func TestTrustedOperatorCount(t *testing.T) {
	pub1, priv1 := generateTestKey(t)
	pub2, priv2 := generateTestKey(t)
	pub3, priv3 := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3}, 3)
	v := NewTrustValidator(genesis)

	if v.TrustedOperatorCount() != 3 {
		t.Errorf("TrustedOperatorCount = %d, want 3", v.TrustedOperatorCount())
	}

	// Add one more
	newPub, _ := generateTestKey(t)
	ts := time.Now().Unix()
	e1, _ := CreateEndorsement(priv1, newPub, ts)
	e2, _ := CreateEndorsement(priv2, newPub, ts)
	e3, _ := CreateEndorsement(priv3, newPub, ts)
	cert := NewTrustCertificate(newPub, "new-op", 10, []Endorsement{*e1, *e2, *e3})

	if err := v.ValidateCertificate(cert); err != nil {
		t.Fatalf("validate: %v", err)
	}
	v.AddTrustedOperator(cert)

	if v.TrustedOperatorCount() != 4 {
		t.Errorf("TrustedOperatorCount = %d, want 4", v.TrustedOperatorCount())
	}
}

func TestNewTrustCertificate(t *testing.T) {
	pub, _ := generateTestKey(t)
	endorsements := []Endorsement{
		{EndorserID: "abc", Signature: "def", Timestamp: 123},
	}

	cert := NewTrustCertificate(pub, "test-label", 15, endorsements)

	if cert.OperatorID != AgentIDFromPublicKey(pub) {
		t.Errorf("OperatorID = %q, want %q", cert.OperatorID, AgentIDFromPublicKey(pub))
	}
	if cert.Label != "test-label" {
		t.Errorf("Label = %q, want %q", cert.Label, "test-label")
	}
	if cert.MaxAgents != 15 {
		t.Errorf("MaxAgents = %d, want 15", cert.MaxAgents)
	}
	if len(cert.Endorsements) != 1 {
		t.Errorf("Endorsements count = %d, want 1", len(cert.Endorsements))
	}
	if cert.CreatedAt == 0 {
		t.Error("CreatedAt should be non-zero")
	}
}

func TestMixedValidAndInvalidEndorsements(t *testing.T) {
	// 3 genesis operators, need 3 endorsements.
	// Provide 2 valid + 1 from unknown endorser = should fail.
	pub1, priv1 := generateTestKey(t)
	pub2, priv2 := generateTestKey(t)
	pub3, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3}, 3)
	v := NewTrustValidator(genesis)

	newPub, _ := generateTestKey(t)
	ts := time.Now().Unix()

	e1, _ := CreateEndorsement(priv1, newPub, ts)
	e2, _ := CreateEndorsement(priv2, newPub, ts)

	// Third endorsement from an unknown key
	_, unknownPriv := generateTestKey(t)
	e3, _ := CreateEndorsement(unknownPriv, newPub, ts)

	cert := NewTrustCertificate(newPub, "mixed", 10, []Endorsement{*e1, *e2, *e3})

	err := v.ValidateCertificate(cert)
	if err == nil {
		t.Fatal("expected error when only 2 of 3 endorsements are from trusted operators")
	}
}

// --- Revocation Certificate Tests ---

func TestCreateRevocationSignature(t *testing.T) {
	_, signerPriv := generateTestKey(t)
	targetPub, _ := generateTestKey(t)
	targetID := AgentIDFromPublicKey(targetPub)
	ts := time.Now().Unix()

	rs, err := CreateRevocationSignature(signerPriv, targetID, "compromised key", ts)
	if err != nil {
		t.Fatalf("CreateRevocationSignature: %v", err)
	}

	if rs.OperatorID == "" {
		t.Error("OperatorID is empty")
	}
	if rs.Signature == "" {
		t.Error("Signature is empty")
	}
	if rs.Timestamp != ts {
		t.Errorf("Timestamp = %d, want %d", rs.Timestamp, ts)
	}

	// Signature must be valid hex.
	sigBytes, err := hex.DecodeString(rs.Signature)
	if err != nil {
		t.Fatalf("Signature is not valid hex: %v", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		t.Errorf("Signature length = %d, want %d", len(sigBytes), ed25519.SignatureSize)
	}

	// OperatorID must match the signer's public key.
	signerPub := signerPriv.Public().(ed25519.PublicKey)
	expectedID := AgentIDFromPublicKey(signerPub)
	if rs.OperatorID != expectedID {
		t.Errorf("OperatorID = %q, want %q", rs.OperatorID, expectedID)
	}
}

func TestValidateRevocation(t *testing.T) {
	// 4 genesis operators: 3 will sign the revocation of the 4th.
	pub1, priv1 := generateTestKey(t)
	pub2, priv2 := generateTestKey(t)
	pub3, priv3 := generateTestKey(t)
	pubTarget, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3, pubTarget}, 3)
	v := NewTrustValidator(genesis)

	targetID := AgentIDFromPublicKey(pubTarget)
	ts := time.Now().Unix()
	reason := "key compromise"

	rs1, err := CreateRevocationSignature(priv1, targetID, reason, ts)
	if err != nil {
		t.Fatalf("sig 1: %v", err)
	}
	rs2, err := CreateRevocationSignature(priv2, targetID, reason, ts)
	if err != nil {
		t.Fatalf("sig 2: %v", err)
	}
	rs3, err := CreateRevocationSignature(priv3, targetID, reason, ts)
	if err != nil {
		t.Fatalf("sig 3: %v", err)
	}

	rev := &RevocationCertificate{
		TargetOperatorID: targetID,
		Reason:           reason,
		Signatures:       []RevocationSignature{*rs1, *rs2, *rs3},
		CreatedAt:        ts,
	}

	if err := v.ValidateRevocation(rev); err != nil {
		t.Fatalf("ValidateRevocation: %v", err)
	}
}

func TestValidateRevocationInsufficientSignatures(t *testing.T) {
	pub1, priv1 := generateTestKey(t)
	pub2, _ := generateTestKey(t)
	pub3, _ := generateTestKey(t)
	pubTarget, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3, pubTarget}, 3)
	v := NewTrustValidator(genesis)

	targetID := AgentIDFromPublicKey(pubTarget)
	ts := time.Now().Unix()
	reason := "policy violation"

	// Only 1 signer when 3 needed.
	rs1, err := CreateRevocationSignature(priv1, targetID, reason, ts)
	if err != nil {
		t.Fatalf("sig: %v", err)
	}

	rev := &RevocationCertificate{
		TargetOperatorID: targetID,
		Reason:           reason,
		Signatures:       []RevocationSignature{*rs1},
		CreatedAt:        ts,
	}

	err = v.ValidateRevocation(rev)
	if err == nil {
		t.Fatal("expected error for insufficient revocation signatures, got nil")
	}
}

func TestValidateRevocationUntrustedSigner(t *testing.T) {
	pub1, _ := generateTestKey(t)
	pub2, _ := generateTestKey(t)
	pub3, _ := generateTestKey(t)
	pubTarget, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3, pubTarget}, 3)
	v := NewTrustValidator(genesis)

	targetID := AgentIDFromPublicKey(pubTarget)
	ts := time.Now().Unix()
	reason := "untrusted test"

	// All signers are unknown (not in the trusted set).
	_, unknownPriv1 := generateTestKey(t)
	_, unknownPriv2 := generateTestKey(t)
	_, unknownPriv3 := generateTestKey(t)

	rs1, _ := CreateRevocationSignature(unknownPriv1, targetID, reason, ts)
	rs2, _ := CreateRevocationSignature(unknownPriv2, targetID, reason, ts)
	rs3, _ := CreateRevocationSignature(unknownPriv3, targetID, reason, ts)

	rev := &RevocationCertificate{
		TargetOperatorID: targetID,
		Reason:           reason,
		Signatures:       []RevocationSignature{*rs1, *rs2, *rs3},
		CreatedAt:        ts,
	}

	err := v.ValidateRevocation(rev)
	if err == nil {
		t.Fatal("expected error for untrusted signers, got nil")
	}
}

func TestRevokeOperator(t *testing.T) {
	pub1, _ := generateTestKey(t)
	pub2, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2}, 1)
	v := NewTrustValidator(genesis)

	targetID := AgentIDFromPublicKey(pub1)

	// Before revocation: trusted.
	if !v.IsTrusted(targetID) {
		t.Fatal("operator should be trusted before revocation")
	}

	v.RevokeOperator(targetID)

	// After revocation: not trusted.
	if v.IsTrusted(targetID) {
		t.Fatal("operator should not be trusted after revocation")
	}
	if !v.IsRevoked(targetID) {
		t.Fatal("operator should be marked as revoked")
	}
}

func TestRevokedOperatorCannotEndorse(t *testing.T) {
	// 4 genesis operators, min endorsements = 3.
	pub1, priv1 := generateTestKey(t)
	pub2, priv2 := generateTestKey(t)
	pub3, priv3 := generateTestKey(t)
	pub4, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3, pub4}, 3)
	v := NewTrustValidator(genesis)

	// Revoke operator 3.
	id3 := AgentIDFromPublicKey(pub3)
	v.RevokeOperator(id3)

	// Now try to get a certificate endorsed by ops 1, 2, and 3 (3 is revoked).
	newPub, _ := generateTestKey(t)
	ts := time.Now().Unix()

	e1, _ := CreateEndorsement(priv1, newPub, ts)
	e2, _ := CreateEndorsement(priv2, newPub, ts)
	e3, _ := CreateEndorsement(priv3, newPub, ts) // revoked endorser

	cert := NewTrustCertificate(newPub, "endorsed-by-revoked", 10, []Endorsement{*e1, *e2, *e3})

	err := v.ValidateCertificate(cert)
	if err == nil {
		t.Fatal("expected error: endorsement from revoked operator should not count")
	}
}

func TestSelfRevocationRejected(t *testing.T) {
	// Target tries to sign their own revocation. Even if they are trusted,
	// the self-signature must not count.
	pub1, priv1 := generateTestKey(t)
	pub2, priv2 := generateTestKey(t)
	pubTarget, privTarget := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pubTarget}, 3)
	v := NewTrustValidator(genesis)

	targetID := AgentIDFromPublicKey(pubTarget)
	ts := time.Now().Unix()
	reason := "self-revoke attempt"

	// 2 valid + 1 self-signature = only 2 valid, need 3.
	rs1, _ := CreateRevocationSignature(priv1, targetID, reason, ts)
	rs2, _ := CreateRevocationSignature(priv2, targetID, reason, ts)
	rsSelf, _ := CreateRevocationSignature(privTarget, targetID, reason, ts)

	rev := &RevocationCertificate{
		TargetOperatorID: targetID,
		Reason:           reason,
		Signatures:       []RevocationSignature{*rs1, *rs2, *rsSelf},
		CreatedAt:        ts,
	}

	err := v.ValidateRevocation(rev)
	if err == nil {
		t.Fatal("expected error: self-revocation signature should not count toward threshold")
	}
}

func TestIsRevokedDefaultFalse(t *testing.T) {
	genesis := DefaultGenesis()
	v := NewTrustValidator(genesis)

	// An operator that has never been seen should not be reported as revoked.
	randomPub, _ := generateTestKey(t)
	randomID := AgentIDFromPublicKey(randomPub)

	if v.IsRevoked(randomID) {
		t.Fatal("unknown operator should not be reported as revoked")
	}
}

func TestRevocationDoesNotAffectGenesis(t *testing.T) {
	// Genesis operators are not immune to revocation. When a genesis operator
	// is revoked, they lose trust like any other operator.
	pub1, _ := generateTestKey(t)
	pub2, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2}, 1)
	v := NewTrustValidator(genesis)

	genesisID := AgentIDFromPublicKey(pub1)

	// Initially trusted.
	if !v.IsTrusted(genesisID) {
		t.Fatal("genesis operator should initially be trusted")
	}

	// Revoke the genesis operator.
	v.RevokeOperator(genesisID)

	// No longer trusted.
	if v.IsTrusted(genesisID) {
		t.Fatal("revoked genesis operator should not be trusted")
	}
	if !v.IsRevoked(genesisID) {
		t.Fatal("revoked genesis operator should be marked as revoked")
	}
}

func TestDuplicateEndorsementsFromSameOperator(t *testing.T) {
	// If the same genesis operator endorses twice, it should count twice
	// (the validator doesn't deduplicate — this tests current behavior).
	// However, depending on security requirements, this could be changed.
	pub1, priv1 := generateTestKey(t)
	pub2, _ := generateTestKey(t)
	pub3, _ := generateTestKey(t)

	genesis := makeGenesisWithKeys(t, []ed25519.PublicKey{pub1, pub2, pub3}, 3)
	v := NewTrustValidator(genesis)

	newPub, _ := generateTestKey(t)
	ts := time.Now().Unix()

	// Same operator endorses 3 times
	e1, _ := CreateEndorsement(priv1, newPub, ts)
	e2, _ := CreateEndorsement(priv1, newPub, ts+1)
	e3, _ := CreateEndorsement(priv1, newPub, ts+2)

	cert := NewTrustCertificate(newPub, "dup-endorser", 10, []Endorsement{*e1, *e2, *e3})

	// Duplicate endorsements from the same operator must be deduplicated.
	// Only distinct endorsers should count toward the threshold.
	err := v.ValidateCertificate(cert)
	if err == nil {
		t.Fatal("expected error: duplicate endorsements from same operator should be deduplicated")
	}
}

func TestDefaultGenesis_EnvironmentVariable(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	hexKey := hex.EncodeToString(pub)
	t.Setenv("NOCTURNE_GENESIS_KEY", hexKey)
	g := DefaultGenesis()
	if len(g.Operators) != 1 {
		t.Fatalf("operators = %d, want 1", len(g.Operators))
	}
	if !bytes.Equal(g.Operators[0].PublicKey, pub) {
		t.Error("genesis public key should match env var")
	}
}

func TestDefaultGenesis_PlaceholderWhenUnset(t *testing.T) {
	t.Setenv("NOCTURNE_GENESIS_KEY", "")
	g := DefaultGenesis()
	if !IsPlaceholderKey(g.Operators[0].PublicKey) {
		t.Error("should be placeholder when env var is empty")
	}
}

func TestIsPlaceholderKey(t *testing.T) {
	zero := make(ed25519.PublicKey, ed25519.PublicKeySize)
	if !IsPlaceholderKey(zero) {
		t.Error("all-zero key should be placeholder")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if IsPlaceholderKey(pub) {
		t.Error("real key should not be placeholder")
	}
}
