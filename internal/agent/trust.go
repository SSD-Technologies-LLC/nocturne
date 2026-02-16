package agent

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

// Genesis is the embedded founding configuration for the Web of Trust.
// It defines the initial set of trusted operators and the rules for
// admitting new operators via endorsement.
type Genesis struct {
	Version             int               `json:"version"`
	MinEndorsements     int               `json:"min_endorsements"`
	RevocationThreshold int               `json:"revocation_threshold"`
	Operators           []GenesisOperator `json:"operators"`
}

// GenesisOperator is a founding operator embedded in the genesis configuration.
type GenesisOperator struct {
	PublicKey ed25519.PublicKey `json:"public_key"`
	Label     string           `json:"label"`
}

// Endorsement is a signed approval of a new operator by an existing trusted operator.
type Endorsement struct {
	EndorserID string `json:"endorser_id"`
	Signature  string `json:"signature"` // hex-encoded Ed25519 signature
	Timestamp  int64  `json:"timestamp"`
}

// TrustCertificate proves an operator has sufficient endorsements to participate
// in the mesh network. It bundles the operator's identity with the endorsements
// that vouch for them.
type TrustCertificate struct {
	OperatorID   string           `json:"operator_id"`
	PublicKey    ed25519.PublicKey `json:"public_key"`
	Label        string           `json:"label"`
	Endorsements []Endorsement    `json:"endorsements"`
	MaxAgents    int              `json:"max_agents"`
	CreatedAt    int64            `json:"created_at"`
}

// RevocationCertificate proves an operator has been revoked by N trusted operators.
type RevocationCertificate struct {
	TargetOperatorID string                `json:"target_operator_id"`
	Reason           string                `json:"reason"`
	Signatures       []RevocationSignature `json:"signatures"`
	CreatedAt        int64                 `json:"created_at"`
}

// RevocationSignature is a single operator's signed vote to revoke another operator.
type RevocationSignature struct {
	OperatorID string `json:"operator_id"`
	Signature  string `json:"signature"` // hex-encoded Ed25519 sig
	Timestamp  int64  `json:"timestamp"`
}

// TrustValidator validates trust certificates against genesis configuration
// and the set of known trusted operators.
type TrustValidator struct {
	genesis            *Genesis
	trustedOperators   map[string]ed25519.PublicKey // operatorID -> pubkey
	revokedOperators   map[string]bool              // operatorID -> revoked
}

// maxTrustDepth is the maximum recursion depth for transitive trust chains.
const maxTrustDepth = 3

// IsPlaceholderKey reports whether key is the all-zero placeholder genesis key.
func IsPlaceholderKey(key ed25519.PublicKey) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}

// DefaultGenesis returns a genesis config with SSD Technologies as the founding
// operator. When the NOCTURNE_GENESIS_KEY environment variable is set to a valid
// hex-encoded 32-byte Ed25519 public key, that key is used. Otherwise a
// placeholder all-zero key is used and a warning is logged.
func DefaultGenesis() *Genesis {
	var genesisKey ed25519.PublicKey

	if envKey := os.Getenv("NOCTURNE_GENESIS_KEY"); envKey != "" {
		decoded, err := hex.DecodeString(envKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			log.Printf("WARNING: NOCTURNE_GENESIS_KEY is invalid (expected %d hex bytes), using placeholder", ed25519.PublicKeySize)
			genesisKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
		} else {
			genesisKey = ed25519.PublicKey(decoded)
		}
	} else {
		log.Println("WARNING: NOCTURNE_GENESIS_KEY not set, using placeholder (unsafe for production)")
		genesisKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	}

	return &Genesis{
		Version:             1,
		MinEndorsements:     3,
		RevocationThreshold: 3,
		Operators: []GenesisOperator{
			{
				PublicKey: genesisKey,
				Label:     "SSD Technologies",
			},
		},
	}
}

// endorsementMessage constructs the canonical message that is signed for an
// endorsement: "ENDORSE:" + hex(targetPubKey) + ":" + timestamp.
func endorsementMessage(targetPubKey ed25519.PublicKey, timestamp int64) []byte {
	msg := "ENDORSE:" + hex.EncodeToString(targetPubKey) + ":" + strconv.FormatInt(timestamp, 10)
	return []byte(msg)
}

// CreateEndorsement signs an endorsement of targetPubKey using the endorser's
// private key. The endorsement message format is:
//
//	"ENDORSE:" + hex(targetPubKey) + ":" + strconv.FormatInt(timestamp, 10)
func CreateEndorsement(endorserPriv ed25519.PrivateKey, targetPubKey ed25519.PublicKey, timestamp int64) (*Endorsement, error) {
	if len(endorserPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid endorser private key length: %d", len(endorserPriv))
	}
	if len(targetPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid target public key length: %d", len(targetPubKey))
	}

	msg := endorsementMessage(targetPubKey, timestamp)
	sig := ed25519.Sign(endorserPriv, msg)

	endorserPub := endorserPriv.Public().(ed25519.PublicKey)
	endorserID := AgentIDFromPublicKey(endorserPub)

	return &Endorsement{
		EndorserID: endorserID,
		Signature:  hex.EncodeToString(sig),
		Timestamp:  timestamp,
	}, nil
}

// VerifyEndorsement verifies that the endorsement signature is valid for
// the given endorser public key and target public key.
func VerifyEndorsement(e *Endorsement, endorserPub ed25519.PublicKey, targetPub ed25519.PublicKey) error {
	if e == nil {
		return fmt.Errorf("nil endorsement")
	}

	sig, err := hex.DecodeString(e.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	msg := endorsementMessage(targetPub, e.Timestamp)
	if !ed25519.Verify(endorserPub, msg, sig) {
		return fmt.Errorf("endorsement signature verification failed")
	}

	return nil
}

// NewTrustValidator creates a validator seeded with genesis operators.
// All genesis operators are immediately trusted.
func NewTrustValidator(genesis *Genesis) *TrustValidator {
	v := &TrustValidator{
		genesis:          genesis,
		trustedOperators: make(map[string]ed25519.PublicKey),
		revokedOperators: make(map[string]bool),
	}

	for _, op := range genesis.Operators {
		id := AgentIDFromPublicKey(op.PublicKey)
		v.trustedOperators[id] = op.PublicKey
	}

	return v
}

// ValidateCertificate checks that a trust certificate has enough valid
// endorsements from trusted operators. Returns nil if the certificate is valid,
// or an error describing why it is not.
func (v *TrustValidator) ValidateCertificate(cert *TrustCertificate) error {
	return v.validateCertificateAtDepth(cert, 0)
}

// validateCertificateAtDepth performs certificate validation with depth tracking
// to prevent infinite trust chain recursion. Maximum depth is maxTrustDepth.
func (v *TrustValidator) validateCertificateAtDepth(cert *TrustCertificate, depth int) error {
	if cert == nil {
		return fmt.Errorf("nil certificate")
	}

	if depth > maxTrustDepth {
		return fmt.Errorf("trust chain exceeds maximum depth of %d", maxTrustDepth)
	}

	validEndorsements := 0
	seen := make(map[string]bool) // deduplicate endorsers

	for _, e := range cert.Endorsements {
		// Each endorser may only count once.
		if seen[e.EndorserID] {
			continue
		}

		// Revoked operators cannot endorse.
		if v.revokedOperators[e.EndorserID] {
			continue
		}

		endorserPub, trusted := v.trustedOperators[e.EndorserID]
		if !trusted {
			continue
		}

		if err := VerifyEndorsement(&e, endorserPub, cert.PublicKey); err != nil {
			continue
		}

		seen[e.EndorserID] = true
		validEndorsements++
	}

	if validEndorsements < v.genesis.MinEndorsements {
		return fmt.Errorf("insufficient endorsements: got %d valid, need %d",
			validEndorsements, v.genesis.MinEndorsements)
	}

	return nil
}

// AddTrustedOperator adds a validated operator to the trusted set. This should
// only be called after ValidateCertificate succeeds.
func (v *TrustValidator) AddTrustedOperator(cert *TrustCertificate) {
	v.trustedOperators[cert.OperatorID] = cert.PublicKey
}

// IsTrusted returns whether an operator ID is in the trusted set and not revoked.
func (v *TrustValidator) IsTrusted(operatorID string) bool {
	if v.revokedOperators[operatorID] {
		return false
	}
	_, ok := v.trustedOperators[operatorID]
	return ok
}

// TrustedOperatorCount returns the number of operators in the trusted set.
func (v *TrustValidator) TrustedOperatorCount() int {
	return len(v.trustedOperators)
}

// NewTrustCertificate creates a new trust certificate for an operator.
func NewTrustCertificate(pub ed25519.PublicKey, label string, maxAgents int, endorsements []Endorsement) *TrustCertificate {
	return &TrustCertificate{
		OperatorID:   AgentIDFromPublicKey(pub),
		PublicKey:    pub,
		Label:        label,
		Endorsements: endorsements,
		MaxAgents:    maxAgents,
		CreatedAt:    time.Now().Unix(),
	}
}

// revocationMessage constructs the canonical message that is signed for a
// revocation: "REVOKE:" + targetOperatorID + ":" + reason + ":" + timestamp.
func revocationMessage(targetOperatorID, reason string, timestamp int64) []byte {
	msg := "REVOKE:" + targetOperatorID + ":" + reason + ":" + strconv.FormatInt(timestamp, 10)
	return []byte(msg)
}

// CreateRevocationSignature signs a revocation vote against targetOperatorID.
// The signed message format is:
//
//	"REVOKE:" + targetOperatorID + ":" + reason + ":" + strconv.FormatInt(timestamp, 10)
func CreateRevocationSignature(signerPriv ed25519.PrivateKey, targetOperatorID, reason string, timestamp int64) (*RevocationSignature, error) {
	if len(signerPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid signer private key length: %d", len(signerPriv))
	}
	if targetOperatorID == "" {
		return nil, fmt.Errorf("target operator ID is empty")
	}

	msg := revocationMessage(targetOperatorID, reason, timestamp)
	sig := ed25519.Sign(signerPriv, msg)

	signerPub := signerPriv.Public().(ed25519.PublicKey)
	signerID := AgentIDFromPublicKey(signerPub)

	return &RevocationSignature{
		OperatorID: signerID,
		Signature:  hex.EncodeToString(sig),
		Timestamp:  timestamp,
	}, nil
}

// ValidateRevocation checks that a revocation certificate is valid:
//  1. Each signer must be a trusted (and non-revoked) operator.
//  2. Each signature must cryptographically verify against the signer's public key.
//  3. The number of valid, unique signatures must meet genesis.RevocationThreshold.
//  4. The target cannot sign their own revocation (self-revocation is rejected).
func (v *TrustValidator) ValidateRevocation(rev *RevocationCertificate) error {
	if rev == nil {
		return fmt.Errorf("nil revocation certificate")
	}

	validSigs := 0
	seen := make(map[string]bool) // deduplicate signers

	for _, rs := range rev.Signatures {
		// Each signer may only count once.
		if seen[rs.OperatorID] {
			continue
		}

		// Target cannot revoke themselves.
		if rs.OperatorID == rev.TargetOperatorID {
			continue
		}

		// Signer must be trusted and not revoked.
		if v.revokedOperators[rs.OperatorID] {
			continue
		}
		signerPub, trusted := v.trustedOperators[rs.OperatorID]
		if !trusted {
			continue
		}

		// Verify the cryptographic signature.
		sigBytes, err := hex.DecodeString(rs.Signature)
		if err != nil {
			continue
		}

		msg := revocationMessage(rev.TargetOperatorID, rev.Reason, rs.Timestamp)
		if !ed25519.Verify(signerPub, msg, sigBytes) {
			continue
		}

		seen[rs.OperatorID] = true
		validSigs++
	}

	if validSigs < v.genesis.RevocationThreshold {
		return fmt.Errorf("insufficient revocation signatures: got %d valid, need %d",
			validSigs, v.genesis.RevocationThreshold)
	}

	return nil
}

// RevokeOperator removes an operator from the trusted set by marking them as
// revoked. After revocation, IsTrusted returns false and endorsements from the
// operator are no longer counted.
func (v *TrustValidator) RevokeOperator(operatorID string) {
	v.revokedOperators[operatorID] = true
}

// IsRevoked returns whether an operator has been revoked.
func (v *TrustValidator) IsRevoked(operatorID string) bool {
	return v.revokedOperators[operatorID]
}
