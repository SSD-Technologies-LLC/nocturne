package agent

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
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

// TrustValidator validates trust certificates against genesis configuration
// and the set of known trusted operators.
type TrustValidator struct {
	genesis          *Genesis
	trustedOperators map[string]ed25519.PublicKey // operatorID -> pubkey
}

// maxTrustDepth is the maximum recursion depth for transitive trust chains.
const maxTrustDepth = 3

// DefaultGenesis returns a genesis config with SSD Technologies as the founding
// operator. The public key is a placeholder; the real key will be set at build time.
func DefaultGenesis() *Genesis {
	// Placeholder key: 32 zero bytes. Replaced at build time with the real
	// SSD Technologies operator key.
	placeholderKey := make(ed25519.PublicKey, ed25519.PublicKeySize)

	return &Genesis{
		Version:             1,
		MinEndorsements:     3,
		RevocationThreshold: 3,
		Operators: []GenesisOperator{
			{
				PublicKey: placeholderKey,
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

// IsTrusted returns whether an operator ID is in the trusted set.
func (v *TrustValidator) IsTrusted(operatorID string) bool {
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
