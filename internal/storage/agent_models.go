// internal/storage/agent_models.go
package storage

// Knowledge entry types.
const (
	KnowledgeObservation = "observation"
	KnowledgeSynthesis   = "synthesis"
	KnowledgeCorrection  = "correction"
	KnowledgeReflection  = "reflection"
)

// Compute task types.
const (
	TaskSynthesize  = "synthesize"
	TaskVerify      = "verify"
	TaskConsolidate = "consolidate"
	TaskReflect     = "reflect"
	TaskFillGap     = "fill_gap"
)

// Vote phases.
const (
	VotePhaseCommit   = "commit"
	VotePhaseRevealed = "revealed"
	VotePhaseExpired  = "expired"
)

// Operator represents a registered operator in the agent network.
type Operator struct {
	ID           string  `json:"id"`
	PublicKey    []byte  `json:"public_key"`
	Label        string  `json:"label"`
	ApprovedBy   string  `json:"approved_by"`
	Reputation   float64 `json:"reputation"`
	Quarantined  bool    `json:"quarantined"`
	MaxAgents    int     `json:"max_agents"`
	CreatedAt    int64   `json:"created_at"`
}

// AgentKey represents an agent's key pair registered under an operator.
type AgentKey struct {
	ID         string `json:"id"`
	OperatorID string `json:"operator_id"`
	PublicKey  []byte `json:"public_key"`
	Label      string `json:"label"`
	LastSeen   int64  `json:"last_seen"`
	CreatedAt  int64  `json:"created_at"`
}

// KnowledgeEntry represents a piece of knowledge contributed by an agent.
type KnowledgeEntry struct {
	ID         string  `json:"id"`
	AgentID    string  `json:"agent_id"`
	OperatorID string  `json:"operator_id"`
	Type       string  `json:"type"`
	Domain     string  `json:"domain"`
	Content    string  `json:"content"`
	Confidence float64 `json:"confidence"`
	Sources    string  `json:"sources"`
	Supersedes string  `json:"supersedes"`
	VotesUp    int     `json:"votes_up"`
	VotesDown  int     `json:"votes_down"`
	VerifiedBy string  `json:"verified_by"`
	TTL        *int64  `json:"ttl,omitempty"`
	CreatedAt  int64   `json:"created_at"`
	Signature  string  `json:"signature"`
}

// ComputeTask represents a task to be claimed and executed by an agent.
type ComputeTask struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Domain      string `json:"domain"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
	ClaimedBy   string `json:"claimed_by"`
	ClaimedAt   int64  `json:"claimed_at"`
	Completed   bool   `json:"completed"`
	ResultID    string `json:"result_id"`
	VerifiedBy  string `json:"verified_by"`
	CreatedAt   int64  `json:"created_at"`
}

// Vote represents a commit-reveal vote on a knowledge entry.
type Vote struct {
	ID          string `json:"id"`
	EntryID     string `json:"entry_id"`
	OperatorID  string `json:"operator_id"`
	Commitment  string `json:"commitment"`
	VoteValue   *int   `json:"vote_value,omitempty"`
	Nonce       string `json:"nonce"`
	Reason      string `json:"reason"`
	Phase       string `json:"phase"`
	CommittedAt int64  `json:"committed_at"`
	RevealedAt  int64  `json:"revealed_at"`
}

// Provenance links a knowledge entry to its source entries.
type Provenance struct {
	EntryID  string `json:"entry_id"`
	SourceID string `json:"source_id"`
}

// AwarenessSnapshot captures the state of the knowledge graph at a point in time.
type AwarenessSnapshot struct {
	ID          string `json:"id"`
	Snapshot    string `json:"snapshot"`
	GeneratedBy string `json:"generated_by"`
	CreatedAt   int64  `json:"created_at"`
}

// AnomalyLog records detected anomalies and actions taken.
type AnomalyLog struct {
	ID          string `json:"id"`
	OperatorID  string `json:"operator_id"`
	Type        string `json:"type"`
	Evidence    string `json:"evidence"`
	ActionTaken string `json:"action_taken"`
	CreatedAt   int64  `json:"created_at"`
}
