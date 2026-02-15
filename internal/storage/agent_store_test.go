package storage

import (
	"fmt"
	"testing"
	"time"
)

// --- Test helpers ---

// seedOperator creates and returns a test operator.
func seedOperator(t *testing.T, db *DB) *Operator {
	t.Helper()
	op := &Operator{
		ID:          "op-001",
		PublicKey:   []byte("operator-pub-key"),
		Label:       "Test Operator",
		ApprovedBy:  "root",
		Reputation:  1.0,
		Quarantined: false,
		MaxAgents:   5,
		CreatedAt:   time.Now().Unix(),
	}
	if err := db.CreateOperator(op); err != nil {
		t.Fatalf("seedOperator: %v", err)
	}
	return op
}

// seedAgentKey seeds an operator and agent key, returning both.
func seedAgentKey(t *testing.T, db *DB) (*Operator, *AgentKey) {
	t.Helper()
	op := seedOperator(t, db)
	ak := &AgentKey{
		ID:         "ak-001",
		OperatorID: op.ID,
		PublicKey:  []byte("agent-pub-key"),
		Label:      "Test Agent",
		LastSeen:   time.Now().Unix(),
		CreatedAt:  time.Now().Unix(),
	}
	if err := db.CreateAgentKey(ak); err != nil {
		t.Fatalf("seedAgentKey: %v", err)
	}
	return op, ak
}

// --- Task 3: Operator CRUD tests ---

func TestCreateAndGetOperator(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	got, err := db.GetOperator(op.ID)
	if err != nil {
		t.Fatalf("GetOperator: %v", err)
	}
	if got.ID != op.ID {
		t.Errorf("ID = %q, want %q", got.ID, op.ID)
	}
	if string(got.PublicKey) != string(op.PublicKey) {
		t.Errorf("PublicKey mismatch")
	}
	if got.Label != op.Label {
		t.Errorf("Label = %q, want %q", got.Label, op.Label)
	}
	if got.ApprovedBy != op.ApprovedBy {
		t.Errorf("ApprovedBy = %q, want %q", got.ApprovedBy, op.ApprovedBy)
	}
	if got.Reputation != op.Reputation {
		t.Errorf("Reputation = %f, want %f", got.Reputation, op.Reputation)
	}
	if got.Quarantined != false {
		t.Errorf("Quarantined = %v, want false", got.Quarantined)
	}
	if got.MaxAgents != op.MaxAgents {
		t.Errorf("MaxAgents = %d, want %d", got.MaxAgents, op.MaxAgents)
	}
}

func TestGetOperatorByPublicKey(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	got, err := db.GetOperatorByPublicKey(op.PublicKey)
	if err != nil {
		t.Fatalf("GetOperatorByPublicKey: %v", err)
	}
	if got.ID != op.ID {
		t.Errorf("ID = %q, want %q", got.ID, op.ID)
	}
}

func TestListOperators(t *testing.T) {
	db := testDB(t)
	for i := 0; i < 3; i++ {
		op := &Operator{
			ID:         fmt.Sprintf("op-%03d", i),
			PublicKey:  []byte(fmt.Sprintf("pubkey-%d", i)),
			Label:      fmt.Sprintf("Operator %d", i),
			ApprovedBy: "root",
			MaxAgents:  5,
			CreatedAt:  time.Now().Unix(),
		}
		if err := db.CreateOperator(op); err != nil {
			t.Fatalf("CreateOperator[%d]: %v", i, err)
		}
	}

	ops, err := db.ListOperators()
	if err != nil {
		t.Fatalf("ListOperators: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("len = %d, want 3", len(ops))
	}
}

func TestQuarantineOperator(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	// Quarantine.
	if err := db.QuarantineOperator(op.ID, true); err != nil {
		t.Fatalf("QuarantineOperator(true): %v", err)
	}
	got, err := db.GetOperator(op.ID)
	if err != nil {
		t.Fatalf("GetOperator: %v", err)
	}
	if !got.Quarantined {
		t.Error("Quarantined = false after quarantine, want true")
	}

	// Un-quarantine.
	if err := db.QuarantineOperator(op.ID, false); err != nil {
		t.Fatalf("QuarantineOperator(false): %v", err)
	}
	got, err = db.GetOperator(op.ID)
	if err != nil {
		t.Fatalf("GetOperator: %v", err)
	}
	if got.Quarantined {
		t.Error("Quarantined = true after un-quarantine, want false")
	}
}

func TestUpdateOperatorReputation(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	if err := db.UpdateOperatorReputation(op.ID, 3.75); err != nil {
		t.Fatalf("UpdateOperatorReputation: %v", err)
	}
	got, err := db.GetOperator(op.ID)
	if err != nil {
		t.Fatalf("GetOperator: %v", err)
	}
	if got.Reputation != 3.75 {
		t.Errorf("Reputation = %f, want 3.75", got.Reputation)
	}
}

func TestDeleteOperator(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	// Create an agent key to verify cascade delete.
	ak := &AgentKey{
		ID:         "ak-cascade",
		OperatorID: op.ID,
		PublicKey:  []byte("ak-key"),
		Label:      "cascade test",
		CreatedAt:  time.Now().Unix(),
	}
	if err := db.CreateAgentKey(ak); err != nil {
		t.Fatalf("CreateAgentKey: %v", err)
	}

	if err := db.DeleteOperator(op.ID); err != nil {
		t.Fatalf("DeleteOperator: %v", err)
	}

	// Operator should be gone.
	_, err := db.GetOperator(op.ID)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}

	// Agent key should also be gone (cascade).
	_, err = db.GetAgentKey(ak.ID)
	if err == nil {
		t.Fatal("expected agent key to be deleted in cascade, got nil error")
	}
}

// --- Task 4: Agent Key CRUD tests ---

func TestCreateAndGetAgentKey(t *testing.T) {
	db := testDB(t)
	op, ak := seedAgentKey(t, db)

	got, err := db.GetAgentKey(ak.ID)
	if err != nil {
		t.Fatalf("GetAgentKey: %v", err)
	}
	if got.ID != ak.ID {
		t.Errorf("ID = %q, want %q", got.ID, ak.ID)
	}
	if got.OperatorID != op.ID {
		t.Errorf("OperatorID = %q, want %q", got.OperatorID, op.ID)
	}
	if string(got.PublicKey) != string(ak.PublicKey) {
		t.Errorf("PublicKey mismatch")
	}
	if got.Label != ak.Label {
		t.Errorf("Label = %q, want %q", got.Label, ak.Label)
	}
}

func TestGetAgentKeyByPublicKey(t *testing.T) {
	db := testDB(t)
	_, ak := seedAgentKey(t, db)

	got, err := db.GetAgentKeyByPublicKey(ak.PublicKey)
	if err != nil {
		t.Fatalf("GetAgentKeyByPublicKey: %v", err)
	}
	if got.ID != ak.ID {
		t.Errorf("ID = %q, want %q", got.ID, ak.ID)
	}
}

func TestListAgentKeysForOperator(t *testing.T) {
	db := testDB(t)
	op := seedOperator(t, db)

	for i := 0; i < 3; i++ {
		ak := &AgentKey{
			ID:         fmt.Sprintf("ak-%03d", i),
			OperatorID: op.ID,
			PublicKey:  []byte(fmt.Sprintf("ak-key-%d", i)),
			Label:      fmt.Sprintf("Agent %d", i),
			CreatedAt:  time.Now().Unix(),
		}
		if err := db.CreateAgentKey(ak); err != nil {
			t.Fatalf("CreateAgentKey[%d]: %v", i, err)
		}
	}

	keys, err := db.ListAgentKeysForOperator(op.ID)
	if err != nil {
		t.Fatalf("ListAgentKeysForOperator: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("len = %d, want 3", len(keys))
	}
}

func TestAgentCountEnforced(t *testing.T) {
	db := testDB(t)
	op := &Operator{
		ID:         "op-limited",
		PublicKey:  []byte("limited-key"),
		Label:      "Limited Operator",
		ApprovedBy: "root",
		MaxAgents:  1,
		CreatedAt:  time.Now().Unix(),
	}
	if err := db.CreateOperator(op); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}

	// First agent should succeed.
	ak1 := &AgentKey{
		ID:         "ak-first",
		OperatorID: op.ID,
		PublicKey:  []byte("first-key"),
		Label:      "First",
		CreatedAt:  time.Now().Unix(),
	}
	if err := db.CreateAgentKey(ak1); err != nil {
		t.Fatalf("CreateAgentKey(first): %v", err)
	}

	// Second agent should fail.
	ak2 := &AgentKey{
		ID:         "ak-second",
		OperatorID: op.ID,
		PublicKey:  []byte("second-key"),
		Label:      "Second",
		CreatedAt:  time.Now().Unix(),
	}
	err := db.CreateAgentKey(ak2)
	if err == nil {
		t.Fatal("expected error for exceeding max_agents, got nil")
	}
}

func TestUpdateAgentLastSeen(t *testing.T) {
	db := testDB(t)
	_, ak := seedAgentKey(t, db)

	newTime := time.Now().Add(time.Hour).Unix()
	if err := db.UpdateAgentLastSeen(ak.ID, newTime); err != nil {
		t.Fatalf("UpdateAgentLastSeen: %v", err)
	}

	got, err := db.GetAgentKey(ak.ID)
	if err != nil {
		t.Fatalf("GetAgentKey: %v", err)
	}
	if got.LastSeen != newTime {
		t.Errorf("LastSeen = %d, want %d", got.LastSeen, newTime)
	}
}

func TestDeleteAgentKey(t *testing.T) {
	db := testDB(t)
	_, ak := seedAgentKey(t, db)

	if err := db.DeleteAgentKey(ak.ID); err != nil {
		t.Fatalf("DeleteAgentKey: %v", err)
	}

	_, err := db.GetAgentKey(ak.ID)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}

// --- Task 5: Knowledge CRUD tests ---

func TestCreateAndQueryKnowledge(t *testing.T) {
	db := testDB(t)
	_, ak := seedAgentKey(t, db)

	entry := &KnowledgeEntry{
		ID:         "k-001",
		AgentID:    ak.ID,
		OperatorID: ak.OperatorID,
		Type:       KnowledgeObservation,
		Domain:     "security",
		Content:    "TLS 1.3 is recommended for all connections",
		Confidence: 0.9,
		CreatedAt:  time.Now().Unix(),
		Signature:  "sig-001",
	}
	if err := db.CreateKnowledgeEntry(entry); err != nil {
		t.Fatalf("CreateKnowledgeEntry: %v", err)
	}

	results, err := db.QueryKnowledge("security", "", nil, 0, 10)
	if err != nil {
		t.Fatalf("QueryKnowledge: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len = %d, want 1", len(results))
	}
	if results[0].ID != entry.ID {
		t.Errorf("ID = %q, want %q", results[0].ID, entry.ID)
	}
	if results[0].Content != entry.Content {
		t.Errorf("Content mismatch")
	}
}

func TestQueryKnowledgeByText(t *testing.T) {
	db := testDB(t)
	_, ak := seedAgentKey(t, db)

	entries := []*KnowledgeEntry{
		{
			ID: "k-text-1", AgentID: ak.ID, OperatorID: ak.OperatorID,
			Type: KnowledgeObservation, Domain: "networking",
			Content: "TCP uses three-way handshake", Confidence: 0.8,
			CreatedAt: time.Now().Unix(), Signature: "sig-t1",
		},
		{
			ID: "k-text-2", AgentID: ak.ID, OperatorID: ak.OperatorID,
			Type: KnowledgeObservation, Domain: "crypto",
			Content: "AES-256 uses 14 rounds of encryption", Confidence: 0.85,
			CreatedAt: time.Now().Unix(), Signature: "sig-t2",
		},
	}
	for _, e := range entries {
		if err := db.CreateKnowledgeEntry(e); err != nil {
			t.Fatalf("CreateKnowledgeEntry(%s): %v", e.ID, err)
		}
	}

	// Query by text — only the TCP entry should match.
	results, err := db.QueryKnowledge("", "handshake", nil, 0, 10)
	if err != nil {
		t.Fatalf("QueryKnowledge: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len = %d, want 1", len(results))
	}
	if results[0].ID != "k-text-1" {
		t.Errorf("ID = %q, want k-text-1", results[0].ID)
	}
}

func TestQueryKnowledgeMinConfidence(t *testing.T) {
	db := testDB(t)
	_, ak := seedAgentKey(t, db)

	entries := []*KnowledgeEntry{
		{
			ID: "k-low", AgentID: ak.ID, OperatorID: ak.OperatorID,
			Type: KnowledgeObservation, Domain: "general",
			Content: "Low confidence entry", Confidence: 0.3,
			CreatedAt: time.Now().Unix(), Signature: "sig-low",
		},
		{
			ID: "k-high", AgentID: ak.ID, OperatorID: ak.OperatorID,
			Type: KnowledgeObservation, Domain: "general",
			Content: "High confidence entry", Confidence: 0.9,
			CreatedAt: time.Now().Unix(), Signature: "sig-high",
		},
	}
	for _, e := range entries {
		if err := db.CreateKnowledgeEntry(e); err != nil {
			t.Fatalf("CreateKnowledgeEntry(%s): %v", e.ID, err)
		}
	}

	results, err := db.QueryKnowledge("", "", nil, 0.5, 10)
	if err != nil {
		t.Fatalf("QueryKnowledge: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len = %d, want 1", len(results))
	}
	if results[0].ID != "k-high" {
		t.Errorf("ID = %q, want k-high", results[0].ID)
	}
}

func TestDeleteKnowledgeEntry(t *testing.T) {
	db := testDB(t)
	_, ak := seedAgentKey(t, db)

	entry := &KnowledgeEntry{
		ID: "k-del", AgentID: ak.ID, OperatorID: ak.OperatorID,
		Type: KnowledgeObservation, Domain: "test",
		Content: "To be deleted", Confidence: 0.5,
		CreatedAt: time.Now().Unix(), Signature: "sig-del",
	}
	if err := db.CreateKnowledgeEntry(entry); err != nil {
		t.Fatalf("CreateKnowledgeEntry: %v", err)
	}

	if err := db.DeleteKnowledgeEntry(entry.ID, ak.ID); err != nil {
		t.Fatalf("DeleteKnowledgeEntry: %v", err)
	}

	_, err := db.GetKnowledgeEntry(entry.ID)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}

func TestUpdateKnowledgeVotes(t *testing.T) {
	db := testDB(t)
	_, ak := seedAgentKey(t, db)

	entry := &KnowledgeEntry{
		ID: "k-votes", AgentID: ak.ID, OperatorID: ak.OperatorID,
		Type: KnowledgeObservation, Domain: "test",
		Content: "Votable entry", Confidence: 0.7,
		CreatedAt: time.Now().Unix(), Signature: "sig-votes",
	}
	if err := db.CreateKnowledgeEntry(entry); err != nil {
		t.Fatalf("CreateKnowledgeEntry: %v", err)
	}

	if err := db.UpdateKnowledgeVotes(entry.ID, 10, 3); err != nil {
		t.Fatalf("UpdateKnowledgeVotes: %v", err)
	}

	got, err := db.GetKnowledgeEntry(entry.ID)
	if err != nil {
		t.Fatalf("GetKnowledgeEntry: %v", err)
	}
	if got.VotesUp != 10 {
		t.Errorf("VotesUp = %d, want 10", got.VotesUp)
	}
	if got.VotesDown != 3 {
		t.Errorf("VotesDown = %d, want 3", got.VotesDown)
	}
}

func TestListKnowledgeDomains(t *testing.T) {
	db := testDB(t)
	_, ak := seedAgentKey(t, db)

	entries := []*KnowledgeEntry{
		{
			ID: "k-d1a", AgentID: ak.ID, OperatorID: ak.OperatorID,
			Type: KnowledgeObservation, Domain: "security",
			Content: "Entry 1a", Confidence: 0.8,
			CreatedAt: time.Now().Unix(), Signature: "sig-d1a",
		},
		{
			ID: "k-d1b", AgentID: ak.ID, OperatorID: ak.OperatorID,
			Type: KnowledgeObservation, Domain: "security",
			Content: "Entry 1b", Confidence: 0.6,
			CreatedAt: time.Now().Unix(), Signature: "sig-d1b",
		},
		{
			ID: "k-d2", AgentID: ak.ID, OperatorID: ak.OperatorID,
			Type: KnowledgeObservation, Domain: "networking",
			Content: "Entry 2", Confidence: 0.9,
			CreatedAt: time.Now().Unix(), Signature: "sig-d2",
		},
		{
			ID: "k-d3", AgentID: ak.ID, OperatorID: ak.OperatorID,
			Type: KnowledgeObservation, Domain: "crypto",
			Content: "Entry 3", Confidence: 0.7,
			CreatedAt: time.Now().Unix(), Signature: "sig-d3",
		},
	}
	for _, e := range entries {
		if err := db.CreateKnowledgeEntry(e); err != nil {
			t.Fatalf("CreateKnowledgeEntry(%s): %v", e.ID, err)
		}
	}

	domains, err := db.ListKnowledgeDomains()
	if err != nil {
		t.Fatalf("ListKnowledgeDomains: %v", err)
	}
	if len(domains) != 3 {
		t.Fatalf("len = %d, want 3", len(domains))
	}

	// First domain should be "security" (count=2).
	if domains[0].Domain != "security" {
		t.Errorf("domains[0].Domain = %q, want security", domains[0].Domain)
	}
	if domains[0].Count != 2 {
		t.Errorf("domains[0].Count = %d, want 2", domains[0].Count)
	}
}

func TestPruneExpiredKnowledge(t *testing.T) {
	db := testDB(t)
	_, ak := seedAgentKey(t, db)

	ttl := int64(100)
	entry := &KnowledgeEntry{
		ID: "k-expire", AgentID: ak.ID, OperatorID: ak.OperatorID,
		Type: KnowledgeObservation, Domain: "test",
		Content: "Expiring entry", Confidence: 0.5,
		TTL: &ttl, CreatedAt: 1000,
		Signature: "sig-expire",
	}
	if err := db.CreateKnowledgeEntry(entry); err != nil {
		t.Fatalf("CreateKnowledgeEntry: %v", err)
	}

	// Prune with now = 1200 (1000 + 100 < 1200), should delete.
	n, err := db.PruneExpiredKnowledge(1200)
	if err != nil {
		t.Fatalf("PruneExpiredKnowledge: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}

	_, err = db.GetKnowledgeEntry(entry.ID)
	if err == nil {
		t.Fatal("expected error after prune, got nil")
	}
}

// --- Task 6: Compute Task, Vote, Provenance, Awareness, Anomaly Log tests ---

func TestCreateAndClaimComputeTask(t *testing.T) {
	db := testDB(t)

	task := &ComputeTask{
		ID:          "ct-001",
		Type:        TaskSynthesize,
		Domain:      "security",
		Description: "Synthesize security observations",
		Priority:    7,
		CreatedAt:   time.Now().Unix(),
	}
	if err := db.CreateComputeTask(task); err != nil {
		t.Fatalf("CreateComputeTask: %v", err)
	}

	claimed, err := db.ClaimComputeTask([]string{TaskSynthesize}, []string{"security"}, "agent-1")
	if err != nil {
		t.Fatalf("ClaimComputeTask: %v", err)
	}
	if claimed == nil {
		t.Fatal("ClaimComputeTask returned nil, expected task")
	}
	if claimed.ClaimedBy != "agent-1" {
		t.Errorf("ClaimedBy = %q, want agent-1", claimed.ClaimedBy)
	}
	if claimed.ClaimedAt == 0 {
		t.Error("ClaimedAt = 0, expected non-zero")
	}
}

func TestClaimComputeTaskNoneAvailable(t *testing.T) {
	db := testDB(t)

	claimed, err := db.ClaimComputeTask([]string{TaskVerify}, []string{"any"}, "agent-1")
	if err != nil {
		t.Fatalf("ClaimComputeTask: %v", err)
	}
	if claimed != nil {
		t.Fatalf("expected nil, got task %q", claimed.ID)
	}
}

func TestCompleteComputeTask(t *testing.T) {
	db := testDB(t)

	task := &ComputeTask{
		ID:          "ct-complete",
		Type:        TaskVerify,
		Domain:      "crypto",
		Description: "Verify crypto knowledge",
		Priority:    5,
		CreatedAt:   time.Now().Unix(),
	}
	if err := db.CreateComputeTask(task); err != nil {
		t.Fatalf("CreateComputeTask: %v", err)
	}

	// Claim it.
	claimed, err := db.ClaimComputeTask([]string{TaskVerify}, []string{"crypto"}, "agent-2")
	if err != nil {
		t.Fatalf("ClaimComputeTask: %v", err)
	}
	if claimed == nil {
		t.Fatal("ClaimComputeTask returned nil")
	}

	// Complete it.
	if err := db.CompleteComputeTask(claimed.ID, "result-42"); err != nil {
		t.Fatalf("CompleteComputeTask: %v", err)
	}

	got, err := db.GetComputeTask(claimed.ID)
	if err != nil {
		t.Fatalf("GetComputeTask: %v", err)
	}
	if !got.Completed {
		t.Error("Completed = false, want true")
	}
	if got.ResultID != "result-42" {
		t.Errorf("ResultID = %q, want result-42", got.ResultID)
	}
}

func TestCommitRevealVote(t *testing.T) {
	db := testDB(t)

	v := &Vote{
		ID:          "vote-001",
		EntryID:     "entry-001",
		OperatorID:  "op-001",
		Commitment:  "hash-of-vote",
		Phase:       VotePhaseCommit,
		CommittedAt: time.Now().Unix(),
	}
	if err := db.CreateVote(v); err != nil {
		t.Fatalf("CreateVote: %v", err)
	}

	// Verify commit phase.
	got, err := db.GetVote(v.ID)
	if err != nil {
		t.Fatalf("GetVote: %v", err)
	}
	if got.Phase != VotePhaseCommit {
		t.Errorf("Phase = %q, want commit", got.Phase)
	}

	// Reveal.
	voteVal := 1
	if err := db.RevealVote(v.ID, &voteVal, "nonce-123", "I agree because data supports it"); err != nil {
		t.Fatalf("RevealVote: %v", err)
	}

	got, err = db.GetVote(v.ID)
	if err != nil {
		t.Fatalf("GetVote after reveal: %v", err)
	}
	if got.Phase != VotePhaseRevealed {
		t.Errorf("Phase = %q, want revealed", got.Phase)
	}
	if got.VoteValue == nil {
		t.Fatal("VoteValue is nil after reveal")
	}
	if *got.VoteValue != 1 {
		t.Errorf("VoteValue = %d, want 1", *got.VoteValue)
	}
	if got.Nonce != "nonce-123" {
		t.Errorf("Nonce = %q, want nonce-123", got.Nonce)
	}
	if got.Reason != "I agree because data supports it" {
		t.Errorf("Reason mismatch")
	}
	if got.RevealedAt == 0 {
		t.Error("RevealedAt = 0, expected non-zero")
	}
}

func TestDuplicateVoteBlocked(t *testing.T) {
	db := testDB(t)

	v := &Vote{
		ID:          "vote-dup-1",
		EntryID:     "entry-dup",
		OperatorID:  "op-dup",
		Commitment:  "commitment-1",
		Phase:       VotePhaseCommit,
		CommittedAt: time.Now().Unix(),
	}
	if err := db.CreateVote(v); err != nil {
		t.Fatalf("CreateVote: %v", err)
	}

	// Duplicate with same entry_id + operator_id should fail.
	v2 := &Vote{
		ID:          "vote-dup-2",
		EntryID:     "entry-dup",
		OperatorID:  "op-dup",
		Commitment:  "commitment-2",
		Phase:       VotePhaseCommit,
		CommittedAt: time.Now().Unix(),
	}
	err := db.CreateVote(v2)
	if err == nil {
		t.Fatal("expected UNIQUE constraint error for duplicate vote, got nil")
	}
}

func TestGetVotesForEntry(t *testing.T) {
	db := testDB(t)

	for i := 0; i < 3; i++ {
		v := &Vote{
			ID:          fmt.Sprintf("vote-list-%d", i),
			EntryID:     "entry-list",
			OperatorID:  fmt.Sprintf("op-%d", i),
			Commitment:  fmt.Sprintf("commit-%d", i),
			Phase:       VotePhaseCommit,
			CommittedAt: time.Now().Unix(),
		}
		if err := db.CreateVote(v); err != nil {
			t.Fatalf("CreateVote[%d]: %v", i, err)
		}
	}

	votes, err := db.GetVotesForEntry("entry-list")
	if err != nil {
		t.Fatalf("GetVotesForEntry: %v", err)
	}
	if len(votes) != 3 {
		t.Fatalf("len = %d, want 3", len(votes))
	}
}

func TestProvenanceChain(t *testing.T) {
	db := testDB(t)

	if err := db.CreateProvenance("entry-A", "source-1"); err != nil {
		t.Fatalf("CreateProvenance(1): %v", err)
	}
	if err := db.CreateProvenance("entry-A", "source-2"); err != nil {
		t.Fatalf("CreateProvenance(2): %v", err)
	}

	sources, err := db.GetProvenance("entry-A")
	if err != nil {
		t.Fatalf("GetProvenance: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("len = %d, want 2", len(sources))
	}

	// Verify both sources are present.
	found := map[string]bool{}
	for _, s := range sources {
		found[s] = true
	}
	if !found["source-1"] || !found["source-2"] {
		t.Errorf("sources = %v, want [source-1, source-2]", sources)
	}
}

func TestProvenanceIdempotent(t *testing.T) {
	db := testDB(t)

	// INSERT OR IGNORE should not error on duplicate.
	if err := db.CreateProvenance("entry-B", "source-1"); err != nil {
		t.Fatalf("CreateProvenance(1): %v", err)
	}
	if err := db.CreateProvenance("entry-B", "source-1"); err != nil {
		t.Fatalf("CreateProvenance(duplicate): %v", err)
	}

	sources, err := db.GetProvenance("entry-B")
	if err != nil {
		t.Fatalf("GetProvenance: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("len = %d, want 1 (duplicate should be ignored)", len(sources))
	}
}

func TestAwarenessSnapshot(t *testing.T) {
	db := testDB(t)

	snap := &AwarenessSnapshot{
		ID:          "aware-001",
		Snapshot:    `{"domains":["security","crypto"],"total_entries":42}`,
		GeneratedBy: "agent-001",
		CreatedAt:   time.Now().Unix(),
	}
	if err := db.CreateAwarenessSnapshot(snap); err != nil {
		t.Fatalf("CreateAwarenessSnapshot: %v", err)
	}

	got, err := db.GetLatestAwareness()
	if err != nil {
		t.Fatalf("GetLatestAwareness: %v", err)
	}
	if got.ID != snap.ID {
		t.Errorf("ID = %q, want %q", got.ID, snap.ID)
	}
	if got.Snapshot != snap.Snapshot {
		t.Errorf("Snapshot mismatch")
	}
	if got.GeneratedBy != snap.GeneratedBy {
		t.Errorf("GeneratedBy = %q, want %q", got.GeneratedBy, snap.GeneratedBy)
	}
}

func TestAwarenessSnapshotLatest(t *testing.T) {
	db := testDB(t)

	// Create two snapshots, verify latest is returned.
	snap1 := &AwarenessSnapshot{
		ID: "aware-old", Snapshot: "old", GeneratedBy: "agent-1",
		CreatedAt: 1000,
	}
	snap2 := &AwarenessSnapshot{
		ID: "aware-new", Snapshot: "new", GeneratedBy: "agent-2",
		CreatedAt: 2000,
	}
	if err := db.CreateAwarenessSnapshot(snap1); err != nil {
		t.Fatalf("CreateAwarenessSnapshot(old): %v", err)
	}
	if err := db.CreateAwarenessSnapshot(snap2); err != nil {
		t.Fatalf("CreateAwarenessSnapshot(new): %v", err)
	}

	got, err := db.GetLatestAwareness()
	if err != nil {
		t.Fatalf("GetLatestAwareness: %v", err)
	}
	if got.ID != "aware-new" {
		t.Errorf("ID = %q, want aware-new (latest)", got.ID)
	}
}

func TestCreateAnomalyLog(t *testing.T) {
	db := testDB(t)

	log := &AnomalyLog{
		ID:          "anom-001",
		OperatorID:  "op-001",
		Type:        "rate_limit_exceeded",
		Evidence:    "100 requests in 10 seconds",
		ActionTaken: "throttled",
		CreatedAt:   time.Now().Unix(),
	}
	if err := db.CreateAnomalyLog(log); err != nil {
		t.Fatalf("CreateAnomalyLog: %v", err)
	}

	logs, err := db.ListAnomalyLogs("op-001")
	if err != nil {
		t.Fatalf("ListAnomalyLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("len = %d, want 1", len(logs))
	}
	if logs[0].ID != log.ID {
		t.Errorf("ID = %q, want %q", logs[0].ID, log.ID)
	}
	if logs[0].Type != log.Type {
		t.Errorf("Type = %q, want %q", logs[0].Type, log.Type)
	}
}

func TestListAnomalyLogsAll(t *testing.T) {
	db := testDB(t)

	for i := 0; i < 3; i++ {
		log := &AnomalyLog{
			ID:          fmt.Sprintf("anom-%03d", i),
			OperatorID:  fmt.Sprintf("op-%03d", i),
			Type:        "test",
			Evidence:    "evidence",
			ActionTaken: "none",
			CreatedAt:   time.Now().Unix(),
		}
		if err := db.CreateAnomalyLog(log); err != nil {
			t.Fatalf("CreateAnomalyLog[%d]: %v", i, err)
		}
	}

	// List all (empty operatorID).
	logs, err := db.ListAnomalyLogs("")
	if err != nil {
		t.Fatalf("ListAnomalyLogs: %v", err)
	}
	if len(logs) != 3 {
		t.Fatalf("len = %d, want 3", len(logs))
	}
}
