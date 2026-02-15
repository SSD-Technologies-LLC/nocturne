package storage

import (
	"fmt"
	"testing"
	"time"
)

// --- Test helpers ---

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
		t.Fatalf("CreateAgentKey: %v", err)
	}

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
		t.Fatalf("CreateAgentKey: %v", err)
	}

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
		t.Fatalf("CreateAgentKey: %v", err)
	}

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
	op := seedOperator(t, db)

	ak := &AgentKey{
		ID:         "ak-001",
		OperatorID: op.ID,
		PublicKey:  []byte("agent-pub-key"),
		Label:      "Test Agent",
		CreatedAt:  time.Now().Unix(),
	}
	if err := db.CreateAgentKey(ak); err != nil {
		t.Fatalf("CreateAgentKey: %v", err)
	}

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
