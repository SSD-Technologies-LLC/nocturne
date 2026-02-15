package server

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

func TestContributionFloodDetection(t *testing.T) {
	db := setupTestDB(t)
	srv := New(db, "test-secret")

	// Create operator.
	opID := uuid.New().String()
	if err := db.CreateOperator(&storage.Operator{
		ID:         opID,
		PublicKey:  []byte("flood-op-key"),
		Label:      "flood-test-op",
		ApprovedBy: "admin",
		Reputation: 5.0,
		MaxAgents:  5,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	// Create agent key.
	agentID := uuid.New().String()
	if err := db.CreateAgentKey(&storage.AgentKey{
		ID:         agentID,
		OperatorID: opID,
		PublicKey:  []byte("flood-agent-key"),
		Label:      "flood-test-agent",
		LastSeen:   time.Now().Unix(),
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create agent key: %v", err)
	}

	// Create 51 knowledge entries for this operator (above threshold of 50).
	now := time.Now().Unix()
	for i := 0; i < 51; i++ {
		entry := &storage.KnowledgeEntry{
			ID:         uuid.New().String(),
			AgentID:    agentID,
			OperatorID: opID,
			Type:       storage.KnowledgeObservation,
			Domain:     "flood.test",
			Content:    "flood entry",
			Confidence: 0.5,
			CreatedAt:  now,
			Signature:  "sig",
		}
		if err := db.CreateKnowledgeEntry(entry); err != nil {
			t.Fatalf("create knowledge entry %d: %v", i, err)
		}
	}

	// Run anomaly detection.
	n := srv.detectAnomalies()
	if n != 1 {
		t.Fatalf("anomalies = %d, want 1", n)
	}

	// Verify operator is quarantined.
	op, err := db.GetOperator(opID)
	if err != nil {
		t.Fatalf("get operator: %v", err)
	}
	if !op.Quarantined {
		t.Error("expected operator to be quarantined")
	}

	// Verify anomaly log was created.
	logs, err := db.ListAnomalyLogs(opID)
	if err != nil {
		t.Fatalf("list anomaly logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("anomaly logs = %d, want 1", len(logs))
	}
	if logs[0].Type != "contribution_flood" {
		t.Errorf("anomaly type = %q, want %q", logs[0].Type, "contribution_flood")
	}
	if logs[0].ActionTaken != "auto_quarantine" {
		t.Errorf("action taken = %q, want %q", logs[0].ActionTaken, "auto_quarantine")
	}
}

func TestVoteBurstDetection(t *testing.T) {
	db := setupTestDB(t)
	srv := New(db, "test-secret")

	// Create operator.
	opID := uuid.New().String()
	if err := db.CreateOperator(&storage.Operator{
		ID:         opID,
		PublicKey:  []byte("vote-burst-op-key"),
		Label:      "vote-burst-op",
		ApprovedBy: "admin",
		Reputation: 5.0,
		MaxAgents:  5,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	// Create agent and a knowledge entry for the votes to reference.
	agentID := uuid.New().String()
	if err := db.CreateAgentKey(&storage.AgentKey{
		ID:         agentID,
		OperatorID: opID,
		PublicKey:  []byte("vote-burst-agent-key"),
		Label:      "vote-burst-agent",
		LastSeen:   time.Now().Unix(),
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create agent key: %v", err)
	}

	// We need a second operator to own the knowledge entries (votes reference entry_id
	// but the unique constraint is on (entry_id, operator_id)), so we'll create
	// separate entries for each vote.
	now := time.Now().Unix()

	// Create 31 votes from this operator (above threshold of 30).
	// Each vote needs a unique (entry_id, operator_id) pair.
	// Create entries first, then vote on each.
	for i := 0; i < 31; i++ {
		entryID := uuid.New().String()
		entry := &storage.KnowledgeEntry{
			ID:         entryID,
			AgentID:    agentID,
			OperatorID: opID,
			Type:       storage.KnowledgeObservation,
			Domain:     "vote.test",
			Content:    "vote target entry",
			Confidence: 0.5,
			CreatedAt:  now,
			Signature:  "sig",
		}
		if err := db.CreateKnowledgeEntry(entry); err != nil {
			t.Fatalf("create knowledge entry %d: %v", i, err)
		}

		vote := &storage.Vote{
			ID:          uuid.New().String(),
			EntryID:     entryID,
			OperatorID:  opID,
			Commitment:  "commit-hash",
			Phase:       storage.VotePhaseCommit,
			CommittedAt: now,
		}
		if err := db.CreateVote(vote); err != nil {
			t.Fatalf("create vote %d: %v", i, err)
		}
	}

	// Run anomaly detection.
	n := srv.detectAnomalies()
	if n != 1 {
		t.Fatalf("anomalies = %d, want 1", n)
	}

	// Verify operator is quarantined.
	op, err := db.GetOperator(opID)
	if err != nil {
		t.Fatalf("get operator: %v", err)
	}
	if !op.Quarantined {
		t.Error("expected operator to be quarantined")
	}

	// Verify anomaly log type.
	logs, err := db.ListAnomalyLogs(opID)
	if err != nil {
		t.Fatalf("list anomaly logs: %v", err)
	}
	if len(logs) < 1 {
		t.Fatal("expected at least one anomaly log")
	}

	// Find the vote_burst log (could also have contribution_flood since we created 31 entries).
	foundVoteBurst := false
	for _, l := range logs {
		if l.Type == "vote_burst" {
			foundVoteBurst = true
			if l.ActionTaken != "auto_quarantine" {
				t.Errorf("action taken = %q, want %q", l.ActionTaken, "auto_quarantine")
			}
		}
	}
	if !foundVoteBurst {
		// The operator may have been quarantined for contribution_flood first
		// (31 entries > 50 threshold? No, 31 < 50). Check again.
		t.Error("expected vote_burst anomaly log")
	}
}

func TestNormalActivityNoAnomaly(t *testing.T) {
	db := setupTestDB(t)
	srv := New(db, "test-secret")

	// Create operator.
	opID := uuid.New().String()
	if err := db.CreateOperator(&storage.Operator{
		ID:         opID,
		PublicKey:  []byte("normal-op-key"),
		Label:      "normal-op",
		ApprovedBy: "admin",
		Reputation: 5.0,
		MaxAgents:  5,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	// Create agent.
	agentID := uuid.New().String()
	if err := db.CreateAgentKey(&storage.AgentKey{
		ID:         agentID,
		OperatorID: opID,
		PublicKey:  []byte("normal-agent-key"),
		Label:      "normal-agent",
		LastSeen:   time.Now().Unix(),
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create agent key: %v", err)
	}

	// Create 5 knowledge entries (well under the 50 threshold).
	now := time.Now().Unix()
	for i := 0; i < 5; i++ {
		entry := &storage.KnowledgeEntry{
			ID:         uuid.New().String(),
			AgentID:    agentID,
			OperatorID: opID,
			Type:       storage.KnowledgeObservation,
			Domain:     "normal.test",
			Content:    "normal entry",
			Confidence: 0.8,
			CreatedAt:  now,
			Signature:  "sig",
		}
		if err := db.CreateKnowledgeEntry(entry); err != nil {
			t.Fatalf("create knowledge entry %d: %v", i, err)
		}
	}

	// Run anomaly detection.
	n := srv.detectAnomalies()
	if n != 0 {
		t.Fatalf("anomalies = %d, want 0", n)
	}

	// Verify operator is NOT quarantined.
	op, err := db.GetOperator(opID)
	if err != nil {
		t.Fatalf("get operator: %v", err)
	}
	if op.Quarantined {
		t.Error("expected operator NOT to be quarantined")
	}

	// Verify no anomaly logs.
	logs, err := db.ListAnomalyLogs(opID)
	if err != nil {
		t.Fatalf("list anomaly logs: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("anomaly logs = %d, want 0", len(logs))
	}
}
