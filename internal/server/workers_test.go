package server

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

func TestTTLCleanup(t *testing.T) {
	db := setupTestDB(t)
	srv := New(db, "test-secret")

	// Create operator and agent key (foreign key requirements).
	opID := uuid.New().String()
	if err := db.CreateOperator(&storage.Operator{
		ID:        opID,
		PublicKey: []byte("op-pub-key"),
		Label:     "ttl-test-op",
		ApprovedBy: "admin",
		Reputation: 5.0,
		MaxAgents:  5,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	agentID := uuid.New().String()
	if err := db.CreateAgentKey(&storage.AgentKey{
		ID:         agentID,
		OperatorID: opID,
		PublicKey:  []byte("agent-pub-key"),
		Label:      "ttl-test-agent",
		LastSeen:   time.Now().Unix(),
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create agent key: %v", err)
	}

	// Create a knowledge entry with TTL = 1 second, created_at in the past.
	ttl := int64(1)
	entry := &storage.KnowledgeEntry{
		ID:         uuid.New().String(),
		AgentID:    agentID,
		OperatorID: opID,
		Type:       storage.KnowledgeObservation,
		Domain:     "ttl.test",
		Content:    "This entry should expire",
		Confidence: 0.8,
		TTL:        &ttl,
		CreatedAt:  time.Now().Unix() - 10, // 10 seconds ago
		Signature:  "sig",
	}
	if err := db.CreateKnowledgeEntry(entry); err != nil {
		t.Fatalf("create knowledge entry: %v", err)
	}

	// Also create one without TTL (should survive).
	permanent := &storage.KnowledgeEntry{
		ID:         uuid.New().String(),
		AgentID:    agentID,
		OperatorID: opID,
		Type:       storage.KnowledgeObservation,
		Domain:     "ttl.test",
		Content:    "This entry should persist",
		Confidence: 0.9,
		CreatedAt:  time.Now().Unix(),
		Signature:  "sig2",
	}
	if err := db.CreateKnowledgeEntry(permanent); err != nil {
		t.Fatalf("create permanent entry: %v", err)
	}

	// Run pruning.
	n := srv.pruneExpired()
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}

	// Verify the expired entry is gone and the permanent one remains.
	_, err := db.GetKnowledgeEntry(entry.ID)
	if err == nil {
		t.Error("expected expired entry to be deleted")
	}

	kept, err := db.GetKnowledgeEntry(permanent.ID)
	if err != nil {
		t.Fatalf("get permanent entry: %v", err)
	}
	if kept.ID != permanent.ID {
		t.Errorf("permanent entry ID = %q, want %q", kept.ID, permanent.ID)
	}
}

func TestTaskGeneration(t *testing.T) {
	db := setupTestDB(t)
	srv := New(db, "test-secret")

	// Create operator and agent.
	opID := uuid.New().String()
	if err := db.CreateOperator(&storage.Operator{
		ID:        opID,
		PublicKey: []byte("op-pub-key"),
		Label:     "task-gen-op",
		ApprovedBy: "admin",
		Reputation: 5.0,
		MaxAgents:  5,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	agentID := uuid.New().String()
	if err := db.CreateAgentKey(&storage.AgentKey{
		ID:         agentID,
		OperatorID: opID,
		PublicKey:  []byte("agent-pub-key-gen"),
		Label:      "task-gen-agent",
		LastSeen:   time.Now().Unix(),
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create agent key: %v", err)
	}

	// Create 6 knowledge entries in the same domain (threshold is 5).
	for i := 0; i < 6; i++ {
		entry := &storage.KnowledgeEntry{
			ID:         uuid.New().String(),
			AgentID:    agentID,
			OperatorID: opID,
			Type:       storage.KnowledgeObservation,
			Domain:     "synthesis.test",
			Content:    "observation content",
			Confidence: 0.7,
			CreatedAt:  time.Now().Unix(),
			Signature:  "sig",
		}
		if err := db.CreateKnowledgeEntry(entry); err != nil {
			t.Fatalf("create knowledge entry %d: %v", i, err)
		}
	}

	// Run task generator.
	n := srv.generateTasks()
	if n < 1 {
		t.Fatalf("generated = %d, want >= 1", n)
	}

	// Verify a synthesize task was created by claiming it.
	task, err := db.ClaimComputeTask(
		[]string{storage.TaskSynthesize},
		[]string{"synthesis.test"},
		"verifier",
	)
	if err != nil {
		t.Fatalf("claim synthesize task: %v", err)
	}
	if task == nil {
		t.Fatal("expected a synthesize task to exist")
	}
	if task.Domain != "synthesis.test" {
		t.Errorf("domain = %q, want %q", task.Domain, "synthesis.test")
	}
	if task.Type != storage.TaskSynthesize {
		t.Errorf("type = %q, want %q", task.Type, storage.TaskSynthesize)
	}
}

func TestTaskGenerationLowConfidence(t *testing.T) {
	db := setupTestDB(t)
	srv := New(db, "test-secret")

	// Create operator and agent.
	opID := uuid.New().String()
	if err := db.CreateOperator(&storage.Operator{
		ID:        opID,
		PublicKey: []byte("op-pub-key-lc"),
		Label:     "low-conf-op",
		ApprovedBy: "admin",
		Reputation: 5.0,
		MaxAgents:  5,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	agentID := uuid.New().String()
	if err := db.CreateAgentKey(&storage.AgentKey{
		ID:         agentID,
		OperatorID: opID,
		PublicKey:  []byte("agent-pub-key-lc"),
		Label:      "low-conf-agent",
		LastSeen:   time.Now().Unix(),
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create agent key: %v", err)
	}

	// Create 3 low-confidence entries (below 0.5 avg, and count > 0).
	for i := 0; i < 3; i++ {
		entry := &storage.KnowledgeEntry{
			ID:         uuid.New().String(),
			AgentID:    agentID,
			OperatorID: opID,
			Type:       storage.KnowledgeObservation,
			Domain:     "lowconf.domain",
			Content:    "uncertain observation",
			Confidence: 0.3,
			CreatedAt:  time.Now().Unix(),
			Signature:  "sig",
		}
		if err := db.CreateKnowledgeEntry(entry); err != nil {
			t.Fatalf("create knowledge entry %d: %v", i, err)
		}
	}

	// Run task generator.
	n := srv.generateTasks()
	if n < 1 {
		t.Fatalf("generated = %d, want >= 1 (verify task for low confidence)", n)
	}

	// Verify a verify task was created.
	task, err := db.ClaimComputeTask(
		[]string{storage.TaskVerify},
		[]string{"lowconf.domain"},
		"verifier",
	)
	if err != nil {
		t.Fatalf("claim verify task: %v", err)
	}
	if task == nil {
		t.Fatal("expected a verify task to exist for low confidence domain")
	}
	if task.Type != storage.TaskVerify {
		t.Errorf("type = %q, want %q", task.Type, storage.TaskVerify)
	}
}

func TestReputationDecay(t *testing.T) {
	db := setupTestDB(t)
	srv := New(db, "test-secret")

	// Create operator with reputation 10.0.
	opID := uuid.New().String()
	if err := db.CreateOperator(&storage.Operator{
		ID:        opID,
		PublicKey: []byte("op-pub-key-decay"),
		Label:     "decay-test-op",
		ApprovedBy: "admin",
		Reputation: 10.0,
		MaxAgents:  5,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	// Create another operator with zero reputation (should not change).
	zeroOpID := uuid.New().String()
	if err := db.CreateOperator(&storage.Operator{
		ID:        zeroOpID,
		PublicKey: []byte("op-pub-key-zero"),
		Label:     "zero-rep-op",
		ApprovedBy: "admin",
		Reputation: 0,
		MaxAgents:  5,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create zero-rep operator: %v", err)
	}

	// Run decay.
	n := srv.decayReputation()
	if n != 1 {
		t.Errorf("decayed = %d, want 1 (only the operator with rep > 0)", n)
	}

	// Verify reputation decreased.
	op, err := db.GetOperator(opID)
	if err != nil {
		t.Fatalf("get operator: %v", err)
	}

	expected := 10.0 * 0.995
	if op.Reputation < expected-0.001 || op.Reputation > expected+0.001 {
		t.Errorf("reputation = %f, want approximately %f", op.Reputation, expected)
	}

	// Verify zero-rep operator unchanged.
	zeroOp, err := db.GetOperator(zeroOpID)
	if err != nil {
		t.Fatalf("get zero-rep operator: %v", err)
	}
	if zeroOp.Reputation != 0 {
		t.Errorf("zero-rep operator reputation = %f, want 0", zeroOp.Reputation)
	}
}

func TestReputationDecayToZero(t *testing.T) {
	db := setupTestDB(t)
	srv := New(db, "test-secret")

	// Create operator with very small reputation that should decay to zero.
	opID := uuid.New().String()
	if err := db.CreateOperator(&storage.Operator{
		ID:        opID,
		PublicKey: []byte("op-pub-key-tiny"),
		Label:     "tiny-rep-op",
		ApprovedBy: "admin",
		Reputation: 0.005, // 0.005 * 0.995 = 0.004975 < 0.01 -> should become 0
		MaxAgents:  5,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	srv.decayReputation()

	op, err := db.GetOperator(opID)
	if err != nil {
		t.Fatalf("get operator: %v", err)
	}
	if op.Reputation != 0 {
		t.Errorf("reputation = %f, want 0 (below threshold)", op.Reputation)
	}
}
