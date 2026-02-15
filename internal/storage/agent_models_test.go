package storage

import "testing"

func TestKnowledgeTypeConstants(t *testing.T) {
	types := []string{
		KnowledgeObservation,
		KnowledgeSynthesis,
		KnowledgeCorrection,
		KnowledgeReflection,
	}
	if len(types) != 4 {
		t.Fatalf("expected 4 knowledge types, got %d", len(types))
	}
	expected := map[string]string{
		"KnowledgeObservation": KnowledgeObservation,
		"KnowledgeSynthesis":   KnowledgeSynthesis,
		"KnowledgeCorrection":  KnowledgeCorrection,
		"KnowledgeReflection":  KnowledgeReflection,
	}
	vals := map[string]bool{
		"observation": false,
		"synthesis":   false,
		"correction":  false,
		"reflection":  false,
	}
	for name, v := range expected {
		if _, ok := vals[v]; !ok {
			t.Errorf("%s has unexpected value %q", name, v)
		}
		vals[v] = true
	}
	for v, seen := range vals {
		if !seen {
			t.Errorf("knowledge type %q not covered by any constant", v)
		}
	}
}

func TestComputeTaskTypeConstants(t *testing.T) {
	types := []string{
		TaskSynthesize,
		TaskVerify,
		TaskConsolidate,
		TaskReflect,
		TaskFillGap,
	}
	if len(types) != 5 {
		t.Fatalf("expected 5 compute task types, got %d", len(types))
	}
	expected := map[string]string{
		"TaskSynthesize":  TaskSynthesize,
		"TaskVerify":      TaskVerify,
		"TaskConsolidate": TaskConsolidate,
		"TaskReflect":     TaskReflect,
		"TaskFillGap":     TaskFillGap,
	}
	vals := map[string]bool{
		"synthesize":  false,
		"verify":      false,
		"consolidate": false,
		"reflect":     false,
		"fill_gap":    false,
	}
	for name, v := range expected {
		if _, ok := vals[v]; !ok {
			t.Errorf("%s has unexpected value %q", name, v)
		}
		vals[v] = true
	}
	for v, seen := range vals {
		if !seen {
			t.Errorf("compute task type %q not covered by any constant", v)
		}
	}
}

func TestVotePhaseConstants(t *testing.T) {
	phases := []string{
		VotePhaseCommit,
		VotePhaseRevealed,
		VotePhaseExpired,
	}
	if len(phases) != 3 {
		t.Fatalf("expected 3 vote phases, got %d", len(phases))
	}
	expected := map[string]string{
		"VotePhaseCommit":   VotePhaseCommit,
		"VotePhaseRevealed": VotePhaseRevealed,
		"VotePhaseExpired":  VotePhaseExpired,
	}
	vals := map[string]bool{
		"commit":   false,
		"revealed": false,
		"expired":  false,
	}
	for name, v := range expected {
		if _, ok := vals[v]; !ok {
			t.Errorf("%s has unexpected value %q", name, v)
		}
		vals[v] = true
	}
	for v, seen := range vals {
		if !seen {
			t.Errorf("vote phase %q not covered by any constant", v)
		}
	}
}

func TestStructInstantiation(t *testing.T) {
	_ = Operator{
		ID:          "op-1",
		PublicKey:    []byte("key"),
		Label:       "test-operator",
		ApprovedBy:  "root",
		Reputation:  1.0,
		Quarantined: false,
		MaxAgents:   5,
		CreatedAt:   1000,
	}

	_ = AgentKey{
		ID:         "ak-1",
		OperatorID: "op-1",
		PublicKey:  []byte("agentkey"),
		Label:      "agent-label",
		LastSeen:   2000,
		CreatedAt:  1000,
	}

	ttl := int64(3600)
	_ = KnowledgeEntry{
		ID:         "ke-1",
		AgentID:    "ak-1",
		OperatorID: "op-1",
		Type:       KnowledgeObservation,
		Domain:     "security",
		Content:    "finding",
		Confidence: 0.85,
		Sources:    `["src-1"]`,
		Supersedes: "",
		VotesUp:    3,
		VotesDown:  0,
		VerifiedBy: `["ak-2"]`,
		TTL:        &ttl,
		CreatedAt:  1000,
		Signature:  "sig-abc",
	}

	_ = ComputeTask{
		ID:          "ct-1",
		Type:        TaskSynthesize,
		Domain:      "security",
		Description: "synthesize findings",
		Priority:    5,
		ClaimedBy:   "ak-1",
		ClaimedAt:   2000,
		Completed:   false,
		ResultID:    "",
		VerifiedBy:  "",
		CreatedAt:   1000,
	}

	voteVal := 1
	_ = Vote{
		ID:          "v-1",
		EntryID:     "ke-1",
		OperatorID:  "op-1",
		Commitment:  "hash-abc",
		VoteValue:   &voteVal,
		Nonce:       "nonce-123",
		Reason:      "accurate",
		Phase:       VotePhaseCommit,
		CommittedAt: 1000,
		RevealedAt:  2000,
	}

	_ = Provenance{
		EntryID:  "ke-2",
		SourceID: "ke-1",
	}

	_ = AwarenessSnapshot{
		ID:          "as-1",
		Snapshot:    `{"domains":["security"]}`,
		GeneratedBy: "ak-1",
		CreatedAt:   1000,
	}

	_ = AnomalyLog{
		ID:          "al-1",
		OperatorID:  "op-1",
		Type:        "reputation_spike",
		Evidence:    `{"delta":0.5}`,
		ActionTaken: "quarantine",
		CreatedAt:   1000,
	}
}

func TestAgentTablesExist(t *testing.T) {
	db := testDB(t)

	expected := []string{
		"operators",
		"agent_keys",
		"knowledge",
		"compute_tasks",
		"votes",
		"provenance",
		"awareness",
		"anomaly_logs",
	}
	for _, table := range expected {
		var name string
		err := db.db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}
}
