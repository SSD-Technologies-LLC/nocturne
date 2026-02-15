package dht

import (
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// TestIntegrationFullP2PFlow exercises the full P2P flow across 3 DHT nodes.
// It covers knowledge publish/query, commit-reveal voting, compute task lifecycle,
// gossip propagation, and anomaly detection in a single end-to-end test.
func TestIntegrationFullP2PFlow(t *testing.T) {
	// Create 3 nodes and connect them in a chain: A <-> B <-> C.
	nodes := testNodes(t, 3)
	a, b, c := nodes[0], nodes[1], nodes[2]

	// Create gossipers for each node.
	gossipers := make([]*Gossiper, 3)
	for i, node := range nodes {
		g := NewGossiper(node)
		node.SetGossiper(g)
		gossipers[i] = g
	}

	// Connect A <-> B and B <-> C.
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("A ping B: %v", err)
	}
	if _, err := b.Ping(c.Addr()); err != nil {
		t.Fatalf("B ping C: %v", err)
	}

	// Wait for routing tables to stabilize.
	waitForTableSize(t, a, 1, 2*time.Second)
	waitForTableSize(t, b, 2, 2*time.Second)
	waitForTableSize(t, c, 1, 2*time.Second)

	t.Run("KnowledgePublishAndCrossNodeQuery", func(t *testing.T) {
		entry := &KnowledgeEntry{
			ID:         "integ-k1",
			AgentID:    "agent-integ",
			OperatorID: "op-integ",
			Type:       "fact",
			Domain:     "security",
			Content:    "AES-256 is secure",
			Confidence: 0.95,
			CreatedAt:  time.Now().Unix(),
			Signature:  "integ-sig",
		}

		// Publish on node A.
		if err := a.PublishKnowledge(entry); err != nil {
			t.Fatalf("PublishKnowledge on A: %v", err)
		}

		// Wait for DHT replication.
		time.Sleep(300 * time.Millisecond)

		// Query from node C.
		results, err := c.QueryKnowledge("security", "", 0, 0)
		if err != nil {
			t.Fatalf("QueryKnowledge from C: %v", err)
		}
		if len(results) == 0 {
			t.Fatal("expected at least 1 result from C, got 0")
		}

		found := false
		for _, r := range results {
			if r.ID == "integ-k1" && r.Content == "AES-256 is secure" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("entry 'integ-k1' not found from C; got %d results", len(results))
		}
	})

	t.Run("CommitRevealVoting", func(t *testing.T) {
		entryKey := ContentKey("security", "integ-vote-entry")

		// Create a vote record with commit window open now.
		now := time.Now().Unix()
		commitEnd := now + 10
		revealEnd := now + 20
		storeVoteRecordWithWindows(t, a, entryKey, commitEnd, revealEnd)

		// Two operators submit commitments on node A.
		ops := []struct {
			id    string
			vote  int
			nonce string
		}{
			{"op-alpha", 1, "nonce-alpha"},
			{"op-beta", -1, "nonce-beta"},
		}

		for _, op := range ops {
			commitment := MakeCommitment(op.vote, op.nonce)
			if err := a.SubmitVoteCommitment(entryKey, op.id, commitment); err != nil {
				t.Fatalf("SubmitVoteCommitment(%s): %v", op.id, err)
			}
			time.Sleep(100 * time.Millisecond)
		}

		// Manually advance to reveal phase: set commitEnd in the past, revealEnd in future.
		record, err := a.getVoteRecord(entryKey)
		if err != nil {
			t.Fatalf("getVoteRecord: %v", err)
		}
		now2 := time.Now().Unix()
		record.CommitEnd = now2 - 1
		record.RevealEnd = now2 + 10
		data, _ := json.Marshal(record)
		key := PrefixKey(voteKeyPrefix, hex.EncodeToString(entryKey[:]))
		if err := a.Store(key, data); err != nil {
			t.Fatalf("store updated vote record: %v", err)
		}
		time.Sleep(200 * time.Millisecond)

		// Both operators reveal their votes.
		for _, op := range ops {
			if err := a.SubmitVoteReveal(entryKey, op.id, op.vote, op.nonce, "integration test"); err != nil {
				t.Fatalf("SubmitVoteReveal(%s): %v", op.id, err)
			}
			time.Sleep(100 * time.Millisecond)
		}

		// Tally votes.
		tally, err := a.TallyVotes(entryKey)
		if err != nil {
			t.Fatalf("TallyVotes: %v", err)
		}
		if tally.UpVotes != 1 {
			t.Fatalf("expected 1 up_vote, got %d", tally.UpVotes)
		}
		if tally.DownVotes != 1 {
			t.Fatalf("expected 1 down_vote, got %d", tally.DownVotes)
		}
		if tally.Total != 2 {
			t.Fatalf("expected total=2, got %d", tally.Total)
		}
	})

	t.Run("ComputeTaskLifecycle", func(t *testing.T) {
		task := &ComputeTask{
			ID:          "integ-task-001",
			Type:        "verify",
			Domain:      "security",
			Description: "Verify integrity of integration test data",
			Priority:    8,
		}

		// Publish on node A.
		if err := a.PublishTask(task); err != nil {
			t.Fatalf("PublishTask on A: %v", err)
		}

		// Wait for replication.
		time.Sleep(300 * time.Millisecond)

		// Claim the task from node C.
		claimed, err := c.ClaimTask("integ-task-001", "agent-c")
		if err != nil {
			t.Fatalf("ClaimTask from C: %v", err)
		}
		if claimed.ClaimedBy != "agent-c" {
			t.Fatalf("expected claimed_by=agent-c, got %s", claimed.ClaimedBy)
		}
		time.Sleep(200 * time.Millisecond)

		// Submit result from node C.
		if err := c.SubmitTaskResult("integ-task-001", "result-integ-42"); err != nil {
			t.Fatalf("SubmitTaskResult from C: %v", err)
		}
		time.Sleep(200 * time.Millisecond)

		// Verify task is completed by listing from node A.
		tasks, err := a.ListTasks()
		if err != nil {
			t.Fatalf("ListTasks from A: %v", err)
		}
		if len(tasks) == 0 {
			t.Fatal("expected at least 1 task from A, got 0")
		}

		found := false
		for _, tk := range tasks {
			if tk.ID == "integ-task-001" {
				if !tk.Completed {
					t.Fatal("expected task to be completed")
				}
				if tk.ResultID != "result-integ-42" {
					t.Fatalf("expected result_id=result-integ-42, got %s", tk.ResultID)
				}
				found = true
				break
			}
		}
		if !found {
			t.Fatal("task integ-task-001 not found in ListTasks from A")
		}
	})

	t.Run("GossipPropagation", func(t *testing.T) {
		// Set up gossip handler on node C to capture trust cert.
		var mu sync.Mutex
		var receivedMsg *GossipMessage
		done := make(chan struct{})

		gossipers[2].OnGossip(GossipTrustCert, func(msg *GossipMessage) {
			mu.Lock()
			defer mu.Unlock()
			if receivedMsg == nil {
				receivedMsg = msg
				close(done)
			}
		})

		// Broadcast a trust cert gossip from node A.
		certData, _ := json.Marshal(map[string]string{
			"subject": "agent-integ",
			"issuer":  "op-integ",
			"trust":   "high",
		})
		if err := gossipers[0].Broadcast(GossipTrustCert, certData); err != nil {
			t.Fatalf("Broadcast from A: %v", err)
		}

		// Verify node C receives it within 5 seconds.
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("node C did not receive gossip within 5 seconds")
		}

		mu.Lock()
		defer mu.Unlock()

		if receivedMsg == nil {
			t.Fatal("expected to receive gossip message on C")
		}
		if receivedMsg.GossipType != GossipTrustCert {
			t.Fatalf("expected gossip type %q, got %q", GossipTrustCert, receivedMsg.GossipType)
		}

		var got map[string]string
		if err := json.Unmarshal(receivedMsg.Data, &got); err != nil {
			t.Fatalf("unmarshal received gossip data: %v", err)
		}
		if got["subject"] != "agent-integ" {
			t.Fatalf("expected subject=agent-integ, got %q", got["subject"])
		}
	})

	t.Run("AnomalyDetection", func(t *testing.T) {
		// Create an AnomalyDetector on node A with low threshold.
		det := NewAnomalyDetector(a)
		det.VoteBurstThreshold = 3
		det.WindowDuration = 5 * time.Second

		operatorID := "op-anomaly-integ"

		// Record enough votes to exceed threshold (3 + 1 = 4 > 3).
		for i := 0; i < 4; i++ {
			det.RecordVote(operatorID)
		}

		// Wait for DHT store.
		time.Sleep(200 * time.Millisecond)

		// Verify anomaly report is detectable from node B via CheckAnomaly.
		det2 := NewAnomalyDetector(b)
		reports := det2.CheckAnomaly(operatorID)
		if len(reports) == 0 {
			t.Fatal("expected at least 1 anomaly report from B, got 0")
		}

		found := false
		for _, r := range reports {
			if r.Type == AnomalyVoteBurst && r.OperatorID == operatorID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("vote_burst anomaly for %q not found from node B", operatorID)
		}
	})
}
