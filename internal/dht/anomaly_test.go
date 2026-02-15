package dht

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// anomalyCluster creates n DHT nodes connected in a chain with gossipers attached.
func anomalyCluster(t *testing.T, n int) ([]*Node, []*Gossiper) {
	t.Helper()
	nodes := testNodes(t, n)
	gossipers := make([]*Gossiper, n)

	for i, node := range nodes {
		g := NewGossiper(node)
		node.SetGossiper(g)
		gossipers[i] = g
	}

	// Connect nodes in a chain: 0->1->2->...
	for i := 1; i < len(nodes); i++ {
		if _, err := nodes[i-1].Ping(nodes[i].Addr()); err != nil {
			t.Fatalf("ping node %d->%d: %v", i-1, i, err)
		}
	}
	time.Sleep(100 * time.Millisecond) // let connections settle
	return nodes, gossipers
}

func TestAnomalyDetectorRecordVote(t *testing.T) {
	nodes := testNodes(t, 1)
	node := nodes[0]

	det := NewAnomalyDetector(node)
	det.VoteBurstThreshold = 3
	det.WindowDuration = 5 * time.Second

	operatorID := "op-vote-test"

	// Record votes below threshold — no anomaly.
	for i := 0; i < 3; i++ {
		det.RecordVote(operatorID)
	}

	// No anomaly should be detected yet (exactly at threshold, not above).
	reports := det.CheckAnomaly(operatorID)
	if len(reports) != 0 {
		t.Fatalf("expected 0 reports below threshold, got %d", len(reports))
	}

	// Record one more vote to exceed threshold.
	det.RecordVote(operatorID)

	// Allow time for DHT store.
	time.Sleep(100 * time.Millisecond)

	// Now there should be an anomaly report.
	reports = det.CheckAnomaly(operatorID)
	if len(reports) != 1 {
		t.Fatalf("expected 1 anomaly report, got %d", len(reports))
	}
	if reports[0].Type != AnomalyVoteBurst {
		t.Fatalf("expected anomaly type %q, got %q", AnomalyVoteBurst, reports[0].Type)
	}
	if reports[0].OperatorID != operatorID {
		t.Fatalf("expected operator %q, got %q", operatorID, reports[0].OperatorID)
	}
}

func TestAnomalyDetectorRecordContribution(t *testing.T) {
	nodes := testNodes(t, 1)
	node := nodes[0]

	det := NewAnomalyDetector(node)
	det.ContributionFloodThreshold = 3
	det.WindowDuration = 5 * time.Second

	operatorID := "op-contrib-test"

	// Record contributions below threshold — no anomaly.
	for i := 0; i < 3; i++ {
		det.RecordContribution(operatorID)
	}

	reports := det.CheckAnomaly(operatorID)
	if len(reports) != 0 {
		t.Fatalf("expected 0 reports below threshold, got %d", len(reports))
	}

	// Exceed threshold.
	det.RecordContribution(operatorID)

	time.Sleep(100 * time.Millisecond)

	reports = det.CheckAnomaly(operatorID)
	if len(reports) != 1 {
		t.Fatalf("expected 1 anomaly report, got %d", len(reports))
	}
	if reports[0].Type != AnomalyContributionFlood {
		t.Fatalf("expected anomaly type %q, got %q", AnomalyContributionFlood, reports[0].Type)
	}
	if reports[0].OperatorID != operatorID {
		t.Fatalf("expected operator %q, got %q", operatorID, reports[0].OperatorID)
	}
}

func TestAnomalyReportGossip(t *testing.T) {
	nodes, gossipers := anomalyCluster(t, 3)
	_ = gossipers

	// Set up a gossip handler on node 2 to capture anomaly reports.
	var mu sync.Mutex
	var receivedReport *AnomalyReport
	done := make(chan struct{})

	gossipers[2].OnGossip(GossipAnomalyReport, func(msg *GossipMessage) {
		mu.Lock()
		defer mu.Unlock()
		if receivedReport != nil {
			return // only capture first
		}
		var report AnomalyReport
		if err := json.Unmarshal(msg.Data, &report); err == nil {
			receivedReport = &report
			close(done)
		}
	})

	// Create anomaly detector on node 0.
	det := NewAnomalyDetector(nodes[0])
	det.VoteBurstThreshold = 2
	det.WindowDuration = 5 * time.Second

	operatorID := "op-gossip-test"

	// Exceed threshold to trigger anomaly + gossip broadcast.
	for i := 0; i < 4; i++ {
		det.RecordVote(operatorID)
	}

	// Wait for gossip propagation.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("gossip handler not called within timeout")
	}

	mu.Lock()
	defer mu.Unlock()

	if receivedReport == nil {
		t.Fatal("expected to receive anomaly report via gossip")
	}
	if receivedReport.Type != AnomalyVoteBurst {
		t.Fatalf("expected anomaly type %q, got %q", AnomalyVoteBurst, receivedReport.Type)
	}
	if receivedReport.OperatorID != operatorID {
		t.Fatalf("expected operator %q, got %q", operatorID, receivedReport.OperatorID)
	}
	if receivedReport.ReporterID != nodes[0].ID() {
		t.Fatal("expected reporter to be node 0")
	}
}

func TestAnomalyDetectorDedup(t *testing.T) {
	nodes := testNodes(t, 1)
	node := nodes[0]

	det := NewAnomalyDetector(node)
	det.VoteBurstThreshold = 2
	det.WindowDuration = 5 * time.Second

	operatorID := "op-dedup-test"

	// Exceed threshold multiple times — should only produce one report.
	for i := 0; i < 10; i++ {
		det.RecordVote(operatorID)
	}

	time.Sleep(100 * time.Millisecond)

	reports := det.CheckAnomaly(operatorID)
	if len(reports) != 1 {
		t.Fatalf("expected exactly 1 anomaly report (dedup), got %d", len(reports))
	}
}

func TestAnomalyDetectorPrune(t *testing.T) {
	nodes := testNodes(t, 1)
	node := nodes[0]

	det := NewAnomalyDetector(node)
	det.VoteBurstThreshold = 100 // high threshold so no anomaly triggers
	det.ContributionFloodThreshold = 100
	det.WindowDuration = 1 * time.Second // very short window

	// Record some events.
	for i := 0; i < 5; i++ {
		det.RecordVote("op-prune")
		det.RecordContribution("op-prune")
	}

	// Verify events are present.
	det.mu.RLock()
	voteCount := len(det.voteEvents["op-prune"])
	contribCount := len(det.contributionEvents["op-prune"])
	det.mu.RUnlock()

	if voteCount != 5 {
		t.Fatalf("expected 5 vote events, got %d", voteCount)
	}
	if contribCount != 5 {
		t.Fatalf("expected 5 contribution events, got %d", contribCount)
	}

	// Wait for events to expire.
	time.Sleep(1500 * time.Millisecond)

	// Prune and verify events are removed.
	det.PruneOldEvents()

	det.mu.RLock()
	voteCount = len(det.voteEvents["op-prune"])
	contribCount = len(det.contributionEvents["op-prune"])
	det.mu.RUnlock()

	if voteCount != 0 {
		t.Fatalf("expected 0 vote events after prune, got %d", voteCount)
	}
	if contribCount != 0 {
		t.Fatalf("expected 0 contribution events after prune, got %d", contribCount)
	}
}

func TestCheckAnomaly(t *testing.T) {
	nodes, _ := anomalyCluster(t, 3)

	// Create anomaly detector on node 0.
	det := NewAnomalyDetector(nodes[0])
	det.ContributionFloodThreshold = 2
	det.WindowDuration = 5 * time.Second

	operatorID := "op-check-test"

	// No anomalies initially.
	reports := det.CheckAnomaly(operatorID)
	if len(reports) != 0 {
		t.Fatalf("expected 0 reports initially, got %d", len(reports))
	}

	// Trigger a contribution flood anomaly.
	for i := 0; i < 4; i++ {
		det.RecordContribution(operatorID)
	}

	// Allow time for DHT store and replication.
	time.Sleep(200 * time.Millisecond)

	// CheckAnomaly from the same node should find the report.
	reports = det.CheckAnomaly(operatorID)
	if len(reports) != 1 {
		t.Fatalf("expected 1 anomaly report, got %d", len(reports))
	}
	if reports[0].Type != AnomalyContributionFlood {
		t.Fatalf("expected anomaly type %q, got %q", AnomalyContributionFlood, reports[0].Type)
	}
	if reports[0].OperatorID != operatorID {
		t.Fatalf("expected operator %q, got %q", operatorID, reports[0].OperatorID)
	}
	if reports[0].ID == "" {
		t.Fatal("expected non-empty report ID")
	}
	if reports[0].ReporterID != nodes[0].ID() {
		t.Fatal("expected reporter to be node 0")
	}

	// CheckAnomaly from a different node should also find it (via DHT lookup).
	det2 := NewAnomalyDetector(nodes[1])
	reports2 := det2.CheckAnomaly(operatorID)
	if len(reports2) != 1 {
		t.Fatalf("expected 1 anomaly report from node 1, got %d", len(reports2))
	}
	if reports2[0].Type != AnomalyContributionFlood {
		t.Fatalf("expected anomaly type %q from node 1, got %q", AnomalyContributionFlood, reports2[0].Type)
	}
}
