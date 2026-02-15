package dht

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AnomalyType identifies the kind of anomaly.
type AnomalyType string

const (
	AnomalyVoteBurst         AnomalyType = "vote_burst"
	AnomalyContributionFlood AnomalyType = "contribution_flood"
)

// AnomalyReport represents a detected anomaly.
type AnomalyReport struct {
	ID         string      `json:"id"`
	Type       AnomalyType `json:"type"`
	OperatorID string      `json:"operator_id"`
	Evidence   string      `json:"evidence"`
	ReporterID NodeID      `json:"reporter_id"` // the node that detected it
	CreatedAt  int64       `json:"created_at"`
}

// AnomalyIndex stores a list of anomaly report IDs for an operator.
type AnomalyIndex struct {
	Reports []string `json:"reports"` // report IDs
}

// AnomalyDetector monitors local activity and detects anomalies.
type AnomalyDetector struct {
	mu   sync.RWMutex
	node *Node

	// Sliding window counters: operatorID -> list of timestamps
	voteEvents         map[string][]int64
	contributionEvents map[string][]int64

	// Thresholds
	VoteBurstThreshold         int           // default 30
	ContributionFloodThreshold int           // default 50
	WindowDuration             time.Duration // default 1 hour

	// Reported anomalies (dedup)
	reported map[string]bool // anomaly key -> reported
}

// NewAnomalyDetector creates a new anomaly detector attached to a DHT node.
func NewAnomalyDetector(node *Node) *AnomalyDetector {
	return &AnomalyDetector{
		node:                       node,
		voteEvents:                 make(map[string][]int64),
		contributionEvents:         make(map[string][]int64),
		VoteBurstThreshold:         30,
		ContributionFloodThreshold: 50,
		WindowDuration:             time.Hour,
		reported:                   make(map[string]bool),
	}
}

// RecordVote records a vote event for an operator and checks for vote burst anomaly.
func (d *AnomalyDetector) RecordVote(operatorID string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now().Unix()
	d.voteEvents[operatorID] = append(d.voteEvents[operatorID], now)
	d.pruneEventsLocked(operatorID, d.voteEvents)

	if len(d.voteEvents[operatorID]) > d.VoteBurstThreshold {
		evidence := fmt.Sprintf("%d votes in %v window (threshold: %d)",
			len(d.voteEvents[operatorID]), d.WindowDuration, d.VoteBurstThreshold)
		d.detectAnomalyLocked(AnomalyVoteBurst, operatorID, evidence)
	}
}

// RecordContribution records a contribution event for an operator and checks for flood anomaly.
func (d *AnomalyDetector) RecordContribution(operatorID string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now().Unix()
	d.contributionEvents[operatorID] = append(d.contributionEvents[operatorID], now)
	d.pruneEventsLocked(operatorID, d.contributionEvents)

	if len(d.contributionEvents[operatorID]) > d.ContributionFloodThreshold {
		evidence := fmt.Sprintf("%d contributions in %v window (threshold: %d)",
			len(d.contributionEvents[operatorID]), d.WindowDuration, d.ContributionFloodThreshold)
		d.detectAnomalyLocked(AnomalyContributionFlood, operatorID, evidence)
	}
}

// detectAnomalyLocked creates an anomaly report, stores it in the DHT, and broadcasts
// it via gossip. Must be called with d.mu held.
func (d *AnomalyDetector) detectAnomalyLocked(atype AnomalyType, operatorID, evidence string) {
	// Dedup: only report once per (type, operator) pair.
	dedupKey := string(atype) + ":" + operatorID
	if d.reported[dedupKey] {
		return
	}
	d.reported[dedupKey] = true

	report := AnomalyReport{
		ID:         randomMsgID(),
		Type:       atype,
		OperatorID: operatorID,
		Evidence:   evidence,
		ReporterID: d.node.ID(),
		CreatedAt:  time.Now().Unix(),
	}

	data, err := json.Marshal(report)
	if err != nil {
		return
	}

	// Store the report in the DHT.
	key := PrefixKey("anomaly", report.ID)
	// Release lock during potentially blocking DHT operations.
	d.mu.Unlock()
	d.node.Store(key, data)

	// Update the operator-level anomaly index.
	d.updateAnomalyIndex(operatorID, report.ID)

	// Broadcast via gossip if a gossiper is available.
	if g := d.node.Gossiper(); g != nil {
		g.Broadcast(GossipAnomalyReport, data)
	}
	d.mu.Lock()
}

// updateAnomalyIndex adds a report ID to the operator's anomaly index in the DHT.
func (d *AnomalyDetector) updateAnomalyIndex(operatorID, reportID string) {
	indexKey := PrefixKey("anomaly_idx", operatorID)

	// Fetch current index.
	data, _ := d.node.FindValue(indexKey)

	var index AnomalyIndex
	if data != nil {
		json.Unmarshal(data, &index)
	}

	// Deduplicate.
	for _, id := range index.Reports {
		if id == reportID {
			return
		}
	}
	index.Reports = append(index.Reports, reportID)

	// Store updated index.
	indexData, err := json.Marshal(index)
	if err != nil {
		return
	}
	d.node.Store(indexKey, indexData)
}

// CheckAnomaly queries the DHT for anomaly reports about a specific operator.
func (d *AnomalyDetector) CheckAnomaly(operatorID string) []AnomalyReport {
	indexKey := PrefixKey("anomaly_idx", operatorID)
	data, err := d.node.FindValue(indexKey)
	if err != nil || data == nil {
		return nil
	}

	var index AnomalyIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil
	}

	var reports []AnomalyReport
	for _, reportID := range index.Reports {
		reportKey := PrefixKey("anomaly", reportID)
		reportData, err := d.node.FindValue(reportKey)
		if err != nil || reportData == nil {
			continue
		}

		var report AnomalyReport
		if err := json.Unmarshal(reportData, &report); err != nil {
			continue
		}
		reports = append(reports, report)
	}

	return reports
}

// PruneOldEvents removes events older than WindowDuration from all counters.
func (d *AnomalyDetector) PruneOldEvents() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for operatorID := range d.voteEvents {
		d.pruneEventsLocked(operatorID, d.voteEvents)
		if len(d.voteEvents[operatorID]) == 0 {
			delete(d.voteEvents, operatorID)
		}
	}
	for operatorID := range d.contributionEvents {
		d.pruneEventsLocked(operatorID, d.contributionEvents)
		if len(d.contributionEvents[operatorID]) == 0 {
			delete(d.contributionEvents, operatorID)
		}
	}
}

// pruneEventsLocked removes events outside the sliding window for a given operator.
// Must be called with d.mu held.
func (d *AnomalyDetector) pruneEventsLocked(operatorID string, events map[string][]int64) {
	cutoff := time.Now().Add(-d.WindowDuration).Unix()
	timestamps := events[operatorID]
	i := 0
	for i < len(timestamps) && timestamps[i] <= cutoff {
		i++
	}
	if i > 0 {
		events[operatorID] = timestamps[i:]
	}
}
