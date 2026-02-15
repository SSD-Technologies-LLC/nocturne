package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

// runAnomalyDetection periodically scans for anomalous operator activity
// (every 5 minutes).
func (s *Server) runAnomalyDetection(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
			n := s.detectAnomalies()
			if n > 0 {
				log.Printf("[anomaly] detected %d anomalies", n)
			}
		}
	}
}

// detectAnomalies checks all non-quarantined operators for suspicious activity
// and auto-quarantines offenders. Returns the number of anomalies found.
func (s *Server) detectAnomalies() int {
	ops, err := s.db.ListOperators()
	if err != nil {
		log.Printf("[anomaly] list operators: %v", err)
		return 0
	}

	anomalies := 0
	now := time.Now().Unix()
	since := now - 3600 // last hour

	for _, op := range ops {
		if op.Quarantined {
			continue
		}

		// Rule 1: Contribution flood — more than 50 knowledge entries in the last hour.
		knowledgeCount, err := s.db.CountRecentKnowledgeByOperator(op.ID, since)
		if err != nil {
			log.Printf("[anomaly] count knowledge for %s: %v", op.ID, err)
			continue
		}
		if knowledgeCount > 50 {
			evidence := fmt.Sprintf("%d knowledge entries in last hour (threshold: 50)", knowledgeCount)
			s.quarantineForAnomaly(op.ID, "contribution_flood", evidence)
			anomalies++
			continue // already quarantined, skip further checks
		}

		// Rule 2: Vote burst — more than 30 votes in the last hour.
		voteCount, err := s.db.CountRecentVotesByOperator(op.ID, since)
		if err != nil {
			log.Printf("[anomaly] count votes for %s: %v", op.ID, err)
			continue
		}
		if voteCount > 30 {
			evidence := fmt.Sprintf("%d votes in last hour (threshold: 30)", voteCount)
			s.quarantineForAnomaly(op.ID, "vote_burst", evidence)
			anomalies++
		}
	}

	return anomalies
}

// quarantineForAnomaly quarantines an operator and logs the anomaly.
func (s *Server) quarantineForAnomaly(operatorID, anomalyType, evidence string) {
	if err := s.db.QuarantineOperator(operatorID, true); err != nil {
		log.Printf("[anomaly] quarantine operator %s: %v", operatorID, err)
		return
	}

	anomalyLog := &storage.AnomalyLog{
		ID:          uuid.New().String(),
		OperatorID:  operatorID,
		Type:        anomalyType,
		Evidence:    evidence,
		ActionTaken: "auto_quarantine",
		CreatedAt:   time.Now().Unix(),
	}
	if err := s.db.CreateAnomalyLog(anomalyLog); err != nil {
		log.Printf("[anomaly] create anomaly log for %s: %v", operatorID, err)
	}
}
