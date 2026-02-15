package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

// StartWorkers launches all background goroutines. Call with a cancellable
// context for graceful shutdown.
func (s *Server) StartWorkers(ctx context.Context) {
	go s.runTTLCleanup(ctx)
	go s.runTaskGenerator(ctx)
	go s.runReputationDecay(ctx)
	go s.runAnomalyDetection(ctx)
}

// --- TTL Cleanup Worker ---

// runTTLCleanup periodically prunes expired knowledge entries (every 5 minutes).
func (s *Server) runTTLCleanup(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Minute):
			n := s.pruneExpired()
			if n > 0 {
				log.Printf("[worker] pruned %d expired knowledge entries", n)
			}
		}
	}
}

// pruneExpired deletes knowledge entries whose TTL has elapsed. Returns the
// number of entries removed.
func (s *Server) pruneExpired() int {
	n, err := s.db.PruneExpiredKnowledge(time.Now().Unix())
	if err != nil {
		log.Printf("[worker] prune expired knowledge: %v", err)
		return 0
	}
	return n
}

// --- Compute Task Generator Worker ---

// runTaskGenerator periodically generates compute tasks (every 10 minutes).
func (s *Server) runTaskGenerator(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
			n := s.generateTasks()
			if n > 0 {
				log.Printf("[worker] generated %d compute tasks", n)
			}
		}
	}
}

// generateTasks inspects knowledge domains and creates synthesis/verification
// tasks where needed. Returns the number of tasks created.
func (s *Server) generateTasks() int {
	domains, err := s.db.ListKnowledgeDomains()
	if err != nil {
		log.Printf("[worker] list knowledge domains: %v", err)
		return 0
	}

	created := 0
	now := time.Now().Unix()

	for _, d := range domains {
		// Synthesize task: domain has >= 5 entries
		if d.Count >= 5 {
			exists, err := s.db.HasUnclaimedTaskForDomain(storage.TaskSynthesize, d.Domain)
			if err != nil {
				log.Printf("[worker] check unclaimed task: %v", err)
				continue
			}
			if !exists {
				priority := d.Count / 2
				if priority > 10 {
					priority = 10
				}
				task := &storage.ComputeTask{
					ID:          uuid.New().String(),
					Type:        storage.TaskSynthesize,
					Domain:      d.Domain,
					Description: fmt.Sprintf("%d unmerged observations in %s. Synthesize into coherent summary.", d.Count, d.Domain),
					Priority:    priority,
					CreatedAt:   now,
				}
				if err := s.db.CreateComputeTask(task); err != nil {
					log.Printf("[worker] create synthesize task: %v", err)
				} else {
					created++
				}
			}
		}

		// Verify task: low confidence domain
		if d.AvgConfidence < 0.5 && d.Count > 0 {
			exists, err := s.db.HasUnclaimedTaskForDomain(storage.TaskVerify, d.Domain)
			if err != nil {
				log.Printf("[worker] check unclaimed verify task: %v", err)
				continue
			}
			if !exists {
				task := &storage.ComputeTask{
					ID:          uuid.New().String(),
					Type:        storage.TaskVerify,
					Domain:      d.Domain,
					Description: fmt.Sprintf("Low confidence in %s (avg %.2f). Cross-check claims.", d.Domain, d.AvgConfidence),
					Priority:    5,
					CreatedAt:   now,
				}
				if err := s.db.CreateComputeTask(task); err != nil {
					log.Printf("[worker] create verify task: %v", err)
				} else {
					created++
				}
			}
		}
	}

	return created
}

// --- Reputation Decay Worker ---

// runReputationDecay periodically applies reputation decay (every hour).
func (s *Server) runReputationDecay(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Hour):
			n := s.decayReputation()
			if n > 0 {
				log.Printf("[worker] decayed reputation for %d operators", n)
			}
		}
	}
}

// decayReputation applies a 0.995 multiplicative decay to all operator
// reputations. Half-life is approximately 30 days with hourly application.
// Returns the number of operators whose reputation was updated.
func (s *Server) decayReputation() int {
	ops, err := s.db.ListOperators()
	if err != nil {
		log.Printf("[worker] list operators for decay: %v", err)
		return 0
	}

	decayed := 0
	for _, op := range ops {
		if op.Reputation <= 0 {
			continue
		}
		newRep := op.Reputation * 0.995
		if newRep < 0.01 {
			newRep = 0
		}
		if err := s.db.UpdateOperatorReputation(op.ID, newRep); err != nil {
			log.Printf("[worker] update operator %s reputation: %v", op.ID, err)
			continue
		}
		decayed++
	}
	return decayed
}
