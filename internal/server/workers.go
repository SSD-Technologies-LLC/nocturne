package server

import "context"

// StartWorkers launches background goroutines. Currently a no-op after the
// agent network was moved to the P2P DHT layer.
func (s *Server) StartWorkers(ctx context.Context) {
	// Agent workers (TTL cleanup, task generation, reputation decay, anomaly
	// detection) have been moved to the P2P DHT layer. The centralized server
	// no longer manages agent state.
}
