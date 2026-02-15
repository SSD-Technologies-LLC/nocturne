package mesh

import (
	"fmt"
	"sync"
	"time"
)

// NodeInfo describes a mesh node.
type NodeInfo struct {
	ID          string
	Address     string
	PublicKey   []byte
	ShardSecret []byte // shared secret for shard download auth
	MaxStorage  int64
	UsedStorage int64
	LastSeen    time.Time
	Online      bool
}

// ShardInfo describes a data shard stored on a node.
type ShardInfo struct {
	ID         string
	FileID     string
	ShardIndex int
	NodeID     string
	Size       int64
	Checksum   string
}

// TrackerStats contains summary statistics for the tracker.
type TrackerStats struct {
	NodesOnline  int   `json:"nodes_online"`
	NodesTotal   int   `json:"nodes_total"`
	TotalStorage int64 `json:"total_storage"`
	UsedStorage  int64 `json:"used_storage"`
	TotalShards  int   `json:"total_shards"`
}

// Tracker is an in-memory registry of mesh nodes and shard assignments.
type Tracker struct {
	mu     sync.RWMutex
	nodes  map[string]*NodeInfo
	shards map[string]*ShardInfo // shard ID -> info
}

// NewTracker creates a new Tracker.
func NewTracker() *Tracker {
	return &Tracker{
		nodes:  make(map[string]*NodeInfo),
		shards: make(map[string]*ShardInfo),
	}
}

// Register adds a node to the tracker and marks it online.
func (t *Tracker) Register(node *NodeInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	node.Online = true
	node.LastSeen = time.Now()
	t.nodes[node.ID] = node
}

// Heartbeat updates the LastSeen timestamp for a node.
func (t *Tracker) Heartbeat(nodeID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n, ok := t.nodes[nodeID]; ok {
		n.LastSeen = time.Now()
		n.Online = true
	}
}

// Unregister removes a node from the tracker entirely.
func (t *Tracker) Unregister(nodeID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.nodes, nodeID)
}

// OnlineNodes returns all nodes that are currently marked online.
func (t *Tracker) OnlineNodes() []*NodeInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var result []*NodeInfo
	for _, n := range t.nodes {
		if n.Online {
			result = append(result, n)
		}
	}
	return result
}

// AssignShard assigns a shard to the least-loaded online node.
func (t *Tracker) AssignShard(shard *ShardInfo) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var best *NodeInfo
	for _, n := range t.nodes {
		if !n.Online {
			continue
		}
		available := n.MaxStorage - n.UsedStorage
		if available < shard.Size {
			continue
		}
		if best == nil || n.UsedStorage < best.UsedStorage {
			best = n
		}
	}
	if best == nil {
		return fmt.Errorf("no online node with sufficient storage for shard %s", shard.ID)
	}

	shard.NodeID = best.ID
	best.UsedStorage += shard.Size
	t.shards[shard.ID] = shard
	return nil
}

// GetShardsForFile returns all shards associated with a file.
func (t *Tracker) GetShardsForFile(fileID string) []*ShardInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var result []*ShardInfo
	for _, s := range t.shards {
		if s.FileID == fileID {
			result = append(result, s)
		}
	}
	return result
}

// RemoveShards removes all shards for a given file.
func (t *Tracker) RemoveShards(fileID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, s := range t.shards {
		if s.FileID == fileID {
			// Reclaim storage on the node.
			if n, ok := t.nodes[s.NodeID]; ok {
				n.UsedStorage -= s.Size
				if n.UsedStorage < 0 {
					n.UsedStorage = 0
				}
			}
			delete(t.shards, id)
		}
	}
}

// PruneOffline marks nodes as offline if their LastSeen exceeds the timeout.
func (t *Tracker) PruneOffline(timeout time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-timeout)
	for _, n := range t.nodes {
		if n.LastSeen.Before(cutoff) {
			n.Online = false
		}
	}
}

// Stats returns summary statistics for the tracker.
func (t *Tracker) Stats() TrackerStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var stats TrackerStats
	stats.NodesTotal = len(t.nodes)
	for _, n := range t.nodes {
		if n.Online {
			stats.NodesOnline++
		}
		stats.TotalStorage += n.MaxStorage
		stats.UsedStorage += n.UsedStorage
	}
	stats.TotalShards = len(t.shards)
	return stats
}
